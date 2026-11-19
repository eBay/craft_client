/*********************************************************************************
 * Modifications Copyright 2026 eBay Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/

// tcp_cluster: the io_uring TCP transport behind an opaque handle. The concrete class lives ENTIRELY here (never
// installed) -- the public surface is craft/tcp.hpp's free functions over tcp_cluster_handle. It builds one
// CraftTcpReplica proxy per endpoint and keeps that proxy type (and every src/net header) off the surface.
// Teardown drains each proxy's in-flight ops off the shared session-mgr thread before any proxy drops (see
// tcp_set.hpp for the same rule the reference server-side set uses).

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <string>

#include <craft/tcp.hpp>

#include "net/tcp_replica.hpp" // CraftTcpReplica (internal)

namespace craft {

namespace {
std::shared_ptr< CraftTcpReplica > make_proxy(replica_endpoint const& m, std::array< uint8_t, 16 > const& vol,
                                              std::chrono::milliseconds op_timeout) {
    auto const colon = m.addr.rfind(':'); // rfind so an IPv6-ish host with colons keeps only the last field
    auto const bad = [&m] { return std::invalid_argument("craft: malformed replica address \"" + m.addr + "\""); };
    if (colon == std::string::npos || colon == 0) throw bad(); // no ":port", or no host
    auto const port_str = m.addr.substr(colon + 1);
    // Strict: all digits, 1..65535. std::stoul alone would accept "9000x" or turn "10.0.0.1" into port 10.
    if (port_str.empty() || port_str.size() > 5 ||
        !std::all_of(port_str.begin(), port_str.end(), [](char c) { return c >= '0' && c <= '9'; }))
        throw bad();
    auto const port = std::stoul(port_str);
    if (port == 0 || port > 65535) throw bad();
    return std::make_shared< CraftTcpReplica >(m.addr.substr(0, colon), static_cast< uint16_t >(port), m.id, vol,
                                               op_timeout, m.credential);
}
} // namespace

class tcp_cluster {
public:
    tcp_cluster(std::vector< std::shared_ptr< CraftTcpReplica > > proxies,
                std::vector< std::shared_ptr< craft_replica > > backends, std::array< uint8_t, 16 > vol,
                std::chrono::milliseconds op_timeout) :
            proxies_{std::move(proxies)}, backends_{std::move(backends)}, vol_{vol}, op_timeout_{op_timeout} {}
    ~tcp_cluster() {
        for (auto& p : proxies_)
            if (p) p->shutdown(); // drain each proxy from HERE (the destroying thread) before any of them drops
    }

    std::vector< std::shared_ptr< craft_replica > > backends() const {
        std::lock_guard< std::mutex > lk{mu_};
        return backends_;
    }

    std::shared_ptr< craft_replica > replace(peer_id_t const& old_id, replica_endpoint const& member) {
        std::lock_guard< std::mutex > lk{mu_};
        // Validate before mutating: a new id that another slot already holds would leave the cluster at, say,
        // B/B/C while craft_client rejects the swap and stays at A/B/C.
        for (auto const& b : backends_)
            if (b->id() == member.id && b->id() != old_id) return nullptr;
        for (auto& b : backends_) {
            if (b->id() != old_id) continue;
            auto proxy = make_proxy(member, vol_, op_timeout_);
            b = proxy;
            proxies_.push_back(std::move(proxy)); // the old proxy stays owned (and drained at teardown)
            return b;
        }
        return nullptr;
    }

private:
    mutable std::mutex mu_;
    std::vector< std::shared_ptr< CraftTcpReplica > > proxies_; // concrete: needed to call shutdown(); old ones too
    std::vector< std::shared_ptr< craft_replica > > backends_;  // current members, in member order
    std::array< uint8_t, 16 > vol_;
    std::chrono::milliseconds op_timeout_;
};

// ── free functions: the public surface ──

tcp_cluster_handle make_tcp_cluster(std::vector< replica_endpoint > const& members, volume_id_t vol_id,
                                    std::chrono::milliseconds op_timeout) {
    std::array< uint8_t, 16 > vol{};
    std::memcpy(vol.data(), &vol_id, 16); // uuid is 16 contiguous bytes -- what HELO presents

    std::vector< std::shared_ptr< CraftTcpReplica > > proxies;
    std::vector< std::shared_ptr< craft_replica > > backends;
    proxies.reserve(members.size());
    backends.reserve(members.size());
    for (auto const& m : members) {
        auto proxy = make_proxy(m, vol, op_timeout);
        backends.push_back(proxy);
        proxies.push_back(std::move(proxy));
    }
    return std::make_shared< tcp_cluster >(std::move(proxies), std::move(backends), vol, op_timeout);
}

std::vector< std::shared_ptr< craft_replica > > backends(tcp_cluster_handle const& c) { return c->backends(); }

std::shared_ptr< craft_replica > replace_tcp_member(tcp_cluster_handle const& c, peer_id_t const& old_id,
                                                    replica_endpoint const& member) {
    return c->replace(old_id, member);
}

} // namespace craft
