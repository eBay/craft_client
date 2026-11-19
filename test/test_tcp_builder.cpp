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

// The PUBLIC remote assembly path: craft/tcp.hpp's make_tcp_cluster() -> make_client, driven over a real
// TCP loopback. A consumer names only endpoints and the two public headers (tcp.hpp for the builder, client.hpp
// for the verbs) -- never a src/net proxy type. The server here is the reference cluster standing in for real
// replica servers; a HomeBlocks CRAFT server would be wire-compatible in its place.

#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <boost/uuid/uuid_generators.hpp>

#include <craft/client.hpp>       // the opaque handle + the free-function verbs
#include <craft/tcp.hpp>          // make_tcp_cluster -- the PUBLIC builder under test
#include "net/cluster_server.hpp" // the reference server to connect to (test-support)

#include "craft_test_util.hpp" // PAGE, blk, page_of, one_iov, rg

using namespace craft;
using namespace craft::test;

TEST(CraftTcpBuilder, ConnectAndDriveOverTcp) {
    // A reference cluster server, standing in for real replica servers listening on TCP.
    auto server = std::make_shared< net::craft_cluster_server >(3, PAGE, /*capacity=*/uint64_t{1} << 30,
                                                                /*max_tx=*/512 * 1024);
    server->start();

    // Discover endpoints the way a consumer would (from a seed / the login member list): {peer id, "host:port"}.
    auto const members = server->members();
    std::vector< replica_endpoint > eps;
    eps.reserve(members.size());
    for (std::size_t i = 0; i < members.size(); ++i) {
        peer_id_t id;
        std::memcpy(&id, members[i].id.data(), 16);
        eps.push_back({id, "127.0.0.1:" + std::to_string(server->port(i))});
    }
    volume_id_t vid;
    std::memcpy(&vid, server->volume_id().data(), 16);

    {
        // The PUBLIC assembly: make_tcp_cluster -> backends -> make_client. No internal proxy type in sight.
        auto cluster = make_tcp_cluster(eps, vid);
        client_handle const c = make_client(backends(cluster));

        ASSERT_TRUE(rg(login(c, 0x1234)).has_value());
        EXPECT_EQ(lba_size(c), PAGE);
        EXPECT_EQ(capacity(c), uint64_t{1} << 30); // surfaced from the server's login response over the wire
        EXPECT_GT(term(c), 0u);

        auto buf = page_of(0x5A);
        ASSERT_TRUE(rg(write(c, blk(3), buf.size(), one_iov(buf))).has_value());
        EXPECT_GE(commit_lsn(c), 0);

        std::vector< uint8_t > dest(PAGE, 0x00);
        ASSERT_TRUE(rg(read(c, blk(3), PAGE, one_iov(dest))).has_value());
        EXPECT_EQ(dest, buf);

        EXPECT_TRUE(rg(flush(c)).has_value());
        EXPECT_TRUE(rg(logout(c)).has_value());
    } // c destroyed first (releases its proxy refs), then cluster drains each worker -- all BEFORE stop() below

    server->stop();
}

// A replica move: the builder hands out the backend for the new endpoint in the old member's slot. Nothing connects
// until an op is issued, so no server is needed to check the swap itself.
TEST(CraftTcpBuilder, ReplaceTcpMemberSwapsTheBackendInPlace) {
    volume_id_t const vid = boost::uuids::random_generator()();
    std::vector< replica_endpoint > members;
    for (int i = 0; i < 3; ++i)
        members.push_back({boost::uuids::random_generator()(), "127.0.0.1:" + std::to_string(9000 + i)});
    auto cluster = make_tcp_cluster(members, vid);
    auto const before = backends(cluster);

    replica_endpoint const moved{boost::uuids::random_generator()(), "127.0.0.2:9100"};
    auto const b = replace_tcp_member(cluster, members[1].id, moved);
    ASSERT_NE(b, nullptr);
    auto const now = backends(cluster);
    ASSERT_EQ(now.size(), 3u);
    EXPECT_EQ(now[1], b);
    EXPECT_NE(now[1], before[1]);
    EXPECT_EQ(now[0], before[0]);
    EXPECT_EQ(now[2], before[2]);
    EXPECT_EQ(replace_tcp_member(cluster, members[1].id, moved), nullptr) << "member 1 is no longer in the set";

    // A new id another slot already holds is refused BEFORE anything changes: the cluster stays as it was, so a
    // corrected retry for the same slot still works.
    EXPECT_EQ(replace_tcp_member(cluster, members[0].id, {members[2].id, "127.0.0.3:9200"}), nullptr);
    EXPECT_EQ(backends(cluster), now);
    auto const again = replace_tcp_member(cluster, members[0].id, {members[0].id, "127.0.0.3:9200"});
    ASSERT_NE(again, nullptr) << "keeping the slot's own id is allowed";
    EXPECT_EQ(backends(cluster)[0], again);

    // A malformed "host:port" throws, as documented (like make_tcp_cluster), and leaves the cluster unchanged;
    // ublkpp's craft_disk::replace_member turns it into invalid_argument.
    auto const before_bad = backends(cluster);
    for (char const* bad : {"127.0.0.4", "127.0.0.4:", ":9000", "host:90x", "host:0", "host:65536", "host:123456"})
        EXPECT_THROW((void)replace_tcp_member(cluster, members[0].id, {members[0].id, bad}), std::invalid_argument)
            << bad;
    EXPECT_EQ(backends(cluster), before_bad);
}
