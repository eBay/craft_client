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
#pragma once

// INTERNAL. The concrete craft_client -- the CRAFT protocol logic (dLSN assignment, quorum broadcast, read
// routing, commit tracking). No consumer ever sees this class: a driver builds it via make_client
// ("replica.hpp") over the backends a transport builder handed it, then holds the opaque handle from
// <craft/client.hpp> and calls the free functions. Only make_client and those free functions (all defined in
// client.cpp) touch it. A storage backend is never on this side of the wire and never constructs one.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <system_error>
#include <vector>

#include <sisl/fds/buffer.hpp> // sisl::sg_list

#include "craft_replica.hpp" // the per-replica backend interface craft_client drives

#include "dlsn_tracker.hpp"   // internal: the dLSN state machine (slot_outcome, tracker_stats, read_plan)
#include "read_route_map.hpp" // internal: the per-member Missing / read-eligibility map

namespace craft {

class craft_client {
public:
    craft_client(std::vector< std::shared_ptr< craft_replica > > replicas, uint32_t leader = 0,
                 uint32_t max_inflight = 128) :
            n_(replicas.size()),
            quorum_(replicas.size() / 2 + 1),
            leader_(leader),
            tracker_(std::make_shared< dlsn_tracker >(max_inflight)) {
        member_sets_.push_back(
            std::make_unique< member_set const >(member_set{std::move(replicas), std::vector< uint64_t >(n_, 0)}));
        members_.store(member_sets_.back().get(), std::memory_order_release);
    }

    // Mid-session verbs carry the caller's queue ring (`q`, null = the blocking tier) straight through to every
    // backend leg they fan out -- one IO's whole leg chain rides one ring, so its resumptions all land back on
    // that queue's reap thread. login/logout are ringless: they bracket every ring's lifetime.
    async_status login(uint64_t client_token);
    async_result< size_t > write(::io_uring* q, uint64_t addr, uint64_t len, sisl::sg_list data);
    async_result< size_t > read(::io_uring* q, uint64_t addr, uint64_t len, sisl::sg_list dest);
    async_status flush(::io_uring* q);
    async_status logout();
    void drive_keepalives(::io_uring* q, std::size_t exclude_idx);
    // Swap the backend of member `old_id` for `backend` while IO runs (a replica move). See client.hpp.
    std::error_condition replace_member(peer_id_t const& old_id, std::shared_ptr< craft_replica > backend);

    uint32_t lba_size() const { return lba_size_; }
    uint64_t capacity() const { return capacity_; }
    uint32_t max_tx() const { return max_tx_; }
    uint64_t term() const { return term_; }
    uint64_t client_token() const { return client_token_; }
    int64_t commit_lsn() const { return tracker_->frontier(); }
    int64_t read_horizon() const { return tracker_->read_horizon(); }
    uint64_t winner_scans() const { return tracker_->winner_scans(); }
    int64_t route_folded() const { return route_->folded(); }
    bool route_caught_up(std::size_t idx) const { return route_->caught_up(idx); }
    int64_t all_committed_lsn() const { return route_->all_committed(); }
    tracker_stats dlsn_stats(std::size_t sample_limit = 16) const { return tracker_->stats(sample_limit); }
    std::size_t replica_count() const { return n_; }
    std::vector< peer_id_t > member_ids() const {
        auto const ms = members();
        std::vector< peer_id_t > ids;
        ids.reserve(ms->backends.size());
        for (auto const& b : ms->backends)
            ids.push_back(b->id());
        return ids;
    }
    uint32_t leader_index() const { return leader_; }

private:
    client_hdr make_hdr() const;
    std::size_t quorum() const { return quorum_; }
    // Trim the router's overlay from the WRITE path, exactly as dlsn_tracker batch-truncates its own
    // StreamTracker on resolve (k_trunc_batch). Without this, read_route_map::fold_to() is reached ONLY from
    // read(), so a write-only stream grows the overlay without bound and the first read after a burst pays to
    // fold all of it at once (measured: 271us of eligible() scan after 64Ki unfolded writes, vs 0.13us folded).
    // Batched on purpose: folded() is one relaxed atomic load, so a write off the batch boundary costs nothing,
    // while fold_to() itself would take the overlay's shared_lock every time.
    void maybe_fold();
    std::optional< std::error_condition > precheck(uint64_t addr, uint64_t len) const;
    async_result< lsn_pair > issue_plan(::io_uring* q, std::shared_ptr< craft_replica > const& target, client_hdr hdr,
                                        read_plan const& plan, uint64_t addr, uint64_t len, sisl::sg_list& dest);

    // The members, as one immutable snapshot swapped atomically by replace_member. Every op loads it ONCE and
    // drives that snapshot's backends; `gens[i]` is the generation of backends[i], carried into the router with
    // each reply so a reply from a replaced backend is ignored. The member count never changes.
    struct member_set {
        std::vector< std::shared_ptr< craft_replica > > backends;
        std::vector< uint64_t > gens;
    };
    //
    // A raw atomic pointer, not atomic<shared_ptr>: libstdc++ implements the latter with a lock bit on the control
    // word, so every IO's load would contend on one cache line across all blk-mq queues. Every set ever published
    // is owned by member_sets_ for the client's lifetime instead (moves are rare and a set is a few pointers), so a
    // loaded pointer never dangles. Ops that outlive the client (detached legs) copy the backend shared_ptr out.
    member_set const* members() const { return members_.load(std::memory_order_acquire); }
    std::size_t const n_;      // member count: fixed for the client's life (a move replaces, never adds/removes)
    std::size_t const quorum_; // n_ / 2 + 1
    std::atomic< member_set const* > members_{nullptr};
    std::vector< std::unique_ptr< member_set const > > member_sets_; // owns every published set; replace_mu_
    // Serializes replace_member against itself. login() does not (and cannot: it co_awaits) take it: calling
    // replace_member concurrently with login/logout is a contract violation (see client.hpp), not serialized here.
    std::mutex replace_mu_;
    uint32_t leader_{0};
    uint64_t term_{0};
    uint64_t client_token_{0};
    uint32_t lba_size_{0};
    uint64_t capacity_{0};
    uint32_t max_tx_{0};

    // shared_ptr like route_: the detached resolution-round runner retires slots into the tracker and may
    // outlive the client, so it holds this map's/tracker's lifetime rather than referencing `this`.
    std::shared_ptr< dlsn_tracker > tracker_;
    // shared_ptr, not a plain member: a detached when_quorum straggler's completion leg records into this map
    // and may finish after the client is destroyed. The leg captures a copy, so a late completion writes into
    // a still-alive (orphaned) map rather than a freed one -- the same discipline the transport uses.
    std::shared_ptr< read_route_map > route_{std::make_shared< read_route_map >()};
};

} // namespace craft
