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

// THE PEER PLANE -- a replica's view of another replica.
//
// The implementor is the storage backend (it is BOTH initiator and responder). craft_peer is a
// pure-virtual interface the backend provides; CRAFT invokes it. A craft_client never calls any
// of these -- they are replica-to-replica only.
//
// craft::peer::encode_* / decode_* convert peer verbs to/from flat byte buffers suitable for any
// point-to-point transport. Use the k_* constants as verb identifiers on the wire.
//
// Buffer contract:
//   encode_* returns a vector<uint8_t> the caller owns and must keep alive until the send
//   completes. encode_fetch_data_rsp additionally references JournalSlot sg_list data in-place
//   (zero-copy); that data must also outlive the send.
//   decode_fetch_data_rsp returns slots whose sg_list iovecs borrow from the input blob; the
//   blob's backing buffer must remain valid while the slots are in use.

#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

#include <sisl/fds/buffer.hpp> // sisl::sg_list, sisl::io_blob, io_blob_list_t

#include <craft/types.hpp> // async_result, lsn_pair, volume_id_t

namespace craft {

// Block-addressing units for the replica-side journal/index. The client API is byte-based;
// only JournalSlot and a replica's own per-block index speak these block units.
using lba_t = uint64_t;
using lba_count_t = uint32_t;

// One journal slot returned by fetch_data(). Replica-to-replica only; never crosses the client wire.
// Four states: data (is_empty=false, all_zeros=false), zero-fill (all_zeros=true),
// empty (is_empty=true -- verdicted permanently empty), absent (omitted from response).
struct JournalSlot {
    int64_t lsn{-1};
    uint64_t term{0}; // the session term the slot was written at; a requester rejects one a later login dropped
    bool is_empty{false};
    bool all_zeros{false};
    lba_t lba{0};
    lba_count_t len{0};
    sisl::sg_list data{}; // borrowed when returned by decode_fetch_data_rsp; see the buffer contract below
    // The owning reference to `data`'s bytes, when the producer has one: a responder sets it so the bytes outlive its
    // journal lock while the reply is serialized; a requester that copies a reply out sets it to that copy.
    std::shared_ptr< std::vector< uint8_t > > owned_data{};
};

// ── peer wire v2 vocabulary ──

// Who asks, about which partition, under which terms. A responder refuses another partition (invalid_argument) or a
// stale RAFT term (STALE_TERM). It does NOT refuse an older session term: a member that is behind is exactly the one
// with the older session. The requester judges the responder's session term instead (it comes back in every reply).
struct peer_ctx {
    volume_id_t partition_id{};
    uint64_t leader_raft_term{0};
    uint64_t session_term{0}; // a login poll carries the login's new term
};

// Inclusive [lo, hi] dLSN range.
struct lsn_range {
    int64_t lo{0};
    int64_t hi{-1};
    bool operator==(lsn_range const&) const = default;
};

// GetRSCommitLSN reply.
struct poll_reply {
    lsn_pair lsns{};
    uint64_t session_term{0};
    uint64_t fence_term{0};    // == session_term unless a login fenced this replica
    int64_t journal_floor{-1}; // the journal holds nothing at or below this (-1: nothing reclaimed)
    bool snapshot_receiving{false};
};

// FetchData reply: held slots in ascending dLSN order, at most one reply's worth.
struct fetch_result {
    std::vector< JournalSlot > slots;
    int64_t next{-1};            // first requested dLSN not covered (-1: every range was covered)
    int64_t reclaimed_below{-1}; // the responder reclaimed every slot <= this; such a slot is not "absent"
    uint64_t session_term{0};    // the responder's session term
};

// The peer-facing surface of one replica: what a peer may ask of it.
class craft_peer {
public:
    virtual ~craft_peer() = default;

    // The replica's positions -- the leader's poll. With is_login the responder fences for the login whose term is
    // ctx.session_term: from then on it refuses the old session's writes.
    virtual async_result< poll_reply > get_rs_commit_lsn(peer_ctx const& ctx, bool is_login) = 0;

    // The held slots in `ranges` (inclusive, ascending, non-overlapping), as many as fit in `max_bytes` of slot data
    // (0: the responder's own bound). A slot verdicted Empty comes back with is_empty; a slot not held is omitted
    // (but see reclaimed_below). Continue from `next` -- or use fetch_all below.
    virtual async_result< fetch_result > fetch_data(peer_ctx const& ctx, std::vector< lsn_range > ranges,
                                                    uint64_t max_bytes) = 0;
};

// ── Codec: flat byte buffers for peer verb transport ─────────────────────────────────────────────
//
// Each encode_* produces the PAYLOAD of one message: the op's fixed header struct (wire.hpp) followed by its body --
// exactly the bytes that follow msg_hdr in the TCP binding, so any point-to-point transport can carry them. The
// status of a reply travels outside the payload (msg_hdr.status in TCP).
//
// Buffer contract: encode_* returns a vector the caller owns until the send completes; encode_fetch_data_rsp also
// references each slot's data in place (zero-copy), so that data (hold JournalSlot::owned_data) must outlive the send
// too. decode_fetch_data_rsp returns slots whose iovecs borrow from the input blob.
namespace peer {

// Verb identifier strings for point-to-point transport registration.
inline constexpr std::string_view k_get_rs_commit_lsn = "craft.get_rs_commit_lsn";
inline constexpr std::string_view k_fetch_data = "craft.fetch_data";

enum class decode_error {
    truncated,   // buffer too short for the declared content
    malformed,   // counts / offsets / ordering are internally inconsistent
    bad_version, // peer_version is not wire::k_peer_version
};

struct poll_request {
    peer_ctx ctx;
    bool is_login{false};
};
std::vector< uint8_t > encode_get_rs_commit_lsn_req(peer_ctx const& ctx, bool is_login);
std::expected< poll_request, decode_error > decode_get_rs_commit_lsn_req(std::span< uint8_t const > payload);
std::vector< uint8_t > encode_get_rs_commit_lsn_rsp(poll_reply const& r);
std::expected< poll_reply, decode_error > decode_get_rs_commit_lsn_rsp(std::span< uint8_t const > payload);

struct fetch_request {
    peer_ctx ctx;
    std::vector< lsn_range > ranges;
    uint64_t max_bytes{0};
};
std::vector< uint8_t > encode_fetch_data_req(peer_ctx const& ctx, std::vector< lsn_range > const& ranges,
                                             uint64_t max_bytes);
// Refuses empty, inverted, unordered or overlapping ranges, and more than wire::k_fetch_max_ranges of them.
std::expected< fetch_request, decode_error > decode_fetch_data_req(std::span< uint8_t const > payload);

// fetch_data response encode: `header` is the op header followed by the slot descriptors; `data_blobs` reference each
// slot's data in place (zero-copy). blobs() is the whole payload, in order.
struct fetch_data_rsp_encoded {
    std::vector< uint8_t > header;
    sisl::io_blob_list_t data_blobs; // per-slot iovs only, no header entry

    // Returns a blob list valid as long as *this is alive and unmodified.
    sisl::io_blob_list_t blobs() const {
        sisl::io_blob_list_t out;
        out.reserve(1 + data_blobs.size());
        out.emplace_back(const_cast< uint8_t* >(header.data()), static_cast< uint32_t >(header.size()), false);
        out.insert(out.end(), data_blobs.begin(), data_blobs.end());
        return out;
    }
    std::size_t size() const {
        std::size_t n = header.size();
        for (auto const& b : data_blobs)
            n += b.size();
        return n;
    }
};
fetch_data_rsp_encoded encode_fetch_data_rsp(fetch_result const& r);
// Refuses descriptors out of dLSN order, data that does not add up, or trailing bytes. Slots borrow from `blob`.
std::expected< fetch_result, decode_error > decode_fetch_data_rsp(sisl::io_blob const& blob);

// The ranges still to fetch after a reply that stopped at `next` (every dLSN below `next` was covered).
std::vector< lsn_range > ranges_from(std::vector< lsn_range > const& ranges, int64_t next);

// ── caller side: fetch every range, one bounded reply at a time ──
struct fetch_all_result {
    std::size_t slots{0};        // slots handed to on_chunk
    std::size_t replies{0};      // round trips
    int64_t reclaimed_below{-1}; // the highest reclaimed_below any reply reported
    uint64_t session_term{0};    // the responder's session term (constant across the replies)
};
// Calls fetch_data until every range is covered, handing each reply to `on_chunk` (whose slots borrow from that reply
// only for the call). Stops with STALE_TERM if the responder's session term changes between replies (its data may now
// belong to another session), with EPROTO if a reply makes no progress, and with the transport's error on a failed
// call -- chunks already handed over stay valid.
async_result< fetch_all_result > fetch_all(craft_peer& peer, peer_ctx ctx, std::vector< lsn_range > ranges,
                                           uint64_t max_bytes, std::function< void(fetch_result&) > on_chunk);

} // namespace peer
} // namespace craft
