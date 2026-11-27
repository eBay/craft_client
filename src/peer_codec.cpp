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
#include <craft/peer.hpp>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstring>

#include <craft/wire.hpp> // the peer v2 layouts: ONE definition, shared with the TCP binding

namespace craft::peer {

namespace {

template < typename T >
void append_pod(std::vector< uint8_t >& out, T const& v) {
    auto const* p = reinterpret_cast< uint8_t const* >(&v);
    out.insert(out.end(), p, p + sizeof(T));
}

template < typename T >
T get(uint8_t const* p) {
    T v;
    std::memcpy(&v, p, sizeof(T));
    return v;
}

wire::peer_req_hdr to_wire(peer_ctx const& c) {
    wire::peer_req_hdr h{};
    h.peer_version = wire::k_peer_version;
    std::memcpy(h.partition_id.data(), c.partition_id.data, h.partition_id.size());
    h.leader_raft_term = c.leader_raft_term;
    h.session_term = c.session_term;
    return h;
}

std::expected< peer_ctx, decode_error > from_wire(wire::peer_req_hdr const& h) {
    if (h.peer_version != wire::k_peer_version) return std::unexpected(decode_error::bad_version);
    peer_ctx c;
    std::memcpy(c.partition_id.data, h.partition_id.data(), h.partition_id.size());
    c.leader_raft_term = h.leader_raft_term;
    c.session_term = h.session_term;
    return c;
}

bool ranges_ok(std::vector< lsn_range > const& r) {
    if (r.empty() || r.size() > wire::k_fetch_max_ranges) return false;
    for (std::size_t i = 0; i < r.size(); ++i) {
        if (r[i].lo < 0 || r[i].hi < r[i].lo) return false;
        if (i > 0 && r[i].lo <= r[i - 1].hi) return false; // ascending, non-overlapping
    }
    return true;
}

} // namespace

// ── get_rs_commit_lsn ────────────────────────────────────────────────────────────────────────────

std::vector< uint8_t > encode_get_rs_commit_lsn_req(peer_ctx const& ctx, bool is_login) {
    wire::get_rs_commit_lsn_req w{};
    w.peer = to_wire(ctx);
    w.is_login = is_login ? 1 : 0;
    std::vector< uint8_t > out;
    append_pod(out, w);
    return out;
}

std::expected< poll_request, decode_error > decode_get_rs_commit_lsn_req(std::span< uint8_t const > payload) {
    if (payload.size() != sizeof(wire::get_rs_commit_lsn_req)) return std::unexpected(decode_error::truncated);
    auto const w = get< wire::get_rs_commit_lsn_req >(payload.data());
    auto ctx = from_wire(w.peer);
    if (!ctx) return std::unexpected(ctx.error());
    return poll_request{*ctx, w.is_login != 0};
}

std::vector< uint8_t > encode_get_rs_commit_lsn_rsp(poll_reply const& r) {
    wire::get_rs_commit_lsn_rsp w{};
    w.commit_lsn = r.lsns.commit_lsn;
    w.last_append_lsn = r.lsns.last_append_lsn;
    w.session_term = r.session_term;
    w.fence_term = r.fence_term;
    w.journal_floor = r.journal_floor;
    w.snapshot_receiving = r.snapshot_receiving ? 1 : 0;
    std::vector< uint8_t > out;
    append_pod(out, w);
    return out;
}

std::expected< poll_reply, decode_error > decode_get_rs_commit_lsn_rsp(std::span< uint8_t const > payload) {
    if (payload.size() != sizeof(wire::get_rs_commit_lsn_rsp)) return std::unexpected(decode_error::truncated);
    auto const w = get< wire::get_rs_commit_lsn_rsp >(payload.data());
    return poll_reply{lsn_pair{w.commit_lsn, w.last_append_lsn}, w.session_term, w.fence_term, w.journal_floor,
                      w.snapshot_receiving != 0};
}

// ── fetch_data request ───────────────────────────────────────────────────────────────────────────

std::vector< uint8_t > encode_fetch_data_req(peer_ctx const& ctx, std::vector< lsn_range > const& ranges,
                                             uint64_t max_bytes) {
    wire::fetch_data_req w{};
    w.peer = to_wire(ctx);
    w.range_count = static_cast< uint32_t >(ranges.size());
    w.max_bytes = max_bytes;
    std::vector< uint8_t > out;
    out.reserve(sizeof(w) + ranges.size() * 2 * sizeof(int64_t));
    append_pod(out, w);
    for (auto const& r : ranges) {
        append_pod(out, r.lo);
        append_pod(out, r.hi);
    }
    return out;
}

std::expected< fetch_request, decode_error > decode_fetch_data_req(std::span< uint8_t const > payload) {
    if (payload.size() < sizeof(wire::fetch_data_req)) return std::unexpected(decode_error::truncated);
    auto const w = get< wire::fetch_data_req >(payload.data());
    auto ctx = from_wire(w.peer);
    if (!ctx) return std::unexpected(ctx.error());
    if (w.range_count > wire::k_fetch_max_ranges) return std::unexpected(decode_error::malformed);
    auto const body = payload.subspan(sizeof(w));
    if (body.size() != static_cast< std::size_t >(w.range_count) * 2 * sizeof(int64_t))
        return std::unexpected(body.size() < w.range_count * 2 * sizeof(int64_t) ? decode_error::truncated
                                                                                 : decode_error::malformed);
    fetch_request req{*ctx, {}, w.max_bytes};
    req.ranges.reserve(w.range_count);
    for (uint32_t i = 0; i < w.range_count; ++i) {
        auto const* p = body.data() + i * 2 * sizeof(int64_t);
        req.ranges.push_back({get< int64_t >(p), get< int64_t >(p + sizeof(int64_t))});
    }
    if (!ranges_ok(req.ranges)) return std::unexpected(decode_error::malformed);
    return req;
}

// ── fetch_data response ──────────────────────────────────────────────────────────────────────────

fetch_data_rsp_encoded encode_fetch_data_rsp(fetch_result const& r) {
    fetch_data_rsp_encoded enc;
    enc.header.reserve(sizeof(wire::fetch_data_rsp) + r.slots.size() * sizeof(wire::fetch_slot_desc));
    wire::fetch_data_rsp h{};
    h.session_term = r.session_term;
    h.next = r.next;
    h.reclaimed_below = r.reclaimed_below;
    h.slot_count = static_cast< uint32_t >(r.slots.size());
    append_pod(enc.header, h);
    for (auto const& s : r.slots) {
        wire::fetch_slot_desc d{};
        d.lsn = s.lsn;
        d.term = s.term;
        d.lba = s.lba;
        d.len = s.len;
        d.is_empty = s.is_empty ? 1 : 0;
        d.all_zeros = s.all_zeros ? 1 : 0;
        if (!s.is_empty && !s.all_zeros) {
            for (auto const& iov : s.data.iovs) {
                d.byte_len += iov.iov_len;
                enc.data_blobs.emplace_back(static_cast< uint8_t* >(iov.iov_base), static_cast< uint32_t >(iov.iov_len),
                                            false);
            }
        }
        append_pod(enc.header, d);
    }
    return enc;
}

std::expected< fetch_result, decode_error > decode_fetch_data_rsp(sisl::io_blob const& blob) {
    uint8_t const* base = blob.cbytes();
    auto const total = static_cast< std::size_t >(blob.size());
    if (total < sizeof(wire::fetch_data_rsp)) return std::unexpected(decode_error::truncated);
    auto const h = get< wire::fetch_data_rsp >(base);
    if (h.slot_count > wire::k_fetch_max_slots) return std::unexpected(decode_error::malformed);

    auto const desc_off = sizeof(h);
    auto const desc_bytes = static_cast< std::size_t >(h.slot_count) * sizeof(wire::fetch_slot_desc);
    if (total < desc_off + desc_bytes) return std::unexpected(decode_error::truncated);

    fetch_result r;
    r.session_term = h.session_term;
    r.next = h.next;
    r.reclaimed_below = h.reclaimed_below;
    r.slots.reserve(h.slot_count);
    std::size_t data_off = desc_off + desc_bytes;
    for (uint32_t i = 0; i < h.slot_count; ++i) {
        auto const d = get< wire::fetch_slot_desc >(base + desc_off + i * sizeof(wire::fetch_slot_desc));
        if (!r.slots.empty() && d.lsn <= r.slots.back().lsn) return std::unexpected(decode_error::malformed);
        if ((d.is_empty || d.all_zeros) && d.byte_len != 0) return std::unexpected(decode_error::malformed);
        JournalSlot s;
        s.lsn = d.lsn;
        s.term = d.term;
        s.lba = d.lba;
        s.len = d.len;
        s.is_empty = d.is_empty != 0;
        s.all_zeros = d.all_zeros != 0;
        if (d.byte_len > 0) {
            if (d.byte_len > total - data_off) return std::unexpected(decode_error::truncated);
            s.data.iovs.push_back(
                iovec{const_cast< uint8_t* >(base + data_off), static_cast< std::size_t >(d.byte_len)});
            s.data.size = d.byte_len;
            data_off += static_cast< std::size_t >(d.byte_len);
        }
        r.slots.push_back(std::move(s));
    }
    if (data_off != total) return std::unexpected(decode_error::malformed); // trailing bytes
    return r;
}

std::vector< lsn_range > ranges_from(std::vector< lsn_range > const& ranges, int64_t next) {
    std::vector< lsn_range > out;
    if (next < 0) return out;
    for (auto const& r : ranges) {
        if (r.hi < next) continue;
        out.push_back({std::max(r.lo, next), r.hi});
    }
    return out;
}

// ── caller side ──

async_result< fetch_all_result > fetch_all(craft_peer& peer, peer_ctx ctx, std::vector< lsn_range > ranges,
                                           uint64_t max_bytes, std::function< void(fetch_result&) > on_chunk) {
    fetch_all_result out;
    bool first = true;
    while (!ranges.empty()) {
        auto r = co_await peer.fetch_data(ctx, ranges, max_bytes);
        if (!r) co_return std::unexpected(r.error());
        ++out.replies;
        if (first) {
            out.session_term = r->session_term;
            first = false;
        } else if (r->session_term != out.session_term) {
            // The responder took a login between two replies: what it serves now may belong to another session.
            co_return std::unexpected(make_error_condition(craft_error::STALE_TERM));
        }
        out.reclaimed_below = std::max(out.reclaimed_below, r->reclaimed_below);
        out.slots += r->slots.size();
        if (on_chunk) on_chunk(*r);
        if (r->next < 0) break;
        // A reply must cover something: `next` past the first requested dLSN.
        if (r->next <= ranges.front().lo)
            co_return std::unexpected(std::make_error_condition(std::errc::protocol_error));
        ranges = ranges_from(ranges, r->next);
    }
    co_return out;
}

} // namespace craft::peer
