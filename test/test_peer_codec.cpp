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

// The peer plane's wire v2 codec (include/craft/peer.hpp) and the caller's fetch loop (peer::fetch_all), with no
// transport: round trips, every refusal, and paging through a fake responder.

#include <cstdint>
#include <cstring>
#include <deque>
#include <vector>

#include <gtest/gtest.h>

#include <boost/uuid/random_generator.hpp>

#include <craft/peer.hpp>
#include <craft/wire.hpp>

#include "craft_test_util.hpp" // rg (sync_get)

using namespace craft;
using craft::test::rg;

namespace {

peer_ctx ctx() { return peer_ctx{boost::uuids::random_generator()(), 7, 3}; }

std::vector< uint8_t > bytes(std::size_t n, uint8_t seed) {
    std::vector< uint8_t > v(n);
    for (std::size_t i = 0; i < n; ++i)
        v[i] = static_cast< uint8_t >(seed + i);
    return v;
}

JournalSlot data_slot(int64_t lsn, uint64_t term, std::vector< uint8_t >& buf) {
    JournalSlot s;
    s.lsn = lsn;
    s.term = term;
    s.lba = static_cast< lba_t >(lsn * 2);
    s.len = 1;
    s.data.size = buf.size();
    s.data.iovs.push_back(iovec{buf.data(), buf.size()});
    return s;
}

std::vector< uint8_t > flatten(peer::fetch_data_rsp_encoded const& e) {
    std::vector< uint8_t > out(e.header);
    for (auto const& b : e.data_blobs)
        out.insert(out.end(), b.cbytes(), b.cbytes() + b.size());
    return out;
}

std::expected< fetch_result, peer::decode_error > decode(std::vector< uint8_t >& flat) {
    return peer::decode_fetch_data_rsp(sisl::io_blob{flat.data(), static_cast< uint32_t >(flat.size()), false});
}

} // namespace

TEST(PeerCodec, PollRoundTrips) {
    auto const c = ctx();
    auto const req = peer::encode_get_rs_commit_lsn_req(c, true);
    ASSERT_EQ(req.size(), sizeof(wire::get_rs_commit_lsn_req));
    auto const d = peer::decode_get_rs_commit_lsn_req(req);
    ASSERT_TRUE(d.has_value());
    EXPECT_EQ(d->ctx.partition_id, c.partition_id);
    EXPECT_EQ(d->ctx.leader_raft_term, 7u);
    EXPECT_EQ(d->ctx.session_term, 3u);
    EXPECT_TRUE(d->is_login);

    poll_reply const r{lsn_pair{10, 12}, 3, 4, 5, true};
    auto const rsp = peer::decode_get_rs_commit_lsn_rsp(peer::encode_get_rs_commit_lsn_rsp(r));
    ASSERT_TRUE(rsp.has_value());
    EXPECT_EQ(rsp->lsns.commit_lsn, 10);
    EXPECT_EQ(rsp->lsns.last_append_lsn, 12);
    EXPECT_EQ(rsp->session_term, 3u);
    EXPECT_EQ(rsp->fence_term, 4u);
    EXPECT_EQ(rsp->journal_floor, 5);
    EXPECT_TRUE(rsp->snapshot_receiving);
}

TEST(PeerCodec, ARequestOfAnotherVersionIsRefused) {
    auto req = peer::encode_get_rs_commit_lsn_req(ctx(), false);
    req[0] = 1; // peer_version 1
    EXPECT_EQ(peer::decode_get_rs_commit_lsn_req(req).error(), peer::decode_error::bad_version);
    auto f = peer::encode_fetch_data_req(ctx(), {{0, 9}}, 0);
    f[0] = 3;
    EXPECT_EQ(peer::decode_fetch_data_req(f).error(), peer::decode_error::bad_version);
}

TEST(PeerCodec, ShortPayloadsAreRefused) {
    auto req = peer::encode_get_rs_commit_lsn_req(ctx(), false);
    req.pop_back();
    EXPECT_EQ(peer::decode_get_rs_commit_lsn_req(req).error(), peer::decode_error::truncated);
    auto rsp = peer::encode_get_rs_commit_lsn_rsp(poll_reply{});
    rsp.pop_back();
    EXPECT_EQ(peer::decode_get_rs_commit_lsn_rsp(rsp).error(), peer::decode_error::truncated);
    auto f = peer::encode_fetch_data_req(ctx(), {{0, 9}, {20, 29}}, 4096);
    f.pop_back();
    EXPECT_EQ(peer::decode_fetch_data_req(f).error(), peer::decode_error::truncated);
}

TEST(PeerCodec, FetchRequestRoundTrips) {
    auto const c = ctx();
    std::vector< lsn_range > const ranges{{0, 9}, {20, 20}, {100, 1u << 20}};
    auto const d = peer::decode_fetch_data_req(peer::encode_fetch_data_req(c, ranges, 65536));
    ASSERT_TRUE(d.has_value());
    EXPECT_EQ(d->ctx.partition_id, c.partition_id);
    EXPECT_EQ(d->ranges, ranges);
    EXPECT_EQ(d->max_bytes, 65536u);
}

TEST(PeerCodec, BadRangesAreRefused) {
    auto bad = [](std::vector< lsn_range > r) {
        return peer::decode_fetch_data_req(peer::encode_fetch_data_req(ctx(), r, 0));
    };
    EXPECT_EQ(bad({}).error(), peer::decode_error::malformed) << "no range";
    EXPECT_EQ(bad({{5, 4}}).error(), peer::decode_error::malformed) << "inverted";
    EXPECT_EQ(bad({{-1, 4}}).error(), peer::decode_error::malformed) << "negative";
    EXPECT_EQ(bad({{0, 9}, {9, 12}}).error(), peer::decode_error::malformed) << "overlapping";
    EXPECT_EQ(bad({{10, 19}, {0, 9}}).error(), peer::decode_error::malformed) << "unordered";
    std::vector< lsn_range > many;
    for (int64_t i = 0; i <= wire::k_fetch_max_ranges; ++i)
        many.push_back({2 * i, 2 * i});
    EXPECT_EQ(bad(many).error(), peer::decode_error::malformed) << "more than k_fetch_max_ranges";
    auto f = peer::encode_fetch_data_req(ctx(), {{0, 9}}, 0);
    f.push_back(0);
    EXPECT_EQ(peer::decode_fetch_data_req(f).error(), peer::decode_error::malformed) << "trailing bytes";
}

// Data, zero and Empty slots, with their terms, next and reclaimed_below; the data goes out zero-copy.
TEST(PeerCodec, FetchReplyRoundTrips) {
    auto b1 = bytes(4096, 1);
    auto b4 = bytes(8192, 9);
    fetch_result r;
    r.session_term = 6;
    r.next = 42;
    r.reclaimed_below = 0;
    r.slots.push_back(data_slot(1, 5, b1));
    JournalSlot z;
    z.lsn = 2;
    z.term = 5;
    z.all_zeros = true;
    z.len = 3;
    r.slots.push_back(z);
    JournalSlot e;
    e.lsn = 3;
    e.term = 6;
    e.is_empty = true;
    r.slots.push_back(e);
    r.slots.push_back(data_slot(4, 6, b4));

    auto const enc = peer::encode_fetch_data_rsp(r);
    ASSERT_EQ(enc.data_blobs.size(), 2u);
    EXPECT_EQ(enc.data_blobs[0].cbytes(), b1.data()) << "zero-copy: the blob points at the slot's own bytes";
    EXPECT_EQ(enc.size(), sizeof(wire::fetch_data_rsp) + 4 * sizeof(wire::fetch_slot_desc) + 4096 + 8192);

    auto flat = flatten(enc);
    auto const d = decode(flat);
    ASSERT_TRUE(d.has_value());
    EXPECT_EQ(d->session_term, 6u);
    EXPECT_EQ(d->next, 42);
    EXPECT_EQ(d->reclaimed_below, 0);
    ASSERT_EQ(d->slots.size(), 4u);
    EXPECT_EQ(d->slots[0].term, 5u);
    EXPECT_EQ(d->slots[0].lba, 2u);
    ASSERT_EQ(d->slots[0].data.size, 4096u);
    EXPECT_EQ(std::memcmp(d->slots[0].data.iovs[0].iov_base, b1.data(), 4096), 0);
    EXPECT_TRUE(d->slots[1].all_zeros);
    EXPECT_EQ(d->slots[1].len, 3u);
    EXPECT_EQ(d->slots[1].data.size, 0u);
    EXPECT_TRUE(d->slots[2].is_empty);
    EXPECT_EQ(d->slots[2].term, 6u);
    EXPECT_EQ(std::memcmp(d->slots[3].data.iovs[0].iov_base, b4.data(), 8192), 0);
}

TEST(PeerCodec, BadFetchRepliesAreRefused) {
    auto b = bytes(512, 3);
    fetch_result r;
    r.slots.push_back(data_slot(5, 1, b));
    r.slots.push_back(data_slot(4, 1, b)); // out of order
    auto flat = flatten(peer::encode_fetch_data_rsp(r));
    EXPECT_EQ(decode(flat).error(), peer::decode_error::malformed) << "descriptors out of dLSN order";

    r.slots.pop_back();
    flat = flatten(peer::encode_fetch_data_rsp(r));
    flat.push_back(0);
    EXPECT_EQ(decode(flat).error(), peer::decode_error::malformed) << "trailing bytes";
    flat.resize(flat.size() - 2);
    EXPECT_EQ(decode(flat).error(), peer::decode_error::truncated) << "data cut short";

    fetch_result many;
    many.slots.resize(wire::k_fetch_max_slots + 1);
    for (std::size_t i = 0; i < many.slots.size(); ++i) {
        many.slots[i].lsn = static_cast< int64_t >(i);
        many.slots[i].all_zeros = true;
    }
    flat = flatten(peer::encode_fetch_data_rsp(many));
    EXPECT_EQ(decode(flat).error(), peer::decode_error::malformed) << "more than k_fetch_max_slots";
}

TEST(PeerCodec, RangesFromNext) {
    std::vector< lsn_range > const r{{0, 9}, {20, 29}, {40, 49}};
    EXPECT_EQ(peer::ranges_from(r, 5), (std::vector< lsn_range >{{5, 9}, {20, 29}, {40, 49}}));
    EXPECT_EQ(peer::ranges_from(r, 15), (std::vector< lsn_range >{{20, 29}, {40, 49}}));
    EXPECT_EQ(peer::ranges_from(r, 45), (std::vector< lsn_range >{{45, 49}}));
    EXPECT_TRUE(peer::ranges_from(r, 50).empty());
    EXPECT_TRUE(peer::ranges_from(r, -1).empty()) << "-1: everything was covered";
}

// ── fetch_all against a scripted responder ──
namespace {
struct scripted_peer : craft_peer {
    std::deque< result< fetch_result > > replies;
    std::vector< std::vector< lsn_range > > asked;
    async_result< poll_reply > get_rs_commit_lsn(peer_ctx const&, bool) override { co_return poll_reply{}; }
    async_result< fetch_result > fetch_data(peer_ctx const&, std::vector< lsn_range > ranges, uint64_t) override {
        asked.push_back(ranges);
        auto r = std::move(replies.front());
        replies.pop_front();
        co_return r;
    }
};
fetch_result reply(std::vector< int64_t > lsns, int64_t next, uint64_t session_term = 3, int64_t reclaimed = -1) {
    fetch_result r;
    r.next = next;
    r.session_term = session_term;
    r.reclaimed_below = reclaimed;
    for (auto l : lsns) {
        JournalSlot s;
        s.lsn = l;
        s.all_zeros = true;
        r.slots.push_back(s);
    }
    return r;
}
} // namespace

TEST(PeerFetchAll, PagesThroughTheRanges) {
    scripted_peer p;
    p.replies.push_back(reply({0, 1, 2}, 3));
    p.replies.push_back(reply({3, 4}, 20, 3, 1));
    p.replies.push_back(reply({21, 25}, -1));
    std::vector< int64_t > got;
    auto const r = rg(peer::fetch_all(p, ctx(), {{0, 9}, {20, 29}}, 0, [&](fetch_result& c) {
        for (auto const& s : c.slots)
            got.push_back(s.lsn);
    }));
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(got, (std::vector< int64_t >{0, 1, 2, 3, 4, 21, 25}));
    EXPECT_EQ(r->replies, 3u);
    EXPECT_EQ(r->slots, 7u);
    EXPECT_EQ(r->reclaimed_below, 1);
    EXPECT_EQ(r->session_term, 3u);
    ASSERT_EQ(p.asked.size(), 3u);
    EXPECT_EQ(p.asked[1], (std::vector< lsn_range >{{3, 9}, {20, 29}}));
    EXPECT_EQ(p.asked[2], (std::vector< lsn_range >{{20, 29}}));
}

TEST(PeerFetchAll, StopsWhenTheResponderTakesALogin) {
    scripted_peer p;
    p.replies.push_back(reply({0}, 1, 3));
    p.replies.push_back(reply({1}, -1, 4)); // a login on the responder between two replies
    std::size_t chunks = 0;
    auto const r = rg(peer::fetch_all(p, ctx(), {{0, 9}}, 0, [&](fetch_result&) { ++chunks; }));
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), make_error_condition(craft_error::STALE_TERM));
    EXPECT_EQ(chunks, 1u) << "the second session's slots are not handed over";
}

TEST(PeerFetchAll, AReplyThatMakesNoProgressIsAnError) {
    scripted_peer p;
    p.replies.push_back(reply({}, 0)); // next == the first requested dLSN
    auto const r = rg(peer::fetch_all(p, ctx(), {{0, 9}}, 0, nullptr));
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), std::make_error_condition(std::errc::protocol_error));
}

TEST(PeerFetchAll, ATransportErrorStopsTheLoop) {
    scripted_peer p;
    p.replies.push_back(reply({0}, 1));
    p.replies.push_back(std::unexpected(make_error_condition(craft_error::REPLICA_DOWN)));
    std::size_t chunks = 0;
    auto const r = rg(peer::fetch_all(p, ctx(), {{0, 9}}, 0, [&](fetch_result&) { ++chunks; }));
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), make_error_condition(craft_error::REPLICA_DOWN));
    EXPECT_EQ(chunks, 1u);
}
