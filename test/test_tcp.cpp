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

// LOGIN / LOGOUT and the IO ops (WRITE / READ / KEEPALIVE) over a real (loopback) io_uring TCP connection --
// the wire codec driven end to end through craft_conn, with the server backing its state with a real
// MemCraftReplica (via its srv_* local-server seam). Client and server in one process. This TU is itself
// wire-only: the client and server headers pull no homeblocks header, so the test speaks wire::status /
// wire::extent_desc, and a fenced op is a VALID reply carrying STALE_TERM, not an error.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <span>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <craft/net/conn.hpp>
#include "net/wire_client.hpp"
#include "net/tcp_server.hpp"
#include "net/tcp_peer.hpp"
#include "registry_mgr.hpp"
#include "helper.hpp" // registry_key

#include <atomic>
#include <optional>
#include <craft/peer.hpp>
#include <boost/uuid/random_generator.hpp>

using namespace craft::net;
namespace wire = craft::wire;

namespace {

constexpr uint32_t k_lba = 4096;

craft::net::server_geometry make_geo() {
    craft::wire::member self{};
    self.addr = "127.0.0.1:0";
    self.id[0] = 0x01;
    return craft::net::server_geometry{
        .capacity = uint64_t{1} << 30,
        .lba_size = k_lba,
        .max_tx = 512 * 1024,
        .member = std::move(self),
    };
}

// A per-byte-nonzero pattern of `n` bytes -- nonzero so no 4 KiB page collapses to a hole on the read path
// (read_range reads an all-zero data page back thin).
std::vector< uint8_t > pattern(std::size_t n, uint8_t seed = 0) {
    std::vector< uint8_t > v(n);
    for (std::size_t i = 0; i < n; ++i)
        v[i] = static_cast< uint8_t >(1 + ((i + seed) % 251));
    return v;
}

// Stand up a fresh single-replica server on an ephemeral loopback port, connect a client, log it in, and run
// `body(client, login_result)`. The client closes at inner-scope exit so serve() sees EOF and returns before
// the jthread joins.
template < class F >
void with_session(F&& body) {
    auto lst = craft_listener::bind_listen(0);
    ASSERT_TRUE(lst.has_value());
    uint16_t const port = lst->port();

    craft_tcp_server server{make_geo()};
    std::jthread srv([&] {
        auto conn = lst->accept();
        if (conn) server.serve(std::move(*conn));
    });

    {
        auto cli = wire_client::connect("127.0.0.1", port);
        ASSERT_TRUE(cli.has_value());
        auto lr = cli->login(/*volume_id=*/{}, 0x1234); // the standalone server fronts one volume: any id binds
        ASSERT_TRUE(lr.has_value());
        body(*cli, *lr);
    }
}

} // namespace

// The commit frontier MUST advance as writes land. This is the behavioral guard for the login-watermark
// off-by-one: if LOGIN hands back "the next dLSN" instead of "the last durable dLSN", the client starts at slot 1,
// slot 0 is never written, and the replica's apply_up_to() stalls on that hole FOREVER -- commit_lsn pins at -1.
// Nothing else fails (reads still serve off the journal-tail overlay), so only a frontier check catches it. The
// symptom in production was a read walking the entire unapplied journal tail: 0.2us -> 350us per read.
TEST(CraftTcp, CommitFrontierAdvances) {
    auto lst = craft_listener::bind_listen(0);
    ASSERT_TRUE(lst.has_value());
    uint16_t const port = lst->port();

    craft_tcp_server server{make_geo()};
    std::jthread srv([&] {
        auto conn = lst->accept();
        if (conn) server.serve(std::move(*conn));
    });

    {
        auto cli = wire_client::connect("127.0.0.1", port);
        ASSERT_TRUE(cli.has_value());
        auto lr = cli->login(/*volume_id=*/{}, 0xABCD);
        ASSERT_TRUE(lr.has_value());
        ASSERT_EQ(lr->dlsn, -1) << "fresh replica: the last durable dLSN is -1, so new IO starts at 0";

        // Drive dLSNs from lr->dlsn + 1, exactly as dlsn_tracker::reset_at does.
        constexpr int N = 8;
        std::vector< uint8_t > page(k_lba, 0x5A);
        int64_t const first = lr->dlsn + 1;
        for (int i = 0; i < N; ++i) {
            int64_t const d = first + i;
            auto w = cli->write(d, static_cast< uint64_t >(d) * k_lba, k_lba, page, /*commit_lsn=*/d - 1,
                                /*all_committed=*/d - 1);
            ASSERT_TRUE(w.has_value());
            ASSERT_EQ(w->status, wire::status::ok);
            // The piggybacked commit: the replica applied everything <= the commit_lsn we stamped. If slot 0 were
            // Missing this would be pinned at -1 for every single write.
            EXPECT_EQ(w->commit_lsn, d - 1) << "commit frontier stalled at write dLSN " << d;
            EXPECT_EQ(w->last_append_lsn, d);
        }
        // One more round-trip carrying the final commit: the frontier must reach the last write.
        auto ka = cli->keep_alive(/*commit_lsn=*/first + N - 1, /*all_committed=*/first + N - 1);
        ASSERT_TRUE(ka.has_value());
        EXPECT_EQ(ka->commit_lsn, first + N - 1) << "frontier did not reach the last written dLSN";
        cli->logout();
    }
}

// login returns the geometry the server advertises; logout tears the session down; a second logout is fenced.
TEST(CraftTcp, LoginLogoutRoundTrip) {
    auto lst = craft_listener::bind_listen(0);
    ASSERT_TRUE(lst.has_value());
    uint16_t const port = lst->port();

    craft_tcp_server server{make_geo()};
    std::jthread srv([&] {
        auto conn = lst->accept();
        if (conn) server.serve(std::move(*conn));
    });

    {
        auto cli = wire_client::connect("127.0.0.1", port);
        ASSERT_TRUE(cli.has_value());

        auto lr = cli->login(/*volume_id=*/{}, 0xABCD);
        ASSERT_TRUE(lr.has_value());
        EXPECT_EQ(lr->term, 1u);
        EXPECT_EQ(lr->capacity, uint64_t{1} << 30);
        EXPECT_EQ(lr->lba_size, k_lba);
        EXPECT_EQ(lr->max_tx, 512u * 1024);
        // The login WATERMARK: the LAST dLSN already durable, which on a fresh replica is -1. NOT the next dLSN
        // to use -- the client derives that itself (next_dlsn_ = dlsn + 1). This assertion used to read `0` (and
        // the server used to send last_append_lsn + 1 to match), which meant the client started at dLSN 1 and
        // slot 0 was never written: every replica sat permanently Missing dLSN 0, apply_up_to() stalled there,
        // and commit_lsn pinned at -1 forever. Reads still served correct bytes off the journal-tail overlay, so
        // nothing failed -- it only showed up as a read walking the entire journal tail. Hence the guard below.
        EXPECT_EQ(lr->dlsn, -1);
        ASSERT_EQ(lr->members.size(), 1u);
        EXPECT_EQ(lr->members[0].addr, "127.0.0.1:0");
        EXPECT_EQ(lr->members[0].id[0], 0x01);

        auto lo = cli->logout();
        ASSERT_TRUE(lo.has_value());
        EXPECT_EQ(*lo, wire::status::ok);

        auto lo2 = cli->logout(); // the session is gone -> fenced
        ASSERT_TRUE(lo2.has_value());
        EXPECT_EQ(*lo2, wire::status::stale_term);
    }
}

// Write two blocks, read them back at the horizon, and verify the bytes round-trip.
TEST(CraftTcp, WriteReadBack) {
    with_session([](wire_client& cli, login_result const&) {
        auto const data = pattern(2 * k_lba);
        auto w = cli.write(/*dlsn=*/0, /*addr=*/0, /*len=*/2 * k_lba, {data.data(), data.size()}, /*commit=*/0);
        ASSERT_TRUE(w.has_value());
        EXPECT_EQ(w->status, wire::status::ok);
        EXPECT_EQ(w->commit_lsn, 0);
        EXPECT_EQ(w->last_append_lsn, 0);

        std::vector< uint8_t > dest(2 * k_lba, 0xEE);
        auto r = cli.read(/*read_lsn=*/0, /*addr=*/0, /*len=*/2 * k_lba, {dest.data(), dest.size()});
        ASSERT_TRUE(r.has_value());
        EXPECT_EQ(r->status, wire::status::ok);
        ASSERT_EQ(r->extents.size(), 1u);
        EXPECT_FALSE(r->extents[0].hole);
        EXPECT_EQ(r->extents[0].addr, 0u);
        EXPECT_EQ(r->extents[0].len, 2u * k_lba);
        EXPECT_EQ(dest, data);
    });
}

// Write blocks 0 and 2 but not 1; a read across all three reconstructs the middle as a zero-filled hole.
TEST(CraftTcp, SparseReadReconstructsHoles) {
    with_session([](wire_client& cli, login_result const&) {
        auto const p0 = pattern(k_lba, 0);
        auto const p2 = pattern(k_lba, 100);
        ASSERT_TRUE(cli.write(0, 0 * k_lba, k_lba, {p0.data(), p0.size()}, /*commit=*/-1).has_value());
        auto w2 = cli.write(1, 2 * k_lba, k_lba, {p2.data(), p2.size()}, /*commit=*/1); // commits dLSN 0 and 1
        ASSERT_TRUE(w2.has_value());
        EXPECT_EQ(w2->status, wire::status::ok);
        EXPECT_EQ(w2->commit_lsn, 1);

        std::vector< uint8_t > dest(3 * k_lba, 0xEE);
        auto r = cli.read(/*read_lsn=*/1, 0, 3 * k_lba, {dest.data(), dest.size()});
        ASSERT_TRUE(r.has_value());
        EXPECT_EQ(r->status, wire::status::ok);
        ASSERT_EQ(r->extents.size(), 3u);
        EXPECT_FALSE(r->extents[0].hole);
        EXPECT_EQ(r->extents[0].addr, 0u * k_lba);
        EXPECT_TRUE(r->extents[1].hole);
        EXPECT_EQ(r->extents[1].addr, 1u * k_lba);
        EXPECT_EQ(r->extents[1].len, k_lba);
        EXPECT_FALSE(r->extents[2].hole);
        EXPECT_EQ(r->extents[2].addr, 2u * k_lba);

        EXPECT_TRUE(std::equal(p0.begin(), p0.end(), dest.begin()));
        EXPECT_TRUE(std::all_of(dest.begin() + k_lba, dest.begin() + 2 * k_lba, [](uint8_t b) { return b == 0; }));
        EXPECT_TRUE(std::equal(p2.begin(), p2.end(), dest.begin() + 2 * k_lba));
    });
}

// A zero write (empty payload) unmaps its range; a later read reads it back as a zero-filled hole.
TEST(CraftTcp, ZeroWriteReadsAsHole) {
    with_session([](wire_client& cli, login_result const&) {
        auto const p0 = pattern(k_lba);
        ASSERT_TRUE(cli.write(0, 0, k_lba, {p0.data(), p0.size()}, /*commit=*/0).has_value());

        std::vector< uint8_t > d1(k_lba, 0xEE);
        auto r1 = cli.read(0, 0, k_lba, {d1.data(), d1.size()});
        ASSERT_TRUE(r1.has_value());
        ASSERT_EQ(r1->extents.size(), 1u);
        EXPECT_FALSE(r1->extents[0].hole);
        EXPECT_EQ(d1, p0);

        auto wz = cli.write(1, 0, k_lba, std::span< uint8_t const >{}, /*commit=*/1); // empty payload => zero write
        ASSERT_TRUE(wz.has_value());
        EXPECT_EQ(wz->status, wire::status::ok);
        EXPECT_EQ(wz->commit_lsn, 1);

        std::vector< uint8_t > d2(k_lba, 0xEE);
        auto r2 = cli.read(1, 0, k_lba, {d2.data(), d2.size()});
        ASSERT_TRUE(r2.has_value());
        ASSERT_EQ(r2->extents.size(), 1u);
        EXPECT_TRUE(r2->extents[0].hole);
        EXPECT_TRUE(std::all_of(d2.begin(), d2.end(), [](uint8_t b) { return b == 0; }));
    });
}

// keep_alive advances the frontier and returns the replica's {commit_lsn, last_append_lsn}.
TEST(CraftTcp, KeepAliveReturnsLsns) {
    with_session([](wire_client& cli, login_result const&) {
        auto const p = pattern(k_lba);
        ASSERT_TRUE(cli.write(0, 0, k_lba, {p.data(), p.size()}, /*commit=*/0).has_value());

        auto k = cli.keep_alive(/*commit=*/0);
        ASSERT_TRUE(k.has_value());
        EXPECT_EQ(k->status, wire::status::ok);
        EXPECT_EQ(k->commit_lsn, 0);
        EXPECT_EQ(k->last_append_lsn, 0);
    });
}

// After LOGOUT, an IO on the same connection is fenced: a valid reply carrying STALE_TERM (not a transport
// error), so the client surfaces the status in the reply, not as a net_error.
TEST(CraftTcp, PostLogoutWriteFenced) {
    with_session([](wire_client& cli, login_result const&) {
        auto lo = cli.logout();
        ASSERT_TRUE(lo.has_value());
        EXPECT_EQ(*lo, wire::status::ok);

        auto const p = pattern(k_lba);
        auto w = cli.write(0, 0, k_lba, {p.data(), p.size()}, /*commit=*/0);
        ASSERT_TRUE(w.has_value());
        EXPECT_EQ(w->status, wire::status::stale_term);
    });
}

// The connect deadline: a peer that silently drops SYNs must fail the connect at the deadline, not after the
// kernel's ~2min retry window -- on the shared session-mgr thread that hang would stall every proxy's admin
// plane. 192.0.2.1 (TEST-NET-1) is reserved-unroutable, so the SYN typically goes unanswered; an environment
// that instead rejects the route errors even faster. Either way connect must return well inside the bound.
TEST(CraftTcp, ConnectDeadlineBoundsABlackholedPeer) {
    auto const t0 = std::chrono::steady_clock::now();
    auto c = wire_client::connect("192.0.2.1", 6666, std::chrono::milliseconds{250});
    auto const elapsed = std::chrono::steady_clock::now() - t0;
    EXPECT_FALSE(c.has_value());
    EXPECT_LT(elapsed, std::chrono::seconds{5}) << "connect must fail at the deadline, not the SYN-retry window";
}

// ── peer plane (wire v2) over a real loopback socket: CraftTcpPeer against the reference server ──
namespace {

// A reference server serving `connections` connections (each on its own thread), with one partition registered so
// its peer handlers accept requests for it.
struct peer_server {
    std::optional< craft_listener > lst;
    std::shared_ptr< craft::registry_manager > reg = std::make_shared< craft::registry_manager >();
    boost::uuids::uuid partition = boost::uuids::random_generator()();
    std::unique_ptr< craft_tcp_server > server;
    std::jthread acceptor;
    uint16_t port{0};

    explicit peer_server(int connections, uint32_t max_tx = 512 * 1024) {
        auto l = craft_listener::bind_listen(0);
        EXPECT_TRUE(l.has_value());
        lst.emplace(std::move(*l));
        port = lst->port();
        auto geo = make_geo();
        geo.max_tx = max_tx;
        server = std::make_unique< craft_tcp_server >(std::move(geo), std::string{}, reg);
        reg->put< std::vector< boost::uuids::uuid > >(
            craft::registry_key("partition_info", partition),
            std::make_shared< std::vector< boost::uuids::uuid > >(std::vector< boost::uuids::uuid >{partition}));
        acceptor = std::jthread([this, connections] {
            std::vector< std::jthread > serving;
            for (int i = 0; i < connections; ++i) {
                auto conn = lst->accept();
                if (!conn) return;
                serving.emplace_back([this, c = std::move(*conn)]() mutable { server->serve(std::move(c)); });
            }
        });
    }
    craft::peer_ctx ctx(uint64_t session_term) const { return craft::peer_ctx{partition, 0, session_term}; }
};

} // namespace

// The poll returns the v2 reply: positions, the responder's session term and its (absent) journal floor.
TEST(CraftTcpPeer, PollReturnsTheV2Reply) {
    peer_server srv{2};
    uint64_t term = 0;
    {
        auto cli = wire_client::connect("127.0.0.1", srv.port);
        ASSERT_TRUE(cli.has_value());
        auto lr = cli->login({}, 0x77);
        ASSERT_TRUE(lr.has_value());
        term = lr->term;
        auto const p = pattern(k_lba);
        ASSERT_TRUE(cli->write(0, 0, k_lba, {p.data(), p.size()}, -1).has_value());
        craft::net::CraftTcpPeer peer{"127.0.0.1", srv.port, {}};
        auto const r = sisl::async::sync_get(peer.get_rs_commit_lsn(srv.ctx(term), false));
        ASSERT_TRUE(r.has_value()) << r.error().message();
        EXPECT_EQ(r->lsns.last_append_lsn, 0);
        EXPECT_EQ(r->session_term, term);
        EXPECT_EQ(r->fence_term, term) << "not fenced";
        EXPECT_EQ(r->journal_floor, -1);
        EXPECT_FALSE(r->snapshot_receiving);
    }
}

// A gap larger than one reply arrives in several bounded replies through fetch_all, every slot with its data and
// term; a zero write comes back as all_zeros.
TEST(CraftTcpPeer, AGapLargerThanMaxTxArrivesInPieces) {
    constexpr uint32_t k_max_tx = 64 * 1024; // 16 pages per reply
    constexpr int N = 40;
    peer_server srv{2, k_max_tx};
    auto cli = wire_client::connect("127.0.0.1", srv.port);
    ASSERT_TRUE(cli.has_value());
    auto lr = cli->login({}, 0x78);
    ASSERT_TRUE(lr.has_value());
    for (int d = 0; d < N; ++d) {
        auto const p = pattern(k_lba, static_cast< uint8_t >(d));
        auto w = d == 17 ? cli->write(d, uint64_t(d) * k_lba, k_lba, std::span< uint8_t const >{}, d - 1)
                         : cli->write(d, uint64_t(d) * k_lba, k_lba, {p.data(), p.size()}, d - 1);
        ASSERT_TRUE(w.has_value());
        ASSERT_EQ(w->status, wire::status::ok);
    }
    {
        craft::net::CraftTcpPeer peer{"127.0.0.1", srv.port, {}, std::chrono::milliseconds{0}, k_max_tx};
        std::vector< craft::JournalSlot > got;
        auto const r = sisl::async::sync_get(
            craft::peer::fetch_all(peer, srv.ctx(lr->term), {{0, N - 1}}, 0, [&](craft::fetch_result& c) {
                for (auto& s : c.slots)
                    got.push_back(std::move(s));
            }));
        ASSERT_TRUE(r.has_value()) << r.error().message();
        EXPECT_GE(r->replies, 3u) << "160 KiB of slot data cannot fit one 64 KiB reply";
        EXPECT_EQ(r->session_term, lr->term);
        ASSERT_EQ(got.size(), std::size_t{N});
        for (int d = 0; d < N; ++d) {
            auto const& s = got[d];
            EXPECT_EQ(s.lsn, d);
            EXPECT_EQ(s.term, lr->term) << "the slot's own session term rides the descriptor";
            if (d == 17) {
                EXPECT_TRUE(s.all_zeros);
                continue;
            }
            ASSERT_TRUE(s.owned_data) << "each slot owns its bytes once the reply buffer is gone";
            EXPECT_EQ(*s.owned_data, pattern(k_lba, static_cast< uint8_t >(d))) << "dLSN " << d;
        }
    }
}

// A request for a partition the server does not serve is refused, and so is any other peer_version.
TEST(CraftTcpPeer, AnotherPartitionOrVersionIsRefused) {
    peer_server srv{2};
    {
        craft::net::CraftTcpPeer peer{"127.0.0.1", srv.port, {}};
        craft::peer_ctx other{boost::uuids::random_generator()(), 0, 1};
        auto const p = sisl::async::sync_get(peer.get_rs_commit_lsn(other, false));
        ASSERT_FALSE(p.has_value());
        EXPECT_EQ(p.error(), std::make_error_condition(std::errc::invalid_argument));
        auto const f = sisl::async::sync_get(peer.fetch_data(other, {{0, 9}}, 0));
        ASSERT_FALSE(f.has_value());
        EXPECT_EQ(f.error(), std::make_error_condition(std::errc::invalid_argument));
    }
    {
        auto conn = craft_conn::connect("127.0.0.1", srv.port);
        ASSERT_TRUE(conn.has_value());
        auto payload = craft::peer::encode_fetch_data_req(srv.ctx(1), {{0, 9}}, 0);
        payload[0] = 1; // peer_version 1
        std::vector< uint8_t > out;
        wire::frame_message(out, wire::op::fetch_data, 0, 9,
                            std::span< uint8_t const >{payload}.first(sizeof(wire::fetch_data_req)),
                            std::span< uint8_t const >{payload}.subspan(sizeof(wire::fetch_data_req)));
        ASSERT_TRUE(conn->send_all(out));
        auto msg = conn->recv_message(wire::fetch_reply_parse_bound(512 * 1024), std::chrono::seconds{5});
        ASSERT_TRUE(msg.has_value());
        auto const parsed = wire::parse_message(*msg, wire::fetch_reply_parse_bound(512 * 1024));
        ASSERT_TRUE(parsed.has_value());
        EXPECT_EQ(static_cast< wire::status >(parsed->hdr.status), wire::status::invalid_argument);
    }
}

// One CraftTcpPeer shared by several threads: each round trip holds the connection, so every caller gets its own
// reply (before, two callers could read each other's).
TEST(CraftTcpPeer, ThreadsSharingOnePeerGetTheirOwnReplies) {
    peer_server srv{2};
    auto cli = wire_client::connect("127.0.0.1", srv.port);
    ASSERT_TRUE(cli.has_value());
    auto lr = cli->login({}, 0x79);
    ASSERT_TRUE(lr.has_value());
    for (int d = 0; d < 8; ++d) {
        auto const p = pattern(k_lba, static_cast< uint8_t >(d));
        ASSERT_TRUE(cli->write(d, uint64_t(d) * k_lba, k_lba, {p.data(), p.size()}, d - 1).has_value());
    }
    craft::net::CraftTcpPeer peer{"127.0.0.1", srv.port, {}};
    std::atomic< int > bad{0};
    {
        std::vector< std::jthread > ts;
        for (int t = 0; t < 4; ++t)
            ts.emplace_back([&, t] {
                for (int i = 0; i < 50; ++i) {
                    int64_t const d = (t + i) % 8;
                    if (t % 2 == 0) {
                        auto r = sisl::async::sync_get(peer.fetch_data(srv.ctx(lr->term), {{d, d}}, 0));
                        if (!r || r->slots.size() != 1 || r->slots[0].lsn != d ||
                            *r->slots[0].owned_data != pattern(k_lba, static_cast< uint8_t >(d)))
                            ++bad;
                    } else {
                        auto r = sisl::async::sync_get(peer.get_rs_commit_lsn(srv.ctx(lr->term), false));
                        if (!r || r->lsns.last_append_lsn != 7) ++bad;
                    }
                }
            });
    }
    EXPECT_EQ(bad.load(), 0);
}
