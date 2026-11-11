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

// The client side of AUTH against a scripted replica: the scripted half runs the server side of the exchange
// (docs/wire.md "Authentication") through craft_auth, then hands an admitted connection to the reference
// craft_tcp_server. Covers both connect paths -- the blocking proxy (CraftTcpReplica: login + IO) and the on-ring
// craft_async_conn (AUTH, then HELO) -- including the fail-closed rules: a rejected or impostor replica never sees
// LOGIN / HELO, and a credentialed client never falls back to an unauthenticated connection.

#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <sisl/async/light_task.hpp>

#include <craft/auth.hpp>
#include <craft/net/conn.hpp>
#include <craft/wire.hpp>
#include "net/async_conn.hpp"
#include "net/tcp_replica.hpp"
#include "net/tcp_server.hpp"
#include <craft/tcp.hpp>
#include "craft_replica.hpp"

#include "craft_test_util.hpp" // rg, one_iov, chdr
#include "ring_driver.hpp"

using namespace craft;
using namespace craft::test;
namespace net = craft::net;

namespace {

constexpr uint32_t k_lba = 4096;
constexpr uint32_t k_max_tx = 512 * 1024;
constexpr uint64_t k_token = 0xA17Bu;
constexpr auto k_timeout = std::chrono::milliseconds{2000};

std::array< uint8_t, 16 > const k_vol{0xA0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0x0F};
auth_credential const k_cred{.username = "0123456789abcdef0123456789abcdef", .password = std::string(64, 'p')};

net::server_geometry make_geo() {
    wire::member self{};
    self.addr = "127.0.0.1:0";
    self.id[0] = 0x01;
    return net::server_geometry{.capacity = uint64_t{1} << 30, .lba_size = k_lba, .max_tx = k_max_tx, .member = self};
}

// What the scripted replica holds and how it behaves.
struct replica_script {
    auth_credential cred{k_cred};
    bool enforce = true;      // false: a reference server that does not do AUTH at all
    bool exposed = true;      // false: answers NOT_EXPOSED
    bool impostor = false;    // does not hold the secret: accepts any client proof, answers with a forged one
    bool reject_helo = false; // after AUTH, answers HELO with STALE_TERM instead of serving
    int serve_first = 0;      // with reject_helo: the first N connections are served normally
    wire::status challenge_status = wire::status::ok; // non-ok: answer AUTH_START with it
    int connections = 1;                              // connections accepted (0 = the client must never connect)
};

void reply(net::craft_conn& conn, wire::op o, wire::status s, uint16_t rid, std::array< uint8_t, 32 > const& hdr) {
    std::vector< uint8_t > out;
    wire::frame_message(out, o, static_cast< uint8_t >(s), rid, hdr, {});
    conn.send_all(out);
}

// The server side of AUTH. true = admitted.
bool serve_auth(net::craft_conn& conn, replica_script const& rs) {
    auto msg = conn.recv_message(k_max_tx, k_timeout);
    if (!msg) return false;
    auto m = wire::parse_message(*msg, k_max_tx);
    if (!m || m->hdr.op != static_cast< uint8_t >(wire::op::auth_start)) return false;
    auto const start = wire::decode< wire::auth_start_req >(m->op_header);
    std::string const user(reinterpret_cast< char const* >(m->body.data()), m->body.size());

    wire::status st = rs.challenge_status;
    if (st == wire::status::ok && (!rs.exposed || start.volume_id != k_vol)) st = wire::status::not_exposed;
    if (st == wire::status::ok && user != rs.cred.username) st = wire::status::stale_credential;
    if (st != wire::status::ok) {
        reply(conn, wire::op::auth_challenge, st, m->hdr.request_id, {});
        return false;
    }
    auto const ms = *auth::make_nonce();
    reply(conn, wire::op::auth_challenge, wire::status::ok, m->hdr.request_id, ms);

    msg = conn.recv_message(k_max_tx, k_timeout);
    if (!msg) return false;
    m = wire::parse_message(*msg, k_max_tx);
    if (!m || m->hdr.op != static_cast< uint8_t >(wire::op::auth_proof)) return false;
    auto const rc = wire::decode< wire::auth_proof_req >(m->op_header).client_proof;
    auto const want = *auth::compute_proof(rs.cred.password, auth::role::client, k_vol, user, start.client_nonce, ms);
    if (!rs.impostor && !auth::proofs_equal(want, rc)) {
        reply(conn, wire::op::auth_result, wire::status::auth_failed, m->hdr.request_id, {});
        return false;
    }
    std::string const key = rs.impostor ? std::string(64, 'x') : rs.cred.password;
    auto const server_proof = *auth::compute_proof(key, auth::role::server, k_vol, user, start.client_nonce, ms);
    reply(conn, wire::op::auth_result, wire::status::ok, m->hdr.request_id, server_proof);
    return true;
}

// A scripted replica accepting up to `connections` connections, each served on its own thread by its own reference
// server (connections share no server state). Destroy every client of it before join(); join() (or the dtor, after
// a failed ASSERT) unblocks an accept() still waiting for a connection the client never made, so a regression
// fails the test instead of hanging it.
class scripted_replica {
public:
    explicit scripted_replica(replica_script rs) : rs_{std::move(rs)} {
        auto lst = net::craft_listener::bind_listen(0);
        if (!lst) throw std::runtime_error("bind_listen failed");
        lst_ = std::move(*lst);
        th_ = std::jthread([this] { run(); });
    }
    ~scripted_replica() { join(); }
    uint16_t port() const { return lst_.port(); }
    void join() {
        if (!th_.joinable()) return;
        stopping_ = true;
        while (!done_) {
            (void)net::craft_conn::connect("127.0.0.1", port(), std::chrono::milliseconds{200});
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
        th_.join();
    }
    // After join(): whether the client sent anything on a connection once the impostor answered.
    bool sent_after_impostor() const { return sent_after_impostor_; }
    // After join(): connections the client made, and those that completed AUTH (or skipped it, not enforcing).
    int accepted() const { return accepted_; }
    int admitted() const { return admitted_; }

private:
    void run() {
        std::vector< std::jthread > conns;
        for (int i = 0; i < rs_.connections; ++i) {
            auto conn = lst_.accept();
            if (!conn || stopping_) break;
            ++accepted_;
            conns.emplace_back([this, i, c = std::move(*conn)]() mutable { serve(std::move(c), i); });
        }
        done_ = true;
    }

    void serve(net::craft_conn conn, int index) {
        if (rs_.enforce && !serve_auth(conn, rs_)) return;
        ++admitted_;
        if (rs_.impostor) {
            if (conn.recv_message(k_max_tx, k_timeout).has_value()) sent_after_impostor_ = true;
            return;
        }
        if (rs_.reject_helo && index >= rs_.serve_first) {
            auto msg = conn.recv_message(k_max_tx, k_timeout);
            if (!msg) return;
            auto m = wire::parse_message(*msg, k_max_tx);
            if (!m) return;
            std::vector< uint8_t > out;
            wire::frame_message(out, wire::op::helo_rsp, static_cast< uint8_t >(wire::status::stale_term),
                                m->hdr.request_id, {}, {});
            conn.send_all(out);
            return;
        }
        net::craft_tcp_server server{make_geo()};
        server.serve(std::move(conn));
    }

    replica_script rs_;
    net::craft_listener lst_;
    std::atomic< bool > sent_after_impostor_{false};
    std::atomic< int > accepted_{0};
    std::atomic< int > admitted_{0};
    std::atomic< bool > stopping_{false};
    std::atomic< bool > done_{false};
    std::jthread th_;
};

// LOGIN through the blocking proxy; the error, or nullopt on success.
std::optional< std::error_condition > login_error(replica_script rs, std::optional< auth_credential > cred,
                                                  bool* sent_after_impostor = nullptr) {
    scripted_replica replica{std::move(rs)};
    std::optional< std::error_condition > err;
    {
        CraftTcpReplica proxy{"127.0.0.1", replica.port(), peer_id_t{}, k_vol, k_timeout, std::move(cred)};
        auto lr = rg(proxy.login(k_token));
        if (!lr) err = lr.error();
    }
    replica.join();
    if (sent_after_impostor) *sent_after_impostor = replica.sent_after_impostor();
    return err;
}

// A port nothing listens on: a client that tries to connect there gets "connection refused", never an AUTH error.
uint16_t closed_port() {
    auto lst = net::craft_listener::bind_listen(0);
    if (!lst) throw std::runtime_error("bind_listen failed");
    return lst->port();
}

using ready_result = std::optional< std::expected< void, net::net_error > >;

// Named wrapper, not a capturing lambda: its frame must outlive the first suspension.
async_status issue_ready(net::craft_async_conn* c, std::shared_ptr< ready_result > out, uint64_t term) {
    *out = co_await c->ensure_ready(k_vol, k_token, term);
    co_return sisl::ok();
}

// One craft_async_conn on a test-owned ring. `driver` is declared after `conn` so it exits the ring first --
// the craft_async_conn::shutdown contract.
struct ring_session {
    std::optional< auth_credential > cred; // before conn, which points into it
    std::unique_ptr< net::craft_async_conn > conn;
    ring_driver driver{64};

    ring_session(uint16_t port, std::optional< auth_credential > c) : cred{std::move(c)} {
        conn = std::make_unique< net::craft_async_conn >("127.0.0.1", port, wire::framed_body_max(k_max_tx, k_lba),
                                                         &driver.ring, cred ? &*cred : nullptr);
    }
    std::shared_ptr< ready_result > start(uint64_t term = 0) {
        auto out = std::make_shared< ready_result >();
        issue_ready(conn.get(), out, term).detach();
        return out;
    }
    std::expected< void, net::net_error > ready(uint64_t term = 0) {
        auto out = start(term);
        EXPECT_TRUE(driver.drive_until([&] { return out->has_value(); })) << "ensure_ready must complete";
        return out->has_value() ? **out : std::unexpected(net::net_error::timed_out);
    }
};

// AUTH then HELO on a fresh ring connection; returns ensure_ready's result.
std::expected< void, net::net_error > ready_on_ring(replica_script rs, std::optional< auth_credential > cred,
                                                    bool* sent_after_impostor = nullptr) {
    scripted_replica replica{std::move(rs)};
    std::expected< void, net::net_error > r;
    {
        ring_session ring{replica.port(), std::move(cred)};
        r = ring.ready();
        if (r) EXPECT_TRUE(ring.conn->ready());
    }
    replica.join();
    if (sent_after_impostor) *sent_after_impostor = replica.sent_after_impostor();
    return r;
}

using ka_result = std::optional< std::expected< net::lsn_reply, net::net_error > >;
// Named wrapper, not a capturing lambda: its frame must outlive the first suspension.
async_status issue_conn_keep_alive(net::craft_async_conn* c, std::shared_ptr< ka_result > out) {
    *out = co_await c->keep_alive(/*commit_lsn=*/-1, /*all_committed_lsn=*/-1);
    co_return sisl::ok();
}

async_status issue_keep_alive(CraftTcpReplica* p, ::io_uring* q, client_hdr hdr,
                              std::shared_ptr< std::optional< result< lsn_pair > > > out) {
    *out = co_await p->keep_alive(q, hdr);
    co_return sisl::ok();
}

} // namespace

// ── blocking path: CraftTcpReplica (login + IO on the session-mgr connection) ──

TEST(CraftAuthHandshake, AuthenticatedLoginWriteRead) {
    scripted_replica replica{replica_script{}};
    {
        CraftTcpReplica proxy{"127.0.0.1", replica.port(), peer_id_t{}, k_vol, k_timeout, k_cred};
        auto lr = rg(proxy.login(k_token));
        ASSERT_TRUE(lr.has_value()) << lr.error().message();
        ASSERT_GT(lr->term, 0u);

        std::vector< uint8_t > data(k_lba, 0x5C);
        ASSERT_TRUE(
            rg(proxy.write(nullptr, chdr(lr->term, 0), /*dlsn=*/0, /*addr=*/0, k_lba, one_iov(data))).has_value());
        std::vector< uint8_t > dst(k_lba, 0);
        ASSERT_TRUE(
            rg(proxy.read(nullptr, chdr(lr->term), /*read_lsn=*/0, /*addr=*/0, k_lba, one_iov(dst))).has_value());
        EXPECT_EQ(dst, data);
    }
    replica.join();
}

TEST(CraftAuthHandshake, StaleCredential) {
    auto rs = replica_script{};
    rs.cred.username = "rotated-username";
    EXPECT_EQ(login_error(rs, k_cred), make_error_condition(craft_error::STALE_CREDENTIAL));
}

TEST(CraftAuthHandshake, NotExposed) {
    auto rs = replica_script{};
    rs.exposed = false;
    EXPECT_EQ(login_error(rs, k_cred), make_error_condition(craft_error::NOT_EXPOSED));
}

TEST(CraftAuthHandshake, WrongPassword) {
    auto cred = k_cred;
    cred.password = std::string(64, 'q');
    EXPECT_EQ(login_error(replica_script{}, cred), make_error_condition(craft_error::AUTH_FAILED));
}

// A replica that does not hold the secret fails the client's check of its proof; the client never sends LOGIN.
TEST(CraftAuthHandshake, ImpostorReplicaIsRejected) {
    auto rs = replica_script{};
    rs.impostor = true;
    bool sent_after = true;
    EXPECT_EQ(login_error(rs, k_cred, &sent_after), make_error_condition(craft_error::AUTH_FAILED));
    EXPECT_FALSE(sent_after) << "the client must drop the connection, not LOGIN on it";
}

// Fail-closed: a credentialed client never falls back to an unauthenticated connection.
TEST(CraftAuthHandshake, CredentialAgainstNonAuthReplicaFails) {
    auto rs = replica_script{};
    rs.enforce = false;
    EXPECT_EQ(login_error(rs, k_cred), make_error_condition(craft_error::REPLICA_DOWN))
        << "the non-enforcing replica resets on AUTH_START; the client must not go on to LOGIN";
}

// A refusal is final for the credential: the second login fails fast without connecting. (The replica accepts
// one connection; a second attempt would sit unanswered in its backlog and time out instead.)
TEST(CraftAuthHandshake, RefusalIsSticky) {
    auto rs = replica_script{};
    rs.cred.username = "rotated-username";
    scripted_replica replica{rs};
    {
        CraftTcpReplica proxy{"127.0.0.1", replica.port(), peer_id_t{}, k_vol, k_timeout, k_cred};
        for (int i = 0; i < 2; ++i) {
            auto lr = rg(proxy.login(k_token));
            ASSERT_FALSE(lr.has_value());
            EXPECT_EQ(lr.error(), make_error_condition(craft_error::STALE_CREDENTIAL)) << "attempt " << i;
        }
    }
    replica.join();
}

// INVALID_ARGUMENT (e.g. an unsupported auth version) cannot succeed on a retry either, so it is final too.
TEST(CraftAuthHandshake, InvalidArgumentRefusalIsSticky) {
    auto rs = replica_script{};
    rs.challenge_status = wire::status::invalid_argument;
    scripted_replica replica{rs};
    {
        CraftTcpReplica proxy{"127.0.0.1", replica.port(), peer_id_t{}, k_vol, k_timeout, k_cred};
        for (int i = 0; i < 2; ++i) {
            auto lr = rg(proxy.login(k_token));
            ASSERT_FALSE(lr.has_value());
            EXPECT_EQ(lr.error(), make_error_condition(craft_error::AUTH_FAILED)) << "attempt " << i;
        }
    }
    replica.join();
    EXPECT_EQ(replica.accepted(), 1);
}

// A status outside 8-10 and INVALID_ARGUMENT (here INTERNAL) is not a refusal of the credential: the second attempt
// reconnects. Nothing was sent either way, so both are REPLICA_DOWN.
TEST(CraftAuthHandshake, NonRefusalStatusIsNotSticky) {
    auto rs = replica_script{};
    rs.challenge_status = wire::status::internal;
    rs.connections = 2;
    scripted_replica replica{rs};
    {
        CraftTcpReplica proxy{"127.0.0.1", replica.port(), peer_id_t{}, k_vol, k_timeout, k_cred};
        for (int i = 0; i < 2; ++i) {
            auto lr = rg(proxy.login(k_token));
            ASSERT_FALSE(lr.has_value());
            EXPECT_EQ(lr.error(), make_error_condition(craft_error::REPLICA_DOWN)) << "attempt " << i;
        }
    }
    replica.join();
    EXPECT_EQ(replica.accepted(), 2) << "not sticky: the second attempt reconnected";
}

TEST(CraftAuthHandshake, UnusableCredentialNeverConnects) {
    CraftTcpReplica proxy{"127.0.0.1", closed_port(), peer_id_t{},
                          k_vol,       k_timeout,     auth_credential{.username = "", .password = k_cred.password}};
    auto lr = rg(proxy.login(k_token));
    ASSERT_FALSE(lr.has_value());
    EXPECT_EQ(lr.error(), make_error_condition(craft_error::AUTH_FAILED)) << "REPLICA_DOWN would mean it connected";
}

// The proxy's on-ring path authenticates its per-ring data connection too. Each scripted connection has its own
// server, so the ring connection's server never saw the LOGIN and fences the op by term; what matters here is
// that the op got past AUTH on a second, authenticated connection.
TEST(CraftAuthHandshake, ProxyRingConnectionAuthenticates) {
    auto rs = replica_script{};
    rs.connections = 2; // the admin LOGIN connection + the ring's data connection
    scripted_replica replica{rs};
    {
        CraftTcpReplica proxy{"127.0.0.1", replica.port(), peer_id_t{}, k_vol, k_timeout, k_cred};
        auto lr = rg(proxy.login(k_token));
        ASSERT_TRUE(lr.has_value()) << lr.error().message();

        ring_driver driver{64}; // after the proxy: exits the ring before the proxy's ring connection drops
        auto out = std::make_shared< std::optional< result< lsn_pair > > >();
        issue_keep_alive(&proxy, &driver.ring, chdr(lr->term), out).detach();
        ASSERT_TRUE(driver.drive_until([&] { return out->has_value(); }));
        if (!out->value().has_value()) {
            EXPECT_EQ(out->value().error(), make_error_condition(craft_error::STALE_TERM))
                << out->value().error().message();
        }
    }
    replica.join();
    EXPECT_EQ(replica.admitted(), 2) << "the admin connection and the ring connection both completed AUTH";
}

// A refusal on the blocking path stops the proxy's ring connections too: they fail fast without connecting.
TEST(CraftAuthHandshake, ProxyRefusalIsSharedWithRingConnections) {
    auto rs = replica_script{};
    rs.cred.username = "rotated-username";
    scripted_replica replica{rs};
    {
        CraftTcpReplica proxy{"127.0.0.1", replica.port(), peer_id_t{}, k_vol, k_timeout, k_cred};
        auto lr = rg(proxy.login(k_token));
        ASSERT_FALSE(lr.has_value());
        ASSERT_EQ(lr.error(), make_error_condition(craft_error::STALE_CREDENTIAL));

        ring_driver driver{64};
        auto out = std::make_shared< std::optional< result< lsn_pair > > >();
        issue_keep_alive(&proxy, &driver.ring, chdr(1), out).detach();
        ASSERT_TRUE(driver.drive_until([&] { return out->has_value(); }));
        ASSERT_FALSE(out->value().has_value());
        EXPECT_EQ(out->value().error(), make_error_condition(craft_error::STALE_CREDENTIAL));
    }
    replica.join();
    EXPECT_EQ(replica.accepted(), 1) << "the ring connection must not reconnect with a refused credential";
}

// A HELO the replica fences on the proxy's ring connection surfaces as STALE_TERM, never REPLICA_DOWN: the client
// must not count it toward a write's Empty verdict (a successor may hold the slot).
TEST(CraftAuthHandshake, ProxyRingHeloRejectionIsStaleTerm) {
    auto rs = replica_script{};
    rs.connections = 2;
    rs.reject_helo = true;
    rs.serve_first = 1; // the admin LOGIN connection is served
    scripted_replica replica{rs};
    {
        CraftTcpReplica proxy{"127.0.0.1", replica.port(), peer_id_t{}, k_vol, k_timeout, k_cred};
        auto lr = rg(proxy.login(k_token));
        ASSERT_TRUE(lr.has_value()) << lr.error().message();

        ring_driver driver{64};
        auto out = std::make_shared< std::optional< result< lsn_pair > > >();
        issue_keep_alive(&proxy, &driver.ring, chdr(lr->term), out).detach();
        ASSERT_TRUE(driver.drive_until([&] { return out->has_value(); }));
        ASSERT_FALSE(out->value().has_value());
        EXPECT_EQ(out->value().error(), make_error_condition(craft_error::STALE_TERM))
            << out->value().error().message();
    }
    replica.join();
}

// The public builder carries replica_endpoint::credential to the proxy.
TEST(CraftAuthHandshake, TcpClusterCarriesCredential) {
    scripted_replica replica{replica_script{}};
    {
        volume_id_t vol;
        std::memcpy(&vol, k_vol.data(), 16);
        auto const ep = replica_endpoint{
            .id = peer_id_t{}, .addr = "127.0.0.1:" + std::to_string(replica.port()), .credential = k_cred};
        auto cluster = make_tcp_cluster({ep}, vol, k_timeout);
        auto lr = rg(backends(cluster).front()->login(k_token));
        EXPECT_TRUE(lr.has_value()) << lr.error().message();
    }
    replica.join();
}

TEST(CraftAuthHandshake, NoCredentialSkipsAuth) {
    auto rs = replica_script{};
    rs.enforce = false;
    EXPECT_FALSE(login_error(rs, std::nullopt).has_value());
}

// ── on-ring path: craft_async_conn::ensure_ready (connect + AUTH + HELO) ──

TEST(CraftAuthHandshake, OnRingAuthenticatesThenHelos) {
    auto const r = ready_on_ring(replica_script{}, k_cred);
    EXPECT_TRUE(r.has_value());
}

TEST(CraftAuthHandshake, OnRingStaleCredential) {
    auto rs = replica_script{};
    rs.cred.username = "rotated-username";
    auto const r = ready_on_ring(rs, k_cred);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), net::net_error::stale_credential);
}

TEST(CraftAuthHandshake, OnRingImpostorReplicaIsRejected) {
    auto rs = replica_script{};
    rs.impostor = true;
    bool sent_after = true;
    auto const r = ready_on_ring(rs, k_cred, &sent_after);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), net::net_error::auth_failed);
    EXPECT_FALSE(sent_after) << "the client must drop the connection, not HELO on it";
}

TEST(CraftAuthHandshake, OnRingNotExposed) {
    auto rs = replica_script{};
    rs.exposed = false;
    EXPECT_EQ(ready_on_ring(rs, k_cred).error(), net::net_error::not_exposed);
}

TEST(CraftAuthHandshake, OnRingWrongPassword) {
    auto cred = k_cred;
    cred.password = std::string(64, 'q');
    EXPECT_EQ(ready_on_ring(replica_script{}, cred).error(), net::net_error::auth_failed);
}

TEST(CraftAuthHandshake, OnRingCredentialAgainstNonAuthReplicaFails) {
    auto rs = replica_script{};
    rs.enforce = false;
    EXPECT_EQ(ready_on_ring(rs, k_cred).error(), net::net_error::closed);
}

TEST(CraftAuthHandshake, OnRingUnusableCredentialNeverConnects) {
    ring_session ring{closed_port(), auth_credential{.username = std::string(65, 'u'), .password = k_cred.password}};
    EXPECT_EQ(ring.ready().error(), net::net_error::auth_failed) << "connect would mean it tried to connect";
}

// Sticky on the ring too, and ops parked behind the failing connect get the same reason.
TEST(CraftAuthHandshake, OnRingRefusalIsSticky) {
    auto rs = replica_script{};
    rs.cred.username = "rotated-username";
    scripted_replica replica{rs};
    {
        ring_session ring{replica.port(), k_cred};
        auto first = ring.start();
        auto parked = ring.start();
        ASSERT_TRUE(ring.driver.drive_until([&] { return first->has_value() && parked->has_value(); }));
        EXPECT_EQ(first->value().error(), net::net_error::stale_credential);
        EXPECT_EQ(parked->value().error(), net::net_error::stale_credential);
        EXPECT_EQ(ring.ready().error(), net::net_error::stale_credential) << "no reconnect with a refused credential";
    }
    replica.join();
}

// A handshake failure leaves the pump's recv in flight. Retrying before that completion is reaped must not
// reclaim the pump (use-after-free under ASan); once it is reaped, the retry reconnects.
TEST(CraftAuthHandshake, OnRingRetryAfterHandshakeFailure) {
    auto rs = replica_script{};
    rs.reject_helo = true;
    rs.connections = 2;
    scripted_replica replica{rs};
    {
        ring_session ring{replica.port(), k_cred};
        auto first = ring.start();
        auto parked = ring.start();
        ASSERT_TRUE(ring.driver.drive_until([&] { return first->has_value() && parked->has_value(); }));
        EXPECT_EQ(first->value().error(), net::net_error::helo_rejected);
        EXPECT_EQ(parked->value().error(), net::net_error::helo_rejected) << "a parked op keeps the HELO status";
        EXPECT_EQ(ring.conn->helo_rejection(), wire::status::stale_term);

        // Both start before any reap, so both see the old pump still in flight and neither reconnects.
        auto same_term = ring.start();
        auto other_term = ring.start(/*term=*/1);
        ASSERT_TRUE(ring.driver.drive_until([&] { return same_term->has_value() && other_term->has_value(); }));
        EXPECT_EQ(same_term->value().error(), net::net_error::helo_rejected) << "the fencing status is kept";
        EXPECT_EQ(other_term->value().error(), net::net_error::connect) << "it was given for term 0, not term 1";

        ring.driver.drain_for(std::chrono::milliseconds{100});
        EXPECT_EQ(ring.ready().error(), net::net_error::helo_rejected)
            << "reconnected, re-authenticated, HELO refused again";
    }
    replica.join();
}

// ── send faults on the ring connection (review on craft_client #6) ──

// A send that fails after part of its frame is on the socket drops the connection: the fragment can never be
// followed by the next message's bytes. The op queued behind it fails too (on the dead socket), nothing is left
// pending, and the next op reconnects and goes through.
TEST(CraftAuthHandshake, OnRingSendFailureMidFrameDropsTheConnection) {
    auto rs = replica_script{};
    rs.enforce = false;
    rs.connections = 2;
    scripted_replica replica{rs};
    {
        ring_session ring{replica.port(), std::nullopt};
        ASSERT_TRUE(ring.ready().has_value());

        int calls = 0;
        ring.conn->set_send_fault_for_test([&calls](std::size_t, std::size_t) -> long {
            ++calls;
            if (calls == 1) return 10;   // the first frame: only 10 bytes go out...
            if (calls == 2) return -EIO; // ...then its send fails
            return 0;
        });
        auto a = std::make_shared< ka_result >();
        auto b = std::make_shared< ka_result >();
        issue_conn_keep_alive(ring.conn.get(), a).detach(); // takes the send slot
        issue_conn_keep_alive(ring.conn.get(), b).detach(); // queued behind it
        ASSERT_TRUE(ring.driver.drive_until([&] { return a->has_value() && b->has_value(); }));
        ASSERT_FALSE(a->value().has_value());
        EXPECT_EQ(a->value().error(), net::net_error::send);
        ASSERT_FALSE(b->value().has_value()) << "the queued op must not follow the fragment";
        EXPECT_FALSE(ring.conn->ready());

        ring.conn->set_send_fault_for_test(nullptr);
        ASSERT_TRUE(ring.ready().has_value()) << "the next op reconnects";
        auto c = std::make_shared< ka_result >();
        issue_conn_keep_alive(ring.conn.get(), c).detach();
        ASSERT_TRUE(ring.driver.drive_until([&] { return c->has_value(); }));
        EXPECT_TRUE(c->value().has_value()) << "the new connection carries traffic";
        ring.driver.drain_for(std::chrono::milliseconds{50});
    }
    replica.join();
    EXPECT_EQ(replica.accepted(), 2);
}

// A send failure that belongs to an older connection (a reconnect opened a newer one meanwhile) must not close the
// newer socket: the connection stays usable and no reconnect happens.
TEST(CraftAuthHandshake, OnRingStaleSendFailureLeavesTheNewConnection) {
    auto rs = replica_script{};
    rs.enforce = false;
    rs.connections = 2;
    scripted_replica replica{rs};
    {
        ring_session ring{replica.port(), std::nullopt};
        ASSERT_TRUE(ring.ready().has_value());

        auto* conn = ring.conn.get();
        ring.conn->set_send_fault_for_test([conn](std::size_t, std::size_t) -> long {
            conn->bump_conn_gen_for_test(); // as if a reconnect had replaced the socket this send was issued on
            return -EIO;
        });
        auto a = std::make_shared< ka_result >();
        issue_conn_keep_alive(ring.conn.get(), a).detach();
        ASSERT_TRUE(ring.driver.drive_until([&] { return a->has_value(); }));
        ASSERT_FALSE(a->value().has_value());
        EXPECT_EQ(a->value().error(), net::net_error::send);
        EXPECT_TRUE(ring.conn->ready()) << "the stale failure left the current socket alone";

        ring.conn->set_send_fault_for_test(nullptr);
        auto b = std::make_shared< ka_result >();
        issue_conn_keep_alive(ring.conn.get(), b).detach();
        ASSERT_TRUE(ring.driver.drive_until([&] { return b->has_value(); }));
        EXPECT_TRUE(b->value().has_value());
        ring.driver.drain_for(std::chrono::milliseconds{50});
    }
    replica.join();
    EXPECT_EQ(replica.accepted(), 1) << "no reconnect";
}

// The send slot survives a teardown it raced with: frame A is mid-send when a recv fault fails everything
// (fail_all frees the slot) and a reconnect opens a newer socket; frame B takes the free slot and starts sending.
// A's send then fails late. A's release must NOT free B's slot -- a third frame C would otherwise start sending
// while B is still on the socket, interleaving the two (review on craft_client #6).
TEST(CraftAuthHandshake, OnRingStaleSendCannotReleaseANewerFramesSlot) {
    auto rs = replica_script{};
    rs.enforce = false;
    rs.connections = 2;
    scripted_replica replica{rs};
    {
        ring_session ring{replica.port(), std::nullopt};
        ASSERT_TRUE(ring.ready().has_value());

        auto* conn = ring.conn.get();
        auto b = std::make_shared< ka_result >();
        int calls = 0;
        ring.conn->set_send_fault_for_test([&, conn, b](std::size_t, std::size_t) -> long {
            if (++calls != 1) return 0; // B and C send normally
            // A's first send: the connection is torn down and replaced under it, and B takes the freed slot.
            conn->fail_all_for_test();
            conn->bump_conn_gen_for_test();
            issue_conn_keep_alive(conn, b).detach(); // acquires the slot, submits its send (call 2), suspends
            return -EIO;                             // ...and A's send fails late
        });
        auto a = std::make_shared< ka_result >();
        issue_conn_keep_alive(ring.conn.get(), a).detach();
        ASSERT_TRUE(a->has_value());
        ASSERT_FALSE(a->value().has_value());
        EXPECT_EQ(a->value().error(), net::net_error::send);
        ASSERT_EQ(calls, 2);

        auto c = std::make_shared< ka_result >();
        issue_conn_keep_alive(ring.conn.get(), c).detach();
        EXPECT_EQ(calls, 2) << "C must wait for B's slot, not send next to it";

        ASSERT_TRUE(ring.driver.drive_until([&] { return b->has_value() && c->has_value(); }));
        EXPECT_TRUE(b->value().has_value());
        EXPECT_TRUE(c->value().has_value());
        EXPECT_EQ(calls, 3);
        ring.driver.drain_for(std::chrono::milliseconds{50});
    }
    replica.join();
}

// An op queued for the send slot when the connection is torn down never sends anything: it fails with `send`
// (provably never delivered), not `closed` (delivery uncertain) -- callers retire a never-delivered write's slot
// instead of pinning it until the next login (review on craft_client #6).
TEST(CraftAuthHandshake, OnRingQueuedOpFailsAsNeverSentOnTeardown) {
    auto rs = replica_script{};
    rs.enforce = false;
    rs.connections = 2;
    scripted_replica replica{rs};
    {
        ring_session ring{replica.port(), std::nullopt};
        ASSERT_TRUE(ring.ready().has_value());

        auto* conn = ring.conn.get();
        auto b = std::make_shared< ka_result >();
        int calls = 0;
        ring.conn->set_send_fault_for_test([&, conn, b](std::size_t, std::size_t) -> long {
            if (++calls == 1) {
                issue_conn_keep_alive(conn, b).detach(); // queues behind A
                conn->fail_all_for_test();               // teardown while B waits for the slot
            }
            return 0;
        });
        auto a = std::make_shared< ka_result >();
        issue_conn_keep_alive(ring.conn.get(), a).detach();
        ASSERT_TRUE(b->has_value());
        ASSERT_FALSE(b->value().has_value());
        EXPECT_EQ(b->value().error(), net::net_error::send);
        EXPECT_EQ(calls, 1) << "B never reached the socket";
        ASSERT_TRUE(ring.driver.drive_until([&] { return a->has_value(); }));
        ring.driver.drain_for(std::chrono::milliseconds{50});
    }
    replica.join();
}
