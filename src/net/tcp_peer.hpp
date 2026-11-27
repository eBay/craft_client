#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <span>
#include <string>
#include <vector>

#include <craft/net/conn.hpp> // craft_conn -- raw transport, NOT wire_client (that's client-plane only)
#include <craft/wire.hpp>

#include "craft_peer.hpp"

namespace craft::net {

// The reference TCP binding of the peer plane (wire v2): one blocking connection to one member, shared by every user
// of the registry entry, so each round trip holds the connection's mutex. A reply must echo the request's id; a
// reply that does not, or a transport error, drops the connection (the next call reconnects).
class CraftTcpPeer final : public craft_peer {
public:
    static constexpr std::chrono::milliseconds k_default_op_timeout{10000};

    // `op_timeout` bounds connect and every reply wait (0: k_default_op_timeout). `max_tx` is the member volume's
    // max transfer: it caps a fetch reply's data and sizes the parse bound.
    CraftTcpPeer(std::string host, uint16_t port, peer_id_t id,
                 std::chrono::milliseconds op_timeout = std::chrono::milliseconds{0},
                 uint32_t max_tx = wire::k_default_max_tx);
    ~CraftTcpPeer() override;

    CraftTcpPeer(CraftTcpPeer const&) = delete;
    CraftTcpPeer& operator=(CraftTcpPeer const&) = delete;

    async_result< poll_reply > get_rs_commit_lsn(peer_ctx const& ctx, bool is_login) override;
    // Each returned slot owns its bytes (owned_data).
    async_result< fetch_result > fetch_data(peer_ctx const& ctx, std::vector< lsn_range > ranges,
                                            uint64_t max_bytes) override;

private:
    // One framed request/response under mu_: the reply message (msg_hdr included) or the error to return.
    result< std::vector< uint8_t > > round_trip(wire::op op, std::size_t op_hdr_size,
                                                std::span< uint8_t const > payload, uint32_t reply_bound);
    bool ensure_connected();

    std::string host_;
    uint16_t port_;
    peer_id_t id_;
    std::chrono::milliseconds op_timeout_;
    uint32_t max_tx_;

    std::mutex mu_; // one round trip at a time on the connection
    craft_conn conn_;
    bool connected_{false};
    uint16_t next_rid_{1};
};

} // namespace craft::net
