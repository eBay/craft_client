#include "net/tcp_peer.hpp"

#include <cstring>

#include <craft/status.hpp> // status_to_error

namespace craft::net {

namespace {
auto fail(std::error_condition e) { return std::unexpected(e); }

std::error_condition net_to_error(net_error e) {
    switch (e) {
    case net_error::send:
    case net_error::setup:
    case net_error::connect:
        return make_error_condition(craft_error::REPLICA_DOWN);
    case net_error::recv:
    case net_error::closed:
    case net_error::malformed:
    case net_error::timed_out:
        return std::make_error_condition(std::errc::timed_out);
    case net_error::invalid_argument:
        return std::make_error_condition(std::errc::invalid_argument);
    }
    return make_error_condition(craft_error::REPLICA_DOWN);
}
} // namespace

CraftTcpPeer::CraftTcpPeer(std::string host, uint16_t port, peer_id_t id, std::chrono::milliseconds op_timeout,
                           uint32_t max_tx) :
        host_{std::move(host)},
        port_{port},
        id_{id},
        op_timeout_{op_timeout > std::chrono::milliseconds{0} ? op_timeout : k_default_op_timeout},
        max_tx_{max_tx} {}

CraftTcpPeer::~CraftTcpPeer() = default;

bool CraftTcpPeer::ensure_connected() {
    if (connected_) return true;
    auto c = craft_conn::connect(host_, port_, op_timeout_);
    if (!c) return false;
    conn_ = std::move(*c);
    connected_ = true;
    return true;
}

result< std::vector< uint8_t > > CraftTcpPeer::round_trip(wire::op op, std::size_t op_hdr_size,
                                                          std::span< uint8_t const > payload, uint32_t reply_bound) {
    std::lock_guard g{mu_};
    if (!ensure_connected()) return fail(make_error_condition(craft_error::REPLICA_DOWN));
    uint16_t const rid = next_rid_++;
    if (next_rid_ == 0) next_rid_ = 1;
    std::vector< uint8_t > out;
    wire::frame_message(out, op, 0, rid, payload.first(op_hdr_size), payload.subspan(op_hdr_size));
    if (!conn_.send_all(out)) {
        connected_ = false;
        return fail(make_error_condition(craft_error::REPLICA_DOWN)); // never delivered
    }
    auto msg = conn_.recv_message(reply_bound, op_timeout_);
    if (!msg) {
        connected_ = false; // a late reply would otherwise answer the next request
        return fail(net_to_error(msg.error()));
    }
    auto const parsed = wire::parse_message(*msg, reply_bound);
    if (!parsed || parsed->hdr.request_id != rid || parsed->hdr.op != static_cast< uint8_t >(op) + 1) {
        connected_ = false;
        return fail(std::make_error_condition(std::errc::protocol_error));
    }
    if (auto const st = static_cast< wire::status >(parsed->hdr.status); st != wire::status::ok)
        return fail(status_to_error(st));
    return std::move(*msg);
}

async_result< poll_reply > CraftTcpPeer::get_rs_commit_lsn(peer_ctx const& ctx, bool is_login) {
    auto const req = peer::encode_get_rs_commit_lsn_req(ctx, is_login);
    auto msg = round_trip(wire::op::get_rs_commit_lsn, sizeof(wire::get_rs_commit_lsn_req), req, max_tx_);
    if (!msg) co_return fail(msg.error());
    auto r = peer::decode_get_rs_commit_lsn_rsp(std::span< uint8_t const >{*msg}.subspan(sizeof(wire::msg_hdr)));
    if (!r) co_return fail(std::make_error_condition(std::errc::protocol_error));
    co_return *r;
}

async_result< fetch_result > CraftTcpPeer::fetch_data(peer_ctx const& ctx, std::vector< lsn_range > ranges,
                                                      uint64_t max_bytes) {
    // Never ask for more than this connection can parse.
    uint64_t const want = (max_bytes == 0 || max_bytes > max_tx_) ? max_tx_ : max_bytes;
    auto const req = peer::encode_fetch_data_req(ctx, ranges, want);
    auto msg =
        round_trip(wire::op::fetch_data, sizeof(wire::fetch_data_req), req, wire::fetch_reply_parse_bound(max_tx_));
    if (!msg) co_return fail(msg.error());
    auto const payload = std::span< uint8_t const >{*msg}.subspan(sizeof(wire::msg_hdr));
    auto r = peer::decode_fetch_data_rsp(
        sisl::io_blob{const_cast< uint8_t* >(payload.data()), static_cast< uint32_t >(payload.size()), false});
    if (!r) co_return fail(std::make_error_condition(std::errc::protocol_error));
    // The slots borrow from `msg`, which dies with this frame: give each its own bytes.
    for (auto& s : r->slots) {
        if (s.data.size == 0) continue;
        s.owned_data = std::make_shared< std::vector< uint8_t > >();
        s.owned_data->reserve(s.data.size);
        for (auto const& iov : s.data.iovs) {
            auto const* p = static_cast< uint8_t const* >(iov.iov_base);
            s.owned_data->insert(s.owned_data->end(), p, p + iov.iov_len);
        }
        s.data.iovs = {iovec{s.owned_data->data(), s.owned_data->size()}};
    }
    co_return std::move(*r);
}

} // namespace craft::net
