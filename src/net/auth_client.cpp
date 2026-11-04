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

#include "net/auth_client.hpp"

namespace craft::net {

namespace {
// The replica's status on a non-ok AUTH reply; it closes the connection right after. Only 8-10 refuse the
// credential; any other status (e.g. INTERNAL) fails this attempt without making the refusal sticky.
net_error rejection(wire::status s) noexcept {
    switch (s) {
    case wire::status::not_exposed:
        return net_error::not_exposed;
    case wire::status::stale_credential:
        return net_error::stale_credential;
    case wire::status::auth_failed:
        return net_error::auth_failed;
    default:
        return net_error::malformed;
    }
}
} // namespace

bool auth_client::usable(std::string_view username, std::string_view password) noexcept {
    return !username.empty() && username.size() <= wire::k_auth_max_username && !password.empty();
}

std::expected< auth_client, net_error > auth_client::begin(std::array< uint8_t, 16 > const& volume_id,
                                                           std::string_view username, std::string_view password) {
    if (!usable(username, password)) return std::unexpected(net_error::auth_failed);
    auto const mc = auth::make_nonce();
    if (!mc) return std::unexpected(net_error::setup);

    auth_client c;
    c.volume_id_ = volume_id;
    c.username_ = username;
    c.password_ = password;
    c.start_.version = wire::k_auth_version;
    c.start_.volume_id = volume_id;
    c.start_.client_nonce = *mc;
    return c;
}

std::span< uint8_t const > auth_client::start_header() const noexcept {
    return {reinterpret_cast< uint8_t const* >(&start_), sizeof(start_)};
}

std::span< uint8_t const > auth_client::start_body() const noexcept {
    return {reinterpret_cast< uint8_t const* >(username_.data()), username_.size()};
}

std::expected< wire::auth_proof_req, net_error > auth_client::on_challenge(wire::message const& reply) noexcept {
    if (reply.hdr.op != static_cast< uint8_t >(wire::op::auth_challenge)) return std::unexpected(net_error::malformed);
    if (auto const s = static_cast< wire::status >(reply.hdr.status); s != wire::status::ok)
        return std::unexpected(rejection(s));
    server_nonce_ = wire::decode< wire::auth_challenge_rsp >(reply.op_header).server_nonce;

    auto const rc =
        auth::compute_proof(password_, auth::role::client, volume_id_, username_, start_.client_nonce, server_nonce_);
    if (!rc) return std::unexpected(net_error::setup);
    return wire::auth_proof_req{*rc};
}

std::expected< void, net_error > auth_client::on_result(wire::message const& reply) const noexcept {
    if (reply.hdr.op != static_cast< uint8_t >(wire::op::auth_result)) return std::unexpected(net_error::malformed);
    if (auto const s = static_cast< wire::status >(reply.hdr.status); s != wire::status::ok)
        return std::unexpected(rejection(s));

    auto const expected_rs =
        auth::compute_proof(password_, auth::role::server, volume_id_, username_, start_.client_nonce, server_nonce_);
    auto const rs = wire::decode< wire::auth_result_rsp >(reply.op_header).server_proof;
    if (!expected_rs) return std::unexpected(net_error::setup);
    if (!auth::proofs_equal(*expected_rs, rs)) return std::unexpected(net_error::auth_failed);
    return {};
}

} // namespace craft::net
