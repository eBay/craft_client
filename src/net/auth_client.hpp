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

// The client side of the AUTH exchange (docs/wire.md "Authentication"), shared by the blocking wire_client and the
// on-ring craft_async_conn: they differ only in how a request reaches the wire and how its reply comes back. Every
// failure is fail-closed -- the caller drops the connection and never falls back to an unauthenticated one.

#include <array>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>

#include <craft/auth.hpp>
#include <craft/net/conn.hpp> // net_error
#include <craft/wire.hpp>

namespace craft::net {

// The replica refused this credential. It cannot succeed again until the caller rebuilds the connection with
// fresh attach info, so the connection holding it stops retrying (docs/transport.md "Failure detection").
inline bool is_auth_rejection(net_error e) noexcept {
    return e == net_error::not_exposed || e == net_error::stale_credential || e == net_error::auth_failed;
}

class auth_client {
public:
    /// A credential the exchange can use (docs/wire.md "Credential"); checked before connecting.
    static bool usable(std::string_view username, std::string_view password) noexcept;

    /// Draw the client nonce and build AUTH_START.
    /// @return auth_failed for an unusable username, setup if the CSPRNG fails.
    static std::expected< auth_client, net_error > begin(std::array< uint8_t, 16 > const& volume_id,
                                                         std::string_view username, std::string_view password);

    std::span< uint8_t const > start_header() const noexcept;
    std::span< uint8_t const > start_body() const noexcept;

    /// Check the AUTH_CHALLENGE reply and build the AUTH_PROOF request from it.
    std::expected< wire::auth_proof_req, net_error > on_challenge(wire::message const& reply) noexcept;

    /// Check the AUTH_RESULT reply, including the replica's proof.
    std::expected< void, net_error > on_result(wire::message const& reply) const noexcept;

private:
    auth_client() = default;

    std::array< uint8_t, 16 > volume_id_{};
    std::string username_;
    std::string password_;
    wire::auth_start_req start_{};
    auth::nonce server_nonce_{};
};

} // namespace craft::net
