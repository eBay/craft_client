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

// The CRAFT AUTH proof helper (docs/wire.md "Authentication"). Client and server both hash through
// compute_proof so the two ends always hash identical bytes. Std-only header; OpenSSL stays in the .cpp.

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace craft::auth {

using nonce = std::array< uint8_t, 32 >;
using proof = std::array< uint8_t, 32 >;

enum class role : uint8_t { client, server };

/// HMAC-SHA-256(password, label(r) | volume_id | u8 len(username) | username | client_nonce | server_nonce).
/// @param password the HMAC key, as provisioned (no decoding).
/// @return nullopt if `password` or `username` is empty, `username` is longer than wire::k_auth_max_username,
///         or HMAC fails.
std::optional< proof > compute_proof(std::string_view password, role r, std::array< uint8_t, 16 > const& volume_id,
                                     std::string_view username, nonce const& client_nonce,
                                     nonce const& server_nonce) noexcept;

/// 32 bytes from a CSPRNG; nullopt if it fails.
std::optional< nonce > make_nonce() noexcept;

/// Constant-time comparison.
bool proofs_equal(proof const& a, proof const& b) noexcept;

/// Overwrite `secret`'s bytes in a way the compiler cannot elide.
void cleanse(std::string& secret) noexcept;

} // namespace craft::auth
