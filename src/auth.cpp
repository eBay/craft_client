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

#include <craft/auth.hpp>

#include <string_view>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <craft/wire.hpp>

namespace craft::auth {

namespace {
constexpr std::string_view k_client_label = "craft-auth-v1 client";
constexpr std::string_view k_server_label = "craft-auth-v1 server";
static_assert(k_client_label.size() == k_server_label.size());
} // namespace

std::optional< proof > compute_proof(std::string_view password, role r, std::array< uint8_t, 16 > const& volume_id,
                                     std::string_view username, nonce const& client_nonce,
                                     nonce const& server_nonce) noexcept {
    if (password.empty() || username.empty() || username.size() > wire::k_auth_max_username) return std::nullopt;
    auto const label = (r == role::client) ? k_client_label : k_server_label;

    std::vector< uint8_t > msg;
    msg.reserve(label.size() + volume_id.size() + 1 + username.size() + client_nonce.size() + server_nonce.size());
    msg.insert(msg.end(), label.begin(), label.end());
    msg.insert(msg.end(), volume_id.begin(), volume_id.end());
    msg.push_back(static_cast< uint8_t >(username.size()));
    msg.insert(msg.end(), username.begin(), username.end());
    msg.insert(msg.end(), client_nonce.begin(), client_nonce.end());
    msg.insert(msg.end(), server_nonce.begin(), server_nonce.end());

    proof out{};
    unsigned int len = 0;
    auto const* const md = ::HMAC(::EVP_sha256(), password.data(), static_cast< int >(password.size()), msg.data(),
                                  msg.size(), out.data(), &len);
    if (nullptr == md || len != out.size()) return std::nullopt;
    return out;
}

std::optional< nonce > make_nonce() noexcept {
    nonce n{};
    if (::RAND_bytes(n.data(), static_cast< int >(n.size())) != 1) return std::nullopt;
    return n;
}

bool proofs_equal(proof const& a, proof const& b) noexcept {
    return ::CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

} // namespace craft::auth
