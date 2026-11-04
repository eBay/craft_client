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

// craft_auth: the AUTH proof both ends hash through. The known answers are HMAC-SHA-256 over the byte layout in
// docs/wire.md "Authentication", computed independently of this implementation.

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

#include <gtest/gtest.h>

#include <craft/auth.hpp>
#include <craft/wire.hpp>

using namespace craft::auth;

namespace {

std::string const k_password = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
constexpr std::string_view k_user = "fedcba9876543210fedcba9876543210";

template < std::size_t N >
std::array< uint8_t, N > iota_from(uint8_t first) {
    std::array< uint8_t, N > a{};
    for (std::size_t i = 0; i < N; ++i)
        a[i] = static_cast< uint8_t >(first + i);
    return a;
}

proof from_hex(std::string_view hex) {
    proof p{};
    for (std::size_t i = 0; i < p.size(); ++i)
        p[i] = static_cast< uint8_t >(std::stoul(std::string(hex.substr(2 * i, 2)), nullptr, 16));
    return p;
}

auto const k_vol = iota_from< 16 >(0x00);
auto const k_mc = iota_from< 32 >(0x20);
auto const k_ms = iota_from< 32 >(0x40);

} // namespace

TEST(CraftAuth, KnownAnswers) {
    auto const rc = compute_proof(k_password, role::client, k_vol, k_user, k_mc, k_ms);
    auto const rs = compute_proof(k_password, role::server, k_vol, k_user, k_mc, k_ms);
    ASSERT_TRUE(rc && rs);
    EXPECT_EQ(*rc, from_hex("a0fbea150e66ac564457053a180a91d9aafdd16534bf08c0e0c9c51b456abcfd"));
    EXPECT_EQ(*rs, from_hex("750424df4c787798a215b1db39702fcc17b4b4665e4cac461b563f820a4ad074"));
}

// Every input is bound into the proof: changing any one of them changes it.
TEST(CraftAuth, EveryInputIsBound) {
    auto const base = *compute_proof(k_password, role::client, k_vol, k_user, k_mc, k_ms);
    auto vol2 = k_vol;
    vol2[15] ^= 1;
    auto mc2 = k_mc;
    mc2[0] ^= 1;
    auto ms2 = k_ms;
    ms2[31] ^= 1;
    EXPECT_NE(*compute_proof(k_password + "x", role::client, k_vol, k_user, k_mc, k_ms), base);
    EXPECT_NE(*compute_proof(k_password, role::server, k_vol, k_user, k_mc, k_ms), base);
    EXPECT_NE(*compute_proof(k_password, role::client, vol2, k_user, k_mc, k_ms), base);
    EXPECT_NE(*compute_proof(k_password, role::client, k_vol, "fedcba9876543210", k_mc, k_ms), base);
    EXPECT_NE(*compute_proof(k_password, role::client, k_vol, k_user, mc2, k_ms), base);
    EXPECT_NE(*compute_proof(k_password, role::client, k_vol, k_user, k_mc, ms2), base);
    EXPECT_NE(*compute_proof(k_password, role::client, k_vol, k_user, k_ms, k_mc), base) << "nonce order matters";
}

TEST(CraftAuth, RejectsUnusableCredential) {
    std::string const max_user(craft::wire::k_auth_max_username, 'u');
    EXPECT_TRUE(compute_proof(k_password, role::client, k_vol, max_user, k_mc, k_ms).has_value());
    EXPECT_FALSE(compute_proof(k_password, role::client, k_vol, max_user + "u", k_mc, k_ms).has_value());
    EXPECT_FALSE(compute_proof(k_password, role::client, k_vol, "", k_mc, k_ms).has_value());
    EXPECT_FALSE(compute_proof("", role::client, k_vol, k_user, k_mc, k_ms).has_value());
}

TEST(CraftAuth, NoncesAndComparison) {
    auto const a = make_nonce();
    auto const b = make_nonce();
    ASSERT_TRUE(a && b);
    EXPECT_NE(*a, *b);

    auto const p = *compute_proof(k_password, role::client, k_vol, k_user, k_mc, k_ms);
    auto q = p;
    EXPECT_TRUE(proofs_equal(p, q));
    q[31] ^= 1;
    EXPECT_FALSE(proofs_equal(p, q));
}
