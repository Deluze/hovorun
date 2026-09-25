#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <utility>

namespace hovorun::crypto
{

// The client encrypts with CryptoAPI RC4 and passes Final=TRUE on every call, which resets the cipher state.
// So every message is XORed with the keystream starting from position 0: always use a fresh state per message.
inline void rc4_apply(std::span<const uint8_t> key, std::span<uint8_t> data)
{
    std::array<uint8_t, 256> s{};
    for (int i = 0; i < 256; ++i)
        s[i] = static_cast<uint8_t>(i);

    uint8_t j = 0;
    for (int i = 0; i < 256; ++i)
    {
        j = static_cast<uint8_t>(j + s[i] + key[i % key.size()]);
        std::swap(s[i], s[j]);
    }

    uint8_t i = 0;
    j = 0;
    for (auto &byte : data)
    {
        i = static_cast<uint8_t>(i + 1);
        j = static_cast<uint8_t>(j + s[i]);
        std::swap(s[i], s[j]);
        byte ^= s[static_cast<uint8_t>(s[i] + s[j])];
    }
}

} // namespace hovorun::crypto
