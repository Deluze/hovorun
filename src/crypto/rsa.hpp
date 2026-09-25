#pragma once

// Just enough RSA for the ProudNet handshake: the client sends its CryptoAPI PUBLICKEYBLOB (RSA-1024, CALG_RSA_KEYX)
// and the server answers with a SIMPLEBLOB holding the RC4 session key encrypted to that public key with
// PKCS#1 v1.5 padding. Only public-key encryption is needed, so a tiny big-number implementation is enough.

#include <algorithm>
#include <cstdint>
#include <expected>
#include <random>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace hovorun::crypto
{

// Unsigned big integer, 32-bit limbs, least significant limb first.
class bigint
{
public:
    bigint() = default;

    static bigint from_le_bytes(const uint8_t *data, size_t size)
    {
        bigint b;
        b.m_limbs.assign((size + 3) / 4, 0);
        for (size_t i = 0; i < size; ++i)
            b.m_limbs[i / 4] |= static_cast<uint32_t>(data[i]) << (8 * (i % 4));
        b.trim();
        return b;
    }

    static bigint from_be_bytes(const std::vector<uint8_t> &be)
    {
        std::vector<uint8_t> le(be.rbegin(), be.rend());
        return from_le_bytes(le.data(), le.size());
    }

    static bigint from_u32(uint32_t v)
    {
        bigint b;
        if (v)
            b.m_limbs.push_back(v);
        return b;
    }

    // Little-endian bytes padded to exactly `size`.
    std::vector<uint8_t> to_le_bytes(size_t size) const
    {
        std::vector<uint8_t> out(size, 0);
        for (size_t i = 0; i < size && i / 4 < m_limbs.size(); ++i)
            out[i] = static_cast<uint8_t>(m_limbs[i / 4] >> (8 * (i % 4)));
        return out;
    }

    size_t bit_length() const
    {
        if (m_limbs.empty())
            return 0;
        uint32_t top = m_limbs.back();
        size_t bits = 0;
        while (top)
        {
            ++bits;
            top >>= 1;
        }
        return (m_limbs.size() - 1) * 32 + bits;
    }

    bool bit(size_t n) const
    {
        size_t limb = n / 32;
        return limb < m_limbs.size() && ((m_limbs[limb] >> (n % 32)) & 1);
    }

    static int compare(const bigint &a, const bigint &b)
    {
        if (a.m_limbs.size() != b.m_limbs.size())
            return a.m_limbs.size() < b.m_limbs.size() ? -1 : 1;
        for (size_t i = a.m_limbs.size(); i-- > 0;)
            if (a.m_limbs[i] != b.m_limbs[i])
                return a.m_limbs[i] < b.m_limbs[i] ? -1 : 1;
        return 0;
    }

    static bigint mul(const bigint &a, const bigint &b)
    {
        bigint r;
        if (a.m_limbs.empty() || b.m_limbs.empty())
            return r;
        r.m_limbs.assign(a.m_limbs.size() + b.m_limbs.size(), 0);
        for (size_t i = 0; i < a.m_limbs.size(); ++i)
        {
            uint64_t carry = 0;
            for (size_t j = 0; j < b.m_limbs.size(); ++j)
            {
                uint64_t cur = r.m_limbs[i + j] + static_cast<uint64_t>(a.m_limbs[i]) * b.m_limbs[j] + carry;
                r.m_limbs[i + j] = static_cast<uint32_t>(cur);
                carry = cur >> 32;
            }
            r.m_limbs[i + b.m_limbs.size()] += static_cast<uint32_t>(carry);
        }
        r.trim();
        return r;
    }

    // a mod m by binary long division. Slow but only runs once per connection.
    static bigint mod(const bigint &a, const bigint &m)
    {
        bigint r;
        for (size_t i = a.bit_length(); i-- > 0;)
        {
            r.shl1();
            if (a.bit(i))
            {
                if (r.m_limbs.empty())
                    r.m_limbs.push_back(0);
                r.m_limbs[0] |= 1;
            }
            if (compare(r, m) >= 0)
                r.sub(m);
        }
        return r;
    }

    static bigint mod_pow(const bigint &base, const bigint &exp, const bigint &m)
    {
        bigint result = from_u32(1);
        bigint b = mod(base, m);
        for (size_t i = exp.bit_length(); i-- > 0;)
        {
            result = mod(mul(result, result), m);
            if (exp.bit(i))
                result = mod(mul(result, b), m);
        }
        return result;
    }

private:
    void trim()
    {
        while (!m_limbs.empty() && m_limbs.back() == 0)
            m_limbs.pop_back();
    }

    void shl1()
    {
        uint32_t carry = 0;
        for (auto &limb : m_limbs)
        {
            uint32_t next = limb >> 31;
            limb = (limb << 1) | carry;
            carry = next;
        }
        if (carry)
            m_limbs.push_back(carry);
    }

    // this -= b, requires this >= b.
    void sub(const bigint &b)
    {
        int64_t borrow = 0;
        for (size_t i = 0; i < m_limbs.size(); ++i)
        {
            int64_t cur = static_cast<int64_t>(m_limbs[i]) - borrow - (i < b.m_limbs.size() ? b.m_limbs[i] : 0);
            borrow = cur < 0;
            m_limbs[i] = static_cast<uint32_t>(cur + (borrow ? (int64_t{1} << 32) : 0));
        }
        trim();
    }

    std::vector<uint32_t> m_limbs;
};

struct rsa_public_key
{
    bigint modulus;
    bigint exponent;
    size_t modulus_bytes = 0;
};

// CryptoAPI constants used in the key blobs.
constexpr uint8_t publickeyblob = 0x06;
constexpr uint8_t simpleblob = 0x01;
constexpr uint8_t cur_blob_version = 0x02;
constexpr uint32_t calg_rsa_keyx = 0x0000A400;
constexpr uint32_t calg_rc4 = 0x00006801;
constexpr uint32_t rsa1_magic = 0x31415352; // "RSA1"

inline uint32_t read_le32(const uint8_t *p)
{
    return p[0] | (p[1] << 8) | (p[2] << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

inline void write_le32(std::vector<uint8_t> &out, uint32_t v)
{
    for (int i = 0; i < 4; ++i)
        out.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

// Parses BLOBHEADER + RSAPUBKEY + little-endian modulus.
inline std::expected<rsa_public_key, std::string_view> parse_publickeyblob(std::span<const uint8_t> blob)
{
    if (blob.size() < 20 || blob[0] != publickeyblob)
        return std::unexpected("not a PUBLICKEYBLOB");
    if (read_le32(&blob[8]) != rsa1_magic)
        return std::unexpected("missing RSA1 magic");

    uint32_t bitlen = read_le32(&blob[12]);
    uint32_t pubexp = read_le32(&blob[16]);
    size_t modulus_bytes = bitlen / 8;
    if (bitlen == 0 || bitlen % 8 || blob.size() < 20 + modulus_bytes)
        return std::unexpected("bad modulus length");

    rsa_public_key key;
    key.modulus = bigint::from_le_bytes(&blob[20], modulus_bytes);
    key.exponent = bigint::from_u32(pubexp);
    key.modulus_bytes = modulus_bytes;
    return key;
}

// RSAES-PKCS1-v1_5 encryption. Returns the ciphertext in big-endian (standard) byte order.
inline std::vector<uint8_t> rsa_pkcs1_encrypt(const rsa_public_key &key, const std::vector<uint8_t> &message,
                                              std::mt19937 &rng)
{
    size_t k = key.modulus_bytes;
    if (message.size() + 11 > k)
        throw std::runtime_error("RSA message too long");

    std::vector<uint8_t> em(k, 0);
    em[0] = 0x00;
    em[1] = 0x02;
    std::uniform_int_distribution<int> nonzero(1, 255);
    size_t ps_len = k - 3 - message.size();
    for (size_t i = 0; i < ps_len; ++i)
        em[2 + i] = static_cast<uint8_t>(nonzero(rng));
    em[2 + ps_len] = 0x00;
    std::copy(message.begin(), message.end(), em.begin() + 3 + ps_len);

    bigint c = bigint::mod_pow(bigint::from_be_bytes(em), key.exponent, key.modulus);
    auto le = c.to_le_bytes(k);
    return std::vector<uint8_t>(le.rbegin(), le.rend());
}

// Builds the SIMPLEBLOB CryptImportKey expects for an RC4 session key wrapped with the client's RSA key.
// CryptoAPI stores the RSA ciphertext little-endian, so the big-endian result is reversed.
inline std::vector<uint8_t> make_rc4_simpleblob(const rsa_public_key &key, const std::vector<uint8_t> &rc4_key,
                                                std::mt19937 &rng)
{
    std::vector<uint8_t> blob;
    blob.push_back(simpleblob);
    blob.push_back(cur_blob_version);
    blob.push_back(0);
    blob.push_back(0);
    write_le32(blob, calg_rc4);
    write_le32(blob, calg_rsa_keyx);

    auto be = rsa_pkcs1_encrypt(key, rc4_key, rng);
    blob.insert(blob.end(), be.rbegin(), be.rend());
    return blob;
}

} // namespace hovorun::crypto
