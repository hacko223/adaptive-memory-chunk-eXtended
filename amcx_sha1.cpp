#include <cstdint>
#include <cstring>
#include <cstddef>

extern "C" {

struct SHA1Context {
    uint32_t state[5];
    uint64_t count;
    uint8_t buffer[64];
};

static uint32_t rol(uint32_t value, int bits) {
    return (value << bits) | (value >> (32 - bits));
}

static void sha1_transform(uint32_t state[5], const uint8_t buffer[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = (uint32_t(buffer[i * 4]) << 24) |
               (uint32_t(buffer[i * 4 + 1]) << 16) |
               (uint32_t(buffer[i * 4 + 2]) << 8) |
               (uint32_t(buffer[i * 4 + 3]));
    }
    for (int i = 16; i < 80; ++i) {
        w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];

    for (int i = 0; i < 80; ++i) {
        uint32_t f, k;
        if (i < 20)      { f = (b & c) | ((~b) & d);        k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;                   k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;                   k = 0xCA62C1D6; }

        uint32_t temp = rol(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol(b, 30); b = a; a = temp;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

void amcx_sha1(const uint8_t* data, int32_t len, uint8_t out_digest[20]) {
    uint32_t state[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};

    uint64_t bitlen = static_cast<uint64_t>(len) * 8;
    int32_t full_blocks = len / 64;

    for (int32_t i = 0; i < full_blocks; ++i) {
        sha1_transform(state, data + i * 64);
    }

    uint8_t tail[128];
    int32_t remaining = len - full_blocks * 64;
    std::memcpy(tail, data + full_blocks * 64, static_cast<size_t>(remaining));
    tail[remaining] = 0x80;

    int32_t pad_len = (remaining < 56) ? 56 - remaining - 1 : 120 - remaining - 1;
    std::memset(tail + remaining + 1, 0, static_cast<size_t>(pad_len));

    int32_t total_len = remaining + 1 + pad_len;
    for (int i = 0; i < 8; ++i) {
        tail[total_len + i] = static_cast<uint8_t>((bitlen >> (56 - 8 * i)) & 0xFF);
    }
    total_len += 8;

    for (int32_t i = 0; i < total_len; i += 64) {
        sha1_transform(state, tail + i);
    }

    for (int i = 0; i < 5; ++i) {
        out_digest[i * 4]     = static_cast<uint8_t>((state[i] >> 24) & 0xFF);
        out_digest[i * 4 + 1] = static_cast<uint8_t>((state[i] >> 16) & 0xFF);
        out_digest[i * 4 + 2] = static_cast<uint8_t>((state[i] >> 8) & 0xFF);
        out_digest[i * 4 + 3] = static_cast<uint8_t>(state[i] & 0xFF);
    }
}

int32_t amcx_accelerator_version() {
    return 1;
}

}
