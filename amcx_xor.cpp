#include <cstdint>
#include <cstring>

extern "C" {

int32_t amcx_xor_parity(
    const uint8_t** buffers,
    const int32_t* buffer_lens,
    int32_t num_buffers,
    uint8_t* out_parity,
    int32_t out_len
) {
    if (!buffers || !buffer_lens || !out_parity || num_buffers <= 0) {
        return -1;
    }

    std::memset(out_parity, 0, static_cast<size_t>(out_len));

    for (int32_t b = 0; b < num_buffers; ++b) {
        const uint8_t* buf = buffers[b];
        int32_t len = buffer_lens[b];
        if (!buf) continue;
        int32_t n = (len < out_len) ? len : out_len;
        for (int32_t i = 0; i < n; ++i) {
            out_parity[i] ^= buf[i];
        }
    }

    return 0;
}

int32_t amcx_xor_recover(
    const uint8_t* parity,
    int32_t parity_len,
    const uint8_t** healthy_buffers,
    const int32_t* healthy_lens,
    int32_t num_healthy,
    uint8_t* out_recovered,
    int32_t out_len
) {
    if (!parity || !healthy_buffers || !healthy_lens || !out_recovered) {
        return -1;
    }

    int32_t n = (parity_len < out_len) ? parity_len : out_len;
    std::memcpy(out_recovered, parity, static_cast<size_t>(n));

    for (int32_t b = 0; b < num_healthy; ++b) {
        const uint8_t* buf = healthy_buffers[b];
        int32_t len = healthy_lens[b];
        if (!buf) continue;
        int32_t m = (len < n) ? len : n;
        for (int32_t i = 0; i < m; ++i) {
            out_recovered[i] ^= buf[i];
        }
    }

    return 0;
}

int32_t amcx_accelerator_version() {
    return 1;
}

}
