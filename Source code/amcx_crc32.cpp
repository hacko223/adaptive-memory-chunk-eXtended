#include <cstdint>
#include <cstddef>

extern "C" {

static uint32_t crc_table[256];
static bool table_built = false;

static void build_table() {
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int j = 0; j < 8; ++j) {
            c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
        }
        crc_table[i] = c;
    }
    table_built = true;
}

uint32_t amcx_crc32(const uint8_t* data, int32_t len) {
    if (!table_built) {
        build_table();
    }
    uint32_t crc = 0xFFFFFFFF;
    for (int32_t i = 0; i < len; ++i) {
        crc = crc_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

int32_t amcx_accelerator_version() {
    return 1;
}

}
