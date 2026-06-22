#include <cstring>
#include <cstdint>
#include <vector>
#include <string>

extern "C" {

struct MatchResult {
    int32_t pattern_index;
    int32_t found;
};

int32_t amcx_scan_buffer(
    const char* buffer,
    int32_t buffer_len,
    const char** patterns,
    const int32_t* pattern_lens,
    int32_t num_patterns,
    int32_t* out_matched_indices,
    int32_t max_matches
) {
    if (!buffer || !patterns || !pattern_lens || !out_matched_indices) {
        return -1;
    }

    std::string haystack(buffer, buffer_len);
    for (auto& c : haystack) {
        c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
    }

    int32_t matches_found = 0;

    for (int32_t i = 0; i < num_patterns && matches_found < max_matches; ++i) {
        if (pattern_lens[i] <= 0 || pattern_lens[i] > buffer_len) {
            continue;
        }

        std::string needle(patterns[i], pattern_lens[i]);
        for (auto& c : needle) {
            c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
        }

        if (haystack.find(needle) != std::string::npos) {
            out_matched_indices[matches_found] = i;
            matches_found++;
        }
    }

    return matches_found;
}

int32_t amcx_scrub_buffer(char* buffer, int32_t buffer_len) {
    if (!buffer || buffer_len <= 0) {
        return -1;
    }
    std::memset(buffer, 0, static_cast<size_t>(buffer_len));
    return 0;
}

int32_t amcx_accelerator_version() {
    return 1;
}

}
