#ifndef CPP_FUZZ_UTILS_H
#define CPP_FUZZ_UTILS_H

#include <cinttypes>
#include <vector>
#include <cstdlib>

inline std::uint8_t rand_byte() {
    return rand() % 0xFF;
}

inline std::vector<std::uint8_t> rand_vec(size_t len) {
    std::vector<std::uint8_t> res{};
    for (size_t i=0; i < len; ++i) {
        res.emplace_back(rand_byte());
    }

    return res;
}

#endif //CPP_FUZZ_UTILS_H
