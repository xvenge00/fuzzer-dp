/*
 * Author: Adam Venger (xvenge00)
 * 2021
 */

#ifndef CPP_VECTOR_GENERATORS_H
#define CPP_VECTOR_GENERATORS_H

#include <vector>
#include <cinttypes>
#include <numeric>

inline std::vector<std::uint8_t> get_filled_vector_with_len(std::uint8_t len, std::uint8_t filler) {
    std::vector<std::uint8_t> res {};
    res.reserve(len + 1);
    res.push_back(len);

    for (int i=0; i<len; ++i) {
        res.push_back(filler);
    }

    return res;
}

// length will be the first element
template<typename T>
std::vector<std::uint8_t> get_filled_vector_with_len(std::uint8_t len, T &src) {
    std::vector<std::uint8_t> res{};
    res.reserve(len + 1);

    res.push_back(len);

    for (int i = 0; i < len; ++i) {
        res.push_back(src[i % src.size()]);
    }

    return res;
}

inline std::vector<std::uint8_t> get_increasing_vector(std::uint8_t len, std::uint8_t start=0) {
    std::vector<std::uint8_t> v(len);
    std::iota(v.begin(), v.end(), start);
    return v;
}

#endif //CPP_VECTOR_GENERATORS_H
