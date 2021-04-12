#ifndef CPP_VECTOR_APPENDER_H
#define CPP_VECTOR_APPENDER_H

#include "vector"
#include <cinttypes>

// TODO inefficien AF, make better when its a problem
template<typename T>
std::vector<T> operator+(const std::vector<T> &v1, const std::vector<T> &v2) {
    std::vector<T> res{};
    res.reserve(v1.size() + v2.size());

    std::copy(v1.cbegin(), v1.cend(), std::back_inserter(res));
    std::copy(v2.cbegin(), v2.cend(), std::back_inserter(res));

    return res;
}

template<typename T>
std::vector<T> combine_vec(std::initializer_list<std::vector<T>> vec_args) {
    std::vector<T> res{};
    for (auto i: vec_args) {
        res = res + i;
    }
    return res;
}

// TODO mind endianness
inline std::vector<std::uint8_t> combine_vec_uint16(std::initializer_list<std::uint16_t> args) {
    std::vector<std::uint8_t> res{};
    res.reserve(args.size());
    for (auto i: args) {
        std::uint8_t high = (i & 0xff00) >> 8;
        res.push_back(high);
        std::uint8_t low = (i & 0x00ff);
        res.push_back(low);
    }
    return res;
}


#endif //CPP_VECTOR_APPENDER_H
