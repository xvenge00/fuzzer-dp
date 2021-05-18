/*
 * Author: Adam Venger (xvenge00)
 * 2021
 */


#ifndef CPP_FUZZ_UTILS_H
#define CPP_FUZZ_UTILS_H

#include <cinttypes>
#include <vector>
#include <cstdlib>
#include <random>

class RandProvider{
    static RandProvider *instance;

    std::mt19937 generator;
    std::uniform_int_distribution<std::uint8_t> distribution_byte;
    std::uniform_int_distribution<unsigned> distribution_unsigned;

    RandProvider() :
        generator(4),   // chosen by fair dice roll, guaranteed to be random
        distribution_byte(),
        distribution_unsigned() {}

public:
    static RandProvider& getInstance()
    {
        static RandProvider instance;
        return instance;
    }

    void set_seed(unsigned seed) {
        generator = std::mt19937{seed};
    }

    std::uint8_t get_byte() {
        return distribution_byte(generator);
    }

    std::vector<std::uint8_t> get_vector() {
        return get_vector(distribution_unsigned(generator));
    }

    std::vector<std::uint8_t> get_vector(unsigned len) {
        std::vector<std::uint8_t> res;
        res.reserve(len);
        for (size_t i=0; i < len; ++i) {
            res.emplace_back(get_byte());
        }
        return res;
    }
};

//inline std::uint8_t rand_byte() {
//    return rand() % 0xFF;
//}
//
//inline std::vector<std::uint8_t> rand_vec(size_t len) {
//    std::vector<std::uint8_t> res{};
//    for (size_t i=0; i < len; ++i) {
//        res.emplace_back(rand_byte());
//    }
//
//    return res;
//}

#endif //CPP_FUZZ_UTILS_H
