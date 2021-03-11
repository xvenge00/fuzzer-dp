#ifndef CPP_RAND_PROVIDER_H
#define CPP_RAND_PROVIDER_H

#include <random>

struct RandProvider{
    std::mt19937 generator;
    std::uniform_int_distribution<std::uint8_t> distribution_byte;
    std::uniform_int_distribution<unsigned> distribution_unsigned;

    explicit RandProvider(unsigned seed) : generator(seed), distribution_byte(), distribution_unsigned() {}

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

#endif //CPP_RAND_PROVIDER_H
