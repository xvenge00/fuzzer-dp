#ifndef CPP_DS_PARAMS_H
#define CPP_DS_PARAMS_H


#include <vector>
#include <cinttypes>
#include <array>
#include <stdexcept>
#include "utils/vector_appender.h"

struct DSParamsFuzzer {   // TODO common interface
    virtual size_t num_mutations() {
        return fuzzing_lengths.size() + invalid_channels.size();
    }


    virtual std::vector<std::uint8_t> get_mutated() {
        std::vector<std::uint8_t> res;

        // fuzzing invalid lengths
        if (i_fuzzed_lengths < fuzzing_lengths.size()) {
            res = get_len(fuzzing_lengths[i_fuzzed_lengths], valid_channels);

            ++i_fuzzed_lengths;
        } else if (i_fuzzed_invalid_channels < invalid_channels.size()) {
            res = {invalid_channels[i_fuzzed_invalid_channels]};

            ++i_fuzzed_invalid_channels;
        } else {
            throw std::runtime_error("exhausted fuzzing pool");
        }

        return res;
    }

private:
    std::array<std::uint8_t, 4> valid_channels {1,2,3,4};
    unsigned i_fuzzed_invalid_channels = 0;
    std::array<std::uint8_t, 8> invalid_channels {0, 13, 14, 15, 16, 17, 128, 255};
    unsigned i_fuzzed_lengths = 0;
    std::array<std::uint8_t, 5> fuzzing_lengths {0, 2, 8, 128, 255};

    // length will be the first element
    template<size_t SIZE>
    std::vector<std::uint8_t> get_len(std::uint8_t len, std::array<std::uint8_t, SIZE> &src) {
        std::vector<std::uint8_t> res{};
        res.reserve(len + 1);

        res.push_back(len);

        for (int i = 0; i < len; ++i) {
            res.push_back(src[i % src.size()]);
        }

        return res;
    }
};


#endif //CPP_DS_PARAMS_H
