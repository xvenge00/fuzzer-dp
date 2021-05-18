/*
 * Author: Adam Venger (xvenge00)
 * 2021
 */

#ifndef CPP_DS_PARAMS_H
#define CPP_DS_PARAMS_H


#include <vector>
#include <cinttypes>
#include <array>
#include <stdexcept>
#include "utils/vector_appender.h"
#include "fuzzer/fuzzable.h"
#include "fuzzer/utils/vector_generators.h"
#include "fuzzer/tags/tagged_params.h"

struct DSParamsFuzzer: public Fuzzable, public TaggedParams {
    DSParamsFuzzer(std::uint8_t channel, unsigned fuzz_random): TaggedParams(0x03, *this, channel, fuzz_random) {}

    size_t num_mutations() override {
        return fuzzing_lengths.size() + invalid_channels.size();
    }

    generator<fuzz_t> get_mutated() override {
        // fuzzing invalid lengths
        for (auto len: fuzzing_lengths) {
            co_yield get_filled_vector_with_len(len, valid_channels);
        }

        for (auto channel: invalid_channels) {
            co_yield fuzz_t{channel};
        }

        if (fuzz_random) {
            for (int i = 0; i < fuzz_random; ++i) {
                auto &rp = RandProvider::getInstance();
                auto len = rp.get_byte();
                co_yield combine_vec({{len}, rp.get_vector(len)});
            }
        }
    }

private:
    std::array<std::uint8_t, 4> valid_channels {1,2,3,4};
    std::array<std::uint8_t, 8> invalid_channels {0, 13, 14, 15, 16, 17, 128, 255};
    std::array<std::uint8_t, 5> fuzzing_lengths {0, 2, 8, 128, 255};


};


#endif //CPP_DS_PARAMS_H
