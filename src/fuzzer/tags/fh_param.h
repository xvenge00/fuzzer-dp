#ifndef CPP_FH_PARAM_H
#define CPP_FH_PARAM_H

#include <vector>
#include <cinttypes>
#include <array>
#include <stdexcept>
#include "utils/vector_appender.h"
#include "fuzzer/fuzzable.h"
#include "fuzzer/utils/vector_generators.h"

struct FHParamsFuzzer: public Fuzzable {
    size_t num_mutations() override {
        return fuzzing_lengths.size() + fuzzing_claimed_lengths.size() + fuzzing_real_lengths.size();
    }

    /*
     * Dwell Time (2B)
     * Hop Set
     * Hop Pattern
     * Hop Index
     */
    generator<fuzz_t> get_mutated() override {
        // trying invalid lengths
        for(auto len: fuzzing_lengths) {
            co_yield get_filled_vector_with_len(len, 0x41);
        }

        for (auto len: fuzzing_real_lengths) {
            auto data = get_filled_vector_with_len(len, 0x41);
            data[0] = 5; // set claimed len to 5
            co_yield data;
        }

        for (auto len: fuzzing_claimed_lengths) {
            auto data = get_filled_vector_with_len(5, 0x41);
            data[0] = len;     // set claimed len to fuzzed value
            co_yield data;
        }
    }

private:
    std::array<std::uint8_t, 9> fuzzing_lengths{0, 1, 2, 3, 4, 6, 127, 128, 255};
    std::array<std::uint8_t, 4> fuzzing_real_lengths{0, 4,6, 255};
    std::array<std::uint8_t, 4> fuzzing_claimed_lengths{0, 4,6, 255};
};

#endif //CPP_FH_PARAM_H
