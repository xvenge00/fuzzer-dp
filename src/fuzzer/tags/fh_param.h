#ifndef CPP_FH_PARAM_H
#define CPP_FH_PARAM_H

#include <vector>
#include <cinttypes>
#include <array>
#include <stdexcept>
#include "utils/vector_appender.h"
#include "fuzzer/fuzzable.h"

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
    std::vector<std::uint8_t> get_mutated() override {
        std::vector<std::uint8_t> res;

        // trying invalid lengths
        if (i_fuzzed_lengths < fuzzing_lengths.size()) {
            res = get_filled_vector_with_len(fuzzing_lengths[i_fuzzed_lengths], 0x41);

            ++i_fuzzed_lengths;
        } else if (i_fuzzed_real_lengths < fuzzing_real_lengths.size()) {
            res = get_filled_vector_with_len(fuzzing_real_lengths[i_fuzzed_real_lengths], 0x41);
            res[0] = 5; // set claimed len to 5

            ++i_fuzzed_real_lengths;
        } else if (i_fuzzed_claimed_lengths < fuzzing_claimed_lengths.size()) {
            res = get_filled_vector_with_len(5, 0x41);
            res[0] = fuzzing_claimed_lengths[i_fuzzed_claimed_lengths];     // set claimed len to fuzzed value

            ++i_fuzzed_claimed_lengths;
        } else {
            throw std::runtime_error("fuzzing pool exhausted");
        }

        return res;
    }

private:


    unsigned i_fuzzed_lengths = 0;
    std::array<std::uint8_t, 9> fuzzing_lengths{0, 1, 2, 3, 4, 6, 127, 128, 255};

    unsigned i_fuzzed_real_lengths = 0;
    std::array<std::uint8_t, 4> fuzzing_real_lengths{0, 4,6, 255};

    unsigned i_fuzzed_claimed_lengths = 0;
    std::array<std::uint8_t, 4> fuzzing_claimed_lengths{0, 4,6, 255};

    std::vector<std::uint8_t> get_filled_vector_with_len(std::uint8_t len, std::uint8_t filler) {
        std::vector<std::uint8_t> res {};
        res.reserve(len + 1);
        res.push_back(len);

        for (int i=0; i<len; ++i) {
            res.push_back(filler);
        }

        return res;
    }

};

#endif //CPP_FH_PARAM_H
