#ifndef CPP_GENERIC_TAG_H
#define CPP_GENERIC_TAG_H

#include <array>
#include <stdexcept>
#include "fuzzer/fuzzable.h"

struct GenericTagFuzzer: public  Fuzzable {
    size_t num_mutations() override {
        return fuzzing_lengths.size() + fuzzing_claimed_lengths.size() + fuzzing_real_lengths.size();
    }

    std::vector<uint8_t> get_mutated() override {
        std::vector<uint8_t> res;

        if (i_fuzzed_lengths < fuzzing_lengths.size()) {
            res = get_filled_vector_with_len(fuzzing_lengths[i_fuzzed_lengths], 0x41);

            ++i_fuzzed_lengths;
        } else if (i_fuzzed_real_lengths < fuzzing_real_lengths.size()) {
            res = get_filled_vector_with_len(fuzzing_real_lengths[i_fuzzed_real_lengths], 0x41);
            res[0] = 6; // set claimed len to 6

            ++i_fuzzed_real_lengths;
        } else if (i_fuzzed_claimed_lengths < fuzzing_claimed_lengths.size()) {
            res = get_filled_vector_with_len(6, 0x41);
            res[0] = fuzzing_claimed_lengths[i_fuzzed_claimed_lengths];     // set claimed len to fuzzed value

            ++i_fuzzed_claimed_lengths;
        } else {
            throw std::runtime_error("fuzzing pool exhausted");
        }

        return res;

    }

private:
    unsigned i_fuzzed_lengths = 0;
    std::array<std::uint8_t, 8> fuzzing_lengths{0, 1, 2, 3, 4, 5, 6, 7};

    unsigned i_fuzzed_real_lengths = 0;
    std::array<std::uint8_t, 4> fuzzing_real_lengths{0, 5,7, 255};

    unsigned i_fuzzed_claimed_lengths = 0;
    std::array<std::uint8_t, 4> fuzzing_claimed_lengths{0, 5,7, 255};

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

#endif //CPP_GENERIC_TAG_H
