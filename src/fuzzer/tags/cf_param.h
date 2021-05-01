#ifndef CPP_CF_PARAM_H
#define CPP_CF_PARAM_H

#include <array>
#include <stdexcept>
#include "fuzzer/fuzzable.h"
#include "fuzzer/tags/tagged_params.h"
#include "fuzzer/utils/vector_generators.h"

struct CFParamsFuzzer: public  Fuzzable, public TaggedParams {
    CFParamsFuzzer(std::uint8_t channel): TaggedParams(0x04, *this, channel) {}

    size_t num_mutations() override {
        return fuzzing_lengths.size() + fuzzing_claimed_lengths.size() + fuzzing_real_lengths.size();
    }

    generator<fuzz_t> get_mutated() override {
        // fuzzing printable
        for (auto len: fuzzing_lengths) {
            co_yield get_filled_vector_with_len(len, 0x41);
        }

        // fuzzing real length, claimed length stays 6
        for (auto len: fuzzing_real_lengths) {
            auto data = get_filled_vector_with_len(len, 0x41);
            data[0] = 6; // set claimed len to 6
            co_yield data;
        }

        // fuzzing claimed length, real length stays 6
        for (auto len: fuzzing_claimed_lengths) {
            auto data = get_filled_vector_with_len(6, 0x41);
            data[0] = len;     // set claimed len to fuzzed value
            co_yield data;
        }
    }

private:
    std::array<std::uint8_t, 8> fuzzing_lengths{0, 1, 2, 3, 4, 5, 6, 7};
    std::array<std::uint8_t, 4> fuzzing_real_lengths{0, 5,7, 255};
    std::array<std::uint8_t, 4> fuzzing_claimed_lengths{0, 5,7, 255};
};

#endif //CPP_CF_PARAM_H
