#ifndef CPP_TIM_H
#define CPP_TIM_H

#include "fuzzer/fuzzable.h"
#include <array>
#include <stdexcept>
#include "fuzzer/utils/vector_generators.h"
#include "fuzzer/tags/tagged_params.h"

struct TIMFuzzer: public Fuzzable, public TaggedParams {
    TIMFuzzer(std::uint8_t channel): TaggedParams(0x05, *this, channel) {}

    size_t num_mutations() override {
        return fuzzing_lengths.size()
            + fuzzing_real_lengths.size()
            + fuzzing_claimed_lengths.size()
            + dtim_periods.size();
    }

    generator<fuzz_t> get_mutated() override {
        for (auto len: fuzzing_lengths) {
            co_yield get_filled_vector_with_len(len, 0x41);
        }

        for (auto len: fuzzing_real_lengths) {
            auto data = get_filled_vector_with_len(len, 0x41);
            data[0] = 6; // set claimed len to 6
            co_yield data;
        }

        for (auto len: fuzzing_claimed_lengths) {
            auto data = get_filled_vector_with_len(6, 0x41);
            data[0] = len;     // set claimed len to fuzzed value
            co_yield data;
        }

        for (auto dtim_period: dtim_periods) {
            auto data = get_filled_vector_with_len(6, 0x41);
            data[3] = dtim_period;  // set dtim period
            co_yield data;
        }
    }

private:
    std::array<std::uint8_t, 8> fuzzing_lengths{0, 1, 2, 3, 4, 5, 6, 7};
    std::array<std::uint8_t, 4> fuzzing_real_lengths{0, 5,7, 255};
    std::array<std::uint8_t, 4> fuzzing_claimed_lengths{0, 5,7, 255};
    std::array<std::uint8_t, 2> dtim_periods{0, 255};
};

#endif //CPP_TIM_H
