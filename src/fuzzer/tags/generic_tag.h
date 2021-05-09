#ifndef CPP_GENERIC_TAG_H
#define CPP_GENERIC_TAG_H

#include <array>
#include <stdexcept>
#include "fuzzer/fuzzable.h"
#include "fuzzer/utils/vector_generators.h"
#include "fuzzer/tags/tagged_params.h"

// TODO nech tam je toho viac, nevadi ze to bude trochu na dlhsie
struct GenericTagFuzzer: public  Fuzzable, public TaggedParams {
    explicit GenericTagFuzzer(std::uint8_t tag, std::uint8_t channel, unsigned fuzz_random): TaggedParams(tag, *this, channel, fuzz_random) {}

    size_t num_mutations() override {
        return fuzzing_lengths.size() + fuzzing_claimed_lengths.size() + fuzzing_real_lengths.size();
    }

    generator<fuzz_t> get_mutated() override {
        for(auto len: fuzzing_lengths) {
            co_yield get_filled_vector_with_len(len, 0x41);
        }

        for (auto len: fuzzing_real_lengths) {
            auto data = get_filled_vector_with_len(len, 0x41);
            data[0] = 6; // set claimed len to 5
            co_yield data;
        }

        for (auto len: fuzzing_claimed_lengths) {
            auto data = get_filled_vector_with_len(6, 0x41);
            data[0] = len;     // set claimed len to fuzzed value
            co_yield data;
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
    std::array<std::uint8_t, 32> fuzzing_lengths{
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        31, 32, 127, 128, 129, 250, 251, 252, 253, 254, 255};
    std::array<std::uint8_t, 4> fuzzing_real_lengths{0, 5,7, 255};
    std::array<std::uint8_t, 4> fuzzing_claimed_lengths{0, 5,7, 255};
};

#endif //CPP_GENERIC_TAG_H
