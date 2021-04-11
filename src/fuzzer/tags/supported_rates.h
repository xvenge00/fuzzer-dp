#ifndef CPP_SUPPORTED_RATES_H
#define CPP_SUPPORTED_RATES_H

#include <vector>
#include <cinttypes>
#include <array>
#include "utils/vector_appender.h"
#include "fuzzer/fuzzable.h"
#include "fuzzer/utils/vector_generators.h"

struct SupportedRatesFuzzer: public Fuzzable {
    size_t num_mutations() override {
        return 1 + rates_len.size() + 1;
    }


    generator<fuzz_t> get_mutated() override {
        // fuzz invalid rates
        co_yield {
            0x08,   // len
            0x00, 0x01, 0xff, 0x01, 0x00, 0x02, 0x41, 0xcb
        };

        // fuzz invalid lengths
        for(auto &len: rates_len) {
            auto rates = get_increasing_vector(len);
            co_yield combine_vec({{len}, rates});
        }

        co_yield combine_vec({
            {8},
            get_increasing_vector(255)
        });
    }

private:
    std::array<std::uint8_t, 7> rates_len = {
        0,
        1,
        8,
        9,
        16,
        32,
        255
    };
};

#endif //CPP_SUPPORTED_RATES_H
