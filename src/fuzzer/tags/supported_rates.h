#ifndef CPP_SUPPORTED_RATES_H
#define CPP_SUPPORTED_RATES_H

#include <vector>
#include <cinttypes>
#include <array>
#include "utils/vector_appender.h"
#include "fuzzer/fuzzable.h"
#include "fuzzer/utils/vector_generators.h"
#include "fuzzer/tags/tagged_params.h"

struct SupportedRatesFuzzer: public Fuzzable, public TaggedParams {
    SupportedRatesFuzzer(): TaggedParams(0x01, *this) {}

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

    generator<std::vector<std::uint8_t>> get_whole_param_set() override {
        // add valid ssid
        std::vector<std::uint8_t> ssid {
            0x00,   // ssid tag
            0x07,   // len(FUZZING)
            0x46, 0x55, 0x5a, 0x5a, 0x49, 0x4e, 0x47
        };

        // add valid DS param
        std::vector<std::uint8_t> ds_param {
            0x03,   // DS tag
            0x01,   // len
            0x02    // channel 2
        };

        // add fuzzed supported rates
        std::vector<std::uint8_t> supp_rates_tag{0x01};
        for (auto &rate: get_mutated()) {
            co_yield combine_vec({ssid, ds_param, supp_rates_tag, rate});
        }
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
