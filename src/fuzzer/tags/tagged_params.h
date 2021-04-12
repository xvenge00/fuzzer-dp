#ifndef CPP_TAGGED_PARAMS_H
#define CPP_TAGGED_PARAMS_H

#include <vector>
#include <cinttypes>
#include "utils/generator.h"
#include "utils/vector_appender.h"

struct TaggedParams {
    explicit TaggedParams(std::uint8_t tag, Fuzzable &fuzzer): tag(tag), fuzzer(fuzzer) {}

    virtual ~TaggedParams() = default;

    virtual generator<std::vector<std::uint8_t>> get_whole_param_set() {
            // add valid ssid
            std::vector<std::uint8_t> ssid {
                0x00,   // ssid tag
                0x07,   // len(FUZZING)
                0x46, 0x55, 0x5a, 0x5a, 0x49, 0x4e, 0x47
            };

            // add supported rates
            std::vector<std::uint8_t> supp_rates {
                0x01,   // supported rates tag
                0x08,   // len
                0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c
            };

            // add fuzzed fields
            std::vector<std::uint8_t> param_tag{tag};
            for (auto &param: fuzzer.get_mutated()) {
                co_yield combine_vec({ssid, supp_rates, param_tag, param});
            }
    };

    const std::uint8_t tag;
    Fuzzable &fuzzer;
};

#endif //CPP_TAGGED_PARAMS_H
