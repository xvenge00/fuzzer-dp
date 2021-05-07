#ifndef CPP_TAGGED_PARAMS_H
#define CPP_TAGGED_PARAMS_H

#include <vector>
#include <cinttypes>
#include "utils/generator.h"
#include "utils/vector_appender.h"
#include "utils/rand.h"

struct TaggedParams {
    explicit TaggedParams(std::uint8_t tag, Fuzzable &fuzzer, std::uint8_t channel, unsigned fuzz_random):
        tag(tag), fuzzer(fuzzer), channel(channel), fuzz_random(fuzz_random) {}

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

        std::vector<std::uint8_t> ds {
            0x03,   // ds
            0x01,   //len
            channel    // channel
        };

        // add fuzzed fields
        std::vector<std::uint8_t> param_tag{tag};
        for (auto &param: fuzzer.get_mutated()) {
            co_yield combine_vec({ssid, supp_rates, ds, param_tag, param});
        }

        if (fuzz_random) {
            for (unsigned i = 0; i < fuzz_random; ++i) {
                auto &rp = RandProvider::getInstance();
                auto len = rp.get_byte();
                co_yield combine_vec({ssid, supp_rates, ds, {tag, len}, rp.get_vector(len)});
            }
        }
    };

    const std::uint8_t tag;
    Fuzzable &fuzzer;
    const std::uint8_t channel;
    const unsigned fuzz_random;
};

#endif //CPP_TAGGED_PARAMS_H
