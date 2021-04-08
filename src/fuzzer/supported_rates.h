#ifndef CPP_SUPPORTED_RATES_H
#define CPP_SUPPORTED_RATES_H

#include <vector>
#include <cinttypes>
#include <array>
#include "utils/vector_appender.h"

struct SupportedRatesFuzzer {   // TODO common interface
    virtual size_t num_mutations() {
        return 1 + rates_len.size() + 1;
    }


    virtual std::vector<std::uint8_t> get_mutated() {
        std::vector<std::uint8_t> res;

        if (!fuzzed_invalid_rates) {    // fuzz invalid rates
            res = {
                0x08,   // len
                0x00, 0x01, 0xff, 0x01, 0x00, 0x02, 0x41, 0xcb};
            fuzzed_invalid_rates = true;
        } else if (i_rates_len < rates_len.size()) {    // fuzz invalid lengths
            auto rates = get_rates(rates_len[i_rates_len]);
            res = combine_vec({{rates_len[i_rates_len]}, rates});

            ++i_rates_len;
        } else {
            res = combine_vec({
                {8},
                get_rates(255)
            });
        }

        return res;
    }

private:
    bool fuzzed_invalid_rates;
    unsigned i_rates_len = 0;
    std::array<std::uint8_t, 7> rates_len = {
        0,
        1,
        8,
        9,
        16,
        32,
        255
    };

    std::vector<std::uint8_t> get_rates(std::uint8_t len) {
        std::vector<std::uint8_t> res{};
        res.reserve(len);
        for (std::uint8_t i = 0; i < len; ++i) {
            res.push_back(i);
        }

        return res;
    }
};

#endif //CPP_SUPPORTED_RATES_H
