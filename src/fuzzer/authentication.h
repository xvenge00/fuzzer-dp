/*
 * Author: Adam Venger (xvenge00)
 * 2021
 */


#ifndef CPP_AUTHENTICATION_H
#define CPP_AUTHENTICATION_H

#include "fuzzer.h"
#include <array>

struct AuthenticationFuzzer: public Fuzzer {
    AuthenticationFuzzer(
        mac_t source_mac,
        mac_t fuzzed_device_mac,
        bool use_bigger_alg_num_set=true,
        bool use_bigger_trans_num_set=false,
        bool use_bigger_stat_code_set=false
    );

    generator<fuzz_t> get_mutated() override;

    size_t num_mutations() override;

private:
    const std::vector<std::uint16_t> &get_uint16_set(bool use_bigger);

    const bool use_bigger_alg_num_set;
    const bool use_bigger_trans_num_set;
    const bool use_bigger_stat_code_set;
};

#endif //CPP_AUTHENTICATION_H
