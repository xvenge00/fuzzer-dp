#ifndef CPP_AUTH_RESP_FUZZER_H
#define CPP_AUTH_RESP_FUZZER_H

#include "response_fuzzer.h"

struct AuthRespFuzzer: public ResponseFuzzer {
    AuthRespFuzzer(
        mac_t source_mac,
        mac_t fuzzed_device_mac,
        std::uint8_t channel,
        unsigned fuzz_random
    );

    generator<fuzz_t> get_mutated() override;

    size_t num_mutations() override;

private:
    const std::vector<std::uint16_t> &get_uint16_set(bool use_bigger);
};

#endif //CPP_AUTH_RESP_FUZZER_H
