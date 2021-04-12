#ifndef CPP_DEAUTH_FUZZER_H
#define CPP_DEAUTH_FUZZER_H

#include "fuzzer/fuzzer.h"

struct DeauthentiactionFuzzer: public Fuzzer {
    explicit DeauthentiactionFuzzer(
        mac_t src_mac,
        mac_t fuzzed_device_mac);

    generator<fuzz_t> get_mutated() override;

    size_t num_mutations() override;

private:
    std::array<unsigned, 20> lengths{0, 1, 2, 16, 127, 128, 140, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 511, 512, 513};

    generator<fuzz_t> get_mutated_content();
};


#endif //CPP_DEAUTH_FUZZER_H
