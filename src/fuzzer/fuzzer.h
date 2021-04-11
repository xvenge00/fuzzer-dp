#ifndef CPP_FUZZER_FUZZER_H
#define CPP_FUZZER_FUZZER_H

#include <array>
#include "fuzzable.h"

using mac_t = std::array<std::uint8_t, 6>;

struct Fuzzer: public Fuzzable {
    explicit Fuzzer(
        mac_t source_mac,
        mac_t fuzzed_device_mac
    ):
        source_mac(source_mac),
        fuzzed_device_mac(fuzzed_device_mac) {}

    const std::array<std::uint8_t, 6> source_mac;
    const mac_t fuzzed_device_mac;
};

#endif //CPP_FUZZER_FUZZER_H
