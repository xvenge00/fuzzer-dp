#ifndef CPP_RESPONSE_FUZZER_H
#define CPP_RESPONSE_FUZZER_H

#include <array>
#include "fuzzable.h"

struct ResponseFuzzer: public Fuzzable {
    ResponseFuzzer(
        std::uint8_t responds_to_subtype,
        std::array<std::uint8_t, 6> source_mac,
        std::array<std::uint8_t, 6> fuzzed_device_mac
    ):  responds_to_subtype(responds_to_subtype),
        source_mac(source_mac),
        fuzzed_device_mac(fuzzed_device_mac) {}

    const std::uint8_t responds_to_subtype;
    const std::array<std::uint8_t, 6> source_mac;
    const std::array<std::uint8_t, 6> fuzzed_device_mac;
};

#endif //CPP_RESPONSE_FUZZER_H
