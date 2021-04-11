#ifndef CPP_RESPONSE_FUZZER_H
#define CPP_RESPONSE_FUZZER_H

#include <array>
#include "fuzzable.h"
#include "fuzzer/fuzzer.h"

struct ResponseFuzzer: public Fuzzer {
    ResponseFuzzer(
        std::uint8_t responds_to_subtype,
        mac_t source_mac,
        mac_t fuzzed_device_mac
    ):  Fuzzer(source_mac),
        responds_to_subtype(responds_to_subtype),
        fuzzed_device_mac(fuzzed_device_mac) {}

    const std::uint8_t responds_to_subtype;
    const mac_t fuzzed_device_mac;
};

#endif //CPP_RESPONSE_FUZZER_H
