#ifndef CPP_SETUP_H
#define CPP_SETUP_H

#include <pcap.h>

void associate(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    std::uint8_t channel
);

void authenticate(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    std::uint8_t channel
);

#endif //CPP_SETUP_H
