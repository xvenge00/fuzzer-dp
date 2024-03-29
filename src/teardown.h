/*
 * Author: Adam Venger (xvenge00)
 * 2021
 */


#ifndef CPP_TEARDOWN_H
#define CPP_TEARDOWN_H

#include <pcap.h>

void deauth(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    std::uint8_t channel
);

void disass(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    std::uint8_t channel
);

#endif //CPP_TEARDOWN_H
