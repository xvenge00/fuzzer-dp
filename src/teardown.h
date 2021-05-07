#ifndef CPP_TEARDOWN_H
#define CPP_TEARDOWN_H

#include <pcap.h>

void deauth(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac
);

#endif //CPP_TEARDOWN_H
