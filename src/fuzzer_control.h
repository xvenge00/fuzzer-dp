#ifndef CPP_FUZZER_CONTROL_H
#define CPP_FUZZER_CONTROL_H

#include <cinttypes>
#include <pcap.h>
#include <vector>
#include "monitor/monitor.h"
#include "config/config.h"

void fuzz_prb_resp(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzz_device_mac,
    Monitor &monitor
);

void fuzz_beacon(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    Monitor &monitor,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count
);

void fuzz_disass(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    Monitor &monitor,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count
);

void fuzz_deauth(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    Monitor &monitor,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count
);

int fuzz(Config config);

#endif //CPP_FUZZER_CONTROL_H
