#ifndef CPP_FUZZER_CONTROL_H
#define CPP_FUZZER_CONTROL_H

#include <cinttypes>
#include <pcap.h>
#include <vector>
#include "logging/guarded_circular_buffer.h"
#include "config/config.h"

[[noreturn]] void fuzz_prb_resp(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzz_device_mac,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames
);

[[noreturn]] void fuzz_beacon(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count
);

[[noreturn]] void fuzz_disass(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count
);

[[noreturn]] void fuzz_deauth(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count
);

int fuzz(Config config);

#endif //CPP_FUZZER_CONTROL_H
