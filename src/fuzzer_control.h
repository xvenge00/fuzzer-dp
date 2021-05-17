#ifndef CPP_FUZZER_CONTROL_H
#define CPP_FUZZER_CONTROL_H

#include <cinttypes>
#include <pcap.h>
#include <vector>
#include "fuzzer/fuzzer.h"
#include "fuzzer/response_fuzzer.h"
#include "monitor/monitor.h"
#include "config/config.h"

using setup_f_t = void (*) (pcap *, const mac_t &, const mac_t &, std::uint8_t);
using teardown_f_t = void (*) (pcap *, const mac_t &, const mac_t &, std::uint8_t);

void fuzz_prb_resp(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzz_device_mac,
    const std::uint8_t channel,
    unsigned packets_resend_count,
    Monitor &monitor,
    setup_f_t setup = nullptr,
    teardown_f_t teardown = nullptr
);

void fuzz_beacon(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    std::uint8_t channel,
    Monitor &monitor,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count,
    unsigned fuzz_random,
    setup_f_t setup = nullptr,
    teardown_f_t teardown = nullptr
);

void fuzz_disass(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    Monitor &monitor,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count,
    std::uint8_t channel,
    setup_f_t setup = nullptr,
    teardown_f_t teardown = nullptr
);

void fuzz_deauth(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    Monitor &monitor,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count,
    std::uint8_t channel,
    setup_f_t setup = nullptr,
    teardown_f_t teardown = nullptr
);

void fuzz_auth(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    Monitor &monitor,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count,
    std::uint8_t channel,
    setup_f_t setup = nullptr,
    teardown_f_t teardown = nullptr
);

void fuzz_push(
    pcap *handle,
    Fuzzer &fuzzer,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count,
    Monitor &monitor,
    std::uint8_t channel,
    setup_f_t = nullptr,
    teardown_f_t teardown = nullptr
);

void fuzz_response(
    pcap *handle,
    ResponseFuzzer &fuzzer,
    unsigned packets_resend_count,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    Monitor &monitor,
    unsigned fuzz_random,
    std::uint8_t channel,
    setup_f_t setup = nullptr,
    teardown_f_t teardown = nullptr
);

int fuzz(const Config &config);

#endif //CPP_FUZZER_CONTROL_H
