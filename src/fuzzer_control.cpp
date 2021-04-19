#include <cinttypes>
#include <pcap.h>
#include <vector>
#include <spdlog/spdlog.h>
#include <thread>
#include <fuzzer/probe_response.h>
#include <utils/progress_bar.h>
#include <monitor/sniffing_monitor.h>
#include "monitor/logging/guarded_circular_buffer.h"
#include "fuzzer_control.h"
#include "net80211.h"
#include "utils/debug.h"
#include "config/config.h"
#include "fuzzer/response_fuzzer.h"
#include "fuzzer/beacon_fuzzer.h"
#include "fuzzer/disass_fuzzer.h"
#include "fuzzer/deauth_fuzzer.h"
#include "fuzzer/authentication.h"
#include "utils/frame.h"
#include "monitor/monitor_passive.h"

#ifdef GRPC_ENABLED
#include "monitor/monitor_grpc.h"
#endif

void fuzz_response(
    pcap *handle,
    ResponseFuzzer &fuzzer,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    Monitor &monitor,
    void (* setup) (pcap *),
    void (* teardown) (pcap *)
) {
    struct pcap_pkthdr header{};
    auto frame_generator = fuzzer.get_mutated();
    auto frame_generator_it = frame_generator.begin();

    unsigned fuzzed_inputs = 0;

    while(true) {
        if (setup != nullptr) {
            setup(handle);
        }

        const u_char *packet = pcap_next(handle, &header);

        size_t rt_size = get_radiotap_size(packet, header.caplen);
        const std::uint8_t *ieee802_11_data = packet + rt_size;
        const std::size_t ieee802_11_size = header.caplen - rt_size;

        try{
            // TODO rename get_prb_req_mac
            auto *mac = get_prb_req_mac(ieee802_11_data, ieee802_11_size);
            if (strncmp((const char *)mac, (const char*) fuzzed_device_mac.data(), 6) == 0) {
                if (get_frame_type(ieee802_11_data, ieee802_11_size) == fuzzer.responds_to_subtype) {
                    if (frame_generator_it != frame_generator.end()) {
                        auto frame = *frame_generator_it;
                        pcap_sendpacket(handle, frame.data(), frame.size());
                        monitor.frame_buff().push_back(*frame_generator_it);
                        ++frame_generator_it;
                        ++fuzzed_inputs;
                    } else {
                        throw std::runtime_error("exhausted fuzz pool");
                    }
                }

                monitor.notify();
            }
        } catch (std::runtime_error &e) {
//            spdlog::warn("Caught exception.");
        }

        if (teardown != nullptr) {
            teardown(handle);
        }

        print_progress_bar(fuzzed_inputs, fuzzer.num_mutations());

        // TODO fuj
        if (fuzzed_inputs >= fuzzer.num_mutations()) {
            break;
        }
    }
}

void fuzz_push(
    pcap *handle,
    Fuzzer &fuzzer,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count,
    Monitor &monitor,
    void (* setup) (pcap *),
    void (* teardown) (pcap *)
) {
    auto frame_generator = fuzzer.get_mutated();
    auto frame_generator_it = frame_generator.begin();

    unsigned fuzzed_inputs = 0;

    while (true) {
        if (setup != nullptr) {
            setup(handle);
        }

        if (frame_generator_it != frame_generator.end()) {

            for (unsigned i = 0; i < packets_resend_count; ++i) {
                pcap_sendpacket(handle, frame_generator_it->data(), frame_generator_it->size());
            }

            monitor.frame_buff().push_back(*frame_generator_it);
            ++frame_generator_it;
            ++fuzzed_inputs;
        } else {
            throw std::runtime_error("exhausted fuzz pool");
        }

        if (teardown != nullptr) {
            teardown(handle);
        }

        print_progress_bar(fuzzed_inputs, fuzzer.num_mutations());

        // TODO fuj
        if (fuzzed_inputs >= fuzzer.num_mutations()) {
            break;
        }

        std::this_thread::sleep_for(wait_duration);
    }
}

void fuzz_prb_resp(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzz_device_mac,
    Monitor &monitor
) {
    spdlog::info("fuzzing probe response");
    ProbeResponseFuzzer fuzzer{src_mac, fuzz_device_mac};
    fuzz_response(
        handle,
        fuzzer,
        fuzz_device_mac,
        monitor,
        nullptr,
        nullptr);
}

void fuzz_beacon(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    Monitor &monitor,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count
) {
    spdlog::info("fuzzing beacon");
    mac_t broadcast_mac{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    BeaconFrameFuzzer fuzzer{src_mac, broadcast_mac};
    fuzz_push(
        handle,
        fuzzer,
        wait_duration,
        packets_resend_count,
        monitor,
        nullptr,
        nullptr
    );
}

void fuzz_disass(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    Monitor &monitor,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count
) {
    spdlog::info("fuzzing disass");
    auto fuzzer = DisassociationFuzzer{src_mac, fuzzed_device_mac};
    fuzz_push(
        handle,
        fuzzer,
        wait_duration,
        packets_resend_count,
        monitor,
        nullptr,
        nullptr
    );
}

void fuzz_deauth(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    Monitor &monitor,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count
) {
    spdlog::info("fuzzing deauth");
    auto fuzzer = DeauthentiactionFuzzer{src_mac, fuzzed_device_mac};
    fuzz_push(
        handle,
        fuzzer,
        wait_duration,
        packets_resend_count,
        monitor,
        nullptr,
        nullptr
    );
}

void fuzz_auth(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    Monitor &monitor,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count
) {
    spdlog::info("fuzzing auth");
    auto fuzzer = AuthenticationFuzzer{src_mac, fuzzed_device_mac};
    fuzz_push(
        handle,
        fuzzer,
        wait_duration,
        packets_resend_count,
        monitor,
        nullptr,
        nullptr
    );
}

std::unique_ptr<Monitor> build_monitor(const ConfigMonitor &config, mac_t target) {
    switch (config.type) {
#ifdef GRPC_ENABLED
    case GRPC:
        return std::make_unique<MonitorGRPC>(
            config.frame_history_len,
            config.dump_file,
            config.server_address);
#endif
    case PASSIVE:
        return std::make_unique<MonitorPassive>(
            config.frame_history_len,
            config.timeout,
            config.dump_file);
    case SNIFFING:
        return std::make_unique<SniffingMonitor<mac_t>>(
            config.frame_history_len,
            config.timeout,
            config.interface,
            target,
            config.dump_file);
    default:
        throw std::runtime_error("case not implemented");
    }
}

void print_report(bool failure_detected, const std::filesystem::path &packets_file) {
    if (failure_detected) {
        spdlog::info("Failure detected! Check '{}' for packets, which may have caused the failure.", packets_file.string());
    } else {
        spdlog::info("No failure detected.");
    }
}

int fuzz(const Config &config) {
    char errbuf[PCAP_ERRBUF_SIZE] = {}; // for errors (required)

    auto *handle = pcap_open_live(config.interface.c_str(), BUFSIZ/10, 0, 1, errbuf);
    if (handle == nullptr) {
        spdlog::critical("ERROR: {}", errbuf);
        return 1;
    }

    auto monitor = build_monitor(config.monitor, config.test_device_mac);

    switch (config.fuzzer_type) {
    case PRB_RESP:
        fuzz_prb_resp(handle, config.src_mac, config.test_device_mac, *monitor);
        break;
    case BEACON:
        fuzz_beacon(
            handle,
            config.src_mac,
            *monitor,
            config.controller.wait_duration,
            config.controller.packet_resend_count);
        break;
    case DEAUTH:
        fuzz_deauth(
            handle,
            config.src_mac,
            config.test_device_mac,
            *monitor,
            config.controller.wait_duration,
            config.controller.packet_resend_count);
        break;
    case AUTH:
        fuzz_auth(
            handle,
            config.src_mac,
            config.test_device_mac,
            *monitor,
            config.controller.wait_duration,
            config.controller.packet_resend_count);
        break;
    case DISASS:
        fuzz_disass(
            handle,
            config.src_mac,
            config.test_device_mac,
            *monitor,
            config.controller.wait_duration,
            config.controller.packet_resend_count);
        break;
    }

    print_report(monitor->detected_failure(), config.monitor.dump_file);

    return 0;
}
