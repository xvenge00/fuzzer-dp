#include <cinttypes>
#include <pcap.h>
#include <vector>
#include <spdlog/spdlog.h>
#include <thread>
#include <fuzzer/probe_response.h>
#include <utils/progress_bar.h>
#include <monitor/sniffing_monitor.h>
#include "fuzzer_control.h"
#include "utils/debug.h"
#include "config/config.h"
#include "fuzzer/response_fuzzer.h"
#include "fuzzer/beacon_fuzzer.h"
#include "fuzzer/disass_fuzzer.h"
#include "fuzzer/deauth_fuzzer.h"
#include "fuzzer/authentication.h"
#include "utils/frame.h"
#include "monitor/monitor_passive.h"
#include "setup.h"
#include "teardown.h"

#ifdef GRPC_ENABLED
#include "monitor/monitor_grpc.h"
#endif

void fuzz_response(
    pcap *handle,
    ResponseFuzzer &fuzzer,
    unsigned packets_resend_count,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    Monitor &monitor,
    setup_f_t setup,
    teardown_f_t teardown
) {
    struct pcap_pkthdr header{};
    auto frame_generator = fuzzer.get_mutated();
    auto frame_generator_it = frame_generator.begin();

    unsigned frame_send_count = packets_resend_count;   // to cause generation of new frame the first time
    fuzz_t frame;

    for(unsigned fuzzed_inputs = 0; fuzzed_inputs < fuzzer.num_mutations(); /*incremented inside loop*/) {
        if (setup != nullptr) {
            setup(handle, fuzzer.source_mac, fuzzed_device_mac);
        }

        auto start_t = std::chrono::system_clock::now();
        // if we don't get the right frame under 10 seconds, we might need to setup again
        // if the frame is sent under 10 seconds, we can break from this loop
        do {
            const u_char *packet = pcap_next(handle, &header);

            size_t rt_size = get_radiotap_size(packet, header.caplen);
            const std::uint8_t *ieee802_11_data = packet + rt_size;
            const std::size_t ieee802_11_size = header.caplen - rt_size;

            try {
                // TODO rename get_prb_req_mac
                auto *mac = get_prb_req_mac(ieee802_11_data, ieee802_11_size);
                if (strncmp((const char *) mac, (const char *) fuzzed_device_mac.data(), 6) == 0) {
                    if (get_frame_type(ieee802_11_data, ieee802_11_size) == fuzzer.responds_to_subtype) {
                        if (frame_send_count < packets_resend_count) {
                            // send already generated frame
                            ++frame_send_count;
                        } else {
                            // should generate new frame to send
                            if (frame_generator_it != frame_generator.end()) {
                                frame = *frame_generator_it;
                                ++frame_generator_it;
                                ++fuzzed_inputs;
                                frame_send_count = 1;
                            } else {
                                throw std::runtime_error("exhausted fuzz pool");
                            }
                        }

                        pcap_sendpacket(handle, frame.data(), frame.size());
                        monitor.frame_buff().push_back(*frame_generator_it);
                        monitor.notify();
                        break;  // we sent the frame, we can go to teardown
                    } else {
                        // we detected the frame from fuzzed device, but it was not the request we wanted,
                        // we can len the monitor know about activity
                        monitor.notify();
                    }
                }
            } catch (std::runtime_error &e) {}
        } while (start_t + std::chrono::seconds(10) > std::chrono::system_clock::now());

        if (teardown != nullptr) {
            teardown(handle, fuzzer.source_mac, fuzzed_device_mac);
        }

        print_progress_bar(fuzzed_inputs, fuzzer.num_mutations());
    }
}

void fuzz_push(
    pcap *handle,
    Fuzzer &fuzzer,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count,
    Monitor &monitor,
    setup_f_t setup,
    teardown_f_t teardown
) {
    auto frame_generator = fuzzer.get_mutated();
    auto frame_generator_it = frame_generator.begin();

    unsigned fuzzed_inputs = 0;

    while (true) {
        if (setup != nullptr) {
            setup(handle, fuzzer.source_mac, fuzzer.fuzzed_device_mac);
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
            teardown(handle, fuzzer.source_mac, fuzzer.fuzzed_device_mac);
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
    const std::uint8_t channel,
    unsigned packets_resend_count,
    Monitor &monitor,
    setup_f_t setup,
    teardown_f_t teardown
) {
    spdlog::info("fuzzing probe response");
    ProbeResponseFuzzer fuzzer{src_mac, fuzz_device_mac, channel};
    fuzz_response(
        handle,
        fuzzer,
        packets_resend_count,
        fuzz_device_mac,
        monitor,
        associate,
        deauth);
}

void fuzz_beacon(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::uint8_t channel,
    Monitor &monitor,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count,
    setup_f_t setup,
    teardown_f_t teardown
) {
    spdlog::info("fuzzing beacon");
    mac_t broadcast_mac{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    BeaconFrameFuzzer fuzzer{src_mac, broadcast_mac, channel};
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
    unsigned packets_resend_count,
    setup_f_t setup,
    teardown_f_t teardown
) {
    spdlog::info("fuzzing disass");
    auto fuzzer = DisassociationFuzzer{src_mac, fuzzed_device_mac};
    fuzz_push(
        handle,
        fuzzer,
        wait_duration,
        packets_resend_count,
        monitor,
        setup,
        teardown
    );
}

void fuzz_deauth(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    Monitor &monitor,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count,
    setup_f_t setup,
    teardown_f_t teardown
) {
    spdlog::info("fuzzing deauth");
    auto fuzzer = DeauthentiactionFuzzer{src_mac, fuzzed_device_mac};
    fuzz_push(
        handle,
        fuzzer,
        wait_duration,
        packets_resend_count,
        monitor,
        setup,
        teardown
    );
}

void fuzz_auth(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    Monitor &monitor,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count,
    setup_f_t setup,
    teardown_f_t teardown
) {
    spdlog::info("fuzzing auth");
    auto fuzzer = AuthenticationFuzzer{src_mac, fuzzed_device_mac};
    fuzz_push(
        handle,
        fuzzer,
        wait_duration,
        packets_resend_count,
        monitor,
        setup,
        teardown
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

setup_f_t get_setup_f(SetUp setup) {
    switch (setup) {
    case SetUp::NoSetUp:
        return nullptr;
    case SetUp::Authenticate:
        return authenticate;
    case SetUp::Associate:
        return associate;
    default:
        throw std::logic_error("SetUp not implemented");
    }
}

teardown_f_t get_teardown_f(TearDown teardown) {
    switch (teardown) {
    case NoTearDown:
        return nullptr;
    case TearDown::Disassociate:
        return disass;
    case TearDown::Deauthentiacte:
        return deauth;
    default:
        throw std::logic_error("TearDown not implemented");
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
    auto setup_f = get_setup_f(config.set_up);
    auto teardown_f = get_teardown_f(config.tear_down);

    switch (config.fuzzer_type) {
    case PRB_RESP:
        fuzz_prb_resp(
            handle,
            config.src_mac,
            config.test_device_mac,
            config.channel,
            config.controller.packet_resend_count,
            *monitor,
            setup_f,
            teardown_f);
        break;
    case BEACON:
        fuzz_beacon(
            handle,
            config.src_mac,
            config.channel,
            *monitor,
            config.controller.wait_duration,
            config.controller.packet_resend_count,
            setup_f,
            teardown_f);
        break;
    case DEAUTH:
        fuzz_deauth(
            handle,
            config.src_mac,
            config.test_device_mac,
            *monitor,
            config.controller.wait_duration,
            config.controller.packet_resend_count,
            setup_f,
            teardown_f);
        break;
    case AUTH:
        fuzz_auth(
            handle,
            config.src_mac,
            config.test_device_mac,
            *monitor,
            config.controller.wait_duration,
            config.controller.packet_resend_count,
            setup_f,
            teardown_f);
        break;
    case DISASS:
        fuzz_disass(
            handle,
            config.src_mac,
            config.test_device_mac,
            *monitor,
            config.controller.wait_duration,
            config.controller.packet_resend_count,
            setup_f,
            teardown_f);
        break;
//    case ASS_RESP:
//        // TODO
//        fuzz_ass_resp(handle, config.src_mac, config.test_device_mac);
//        break;
    }

    print_report(monitor->detected_failure(), config.monitor.dump_file);

    return 0;
}
