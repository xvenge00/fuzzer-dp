#include <cinttypes>
#include <pcap.h>
#include <vector>
#include <spdlog/spdlog.h>
#include <thread>
#include <monitor/monitor.h>
#include <fuzzer/probe_response.h>
#include <utils/progress_bar.h>
#include "logging/guarded_circular_buffer.h"
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

void fuzz_response(
    pcap *handle,
    ResponseFuzzer &fuzzer,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames,
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
            if (get_frame_type(ieee802_11_data, ieee802_11_size) == fuzzer.responds_to_subtype) {
                auto *mac = get_prb_req_mac(ieee802_11_data, ieee802_11_size);

                if (strncmp((const char *)mac, (const char*) fuzzed_device_mac.data(), 6) == 0) {
//                    print_mac(mac);

                    if (frame_generator_it != frame_generator.end()) {
                        pcap_sendpacket(handle, frame_generator_it->data(), frame_generator_it->size());
                        sent_frames.push_back(*frame_generator_it);
                        ++frame_generator_it;
                        ++fuzzed_inputs;
                    } else {
                        throw std::runtime_error("exhausted fuzz pool");
                    }
                }
            }
        } catch (std::runtime_error &e) {
            spdlog::warn("Caught exception.");
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

[[noreturn]] void fuzz_push(
    pcap *handle,
    Fuzzer &fuzzer,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames,
    void (* setup) (pcap *),
    void (* teardown) (pcap *)
) {
    auto frame_generator = fuzzer.get_mutated();
    auto frame_generator_it = frame_generator.begin();

    while (true) {
        if (setup != nullptr) {
            setup(handle);
        }

        if (frame_generator_it != frame_generator.end()) {

            for (unsigned i = 0; i < packets_resend_count; ++i) {
                pcap_sendpacket(handle, frame_generator_it->data(), frame_generator_it->size());
            }

            sent_frames.push_back(*frame_generator_it);
            ++frame_generator_it;
        } else {
            throw std::runtime_error("exhausted fuzz pool");
        }

        if (teardown != nullptr) {
            teardown(handle);
        }

        std::this_thread::sleep_for(wait_duration);
    }
}

void fuzz_prb_resp(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzz_device_mac,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames
) {
    spdlog::info("fuzzing probe response");
    ProbeResponseFuzzer fuzzer{src_mac, fuzz_device_mac};
    fuzz_response(
        handle,
        fuzzer,
        fuzz_device_mac,
        sent_frames,
        nullptr,
        nullptr);
}

[[noreturn]] void fuzz_beacon(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames,
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
        sent_frames,
        nullptr,
        nullptr
    );
}

[[noreturn]] void fuzz_disass(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames,
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
        sent_frames,
        nullptr,
        nullptr
    );
}

[[noreturn]] void fuzz_deauth(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames,
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
        sent_frames,
        nullptr,
        nullptr
    );
}

// TODO config AuthenticationFuzzer
[[noreturn]] void fuzz_auth(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames,
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
        sent_frames,
        nullptr,
        nullptr
    );
}

int fuzz(Config config) {
    char errbuf[PCAP_ERRBUF_SIZE] = {}; // for errors (required)

    auto *handle = pcap_open_live(config.interface.c_str(), BUFSIZ/10, 0, 1, errbuf);
    if (handle == nullptr) {
        spdlog::critical("ERROR: {}", errbuf);
        return 1;
    }

    auto sent_frames = GuardedCircularBuffer(boost::circular_buffer<std::vector<std::uint8_t>>(config.frame_history_len));
    MonitorESP monitor{sent_frames};

    switch (config.fuzzer_type) {
    case PRB_REQ:
        fuzz_prb_resp(handle, config.src_mac, config.test_device_mac, sent_frames);
        break;
    case BEACON:
        fuzz_beacon(handle, config.src_mac, sent_frames, std::chrono::milliseconds{10}, 5); // TODO pass from config
        break;
    case DEAUTH:
        fuzz_deauth(handle, config.src_mac, config.test_device_mac, sent_frames, std::chrono::milliseconds{100}, 5);
        break;
    case DISASS:
        fuzz_disass(handle, config.src_mac, config.test_device_mac, sent_frames, std::chrono::milliseconds{100}, 5);
        break;
    }

    return 0;
}
