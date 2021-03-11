#include <cinttypes>
#include <pcap.h>
#include <vector>
#include <spdlog/spdlog.h>
#include <thread>
#include <monitor/monitor.h>
#include "fuzzer/frame_factory.h"
#include "logging/guarded_circular_buffer.h"
#include "fuzzer.h"
#include "net80211.h"
#include "utils/debug.h"
#include "config.h"

std::size_t get_radiotap_size(const std::uint8_t *data, std::size_t len) {
    if (len > 4) {
        return (((uint16_t)*(data+3)) << 4) | *(data+2);    // little endian to big endian
    }

    return 0;
}

const std::uint8_t *get_prb_req_mac(const std::uint8_t *data, std::size_t len) {
    if (len < 16) {
        throw std::runtime_error("frame too small to extract req mac");
    }

    return data + 10;
}

int8_t get_frame_type(const std::uint8_t *packet, size_t packet_size) {
    if (packet_size < 2) {
        throw std::runtime_error("too small ieee802 frame");
    }

    return *packet;
}


void fuzz_prb_resp(pcap *handle,
                   const std::uint8_t *src_mac,
                   const std::uint8_t *fuzz_device_mac,
                   GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames,
                   unsigned rand_seed)
{
    spdlog::info("fuzzing probe response");

    struct pcap_pkthdr header{};
    auto fuzzer = PrbRespFrameFuzzer{src_mac, rand_seed};

#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"
    while(true) {
        const u_char *packet = pcap_next(handle, &header);

        size_t rt_size = get_radiotap_size(packet, header.caplen);
        const std::uint8_t *ieee802_11_data = packet + rt_size;
        const std::size_t ieee802_11_size = header.caplen - rt_size;

        try{
            if (get_frame_type(ieee802_11_data, ieee802_11_size) == IEEE80211_FC0_SUBTYPE_PROBE_REQ) {
                auto *mac = get_prb_req_mac(ieee802_11_data, ieee802_11_size);

                if (strncmp((const char *)mac, (const char*) fuzz_device_mac, 6) == 0) {
                    print_mac(mac);
                    auto frame = fuzzer.get_prb_resp(mac);
                    pcap_sendpacket(handle, frame.data(), frame.size());

                    sent_frames.push_back(frame);
                }
            }
        } catch (std::runtime_error &e) {
            spdlog::warn("Caught exception.");
        }

    }
#pragma clang diagnostic pop
}

[[noreturn]] void fuzz_beacon(
    // TODO sleep_for
    pcap *handle,
    const std::uint8_t *src_mac,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames,
    unsigned int rand_seed
) {
    spdlog::info("fuzzing beacon");

    auto fuzzer = BeaconFrameFuzzer{src_mac, rand_seed};

    while (true) {
        auto frame = fuzzer.next();
        pcap_sendpacket(handle, frame.data(), frame.size());

        // uvidime ci to je treba
        for (int i=0; i<5; ++i) {
            sent_frames.push_back(frame);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

[[noreturn]] void fuzz_disass(
    pcap *handle,
    const std::uint8_t *src_mac,
    const std::uint8_t *dst_mac,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames,
    unsigned rand_seed
) {
    spdlog::info("fuzzing disass");

    auto fuzzer = DisassociationFuzzer{src_mac, dst_mac, rand_seed};

    while (true) {
        auto frame = fuzzer.next();
        pcap_sendpacket(handle, frame.data(), frame.size());

        // uvidime ci to je treba
        for (int i=0; i<5; ++i) {
            sent_frames.push_back(frame);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

[[noreturn]] void fuzz_deauth(
    pcap *handle,
    const std::uint8_t *src_mac,
    const std::uint8_t *dst_mac,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames,
    unsigned rand_seed
) {
    spdlog::info("fuzzing disauth");

    auto fuzzer = DeauthentiactionFuzzer{src_mac, dst_mac, rand_seed};

    while (true) {
        auto frame = fuzzer.next();
        pcap_sendpacket(handle, frame.data(), frame.size());

        // uvidime ci to je treba
        for (int i=0; i<5; ++i) {
            sent_frames.push_back(frame);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

int fuzz(Config config) {
    char errbuf[PCAP_ERRBUF_SIZE] = {}; // for errors (required)

    auto *handle = pcap_open_live(config.interface.c_str(), BUFSIZ/10, 0, 1, errbuf);
    if (handle == nullptr) {
        spdlog::critical("ERROR: {}", errbuf);
        return 1;
    }

    auto sent_frames = GuardedCircularBuffer(boost::circular_buffer<std::vector<std::uint8_t>>(config.frame_history_len));

    // start monitor thread
    std::thread th_monitor(monitor_esp, std::ref(sent_frames));

    switch (config.fuzzer_type) {
    case PRB_REQ:
        fuzz_prb_resp(handle, config.src_mac.data(), config.test_device_mac.data(), sent_frames, config.random_seed);
    case BEACON:
        fuzz_beacon(handle, config.src_mac.data(), sent_frames, config.random_seed);
    case DEAUTH:
        fuzz_deauth(handle, config.src_mac.data(), config.test_device_mac.data(), sent_frames, config.random_seed);
    case DISASS:
        fuzz_disass(handle, config.src_mac.data(), config.test_device_mac.data(), sent_frames, config.random_seed);
    }

    return 0;
}