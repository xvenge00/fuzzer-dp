#include "compat.h"
#include <pcap.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <net80211/ieee80211.h>
#include <spdlog/spdlog.h>
#include <iostream>
#include <thread>
#include "radiotap.h"
#include "utils/debug.h"
#include "fuzzer/fuzzer.h"
#include "boost/circular_buffer.hpp"
#include "logging/logging.h"
#include "monitor/monitor.h"
#include "logging/guarded_circular_buffer.h"

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

struct Config {
    size_t frame_hist_len;
};

int main(int argc, char **argv)
{
    if (argc < 2) {
        std::cout << "nemas tam interface\n";
        return 1;
    }
    std::string interface = argv[1];    // "wlp3s0"

    char errbuf[PCAP_ERRBUF_SIZE] = {}; // for errors (required)

    auto *handle = pcap_open_live(interface.c_str(), BUFSIZ/10, 0, 1, errbuf);
    if (handle == nullptr) {
        spdlog::critical("ERROR: {}", errbuf);
        exit(1);
    }

    Config config{
        .frame_hist_len = 10
    };

    auto sent_frames = GuardedCircularBuffer(boost::circular_buffer<std::vector<std::uint8_t>>(config.frame_hist_len));

    // start monitor thread
    std::thread th_monitor(monitor_esp, std::ref(sent_frames));

    spdlog::info("starting");

    struct pcap_pkthdr header{};

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

                print_mac(mac);

                auto frame = FrameFuzzer{}.get_prb_resp(mac);
                pcap_sendpacket(handle, frame.data(), frame.size());

                sent_frames.push_back(frame);
            }
        } catch (std::runtime_error &e) {
            spdlog::warn("Caught exception.");
        }

    }
#pragma clang diagnostic pop
}
