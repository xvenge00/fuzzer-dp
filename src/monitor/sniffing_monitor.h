#ifndef CPP_SNIFFING_MONITOR_H
#define CPP_SNIFFING_MONITOR_H

#include <pcap/pcap.h>
#include <cstring>
#include "monitor_passive.h"
#include "utils/frame.h"

template<typename mac_t>
struct SniffingMonitor: public MonitorPassive {
    SniffingMonitor(
        size_t buff_size,
        const std::chrono::seconds &timeout,
        const std::string &interface,
        mac_t target,
        std::filesystem::path dump_file
    ): MonitorPassive(buff_size, timeout, std::move(dump_file)) {
        auto *h = pcap_open_live(interface.c_str(), BUFSIZ/10, 0, 1, errbuf);
        if (h == nullptr) {
            throw std::runtime_error("could not init sniffing interface " + interface);
        }
        handle = h;
        sniff_thread = std::thread(&SniffingMonitor::sniffing, this);
    }

    ~SniffingMonitor() {
        pcap_breakloop(handle);
        sniff_thread.join();
    }

    mac_t fuzzed_device_mac;

private:
    char errbuf[PCAP_ERRBUF_SIZE] = {}; // for errors (required)

    static void handler(u_char *mon, const struct pcap_pkthdr *header, const u_char *packet) {
        auto *monitor = (SniffingMonitor *) mon;
        size_t rt_size = get_radiotap_size(packet, header->caplen);
        const std::uint8_t *ieee802_11_data = packet + rt_size;
        const std::size_t ieee802_11_size = header->caplen - rt_size;

        try {
            auto *mac = get_src_mac(ieee802_11_data, ieee802_11_size);
            if (strncmp((const char *) mac, (const char *) monitor->fuzzed_device_mac.data(), 6) == 0) {
                monitor->notify();
            }

        }  catch (std::runtime_error &e) {
        }
    }

    void sniffing() {
        pcap_loop(handle, 0, handler, (u_char *) this);
    }


    std::thread sniff_thread;
    pcap *handle;
};

#endif //CPP_SNIFFING_MONITOR_H
