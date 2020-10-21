#ifndef CPP_SNIFFER_H
#define CPP_SNIFFER_H

#include <string>
#include "packet.h"

namespace wi_fuzz {

struct Sniffer {
    std::string interface;
    void (*pcap_handler)(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
    u_char i = 1;
    pcap_t *handle;

    explicit Sniffer(std::string interface) : interface(std::move(interface)), pcap_handler(nullptr) {}

    void set_handler(void (*tmp)(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)) {
        pcap_handler = tmp;
    }

    Packet sniff()
    {
        char erbuf[BUFSIZ] = {}; // for errors (required)

        std::cerr << "openning...\n";

        handle = pcap_open_live(interface.c_str(), BUFSIZ/10, 0, 1, erbuf);
        if (handle == nullptr) {
            printf("ERROR: %s\n", erbuf);
            exit(1);
            // todo exception
        }

        std::cerr << "sniffing...\n";

        // Create a filter
//        std::string filter = "type ctl subtype rts";
//
//        struct bpf_program fp{};
//        bpf_u_int32 netp{}; // Berkley Packet Filter (same as u_int32_t i believe)
//
//        if (pcap_compile(handle, &fp, filter.c_str(), 0, netp) == -1) {
//            std::cerr << "Error compiling Libpcap filter, " << filter << '\n';
//        }
//
//        if (pcap_setfilter(handle, &fp) == -1) {
//            std::cerr << "Error setting Libpcap filter, " << filter << '\n';
//        }

        pcap_loop(handle, 0, pcap_handler, (u_char *) handle); // dispatch to call upon packet

        return {0, nullptr};
    }

};

}

#endif //CPP_SNIFFER_H
