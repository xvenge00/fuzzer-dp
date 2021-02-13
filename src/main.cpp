#include "compat.h"
#include <pcap.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net80211/ieee80211_radiotap.h>
#include <net80211/ieee80211.h>
#include <spdlog/spdlog.h>
#include <iostream>
#include "radiotap.h"
#include "hash.h"
#include "debug.h"
//#include "hash.h"
//#include "radiotap.h"
//#include "responder.h"
//#include "packet.h"
//#include "sniffer.h"

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

uint8_t *get_response(const std::uint8_t *dest_mac) {
    auto *resp = (uint8_t *) malloc(RadiotapBase::size() + sizeof(struct ieee80211_frame) + 37 + 4);

    /* build readiotap header */

    auto *rt_frame = (struct ieee80211_radiotap_header *) resp;
    memcpy(rt_frame, RadiotapBase::get(), RadiotapBase::size());

    /* build mac header */
    auto *i802_frame = (struct ieee80211_frame *) (resp + RadiotapBase::size());

    i802_frame->i_fc[0] = 0x50;     // probe response
    i802_frame->i_fc[1] = 0x00;

    i802_frame->i_dur[0] = 0x3a;    // copied from wireshark
    i802_frame->i_dur[1] = 0x01;

    memcpy(i802_frame->i_addr1, dest_mac, 6);   // copy destination mac

    const uint8_t my_mac[6] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab};
    memcpy(i802_frame->i_addr2, my_mac, 6);   // copy my mac
    memcpy(i802_frame->i_addr3, my_mac, 6);   // copy my mac

    // idk why
    i802_frame->i_seq[0] = 0x90;
    i802_frame->i_seq[1] = 0x08;

    /* build content */
    uint8_t content[] = {
        0xa6, 0xee, 0x41, 0x98, 0xf8, 0xb1, 0x05, 0x00, 0x64, 0x00, 0x01, 0x04, 0x00, 0x04,

        0x46, 0x61, 0x6b, 0x65, // name

        0x01, 0x04, 0x02, 0x04, 0x0b, 0x16, 0x03, 0x01, 0x01, 0x32, 0x08, 0x0c, 0x12, 0x18,
        0x24, 0x30, 0x48, 0x60, 0x6c

    };



    memcpy(resp + sizeof(struct ieee80211_frame) + RadiotapBase::size(), content, sizeof(content));

    /* crc */
    auto packet_size = sizeof(struct ieee80211_frame) + RadiotapBase::size() + sizeof(content);
    *((uint32_t *)(resp + packet_size)) = crc32(packet_size, resp);

    return resp;
}

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

    spdlog::info("starting");

    struct pcap_pkthdr header{};

#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"
    while(true) {
        const u_char *packet = pcap_next(handle, &header);

        size_t rt_size = get_radiotap_size(packet, header.caplen);
        const std::uint8_t *ieee802_11_data = packet + rt_size;
        const std::size_t ieee802_11_size = header.caplen - rt_size;

        if (get_frame_type(ieee802_11_data, ieee802_11_size) == IEEE80211_FC0_SUBTYPE_PROBE_REQ) {
            auto *mac = get_prb_req_mac(ieee802_11_data, ieee802_11_size);  // TODO copy this

            print_mac(mac);

            auto *resp = get_response(mac);
            pcap_sendpacket(handle, resp, RadiotapBase::size() + sizeof(struct ieee80211_frame) + 37 + 4);
            free(resp);

        }
    }
#pragma clang diagnostic pop
}
