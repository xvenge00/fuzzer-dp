#include <vector>
#include <cinttypes>
#include <array>
#include <cstring>
#include <spdlog/spdlog.h>
#include "utils/vector_appender.h"
#include "net80211.h"
#include "fuzzer/utils/rt.h"
#include "setup.h"
#include "fuzzer/fuzzer.h"
#include "utils/frame.h"

std::vector<std::uint8_t> get_prb_req(
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac
) {
    std::vector<std::uint8_t> rt = get_base_rt();

    /* MAC header */
    struct ieee80211_frame ieee802_frame{};

    ieee802_frame.i_fc[0] = 0x50;     // probe response
    ieee802_frame.i_fc[1] = 0x00;

    ieee802_frame.i_dur[0] = 0x3a;    // copied from wireshark
    ieee802_frame.i_dur[1] = 0x01;

    memcpy(ieee802_frame.i_addr1, fuzzed_device_mac.data(), 6);   // copy destination mac
    memcpy(ieee802_frame.i_addr2, src_mac.data(), 6);   // copy my mac
    memcpy(ieee802_frame.i_addr3, src_mac.data(), 6);   // copy my mac

    // idk why
    ieee802_frame.i_seq[0] = 0x90;
    ieee802_frame.i_seq[1] = 0x08;

    std::vector<std::uint8_t> ieee802_frame_ {(std::uint8_t *)&ieee802_frame, (std::uint8_t *)&ieee802_frame + sizeof(struct ieee80211_frame)};

    /* prb content */
    std::vector<std::uint8_t> timestamp{0xa6, 0xee, 0x41, 0x98, 0xf8, 0xb1, 0x05, 0x00};
    std::vector<std::uint8_t> beacon_interval{0x64, 0x00};
    std::vector<std::uint8_t> capability{0x01, 0x15};

    // add valid ssid
    std::vector<std::uint8_t> ssid {
        0x00,   // ssid tag
        0x07,   // len(FUZZING)
        0x46, 0x55, 0x5a, 0x5a, 0x49, 0x4e, 0x47
    };

    // add supported rates
    std::vector<std::uint8_t> supp_rates {
        0x01,   // supported rates tag
        0x08,   // len
        0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c
    };

    std::vector<std::uint8_t> ds {
        0x03,   // ds
        0x01,   //len
        0x02    // channel 2
    };

    auto result = combine_vec({
                                  rt, ieee802_frame_, timestamp, beacon_interval, capability,
                                  ssid,
                                  supp_rates,
                                  ds,
                              });

    return result;
}

std::vector<std::uint8_t> get_auth_succ(
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac
) {
    std::vector<std::uint8_t> rt = get_base_rt();

    /* MAC header */
    struct ieee80211_frame ieee802_frame{};

    ieee802_frame.i_fc[0] = 0xb0;     // probe response
    ieee802_frame.i_fc[1] = 0x00;

    ieee802_frame.i_dur[0] = 0x3a;    // copied from wireshark
    ieee802_frame.i_dur[1] = 0x01;

    memcpy(ieee802_frame.i_addr1, fuzzed_device_mac.data(), 6);   // copy destination mac
    memcpy(ieee802_frame.i_addr2, src_mac.data(), 6);   // copy my mac
    memcpy(ieee802_frame.i_addr3, src_mac.data(), 6);   // copy my mac

    // idk why
    ieee802_frame.i_seq[0] = 0x90;
    ieee802_frame.i_seq[1] = 0x08;

    std::vector<std::uint8_t> ieee802_frame_ {(std::uint8_t *)&ieee802_frame, (std::uint8_t *)&ieee802_frame + sizeof(struct ieee80211_frame)};

    /* auth content */
    std::vector<std::uint8_t> content = {
        0x00, 0x00, // open system
        0x02, 0x00, // seq num TODO check if correct endianess
        0x00, 0x00,  // successful
    };


    auto result = combine_vec({rt, ieee802_frame_, content});

    return result;
}

std::vector<std::uint8_t> get_cts(
    mac_t target
) {
    std::vector<std::uint8_t> rt = get_base_rt();

    std::vector<std::uint8_t> cts{
        0xc4,   // cts
        0x00,   // flags
        0x18, 0x0e, // duration
    };

    std::vector<std::uint8_t> mac{target.data(), target.data() + target.size()};

    return combine_vec({rt, cts, mac});
}

std::vector<std::uint8_t> get_ass_succ(
    mac_t src_mac,
    mac_t target_mac
) {
    std::vector<std::uint8_t> rt = get_base_rt();

    /* MAC header */
    struct ieee80211_frame ieee802_frame{};

    ieee802_frame.i_fc[0] = 0x10;     // ass_succ
    ieee802_frame.i_fc[1] = 0x00;

    ieee802_frame.i_dur[0] = 0x3a;    // copied from wireshark
    ieee802_frame.i_dur[1] = 0x01;

    memcpy(ieee802_frame.i_addr1, target_mac.data(), 6);   // copy destination mac
    memcpy(ieee802_frame.i_addr2, src_mac.data(), 6);   // copy my mac
    memcpy(ieee802_frame.i_addr3, src_mac.data(), 6);   // copy my mac

    // idk why
    ieee802_frame.i_seq[0] = 0x90;
    ieee802_frame.i_seq[1] = 0x08;

    std::vector<std::uint8_t> ieee802_frame_ {(std::uint8_t *)&ieee802_frame, (std::uint8_t *)&ieee802_frame + sizeof(struct ieee80211_frame)};

    /* ass resp content */
    std::vector<std::uint8_t> capability{0x21, 0x04};
    std::vector<std::uint8_t> status_code{0x00, 0x00};
    std::vector<std::uint8_t> ass_id{0x01, 0xc0};

    // add supported rates
    std::vector<std::uint8_t> supp_rates {
        0x01,   // supported rates tag
        0x08,   // len
        0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c
    };

    std::vector<std::uint8_t> ds {
        0x03,   // ds
        0x01,   //len
        0x02    // channel 2
    };

    auto result = combine_vec({
                                  rt, ieee802_frame_,
                                  capability, status_code, ass_id,
                                  supp_rates,
                                  ds,
                              });

    return result;
}

void associate(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac
) {
    spdlog::info("fuzzing association response");

    struct pcap_pkthdr header{};

    // wait for prb req and send them
    auto prb_resp = get_prb_req(src_mac, fuzzed_device_mac);

    while(true) {
        const u_char *packet = pcap_next(handle, &header);

        size_t rt_size = get_radiotap_size(packet, header.caplen);
        const std::uint8_t *ieee802_11_data = packet + rt_size;
        const std::size_t ieee802_11_size = header.caplen - rt_size;

        try{
            auto *mac = get_prb_req_mac(ieee802_11_data, ieee802_11_size);
            if (strncmp((const char *)mac, (const char*) fuzzed_device_mac.data(), 6) == 0) {
                if (get_frame_type(ieee802_11_data, ieee802_11_size) == 0x40) { // prb request
                    for (int i = 0; i < 15; ++i) {
                        pcap_sendpacket(handle, prb_resp.data(), prb_resp.size());
                    }
                    spdlog::info("sent probe responses");
                }
                if (get_frame_type(ieee802_11_data, ieee802_11_size) == 0xb0) { // auth packet 1
                    auto auth_succ = get_auth_succ(src_mac, fuzzed_device_mac);
                    for (int i = 0; i < 1; ++i) {
                        pcap_sendpacket(handle, auth_succ.data(), auth_succ.size());
                    }
                    spdlog::info("auth");
                }
                if (get_frame_type(ieee802_11_data, ieee802_11_size) == (0xb0 & 0x4)) { // rts
                    auto cts = get_cts(fuzzed_device_mac);
                    for (int i = 0; i < 1; ++i) {
                        pcap_sendpacket(handle, cts.data(), cts.size());
                    }
                    spdlog::info("cts");
                }
                if (get_frame_type(ieee802_11_data, ieee802_11_size) == (0x00)) { // ass req
                    auto ass_resp = get_ass_succ(src_mac, fuzzed_device_mac);
                    for (int i = 0; i < 10; ++i) {
                        pcap_sendpacket(handle, ass_resp.data(), ass_resp.size());
                    }
                    spdlog::info("ass resp");
                    break;
                }
            }
        } catch (std::runtime_error &e) {
//            spdlog::warn("Caught exception. {}", e.what());
        }
    }
    spdlog::info("can fuzz");
}

void authenticate(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac
) {
    struct pcap_pkthdr header{};

    // wait for prb req and send them
    auto prb_resp = get_prb_req(src_mac, fuzzed_device_mac);

    while(true) {
        const u_char *packet = pcap_next(handle, &header);

        size_t rt_size = get_radiotap_size(packet, header.caplen);
        const std::uint8_t *ieee802_11_data = packet + rt_size;
        const std::size_t ieee802_11_size = header.caplen - rt_size;

        try{
            auto *mac = get_prb_req_mac(ieee802_11_data, ieee802_11_size);
            if (strncmp((const char *)mac, (const char*) fuzzed_device_mac.data(), 6) == 0) {
                if (get_frame_type(ieee802_11_data, ieee802_11_size) == 0x40) { // prb request
                    for (int i = 0; i < 15; ++i) {
                        pcap_sendpacket(handle, prb_resp.data(), prb_resp.size());
                    }
                    spdlog::info("sent probe responses");
                }
                if (get_frame_type(ieee802_11_data, ieee802_11_size) == 0xb0) { // auth packet 1
                    auto auth_succ = get_auth_succ(src_mac, fuzzed_device_mac);
                    for (int i = 0; i < 10; ++i) {
                        pcap_sendpacket(handle, auth_succ.data(), auth_succ.size());
                    }
                    break;
                }
                if (get_frame_type(ieee802_11_data, ieee802_11_size) == (0xb0 & 0x4)) { // rts
                    auto cts = get_cts(fuzzed_device_mac);
                    for (int i = 0; i < 1; ++i) {
                        pcap_sendpacket(handle, cts.data(), cts.size());
                    }
                    spdlog::info("cts");
                }
            }
        } catch (std::runtime_error &e) {
//            spdlog::warn("Caught exception. {}", e.what());
        }
    }
}