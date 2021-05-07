#include <vector>
#include <cinttypes>
#include <array>
#include <cstring>
#include <spdlog/spdlog.h>
#include "utils/vector_appender.h"
#include "net80211.h"
#include "fuzzer/utils/rt.h"
#include "fuzzer/fuzzer.h"
#include "utils/frame.h"
#include "teardown.h"

fuzz_t deauth(mac_t fuzzed_device_mac, mac_t source_mac) {
    std::vector<std::uint8_t> rt = get_base_rt();

    /* MAC header */
    struct ieee80211_frame ieee802_frame{};

    ieee802_frame.i_fc[0] = 0xc0;     // deauth
    ieee802_frame.i_fc[1] = 0x00;

    ieee802_frame.i_dur[0] = 0x3a;    // copied from wireshark
    ieee802_frame.i_dur[1] = 0x01;

    memcpy(ieee802_frame.i_addr1, fuzzed_device_mac.data(), 6);   // copy destination mac
    memcpy(ieee802_frame.i_addr2, source_mac.data(), 6);   // copy my mac
    memcpy(ieee802_frame.i_addr3, source_mac.data(), 6);   // copy my mac

    // idk why
    ieee802_frame.i_seq[0] = 0x90;
    ieee802_frame.i_seq[1] = 0x08;

    std::vector<std::uint8_t> ieee802_frame_ {(std::uint8_t *)&ieee802_frame, (std::uint8_t *)&ieee802_frame + sizeof(struct ieee80211_frame)};

    return combine_vec({rt, ieee802_frame_, {3,0}});
}

void deauth(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac
) {

    auto deauth_frame = deauth(fuzzed_device_mac, src_mac);
    for (int i = 0; i < 15; ++i) {
        pcap_sendpacket(handle, deauth_frame.data(), deauth_frame.size());
    };
}
