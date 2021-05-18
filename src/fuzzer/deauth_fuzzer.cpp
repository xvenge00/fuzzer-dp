#include <cstring>
#include "fuzzer/utils/rt.h"
#include "net80211.h"
#include "utils/rand.h"
#include "utils/vector_appender.h"
#include "utils/debug.h"
#include "fuzzer/deauth_fuzzer.h"

DeauthentiactionFuzzer::DeauthentiactionFuzzer(mac_t src_mac, mac_t fuzzed_device_mac):
    Fuzzer(src_mac, fuzzed_device_mac) {}

generator<fuzz_t> DeauthentiactionFuzzer::get_mutated() {
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

    ieee802_frame.i_seq[0] = 0x90;
    ieee802_frame.i_seq[1] = 0x08;

    std::vector<std::uint8_t> ieee802_frame_ {(std::uint8_t *)&ieee802_frame, (std::uint8_t *)&ieee802_frame + sizeof(struct ieee80211_frame)};

    for (auto &content: get_mutated_content()) {
        co_yield combine_vec({rt, ieee802_frame_, content});
    }
}

generator<fuzz_t> DeauthentiactionFuzzer::get_mutated_content() {
    for (auto len: lengths) {
        fuzz_t content(len);
        std::fill(content.begin(), content.end(), 0);
        co_yield content;
    }

    for (auto len: lengths) {
        fuzz_t content(len);
        std::fill(content.begin(), content.end(), 0xff);
        co_yield content;
    }

    for (auto len: lengths) {
        fuzz_t content(len);
        std::fill(content.begin(), content.end(), 0x1);
        co_yield content;
    }
}

size_t DeauthentiactionFuzzer::num_mutations() {
    return 3 * lengths.size();
}