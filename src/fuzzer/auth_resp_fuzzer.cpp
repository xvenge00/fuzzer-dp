#include <cstring>
#include "fuzzer/utils/rt.h"
#include "auth_resp_fuzzer.h"
#include "net80211.h"
#include "fuzzer/primitives/int.h"
#include "fuzzer/primitives/string.h"
#include "utils/vector_appender.h"

AuthRespFuzzer::AuthRespFuzzer(
    mac_t source_mac,
    mac_t fuzzed_device_mac,
    std::uint8_t channel,
    unsigned fuzz_random
): ResponseFuzzer(0xb0, source_mac, fuzzed_device_mac) {}

const std::vector<std::uint16_t> &AuthRespFuzzer::get_uint16_set(bool use_bigger) {
    return use_bigger ? primitives::fuzz_uint16_bigger_complement : primitives::fuzz_uint16;
}

generator<fuzz_t> AuthRespFuzzer::get_mutated() {
    std::vector<std::uint8_t> rt = get_base_rt();

    /* MAC header */
    struct ieee80211_frame ieee802_frame{};

    ieee802_frame.i_fc[0] = 0xb0;     // authentication
    ieee802_frame.i_fc[1] = 0x00;

    ieee802_frame.i_dur[0] = 0x3a;    // copied from wireshark
    ieee802_frame.i_dur[1] = 0x01;

    memcpy(ieee802_frame.i_addr1, fuzzed_device_mac.data(), 6);   // copy destination mac
    memcpy(ieee802_frame.i_addr2, source_mac.data(), 6);   // copy my mac
    memcpy(ieee802_frame.i_addr3, fuzzed_device_mac.data(), 6);   // copy my mac

    ieee802_frame.i_seq[0] = 0x90;
    ieee802_frame.i_seq[1] = 0x08;

    std::vector<std::uint8_t> ieee802_frame_ {(std::uint8_t *)&ieee802_frame, (std::uint8_t *)&ieee802_frame + sizeof(struct ieee80211_frame)};

    for (auto alg_num: get_uint16_set(true)) {
        for (auto status_code: get_uint16_set(true)) {

            // fuzz prepared strings
            for (auto &str: primitives::fuzz_strings) {
                auto codes = combine_vec_uint16({alg_num, 2, status_code});
                auto str_vec = std::vector<uint8_t>{(uint8_t) str.length()};

                co_yield combine_vec({rt, ieee802_frame_, codes, str_vec});
            }
        }
    }
}

size_t AuthRespFuzzer::num_mutations() {
    return get_uint16_set(true).size() *
        get_uint16_set(true).size() *
        primitives::fuzz_strings.size();
}