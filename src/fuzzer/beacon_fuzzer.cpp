#include <cstring>
#include "fuzzer/utils/rt.h"
#include "utils/vector_appender.h"
#include "net80211.h"
#include "beacon_fuzzer.h"

BeaconFrameFuzzer::BeaconFrameFuzzer(
    mac_t src_mac,
    mac_t fuzzed_device_mac,
    std::uint8_t channel
): Fuzzer(src_mac, fuzzed_device_mac), channel(channel) {}

generator<fuzz_t> BeaconFrameFuzzer::fuzz_content()
{
    /*
     * Management Frame Information Elements
     *
     * 0: Service Set Identity (SSID)
     * 1: Supported Rates
     * 2: FH Parameter Set
     * 3: DS Parameter Set
     * 4: CF Parameter Set
     * 5: Traffic Indication Map (TIM)
     * 6: IBSS Parameter Set
     * 7-15: Reserved; unused
     * 16: Challenge text
     * 17-31: Reserved for challenge text extension
     * 32-255: Reserved; unused
     */

    std::vector<std::uint8_t> timestamp{0xa6, 0xee, 0x41, 0x98, 0xf8, 0xb1, 0x05, 0x00};
    std::vector<std::uint8_t> beacon_interval{0x64, 0x00};
    std::vector<std::uint8_t> capability{0x01, 0x04};

    for (auto &fuzzed_ssid: fuzzer_ssid.get_whole_param_set()) {
        co_yield combine_vec({timestamp, beacon_interval, capability, fuzzed_ssid});
    }

    for (auto &fuzzed_supp_rate: fuzzer_supported_rates.get_whole_param_set()) {
        co_yield combine_vec({timestamp, beacon_interval, capability, fuzzed_supp_rate});
    }

    for (auto &fuzzed_ds_param: fuzzer_ds_params.get_whole_param_set()) {
        co_yield combine_vec({timestamp, beacon_interval, capability, fuzzed_ds_param});
    }

    for (auto &fuzzed_fh_param: fuzzer_fh_params.get_whole_param_set()) {
        co_yield combine_vec({timestamp, beacon_interval, capability, fuzzed_fh_param});
    }

    for (auto &fuzzed_tim: fuzzer_tim.get_whole_param_set()) {
        co_yield combine_vec({timestamp, beacon_interval, capability, fuzzed_tim});
    }

    for (auto &fuzzed_cf_param: fuzzer_cf_params.get_whole_param_set()) {
        co_yield combine_vec({timestamp, beacon_interval, capability, fuzzed_cf_param});
    }

    for (auto &fuzzed_erp: fuzzer_erp.get_whole_param_set()) {
        co_yield combine_vec({timestamp, beacon_interval, capability, fuzzed_erp});
    }
}

generator<fuzz_t> BeaconFrameFuzzer::get_mutated() {
    std::vector<std::uint8_t> rt = get_base_rt();

//        std::vector<std::uint8_t> mac{mac_arr, mac_arr + 6};

    /* MAC header */
    struct ieee80211_frame ieee802_frame{};

    ieee802_frame.i_fc[0] = 0x80;     // beacon
    ieee802_frame.i_fc[1] = 0x00;

    ieee802_frame.i_dur[0] = 0x3a;    // copied from wireshark
    ieee802_frame.i_dur[1] = 0x01;

    mac_t broadcast_mac{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(ieee802_frame.i_addr1, broadcast_mac.data(), 6);   // copy destination mac
    memcpy(ieee802_frame.i_addr2, source_mac.data(), 6);   // copy my mac
    memcpy(ieee802_frame.i_addr3, source_mac.data(), 6);   // copy my mac

    // idk why
    ieee802_frame.i_seq[0] = 0x90;
    ieee802_frame.i_seq[1] = 0x08;

    std::vector<std::uint8_t> ieee802_frame_ {(std::uint8_t *)&ieee802_frame, (std::uint8_t *)&ieee802_frame + sizeof(struct ieee80211_frame)};

    /* beacon content */
    for (auto &content: fuzz_content()) {
        co_yield combine_vec({rt, ieee802_frame_, content});
    }
}

size_t BeaconFrameFuzzer::num_mutations() {
    return fuzzer_ssid.num_mutations() +
        fuzzer_supported_rates.num_mutations() +
        fuzzer_ds_params.num_mutations() +
        fuzzer_fh_params.num_mutations() +
        fuzzer_tim.num_mutations() +
        fuzzer_cf_params.num_mutations() +
        fuzzer_erp.num_mutations();
}