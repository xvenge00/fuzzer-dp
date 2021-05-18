#include <cstring>
#include "probe_response.h"
#include "net80211.h"
#include "fuzzer/utils/rt.h"

ProbeResponseFuzzer::ProbeResponseFuzzer(
    mac_t source_mac,
    mac_t fuzzed_device_mac,
    std::uint8_t channel,
    unsigned fuzz_random
): ResponseFuzzer(IEEE80211_FC0_SUBTYPE_PROBE_REQ, source_mac, fuzzed_device_mac), channel(channel), fuzz_random(fuzz_random) {}

size_t ProbeResponseFuzzer::num_mutations() {
    return fuzzer_ssid.num_mutations() +
        fuzzer_supported_rates.num_mutations() +
        fuzzer_ds_params.num_mutations() +
        fuzzer_fh_params.num_mutations() +
        fuzzer_tim.num_mutations() +
        fuzzer_cf_params.num_mutations() +
        fuzzer_erp.num_mutations() +
        fuzzer_erp.num_mutations()*255;
}

generator<fuzz_t> ProbeResponseFuzzer::get_mutated() {
    std::vector<std::uint8_t> rt = get_base_rt();

    /* MAC header */
    struct ieee80211_frame ieee802_frame{};

    ieee802_frame.i_fc[0] = 0x50;     // probe response
    ieee802_frame.i_fc[1] = 0x00;

    ieee802_frame.i_dur[0] = 0x3a;    // copied from wireshark
    ieee802_frame.i_dur[1] = 0x01;

    memcpy(ieee802_frame.i_addr1, fuzzed_device_mac.data(), 6);   // copy destination mac
    memcpy(ieee802_frame.i_addr2, source_mac.data(), 6);   // copy my mac
    memcpy(ieee802_frame.i_addr3, source_mac.data(), 6);   // copy my mac

    ieee802_frame.i_seq[0] = 0x90;
    ieee802_frame.i_seq[1] = 0x08;

    std::vector<std::uint8_t> ieee802_frame_ {(std::uint8_t *)&ieee802_frame, (std::uint8_t *)&ieee802_frame + sizeof(struct ieee80211_frame)};

    /* prb content */
    for (auto &content: fuzz_prb_req_content()) {
        co_yield combine_vec({rt, ieee802_frame_, content});
    }
}

generator<fuzz_t> ProbeResponseFuzzer::fuzz_prb_req_content() {
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

    for (unsigned tag = 0; tag <= 255; ++tag) {
        auto tag_fuzzer = GenericTagFuzzer(tag, channel, fuzz_random);
        for (auto &fuzzed_params: tag_fuzzer.get_whole_param_set()) {
            co_yield combine_vec({timestamp, beacon_interval, capability, fuzzed_params});
        }
    }
}
