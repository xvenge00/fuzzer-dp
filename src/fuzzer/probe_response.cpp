#include <cstring>
#include "probe_response.h"
#include "net80211.h"
#include "utils/hash.h"
#include "frame_factory.h"

ProbeResponseFuzzer::ProbeResponseFuzzer(
    mac_t source_mac,
    mac_t fuzzed_device_mac
): ResponseFuzzer(IEEE80211_FC0_SUBTYPE_PROBE_REQ, source_mac, fuzzed_device_mac) {}

size_t ProbeResponseFuzzer::num_mutations() {
    return fuzzer_ssid.num_mutations() +
        fuzzer_supported_rates.num_mutations() +
        fuzzer_ds_params.num_mutations() +
        fuzzer_fh_params.num_mutations() +
        fuzzer_tim.num_mutations() +
        fuzzer_cf_params.num_mutations() +
        fuzzer_erp.num_mutations();
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

    // idk why
    ieee802_frame.i_seq[0] = 0x90;
    ieee802_frame.i_seq[1] = 0x08;

    std::vector<std::uint8_t> ieee802_frame_ {(std::uint8_t *)&ieee802_frame, (std::uint8_t *)&ieee802_frame + sizeof(struct ieee80211_frame)};

    /* prb content */
    for (auto &content: fuzz_prb_req_content()) {
        auto result = combine_vec({rt, ieee802_frame_, content});
        uint32_t crc = crc32(result.size(), result.data());
        std::copy((uint8_t *)&crc, (uint8_t *)(&crc) + 4, std::back_inserter(result));

        co_yield result;
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


    for (auto &fuzzed_ssid: fuzz_ssid()) {
        co_yield combine_vec({timestamp, beacon_interval, capability, fuzzed_ssid});
    }

    for (auto &fuzzed_supp_rate: fuzz_supported_rates()) {
        co_yield combine_vec({timestamp, beacon_interval, capability, fuzzed_supp_rate});
    }

    for (auto &fuzzed_ds_param: fuzz_ds_params()) {
        co_yield combine_vec({timestamp, beacon_interval, capability, fuzzed_ds_param});
    }

    for (auto &fuzzed_fh_param: fuzz_fh_params()) {
        co_yield combine_vec({timestamp, beacon_interval, capability, fuzzed_fh_param});
    }

    for (auto &fuzzed_tim: fuzz_tim()) {
        co_yield combine_vec({timestamp, beacon_interval, capability, fuzzed_tim});
    }

    for (auto &fuzzed_cf_param: fuzz_cf_params()) {
        co_yield combine_vec({timestamp, beacon_interval, capability, fuzzed_cf_param});
    }

    for (auto &fuzzed_erp: fuzz_erp()) {
        co_yield combine_vec({timestamp, beacon_interval, capability, fuzzed_erp});
    }
}

generator<fuzz_t> ProbeResponseFuzzer::fuzz_ssid() {
// add valid supported rates
    std::vector<std::uint8_t> supp_rates {
        0x01,   // supported rates tag
        0x08,   // len
        0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c
    };

    // add valid DS param
    std::vector<std::uint8_t> ds_param {
        0x03,   // DS tag
        0x01,   // len
        0x02    // channel 2    // TODO get channel
    };

    // add fuzzed ssid
    std::vector<std::uint8_t> ssid_tag{0x00};

    for (auto &ssid: fuzzer_ssid.get_mutated()) {
        co_yield combine_vec({supp_rates, ds_param, ssid_tag, ssid});
    }
}

generator<fuzz_t> ProbeResponseFuzzer::fuzz_supported_rates() {
    // add valid ssid
    std::vector<std::uint8_t> ssid {
        0x00,   // ssid tag
        0x07,   // len(FUZZING)
        0x46, 0x55, 0x5a, 0x5a, 0x49, 0x4e, 0x47
    };

    // add valid DS param
    std::vector<std::uint8_t> ds_param {
        0x03,   // DS tag
        0x01,   // len
        0x02    // channel 2
    };

    // add fuzzed supported rates
    std::vector<std::uint8_t> supp_rates_tag{0x01};
    for (auto &rate: fuzzer_supported_rates.get_mutated()) {
        co_yield combine_vec({ssid, ds_param, supp_rates_tag, rate});
    }
}

generator<fuzz_t> ProbeResponseFuzzer::fuzz_ds_params() {
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

    // add fuzzed supported rates
    std::vector<std::uint8_t> ds_params_tag{0x03};
    for (auto &ds_param: fuzzer_ds_params.get_mutated()) {
        co_yield combine_vec({ssid, supp_rates, ds_params_tag, ds_param});
    }
}

generator<fuzz_t> ProbeResponseFuzzer::fuzz_fh_params() {
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

    // add fuzzed supported rates
    std::vector<std::uint8_t> fh_params_tag{0x02};
    for (auto &fh_param: fuzzer_fh_params.get_mutated()) {
        co_yield combine_vec({ssid, supp_rates, fh_params_tag, fh_param});
    }
}

generator<fuzz_t> ProbeResponseFuzzer::fuzz_tim() {
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

    // add fuzzed supported rates
    std::vector<std::uint8_t> tim_params_tag{0x05};
    for (auto &tim: fuzzer_tim.get_mutated()) {
        co_yield combine_vec({ssid, supp_rates, tim_params_tag, tim});
    }
}

generator<fuzz_t> ProbeResponseFuzzer::fuzz_cf_params() {
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

    // add fuzzed supported rates
    std::vector<std::uint8_t> cf_params_tag{0x04};
    for(auto &cf_param: fuzzer_cf_params.get_mutated()) {
        co_yield combine_vec({ssid, supp_rates, cf_params_tag, cf_param});
    }
}

generator<fuzz_t> ProbeResponseFuzzer::fuzz_generic(std::uint8_t tag, Fuzzable &fuzzer) {
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

    // add fuzzed fields
    std::vector<std::uint8_t> param_tag{tag};
    for (auto &param: fuzzer.get_mutated()) {
        co_yield combine_vec({ssid, supp_rates, param_tag, param});
    }
}

generator<fuzz_t> ProbeResponseFuzzer::fuzz_erp() {
    return fuzz_generic(0x2a, fuzzer_erp);
}