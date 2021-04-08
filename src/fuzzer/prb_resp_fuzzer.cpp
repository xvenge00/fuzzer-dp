#include <cstring>
#include <stdexcept>
#include "frame_factory.h"
#include "rand.h"
#include "utils/vector_appender.h"
//#include "exception.h"
#include "net80211.h"
#include "utils/hash.h"

PrbRespFrameFuzzer::PrbRespFrameFuzzer(const std::uint8_t *src_mac, unsigned rand_seed):
rand_provider(rand_seed)
{
    memcpy(source_mac, src_mac, 6);
}

/*
 * Fill valid info and fuzz SSID as last element.
 */
std::vector<std::uint8_t> PrbRespFrameFuzzer::fuzz_ssid() {
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
        0x02    // channel 2    // TODO get chanel
    };

    // add fuzzed ssid
    std::vector<std::uint8_t> ssid_tag{0x00};
    std::vector<std::uint8_t> ssid = fuzzer_ssid.get_mutated();

    return combine_vec({supp_rates, ds_param, ssid_tag, ssid});
}

std::vector<std::uint8_t> PrbRespFrameFuzzer::fuzz_supported_rates() {
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
    std::vector<std::uint8_t> supp_rates = fuzzer_supported_rates.get_mutated();

    return combine_vec({ssid, ds_param, supp_rates_tag, supp_rates});
}

std::vector<std::uint8_t> PrbRespFrameFuzzer::fuzz_prb_req_content() {
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


    std::vector<std::uint8_t> tagged_params;
    if (fuzzed_ssids < fuzzer_ssid.num_mutations()) {
        tagged_params = fuzz_ssid();

        ++fuzzed_ssids;
    } else if (fuzzed_supp_rates < fuzzer_supported_rates.num_mutations()) {
        tagged_params = fuzz_supported_rates();

        ++fuzzed_supp_rates;
    } else {
        throw std::runtime_error("fuzzing pool exhausted");
    }

    return combine_vec({timestamp, beacon_interval, capability, tagged_params});
}

std::vector<std::uint8_t> PrbRespFrameFuzzer::get_prb_resp(const std::uint8_t *dest_mac) {
    std::vector<std::uint8_t> rt = get_base_rt();

    /* MAC header */
    struct ieee80211_frame ieee802_frame{};

    ieee802_frame.i_fc[0] = 0x50;     // probe response
    ieee802_frame.i_fc[1] = 0x00;

    ieee802_frame.i_dur[0] = 0x3a;    // copied from wireshark
    ieee802_frame.i_dur[1] = 0x01;

    memcpy(ieee802_frame.i_addr1, dest_mac, 6);   // copy destination mac
    memcpy(ieee802_frame.i_addr2, source_mac, 6);   // copy my mac
    memcpy(ieee802_frame.i_addr3, source_mac, 6);   // copy my mac

    // idk why
    ieee802_frame.i_seq[0] = 0x90;
    ieee802_frame.i_seq[1] = 0x08;

    std::vector<std::uint8_t> ieee802_frame_ {(std::uint8_t *)&ieee802_frame, (std::uint8_t *)&ieee802_frame + sizeof(struct ieee80211_frame)};

    /* prb content */
    std::vector<std::uint8_t> content = fuzz_prb_req_content();


    std::vector<std::uint8_t> result{};
    // TODO generic vector combiner
    std::copy(rt.begin(), rt.end(), std::back_inserter(result));
    std::copy(ieee802_frame_.begin(), ieee802_frame_.end(), std::back_inserter(result));
    std::copy(content.begin(), content.end(), std::back_inserter(result));

    uint32_t crc = crc32(result.size(), result.data());
    std::copy((uint8_t *)&crc, (uint8_t *)(&crc) + 4, std::back_inserter(result));
    return result;
}