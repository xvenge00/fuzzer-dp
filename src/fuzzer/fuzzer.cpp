#include <cstring>
#include "net80211.h"
#include "fuzzer.h"
#include "utils/hash.h"
#include <cstdlib>
#include <iostream>
#include "utils/vector_appender.h"
#include "ssid.h"
#include "rand.h"


std::vector<std::uint8_t> get_base_rt() {
    return {
        0x00, 0x00, // <-- radiotap version (ignore this)
        0x18, 0x00, // <-- number of bytes in our header (count the number of "0x"s)

        /**
         * The next field is a bitmap of which options we are including.
         * The full list of which field is which option is in ieee80211_radiotap.h,
         * but I've chosen to include:
         *   0x00 0x01: timestamp
         *   0x00 0x02: flags
         *   0x00 0x03: rate
         *   0x00 0x04: channel
         *   0x80 0x00: tx flags (seems silly to have this AND flags, but oh well)
         */
        0x0f, 0x80, 0x00, 0x00,

        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp

        /**
         * This is the first set of flags, and we've set the bit corresponding to
         * IEEE80211_RADIOTAP_F_FCS, meaning we want the card to add a FCS at the end
         * of our buffer for us.
         */
        0x10,

        0x00, // <-- rate
        0x00, 0x00, 0x00, 0x00, // <-- channel

        /**
         * This is the second set of flags, specifically related to transmissions. The
         * bit we've set is IEEE80211_RADIOTAP_F_TX_NOACK, which means the card won't
         * wait for an ACK for this frame, and that it won't retry if it doesn't get
         * one.
         */
        0x00, 0x00
    };
}

std::vector<std::uint8_t> SSIDFuzzer::next() {
    std::vector<std::uint8_t> len;
    std::vector<std::uint8_t> ssid;

    if (curr_len > max_len) {
        curr_len = 0;
    } else {
        curr_len += 10;
    }

    len = {static_cast<std::uint8_t>(curr_len)};

    if (curr_gen_len > max_gen_len) {
        curr_gen_len = 0;
    } else {
        curr_gen_len += 10;
    }

    ssid = rand_vec(curr_len);


    return combine_vec({len, ssid});
}

//std::uint8_t rand_byte() {
//    return rand() % 0xFF;
//}
//
//std::vector<std::uint8_t> rand_vec(size_t len) {
//    std::vector<std::uint8_t> res{};
//    for (size_t i=0; i < len; ++i) {
//        res.emplace_back(rand_byte());
//    }
//
//    return res;
//}

