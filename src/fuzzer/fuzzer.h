#ifndef CPP_FUZZER_H
#define CPP_FUZZER_H

#include <cinttypes>
#include <vector>
#include <cstring>
#include <net80211/ieee80211.h>
#include "../hash.h"

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

struct FrameFuzzer {
    std::vector<std::uint8_t> get_prb_resp(const std::uint8_t *dest_mac) {
        std::vector<std::uint8_t> rt = get_base_rt();

//        std::vector<std::uint8_t> mac{mac_arr, mac_arr + 6};

        /* MAC header */
        struct ieee80211_frame ieee802_frame{};

        ieee802_frame.i_fc[0] = 0x50;     // probe response
        ieee802_frame.i_fc[1] = 0x00;

        ieee802_frame.i_dur[0] = 0x3a;    // copied from wireshark
        ieee802_frame.i_dur[1] = 0x01;

        memcpy(ieee802_frame.i_addr1, dest_mac, 6);   // copy destination mac

        const uint8_t my_mac[6] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab};
        memcpy(ieee802_frame.i_addr2, my_mac, 6);   // copy my mac
        memcpy(ieee802_frame.i_addr3, my_mac, 6);   // copy my mac

        // idk why
        ieee802_frame.i_seq[0] = 0x90;
        ieee802_frame.i_seq[1] = 0x08;

        std::vector<std::uint8_t> ieee802_frame_ {(std::uint8_t *)&ieee802_frame, (std::uint8_t *)&ieee802_frame + sizeof(struct ieee80211_frame)};

        /* prb content */
        std::vector<std::uint8_t> content {
            0xa6, 0xee, 0x41, 0x98, 0xf8, 0xb1, 0x05, 0x00, 0x64, 0x00, 0x01, 0x04, 0x00, 0x04,

            0x46, 0x61, 0x6b, 0x65, // name

            0x01, 0x04, 0x02, 0x04, 0x0b, 0x16, 0x03, 0x01, 0x01, 0x32, 0x08, 0x0c, 0x12, 0x18,
            0x24, 0x30, 0x48, 0x60, 0x6c
        };


        std::vector<std::uint8_t> result{};
        // TODO generic vector combiner
        std::copy(rt.begin(), rt.end(), std::back_inserter(result));
        std::copy(ieee802_frame_.begin(), ieee802_frame_.end(), std::back_inserter(result));
        std::copy(content.begin(), content.end(), std::back_inserter(result));

        uint32_t crc = crc32(result.size(), result.data());
        std::copy((uint8_t *)&crc, (uint8_t *)(&crc) + 4, std::back_inserter(result));
        return result;
    }
};

#endif //CPP_FUZZER_H
