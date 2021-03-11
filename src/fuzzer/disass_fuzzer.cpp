#include <cstring>
#include "frame_factory.h"
#include "net80211.h"
#include "rand.h"
#include "utils/vector_appender.h"
#include "utils/hash.h"
#include "utils/debug.h"

DisassociationFuzzer::DisassociationFuzzer(
    const std::uint8_t *src_mac_,
    const std::uint8_t *dst_mac_,
    unsigned int rand_seed) :
rand_provider(rand_seed)
{
    memcpy(src_mac, src_mac_, 6);
    memcpy(dst_mac, dst_mac_, 6);
}

std::vector<std::uint8_t> DisassociationFuzzer::next() {
    std::vector<std::uint8_t> rt = get_base_rt();

    /* MAC header */
    struct ieee80211_frame ieee802_frame{};

    ieee802_frame.i_fc[0] = 0xa0;     // disass
    ieee802_frame.i_fc[1] = 0x00;

    ieee802_frame.i_dur[0] = 0x3a;    // copied from wireshark
    ieee802_frame.i_dur[1] = 0x01;

    memcpy(ieee802_frame.i_addr1, dst_mac, 6);   // copy destination mac
    memcpy(ieee802_frame.i_addr2, src_mac, 6);   // copy my mac
    memcpy(ieee802_frame.i_addr3, src_mac, 6);   // copy my mac

    // idk why
    ieee802_frame.i_seq[0] = 0x90;
    ieee802_frame.i_seq[1] = 0x08;

    std::vector<std::uint8_t> ieee802_frame_ {(std::uint8_t *)&ieee802_frame, (std::uint8_t *)&ieee802_frame + sizeof(struct ieee80211_frame)};

    std::vector<std::uint8_t> content = rand_provider.get_vector(rand_provider.get_byte());


//    std::vector<std::uint8_t> result{};
//    // TODO generic vector combiner
//    std::copy(rt.begin(), rt.end(), std::back_inserter(result));
//    std::copy(ieee802_frame_.begin(), ieee802_frame_.end(), std::back_inserter(result));
//    std::copy(content.begin(), content.end(), std::back_inserter(result));

    auto result = combine_vec({rt, ieee802_frame_, content});

    uint32_t crc = crc32(result.size(), result.data());
    std::copy((uint8_t *)&crc, (uint8_t *)(&crc) + 4, std::back_inserter(result));
    return result;
}