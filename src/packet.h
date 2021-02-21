#ifndef CPP_PACKET_H
#define CPP_PACKET_H

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include "radiotap.h"
#include "net80211.h"
#include "utils/hash.h"

namespace wi_fuzz {

struct Packet {
    std::size_t size;
    std::uint8_t *data;

    Packet(std::size_t size, uint8_t *data) : size(size), data(data) {}
    virtual ~Packet() {
        free(data);
    }
};

inline Packet RTS_base_packet() {
    const uint8_t ap_mac[] = {0x5c, 0x6a, 0x80, 0x9a, 0xaa, 0xed};
    const uint8_t mac[6] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab };

    std::size_t packet_size = RadiotapBase::size() + sizeof(struct ieee80211_frame_rts) + 4 /* FCS */;
    auto *buf = (uint8_t *) malloc(packet_size);

    /* Copy radiotap header to the start of packet buffer */
    memcpy(buf, RadiotapBase::get(), RadiotapBase::size());

    /* Copy 802.11 header behind radiotap */
//    memcpy(buf + RadiotapBase::size(), )
    auto *hdr = (struct ieee80211_frame_rts *) (buf+RadiotapBase::size());

    *(&hdr->i_fc[0]) = (IEEE80211_FC0_TYPE_CTL | IEEE80211_FC0_SUBTYPE_RTS);
    *(&hdr->i_fc[1]) = 0;

    hdr->i_dur[0] = 0x00;
    hdr->i_dur[1] = 0xfe;

    memcpy(&hdr->i_ra[0], ap_mac, 6*sizeof(uint8_t));
    memcpy(&hdr->i_ta[0], mac, 6*sizeof(uint8_t));

    std::size_t usefull_payload_size = RadiotapBase::size() + sizeof(struct ieee80211_frame_rts);
    auto *fcs = (std::uint16_t *) (buf + usefull_payload_size);
    *fcs = hash::inet_csum(buf, usefull_payload_size);

    return {packet_size, buf};
}

}

#endif //CPP_PACKET_H
