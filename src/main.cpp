#include "compat.h"
#include <pcap.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net80211/ieee80211_radiotap.h>
#include <net80211/ieee80211.h>
#include "hash.h"
#include "radiotap.h"



/* A bogus MAC address just to show that it can be done */
const uint8_t mac[6] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab };

/**
 * Note that we are using the broadcast address as the destination and the
 * link-local address as the source to be nice to routers and such.
 *
 */
const char * to = "255.255.255.255";
const char * from = "169.254.1.1";

using namespace wi_fuzz;

int main(int, char **) {

    /* The parts of our packet */
//    uint8_t *radiotap = RadiotapBase::get();
//    struct ieee80211_frame *hdr;

    /* PCAP vars */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *ppcap;

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

    memcpy(&hdr->i_ra[0], mac, 6*sizeof(uint8_t));
    memcpy(&hdr->i_ta[0], mac, 6*sizeof(uint8_t));

    // TODO frame check
    ppcap = pcap_open_live("wlp2s0", 800, 1, 20, errbuf);
    if (ppcap == NULL) {
        printf("Could not open interface wlan0 for packet injection: %s", errbuf);
        return 2;
    }

    /**
     * Then we send the packet and clean up after ourselves
     */
    if (pcap_sendpacket(ppcap, buf, packet_size) == 0) {
        pcap_close(ppcap);
        return 0;
    }

    /**
     * If something went wrong, let's let our user know
     */
    pcap_perror(ppcap, "Failed to inject packet");
    pcap_close(ppcap);
    return 1;
}
