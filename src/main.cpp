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
#include "responder.h"
#include "packet.h"
#include "sniffer.h"

using namespace wi_fuzz;

int main(int argc, char **argv)
{
    if (argc < 2) {
        std::cout << "nemas tam interface\n";
        return 1;
    }

    std::string interface = argv[1];    // "wlp2s0"

//    auto responder = Responder();

    // capture

    std::cerr << "constructing...\n";

    auto sniffer = Sniffer(interface);
    sniffer.set_handler(Responder::dispatch);
    sniffer.sniff();

    std::cerr << "...end\n";
}
