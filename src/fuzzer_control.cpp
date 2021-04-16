#include <cinttypes>
#include <pcap.h>
#include <vector>
#include <spdlog/spdlog.h>
#include <thread>
#include <monitor/monitor.h>
#include <fuzzer/probe_response.h>
#include <utils/progress_bar.h>
#include "logging/guarded_circular_buffer.h"
#include "fuzzer_control.h"
#include "net80211.h"
#include "utils/debug.h"
#include "config/config.h"
#include "fuzzer/response_fuzzer.h"
#include "fuzzer/beacon_fuzzer.h"
#include "fuzzer/disass_fuzzer.h"
#include "fuzzer/deauth_fuzzer.h"
#include "fuzzer/authentication.h"
#include "utils/frame.h"

void fuzz_response(
    pcap *handle,
    ResponseFuzzer &fuzzer,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames,
    void (* setup) (pcap *),
    void (* teardown) (pcap *)
) {
    struct pcap_pkthdr header{};
    auto frame_generator = fuzzer.get_mutated();
    auto frame_generator_it = frame_generator.begin();

    unsigned fuzzed_inputs = 0;

    while(true) {
        if (setup != nullptr) {
            setup(handle);
        }

        const u_char *packet = pcap_next(handle, &header);

        size_t rt_size = get_radiotap_size(packet, header.caplen);
        const std::uint8_t *ieee802_11_data = packet + rt_size;
        const std::size_t ieee802_11_size = header.caplen - rt_size;

        try{
            if (get_frame_type(ieee802_11_data, ieee802_11_size) == fuzzer.responds_to_subtype) {
                auto *mac = get_prb_req_mac(ieee802_11_data, ieee802_11_size);

                if (strncmp((const char *)mac, (const char*) fuzzed_device_mac.data(), 6) == 0) {
                    if (frame_generator_it != frame_generator.end()) {
                        auto frame = *frame_generator_it;
                        pcap_sendpacket(handle, frame.data(), frame.size());
                        sent_frames.push_back(*frame_generator_it);
                        ++frame_generator_it;
                        ++fuzzed_inputs;
                    } else {
                        throw std::runtime_error("exhausted fuzz pool");
                    }
                }
            }
        } catch (std::runtime_error &e) {
            spdlog::warn("Caught exception.");
        }

        if (teardown != nullptr) {
            teardown(handle);
        }

        print_progress_bar(fuzzed_inputs, fuzzer.num_mutations());

        // TODO fuj
        if (fuzzed_inputs >= fuzzer.num_mutations()) {
            break;
        }
    }
}

void fuzz_push(
    pcap *handle,
    Fuzzer &fuzzer,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames,
    void (* setup) (pcap *),
    void (* teardown) (pcap *)
) {
    auto frame_generator = fuzzer.get_mutated();
    auto frame_generator_it = frame_generator.begin();

    unsigned fuzzed_inputs = 0;

    while (true) {
        if (setup != nullptr) {
            setup(handle);
        }

        if (frame_generator_it != frame_generator.end()) {

            for (unsigned i = 0; i < packets_resend_count; ++i) {
                pcap_sendpacket(handle, frame_generator_it->data(), frame_generator_it->size());
            }

            sent_frames.push_back(*frame_generator_it);
            ++frame_generator_it;
            ++fuzzed_inputs;
        } else {
            throw std::runtime_error("exhausted fuzz pool");
        }

        if (teardown != nullptr) {
            teardown(handle);
        }

        print_progress_bar(fuzzed_inputs, fuzzer.num_mutations());

        // TODO fuj
        if (fuzzed_inputs >= fuzzer.num_mutations()) {
            break;
        }

        std::this_thread::sleep_for(wait_duration);
    }
}

void fuzz_prb_resp(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzz_device_mac,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames
) {
    spdlog::info("fuzzing probe response");
    ProbeResponseFuzzer fuzzer{src_mac, fuzz_device_mac};
    fuzz_response(
        handle,
        fuzzer,
        fuzz_device_mac,
        sent_frames,
        nullptr,
        nullptr);
}

void fuzz_beacon(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count
) {
    spdlog::info("fuzzing beacon");
    mac_t broadcast_mac{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    BeaconFrameFuzzer fuzzer{src_mac, broadcast_mac};
    fuzz_push(
        handle,
        fuzzer,
        wait_duration,
        packets_resend_count,
        sent_frames,
        nullptr,
        nullptr
    );
}

void fuzz_disass(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count
) {
    spdlog::info("fuzzing disass");
    auto fuzzer = DisassociationFuzzer{src_mac, fuzzed_device_mac};
    fuzz_push(
        handle,
        fuzzer,
        wait_duration,
        packets_resend_count,
        sent_frames,
        nullptr,
        nullptr
    );
}

void fuzz_deauth(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count
) {
    spdlog::info("fuzzing deauth");
    auto fuzzer = DeauthentiactionFuzzer{src_mac, fuzzed_device_mac};
    fuzz_push(
        handle,
        fuzzer,
        wait_duration,
        packets_resend_count,
        sent_frames,
        nullptr,
        nullptr
    );
}

void fuzz_auth(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames,
    const std::chrono::milliseconds &wait_duration,
    unsigned packets_resend_count
) {
    spdlog::info("fuzzing auth");
    auto fuzzer = AuthenticationFuzzer{src_mac, fuzzed_device_mac};
    fuzz_push(
        handle,
        fuzzer,
        wait_duration,
        packets_resend_count,
        sent_frames,
        nullptr,
        nullptr
    );
}

#include "fuzzer/utils/rt.h"
#include "utils/hash.h"

fuzz_t get_prb_req(
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac
) {
    std::vector<std::uint8_t> rt = get_base_rt();

    /* MAC header */
    struct ieee80211_frame ieee802_frame{};

    ieee802_frame.i_fc[0] = 0x50;     // probe response
    ieee802_frame.i_fc[1] = 0x00;

    ieee802_frame.i_dur[0] = 0x3a;    // copied from wireshark
    ieee802_frame.i_dur[1] = 0x01;

    memcpy(ieee802_frame.i_addr1, fuzzed_device_mac.data(), 6);   // copy destination mac
    memcpy(ieee802_frame.i_addr2, src_mac.data(), 6);   // copy my mac
    memcpy(ieee802_frame.i_addr3, src_mac.data(), 6);   // copy my mac

    // idk why
    ieee802_frame.i_seq[0] = 0x90;
    ieee802_frame.i_seq[1] = 0x08;

    std::vector<std::uint8_t> ieee802_frame_ {(std::uint8_t *)&ieee802_frame, (std::uint8_t *)&ieee802_frame + sizeof(struct ieee80211_frame)};

    /* prb content */
    std::vector<std::uint8_t> timestamp{0xa6, 0xee, 0x41, 0x98, 0xf8, 0xb1, 0x05, 0x00};
    std::vector<std::uint8_t> beacon_interval{0x64, 0x00};
//    std::vector<std::uint8_t> capability{0x01, 0x04};
    fuzz_t capability{0x01, 0x15};

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

    fuzz_t ds {
        0x03,   // ds
        0x01,   //len
        0x02    // channel 2
    };

//    fuzz_t country {
//        0x07,   // country
//        0x06,   // len
//        0x53, 0x4b,     // code sk
//        0x20,   // env any
//        0x01,   // first channel
//        0x0d,   // num of channels
//        0x14    // max trans. power
//    };
//
//    fuzz_t power_constraints {
//        0x20,   // pow constr.
//        0x01,   // len
//        0x00    // 0
//    };
//
//    fuzz_t tpc {
//        0x23, 0x02, 0x11, 0x00
//    };
//
//    fuzz_t cf {
//        0x04, 0x06, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41
//    };
//
//    fuzz_t erp {
//        0x2a,
//        0x01,
//        0x00
//    };
//
//    fuzz_t extended_rates {
//        0x32, 0x04, 0x0c, 0x12, 0x18, 0x60
//    };
//
//    fuzz_t ht_cap {
//        0x2d,
//        0x1a,
//        0xad, 0x01, 0x1b, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
//    };
//
//    fuzz_t ht_info {
//        0x3d, 0x16, 0x02, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
//    };
//
//    fuzz_t ext_cap {
//        0x7f, 0x08, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x40
//    };

    auto result = combine_vec({
        rt, ieee802_frame_, timestamp, beacon_interval, capability,
        ssid,
        supp_rates,
        ds,
//        country,
//        power_constraints,
//        tpc,
//        erp,
//        extended_rates,
//        ht_cap,
//        ht_info,
//        ext_cap,
//        cf,
    });
//    uint32_t crc = crc32(result.size(), result.data());
//    std::copy((uint8_t *)&crc, (uint8_t *)(&crc) + 4, std::back_inserter(result));

    return result;
}

fuzz_t get_auth_succ(
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac
) {
    std::vector<std::uint8_t> rt = get_base_rt();

    /* MAC header */
    struct ieee80211_frame ieee802_frame{};

    ieee802_frame.i_fc[0] = 0xb0;     // probe response
    ieee802_frame.i_fc[1] = 0x00;

    ieee802_frame.i_dur[0] = 0x3a;    // copied from wireshark
    ieee802_frame.i_dur[1] = 0x01;

    memcpy(ieee802_frame.i_addr1, fuzzed_device_mac.data(), 6);   // copy destination mac
    memcpy(ieee802_frame.i_addr2, src_mac.data(), 6);   // copy my mac
    memcpy(ieee802_frame.i_addr3, src_mac.data(), 6);   // copy my mac

    // idk why
    ieee802_frame.i_seq[0] = 0x90;
    ieee802_frame.i_seq[1] = 0x08;

    std::vector<std::uint8_t> ieee802_frame_ {(std::uint8_t *)&ieee802_frame, (std::uint8_t *)&ieee802_frame + sizeof(struct ieee80211_frame)};

    /* auth content */
    fuzz_t content = {
        0x00, 0x00, // open system
        0x02, 0x00, // seq num TODO check if correct endianess
        0x00, 0x00,  // successful
    };


    auto result = combine_vec({rt, ieee802_frame_, content});
//    uint32_t crc = crc32(result.size(), result.data());
//    std::copy((uint8_t *)&crc, (uint8_t *)(&crc) + 4, std::back_inserter(result));

    return result;
}

fuzz_t get_cts(
    mac_t target
) {
    std::vector<std::uint8_t> rt = get_base_rt();

    fuzz_t cts{
        0xc4,   // cts
        0x00,   // flags
        0x18, 0x0e, // duration
//        0xe0, 0x3e, 0x44, 0x08, 0x98, 0x1a  // reciever addr
    };

    fuzz_t mac{target.data(), target.data() + target.size()};

    return combine_vec({rt, cts, mac});
}

fuzz_t get_ass_succ(
    mac_t src_mac,
    mac_t target_mac
) {
    std::vector<std::uint8_t> rt = get_base_rt();

    /* MAC header */
    struct ieee80211_frame ieee802_frame{};

    ieee802_frame.i_fc[0] = 0x10;     // ass_succ
    ieee802_frame.i_fc[1] = 0x00;

    ieee802_frame.i_dur[0] = 0x3a;    // copied from wireshark
    ieee802_frame.i_dur[1] = 0x01;

    memcpy(ieee802_frame.i_addr1, target_mac.data(), 6);   // copy destination mac
    memcpy(ieee802_frame.i_addr2, src_mac.data(), 6);   // copy my mac
    memcpy(ieee802_frame.i_addr3, src_mac.data(), 6);   // copy my mac

    // idk why
    ieee802_frame.i_seq[0] = 0x90;
    ieee802_frame.i_seq[1] = 0x08;

    std::vector<std::uint8_t> ieee802_frame_ {(std::uint8_t *)&ieee802_frame, (std::uint8_t *)&ieee802_frame + sizeof(struct ieee80211_frame)};

    /* ass resp content */
//    std::vector<std::uint8_t> timestamp{0xa6, 0xee, 0x41, 0x98, 0xf8, 0xb1, 0x05, 0x00};
//    std::vector<std::uint8_t> beacon_interval{0x64, 0x00};
//    std::vector<std::uint8_t> capability{0x01, 0x04};
    fuzz_t capability{0x21, 0x04};
    fuzz_t status_code{0x00, 0x00};
    fuzz_t ass_id{0x01, 0xc0};

    // add supported rates
    std::vector<std::uint8_t> supp_rates {
        0x01,   // supported rates tag
        0x08,   // len
        0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c
    };

    fuzz_t ds {
        0x03,   // ds
        0x01,   //len
        0x02    // channel 2
    };

    fuzz_t country {
        0x07,   // country
        0x06,   // len
        0x53, 0x4b,     // code sk
        0x20,   // env any
        0x01,   // first channel
        0x0d,   // num of channels
        0x14    // max trans. power
    };

    fuzz_t power_constraints {
        0x20,   // pow constr.
        0x01,   // len
        0x00    // 0
    };

    fuzz_t tpc {
        0x23, 0x02, 0x11, 0x00
    };

    fuzz_t cf {
        0x04, 0x06, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41
    };

    fuzz_t erp {
        0x2a,
        0x01,
        0x00
    };

    fuzz_t extended_rates {
        0x32, 0x04, 0x0c, 0x12, 0x18, 0x60
    };

    fuzz_t ht_cap {
        0x2d,
        0x1a,
        0xad, 0x01, 0x1b, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    fuzz_t ht_info {
        0x3d, 0x16, 0x02, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    fuzz_t ext_cap {
        0x7f, 0x08, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x40
    };

    auto result = combine_vec({
        rt, ieee802_frame_,
        capability, status_code, ass_id,
        supp_rates,
        ds,
//        country,
//        power_constraints,
//        tpc,
//        erp,
//        extended_rates,
//        ht_cap,
//        ht_info,
//        ext_cap,
    });

    return result;
}

void fuzz_ass_resp(
    pcap *handle,
    const std::array<std::uint8_t, 6> &src_mac,
    const std::array<std::uint8_t, 6> &fuzzed_device_mac,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames
) {
    spdlog::info("fuzzing association response");

    struct pcap_pkthdr header{};

    // wait for prb req and send them
    auto prb_resp = get_prb_req(src_mac, fuzzed_device_mac);
//    while(true) {
//        const u_char *packet = pcap_next(handle, &header);
//
//        size_t rt_size = get_radiotap_size(packet, header.caplen);
//        const std::uint8_t *ieee802_11_data = packet + rt_size;
//        const std::size_t ieee802_11_size = header.caplen - rt_size;
//
//        try{
//            if (get_frame_type(ieee802_11_data, ieee802_11_size) == 0x40) { // prb request
//                auto *mac = get_prb_req_mac(ieee802_11_data, ieee802_11_size);
//
//                if (strncmp((const char *)mac, (const char*) fuzzed_device_mac.data(), 6) == 0) {
//                    for (int i = 0; i < 500; ++i) {
//                        pcap_sendpacket(handle, prb_resp.data(), prb_resp.size());
//                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
//                    }
//                    break;
//                }
//            }
//        } catch (std::runtime_error &e) {
////            spdlog::warn("Caught exception.");
//        }
//    }


//    auto fuzzer = AssociationRespFuzzer{src_mac, fuzzed_device_mac};
//    auto frame_generator = fuzzer.get_mutated();
//    auto frame_generator_it = frame_generator.begin();

    while(true) {
        const u_char *packet = pcap_next(handle, &header);

        size_t rt_size = get_radiotap_size(packet, header.caplen);
        const std::uint8_t *ieee802_11_data = packet + rt_size;
        const std::size_t ieee802_11_size = header.caplen - rt_size;

        try{
            auto *mac = get_prb_req_mac(ieee802_11_data, ieee802_11_size);
            if (strncmp((const char *)mac, (const char*) fuzzed_device_mac.data(), 6) == 0) {
                if (get_frame_type(ieee802_11_data, ieee802_11_size) == 0x40) { // prb request
                    for (int i = 0; i < 15; ++i) {
                        pcap_sendpacket(handle, prb_resp.data(), prb_resp.size());
                    }
                    spdlog::info("sent probe responses");
                }
                if (get_frame_type(ieee802_11_data, ieee802_11_size) == 0xb0) { // auth packet 1
                    auto auth_succ = get_auth_succ(src_mac, fuzzed_device_mac);
                    for (int i = 0; i < 1; ++i) {
                        pcap_sendpacket(handle, auth_succ.data(), auth_succ.size());
                    }
                    spdlog::info("auth");
                }
                if (get_frame_type(ieee802_11_data, ieee802_11_size) == (0xb0 & 0x4)) { // rts
                    auto cts = get_cts(fuzzed_device_mac);
                    for (int i = 0; i < 1; ++i) {
                        pcap_sendpacket(handle, cts.data(), cts.size());
                    }
                    spdlog::info("cts");
                }
                if (get_frame_type(ieee802_11_data, ieee802_11_size) == (0x00)) { // ass req
                    auto ass_resp = get_ass_succ(src_mac, fuzzed_device_mac);
                    for (int i = 0; i < 1; ++i) {
                        pcap_sendpacket(handle, ass_resp.data(), ass_resp.size());
                    }
                    spdlog::info("ass resp");
                }
            }
        } catch (std::runtime_error &e) {
//            spdlog::warn("Caught exception. {}", e.what());
        }
    }
}

int fuzz(Config config) {
    char errbuf[PCAP_ERRBUF_SIZE] = {}; // for errors (required)

    auto *handle = pcap_open_live(config.interface.c_str(), BUFSIZ/10, 0, 1, errbuf);
    if (handle == nullptr) {
        spdlog::critical("ERROR: {}", errbuf);
        return 1;
    }

    auto sent_frames = GuardedCircularBuffer(boost::circular_buffer<std::vector<std::uint8_t>>(config.frame_history_len));
    MonitorESP monitor{sent_frames};

    switch (config.fuzzer_type) {
    case PRB_RESP:
        fuzz_prb_resp(handle, config.src_mac, config.test_device_mac, sent_frames);
        break;
    case BEACON:
        fuzz_beacon(handle, config.src_mac, sent_frames, std::chrono::milliseconds{10}, 5); // TODO pass from config
        break;
    case DEAUTH:
        fuzz_deauth(handle, config.src_mac, config.test_device_mac, sent_frames, std::chrono::milliseconds{100}, 5);
        break;
    case AUTH:
        fuzz_auth(handle, config.src_mac, config.test_device_mac, sent_frames, std::chrono::milliseconds{100}, 5);
        break;
    case DISASS:
        fuzz_disass(handle, config.src_mac, config.test_device_mac, sent_frames, std::chrono::milliseconds{100}, 5);
        break;
    case ASS_RESP:
        // TODO
        fuzz_ass_resp(handle, config.src_mac, config.test_device_mac, sent_frames);
        break;
    }

    return 0;
}
