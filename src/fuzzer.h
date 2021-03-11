#ifndef CPP_FUZZER_H
#define CPP_FUZZER_H

#include <cinttypes>
#include <pcap.h>
#include <vector>
#include "logging/guarded_circular_buffer.h"
#include "config.h"

std::size_t get_radiotap_size(const std::uint8_t *data, std::size_t len);

const std::uint8_t *get_prb_req_mac(const std::uint8_t *data, std::size_t len);

int8_t get_frame_type(const std::uint8_t *packet, size_t packet_size);


void fuzz_prb_resp(pcap *handle,
                   const std::uint8_t *src_mac,
                   const std::uint8_t *fuzz_device_mac,
                   GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames,
                   unsigned rand_seed);

[[noreturn]] void fuzz_beacon(
    // TODO sleep_for
    pcap *handle,
    const std::uint8_t *src_mac,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames,
    unsigned rand_seed
);

[[noreturn]] void fuzz_disass(
    pcap *handle,
    const std::uint8_t *src_mac,
    const std::uint8_t *dst_mac,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames,
    unsigned rand_seed
);

[[noreturn]] void fuzz_deauth(
    pcap *handle,
    const std::uint8_t *src_mac,
    const std::uint8_t *dst_mac,
    GuardedCircularBuffer<std::vector<std::uint8_t>> &sent_frames,
    unsigned rand_seed
);

int fuzz(Config config);

#endif //CPP_FUZZER_H
