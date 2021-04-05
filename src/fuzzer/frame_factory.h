#ifndef CPP_FRAME_FACTORY_H
#define CPP_FRAME_FACTORY_H

#include <cinttypes>
#include <vector>
#include "utils/rand_provider.h"
#include "ssid.h"

std::vector<std::uint8_t> get_base_rt();
//
//std::uint8_t rand_byte();
//std::vector<std::uint8_t> rand_vec(size_t len);

struct SSIDFuzzer {
    explicit SSIDFuzzer(unsigned int rand_seed): rand_provider(rand_seed) {}

    void init() {
        curr_len = 0;
        curr_gen_len = 0;
    }

    unsigned num_mutations() {
        return 10; // TODO
    }

    std::vector<std::uint8_t> next();

private:
    RandProvider rand_provider;

    const int max_len = 255;
    const int max_gen_len = 1024;

    int curr_len = 0;
    int curr_gen_len = 0;
};

struct PrbRespFrameFuzzer {

    explicit PrbRespFrameFuzzer(const std::uint8_t *src_mac, unsigned rand_seed);
    std::vector<std::uint8_t> get_prb_resp(const std::uint8_t *dest_mac);

    std::vector<std::uint8_t> fuzz_prb_req_content();

    std::vector<std::uint8_t> fuzz_ssid();

private:
    FuzzableSSID fuzzer_ssid{};

    RandProvider rand_provider;

    std::uint8_t source_mac[6]{};

    unsigned fuzzed_ssids = 0;
};

struct BeaconFrameFuzzer {
    explicit BeaconFrameFuzzer(const std::uint8_t *src_mac, unsigned int rand_seed);
    std::vector<std::uint8_t> next();

private:
    std::vector<std::uint8_t> fuzz_content();

    SSIDFuzzer ssid_fuzzer;

    RandProvider rand_provider;

    std::uint8_t source_mac[6];
};

struct DisassociationFuzzer {
    explicit DisassociationFuzzer(const std::uint8_t *src_mac_,
                                  const std::uint8_t *dst_mac_,
                                  unsigned int rand_seed);
    std::vector<std::uint8_t> next();

private:
    RandProvider rand_provider;

    std::uint8_t src_mac[6]{};
    std::uint8_t dst_mac[6]{};
};

struct DeauthentiactionFuzzer {
    explicit DeauthentiactionFuzzer(const std::uint8_t *src_mac,
                                    const std::uint8_t *dst_mac,
                                    unsigned int rand_seed);
    std::vector<std::uint8_t> next();

private:
    RandProvider rand_provider;

    std::uint8_t src_mac[6]{};
    std::uint8_t dst_mac[6]{};
};

#endif //CPP_FRAME_FACTORY_H
