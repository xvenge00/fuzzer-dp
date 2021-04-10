#ifndef CPP_FRAME_FACTORY_H
#define CPP_FRAME_FACTORY_H

#include <cinttypes>
#include <vector>
#include <fuzzer/tags/tim.h>
#include <fuzzer/tags/cf_param.h>
#include <fuzzer/tags/generic_tag.h>
#include "utils/rand_provider.h"
#include "fuzzer/tags/ssid.h"
#include "fuzzer/tags/supported_rates.h"
#include "fuzzer/tags/ds_params.h"
#include "fuzzer/tags/fh_param.h"

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

    std::vector<std::uint8_t> fuzz_supported_rates();

    std::vector<std::uint8_t> fuzz_ds_params();

    std::vector<std::uint8_t> fuzz_fh_params();

    std::vector<std::uint8_t> fuzz_tim();

    std::vector<std::uint8_t> fuzz_cf_params();

    std::vector<std::uint8_t> fuzz_erp();

    std::vector<std::uint8_t> fuzz_generic(std::uint8_t tag, Fuzzable &fuzzer);

private:
    FuzzableSSID fuzzer_ssid{};

    SupportedRatesFuzzer fuzzer_supported_rates{};

    DSParamsFuzzer fuzzer_ds_params{};

    FHParamsFuzzer fuzzer_fh_params{};

    TIMFuzzer fuzzer_tim{};

    CFParamsFuzzer fuzzer_cf_params{};

    GenericTagFuzzer fuzzer_erp{};

    RandProvider rand_provider;

    std::uint8_t source_mac[6]{};

    unsigned fuzzed_ssids = 0;
    unsigned fuzzed_supp_rates = 0;
    unsigned fuzzed_ds_params = 0;
    unsigned fuzzed_fh_params = 0;
    unsigned fuzzed_tims = 0;
    unsigned fuzzed_cf_params = 0;
    unsigned fuzzed_erp_params = 0;
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
