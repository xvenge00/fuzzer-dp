#ifndef CPP_PROBE_RESPONSE_H
#define CPP_PROBE_RESPONSE_H

#include "response_fuzzer.h"
#include <array>
#include <fuzzer/tags/ssid.h>
#include <fuzzer/tags/supported_rates.h>
#include <fuzzer/tags/ds_params.h>
#include <fuzzer/tags/fh_param.h>
#include <fuzzer/tags/cf_param.h>
#include <fuzzer/tags/tim.h>
#include <fuzzer/tags/generic_tag.h>

struct ProbeResponseFuzzer: public ResponseFuzzer {
    ProbeResponseFuzzer(
        std::array<std::uint8_t, 6> source_mac,
        std::array<std::uint8_t, 6> fuzzed_device_mac
    );

    size_t num_mutations() override;

    std::vector<uint8_t> get_mutated() override;

private:
    std::vector<std::uint8_t> fuzz_prb_req_content();
    std::vector<std::uint8_t> fuzz_ssid();
    std::vector<std::uint8_t> fuzz_supported_rates();
    std::vector<std::uint8_t> fuzz_ds_params();
    std::vector<std::uint8_t> fuzz_fh_params();
    std::vector<std::uint8_t> fuzz_tim();
    std::vector<std::uint8_t> fuzz_cf_params();
    std::vector<std::uint8_t> fuzz_erp();
    std::vector<std::uint8_t> fuzz_generic(std::uint8_t tag, Fuzzable &fuzzer);

    FuzzableSSID fuzzer_ssid{};
    SupportedRatesFuzzer fuzzer_supported_rates{};
    DSParamsFuzzer fuzzer_ds_params{};
    FHParamsFuzzer fuzzer_fh_params{};
    TIMFuzzer fuzzer_tim{};
    CFParamsFuzzer fuzzer_cf_params{};
    GenericTagFuzzer fuzzer_erp{};

//    RandProvider rand_provider;

    unsigned fuzzed_ssids = 0;
    unsigned fuzzed_supp_rates = 0;
    unsigned fuzzed_ds_params = 0;
    unsigned fuzzed_fh_params = 0;
    unsigned fuzzed_tims = 0;
    unsigned fuzzed_cf_params = 0;
    unsigned fuzzed_erp_params = 0;
};

#endif //CPP_PROBE_RESPONSE_H
