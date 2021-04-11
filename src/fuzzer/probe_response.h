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
        mac_t source_mac,
        mac_t fuzzed_device_mac
    );

    size_t num_mutations() override;

    generator<fuzz_t> get_mutated() override;

private:
    generator<fuzz_t> fuzz_prb_req_content();
    generator<fuzz_t> fuzz_ssid();
    generator<fuzz_t> fuzz_supported_rates();
    generator<fuzz_t> fuzz_ds_params();
    generator<fuzz_t> fuzz_fh_params();
    generator<fuzz_t> fuzz_tim();
    generator<fuzz_t> fuzz_cf_params();
    generator<fuzz_t> fuzz_erp();
    generator<fuzz_t> fuzz_generic(std::uint8_t tag, Fuzzable &fuzzer);

    SSIDFuzzer fuzzer_ssid{};
    SupportedRatesFuzzer fuzzer_supported_rates{};
    DSParamsFuzzer fuzzer_ds_params{};
    FHParamsFuzzer fuzzer_fh_params{};
    TIMFuzzer fuzzer_tim{};
    CFParamsFuzzer fuzzer_cf_params{};
    GenericTagFuzzer fuzzer_erp{};
};

#endif //CPP_PROBE_RESPONSE_H
