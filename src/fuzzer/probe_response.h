/*
 * Author: Adam Venger (xvenge00)
 * 2021
 */


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
        mac_t fuzzed_device_mac,
        std::uint8_t channel,
        unsigned fuzz_random
    );

    size_t num_mutations() override;

    generator<fuzz_t> get_mutated() override;

private:
    generator<fuzz_t> fuzz_prb_req_content();

    const std::uint8_t channel;
    const unsigned fuzz_random;

    SSIDFuzzer fuzzer_ssid{channel, fuzz_random};
    SupportedRatesFuzzer fuzzer_supported_rates{channel, fuzz_random};
    DSParamsFuzzer fuzzer_ds_params{channel, fuzz_random};
    FHParamsFuzzer fuzzer_fh_params{channel, fuzz_random};
    TIMFuzzer fuzzer_tim{channel, fuzz_random};
    CFParamsFuzzer fuzzer_cf_params{channel, fuzz_random};
    GenericTagFuzzer fuzzer_erp{0x2a, channel, fuzz_random};
};

#endif //CPP_PROBE_RESPONSE_H
