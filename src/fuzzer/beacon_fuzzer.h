#ifndef CPP_BEACON_FUZZER_H
#define CPP_BEACON_FUZZER_H

#include "fuzzer/fuzzer.h"
#include <fuzzer/tags/ssid.h>
#include <fuzzer/tags/supported_rates.h>
#include <fuzzer/tags/ds_params.h>
#include <fuzzer/tags/fh_param.h>
#include <fuzzer/tags/cf_param.h>
#include <fuzzer/tags/tim.h>
#include <fuzzer/tags/generic_tag.h>


struct BeaconFrameFuzzer: public Fuzzer {
    explicit BeaconFrameFuzzer(
        mac_t src_mac,
        mac_t fuzzed_device_mac,
        std::uint8_t channel,
        unsigned fuzz_random);

    generator<fuzz_t> get_mutated() override;

    size_t num_mutations() override;

private:
    generator<fuzz_t> fuzz_content();

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


#endif //CPP_BEACON_FUZZER_H
