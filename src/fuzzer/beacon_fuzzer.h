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
        std::uint8_t channel);

    generator<fuzz_t> get_mutated() override;

    size_t num_mutations() override;

private:
    generator<fuzz_t> fuzz_content();

    const std::uint8_t channel;

    SSIDFuzzer fuzzer_ssid{channel};
    SupportedRatesFuzzer fuzzer_supported_rates{channel};
    DSParamsFuzzer fuzzer_ds_params{channel};
    FHParamsFuzzer fuzzer_fh_params{channel};
    TIMFuzzer fuzzer_tim{channel};
    CFParamsFuzzer fuzzer_cf_params{channel};
    GenericTagFuzzer fuzzer_erp{0x2a, channel};
};


#endif //CPP_BEACON_FUZZER_H
