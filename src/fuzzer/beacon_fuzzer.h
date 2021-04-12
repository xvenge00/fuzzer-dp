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
        mac_t fuzzed_device_mac);

    generator<fuzz_t> get_mutated() override;

    size_t num_mutations() override;

private:
    generator<fuzz_t> fuzz_content();

    SSIDFuzzer fuzzer_ssid{};
    SupportedRatesFuzzer fuzzer_supported_rates{};
    DSParamsFuzzer fuzzer_ds_params{};
    FHParamsFuzzer fuzzer_fh_params{};
    TIMFuzzer fuzzer_tim{};
    CFParamsFuzzer fuzzer_cf_params{};
    GenericTagFuzzer fuzzer_erp{0x2a};
};


#endif //CPP_BEACON_FUZZER_H
