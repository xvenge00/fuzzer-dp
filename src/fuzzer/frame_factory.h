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


//struct DeauthentiactionFuzzer {
//    explicit DeauthentiactionFuzzer(const std::uint8_t *src_mac,
//                                    const std::uint8_t *dst_mac,
//                                    unsigned int rand_seed);
//    std::vector<std::uint8_t> next();
//
//private:
//    RandProvider rand_provider;
//
//    std::uint8_t src_mac[6]{};
//    std::uint8_t dst_mac[6]{};
//};

#endif //CPP_FRAME_FACTORY_H
