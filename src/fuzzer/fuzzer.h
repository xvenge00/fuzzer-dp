#ifndef CPP_FUZZER_H
#define CPP_FUZZER_H

#include <cinttypes>
#include <vector>

std::vector<std::uint8_t> get_base_rt();

struct FrameFuzzer {
    std::vector<std::uint8_t> get_prb_resp(const std::uint8_t *dest_mac);
};

#endif //CPP_FUZZER_H
