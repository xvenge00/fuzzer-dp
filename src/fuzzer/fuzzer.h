#ifndef CPP_FUZZER_H
#define CPP_FUZZER_H

#include <cinttypes>
#include <vector>

std::vector<std::uint8_t> get_base_rt();

struct FrameFuzzer {

    explicit FrameFuzzer(const std::uint8_t *src_mac);
    std::vector<std::uint8_t> get_prb_resp(const std::uint8_t *dest_mac);

    std::vector<std::uint8_t> fuzz_prb_req_content();

private:
    std::uint8_t source_mac[6];
};

#endif //CPP_FUZZER_H
