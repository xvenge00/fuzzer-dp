#ifndef CPP_FUZZER_H
#define CPP_FUZZER_H

#include <cinttypes>
#include <vector>

std::vector<std::uint8_t> get_base_rt();

std::uint8_t rand_byte();
std::vector<std::uint8_t> rand_vec(size_t len);

struct FuzzerSSID {
    void init() {
        curr_len = 0;
        curr_gen_len = 0;
    }

    std::vector<std::uint8_t> next();

private:
    const int max_len = 255;
    const int max_gen_len = 1024;

    int curr_len = 0;
    int curr_gen_len = 0;
};

struct PrbRespFrameFuzzer {

    explicit PrbRespFrameFuzzer(const std::uint8_t *src_mac);
    std::vector<std::uint8_t> get_prb_resp(const std::uint8_t *dest_mac);

    std::vector<std::uint8_t> fuzz_prb_req_content();

private:
    FuzzerSSID fuzzer_ssid{};

    std::uint8_t source_mac[6];
};

#endif //CPP_FUZZER_H
