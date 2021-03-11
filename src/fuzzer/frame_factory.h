#ifndef CPP_FRAME_FACTORY_H
#define CPP_FRAME_FACTORY_H

#include <cinttypes>
#include <vector>

std::vector<std::uint8_t> get_base_rt();
//
//std::uint8_t rand_byte();
//std::vector<std::uint8_t> rand_vec(size_t len);

struct SSIDFuzzer {
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
    SSIDFuzzer fuzzer_ssid{};

    std::uint8_t source_mac[6]{};
};

struct BeaconFrameFuzzer {
    explicit BeaconFrameFuzzer(const std::uint8_t *src_mac);
    std::vector<std::uint8_t> next();

private:
    std::vector<std::uint8_t> fuzz_content();

    SSIDFuzzer ssid_fuzzer{};

    std::uint8_t source_mac[6];
};

struct DisassociationFuzzer {
    explicit DisassociationFuzzer(const std::uint8_t *src_mac, const std::uint8_t *dst_mac);
    std::vector<std::uint8_t> next();

private:
    std::uint8_t src_mac[6]{};
    std::uint8_t dst_mac[6]{};
};

struct DeauthentiactionFuzzer {
    explicit DeauthentiactionFuzzer(const std::uint8_t *src_mac, const std::uint8_t *dst_mac);
    std::vector<std::uint8_t> next();

private:
    std::uint8_t src_mac[6]{};
    std::uint8_t dst_mac[6]{};
};

#endif //CPP_FRAME_FACTORY_H
