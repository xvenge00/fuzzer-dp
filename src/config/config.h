#ifndef CPP_CONFIG_H
#define CPP_CONFIG_H

#include <string>
#include <array>

enum FuzzerType {
    PRB_RESP,
    DISASS,
    DEAUTH,
    AUTH,
    ASS_RESP,
    BEACON,
};

struct Config {
    std::string interface;
    unsigned random_seed;
    std::array<std::uint8_t, 6> src_mac;
    std::array<std::uint8_t, 6> test_device_mac;
    FuzzerType fuzzer_type;
    unsigned frame_history_len;
};

#endif //CPP_CONFIG_H
