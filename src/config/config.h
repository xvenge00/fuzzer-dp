#ifndef CPP_CONFIG_H
#define CPP_CONFIG_H

#include <string>
#include <array>
#include <chrono>

enum FuzzerType {
    PRB_RESP,
    DISASS,
    DEAUTH,
    AUTH,
    BEACON,
};

enum MonitorType {
    GRPC,
    PASSIVE,
    SNIFFING,
};

struct ConfigMonitor {
    unsigned frame_history_len;
    MonitorType type;
    std::string server_address;
    std::chrono::seconds timeout;
    std::string interface;
};

struct ConfigController {
    std::chrono::milliseconds wait_duration;
    unsigned packet_resend_count;
};

struct Config {
    std::string interface;
    unsigned random_seed;
    std::array<std::uint8_t, 6> src_mac;
    std::array<std::uint8_t, 6> test_device_mac;
    FuzzerType fuzzer_type;
    ConfigMonitor monitor;
    ConfigController controller;
};

#endif //CPP_CONFIG_H
