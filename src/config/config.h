#ifndef CPP_CONFIG_H
#define CPP_CONFIG_H

#include <string>
#include <array>
#include <chrono>
#include <filesystem>

enum FuzzerType {
    PRB_RESP,
    DISASS,
    DEAUTH,
    AUTH,
    AUTH_RESP,
    ASS_RESP,
    BEACON,
};

enum MonitorType {
#ifdef GRPC_ENABLED
    GRPC,
#endif
    PASSIVE,
    SNIFFING,
};

enum SetUp {
    NoSetUp,
    PrbResp,
    Associate,
    Authenticate,
};

enum TearDown {
    NoTearDown,
    Deauthentiacte,
    Disassociate,
};

struct ConfigMonitor {
    unsigned frame_history_len;
    MonitorType type;
    std::string server_address;
    std::chrono::seconds timeout;
    std::string interface;
    std::filesystem::path dump_file;
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
    std::uint8_t channel;
    FuzzerType fuzzer_type;
    unsigned fuzz_random;
    SetUp set_up;
    TearDown tear_down;
    ConfigMonitor monitor;
    ConfigController controller;
};

#endif //CPP_CONFIG_H
