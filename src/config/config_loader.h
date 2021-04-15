#ifndef CPP_CONFIG_LOADER_H
#define CPP_CONFIG_LOADER_H

#include <filesystem>
#include <fstream>
#include "config/config.h"
#include <yaml-cpp/yaml.h>

// from https://stackoverflow.com/questions/276099/c-converting-a-mac-id-string-into-an-array-of-uint8-t
std::array<uint8_t, 6> parse_mac(std::string const& in) {
    unsigned int bytes[6];
    if (std::sscanf(in.c_str(),
                    "%02x:%02x:%02x:%02x:%02x:%02x",
                    &bytes[0], &bytes[1], &bytes[2],
                    &bytes[3], &bytes[4], &bytes[5]) != 6)
    {
        throw std::runtime_error(in+std::string(" is an invalid MAC address"));
    }

    std::array<uint8_t, 6> out{};
    for (int i = 0; i < 6; ++ i) {
        out[i] = bytes[i];
    }
    return out;
}

FuzzerType parse_fuzzer_type(std::string const& in ) {
    if (in == "prb_resp") {
        return PRB_RESP;
    } else if (in == "disassociation") {
        return DISASS;
    } else if (in == "deauthentication") {
        return DEAUTH;
    } else if (in == "beacon") {
        return BEACON;
    } else {
        throw std::runtime_error(in + std::string(" is not valid fuzzer type"));
    }
}

Config load_config(const std::filesystem::path &config_file) {
    auto config_node = YAML::LoadFile(config_file);
    return {
        .interface = config_node["interface"].as<std::string>(),
        .random_seed = config_node["random_seed"].as<unsigned>(),
        .src_mac = parse_mac(config_node["src_mac"].as<std::string>()),
        .test_device_mac = parse_mac(config_node["test_device_mac"].as<std::string>()),
        .fuzzer_type = parse_fuzzer_type(config_node["fuzzer_type"].as<std::string>()),
        .frame_history_len = config_node["frame_history_len"].as<unsigned >()
    };
}

#endif //CPP_CONFIG_LOADER_H
