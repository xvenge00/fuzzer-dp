#ifndef CPP_CONFIG_LOADER_H
#define CPP_CONFIG_LOADER_H

#include <filesystem>
#include <fstream>
#include "config/config.h"
#include <yaml-cpp/yaml.h>

// TODO to cpp
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
    } else if (in == "auth") {
        return AUTH;
    } else if (in == "beacon") {
        return BEACON;
    } else if (in == "ass_resp") {
        return ASS_RESP;
    } else {
        throw std::runtime_error(in + std::string(" is not valid fuzzer type"));
    }
}

std::chrono::seconds parse_duration_s(const std::string &d) {
    return std::chrono::seconds(std::stoi(d));
}

std::chrono::milliseconds parse_duration_ms(const std::string &d) {
    return std::chrono::milliseconds (std::stoi(d));
}

ConfigMonitor parse_monitor_config(const YAML::Node &monitor_node) {
    auto type = monitor_node["type"].as<std::string>();
    auto frame_history_len = monitor_node["frame_history_len"].as<unsigned >();
    std::filesystem::path dump_file = monitor_node["dump_file"].as<std::string>();

    if (type == "passive") {
        return {
            .frame_history_len = frame_history_len,
            .type = PASSIVE,
            .timeout = parse_duration_s(monitor_node["timeout_s"].as<std::string>()),
            .dump_file = dump_file,
        };
#ifdef GRPC_ENABLED
    } else if (type == "grpc") {
        return {
            .frame_history_len = frame_history_len,
            .type = GRPC,
            .server_address = monitor_node["server_address"].as<std::string>(),
            .dump_file = dump_file,
        };
#endif
    } else if (type == "sniffing") {
        return {
            .frame_history_len = frame_history_len,
            .type = SNIFFING,
            .timeout = parse_duration_s(monitor_node["timeout_s"].as<std::string>()),
            .interface = monitor_node["interface"].as<std::string>(),
            .dump_file = dump_file,
        };
    } else {
        throw std::logic_error("invalid monitor type");
    }
}


ConfigController parse_controller_config(const YAML::Node &controller_node) {
    // not mandatory
    std::chrono::milliseconds wait_duration;
    try {
        wait_duration = parse_duration_ms(controller_node["wait_duration_ms"].as<std::string>());
    } catch (std::exception &e) {
        wait_duration = std::chrono::milliseconds(0);
    }

    return {
        .wait_duration = wait_duration,
        .packet_resend_count = controller_node["packet_resend_count"].as<unsigned>(),
    };
}

Config load_config(const std::filesystem::path &config_file) {
    auto config_node = YAML::LoadFile(config_file);
    return {
        .interface = config_node["interface"].as<std::string>(),
        .random_seed = config_node["random_seed"].as<unsigned>(),
        .src_mac = parse_mac(config_node["src_mac"].as<std::string>()),
        .test_device_mac = parse_mac(config_node["test_device_mac"].as<std::string>()),
        .channel = config_node["channel"].as<std::uint8_t>(),
        .fuzzer_type = parse_fuzzer_type(config_node["fuzzer_type"].as<std::string>()),
        .monitor = parse_monitor_config(config_node["monitor"]),
        .controller = parse_controller_config(config_node["controller"]),
    };
}

#endif //CPP_CONFIG_LOADER_H
