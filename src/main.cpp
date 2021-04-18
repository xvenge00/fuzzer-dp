#include <iostream>
#include <utils/debug.h>
#include "config/config.h"
#include "fuzzer_control.h"
#include "config/config_loader.h"

void print_usage() {
    std::cout << "usage: wi_fuzz config.yaml\n";
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        print_usage();
        return 1;
    }
    std::string config_file = argv[1];

    Config config;
    try {
        config = load_config({config_file});
    } catch (YAML::Exception &e) {
        std::cout << "invalid config\n";
        return 1;
    }

    return fuzz(config);
}
