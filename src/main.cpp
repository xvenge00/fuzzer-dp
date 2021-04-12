#include <iostream>
#include <utils/debug.h>
#include "config/config.h"
#include "fuzzer_control.h"
#include "config/config_loader.h"

int main(int argc, char **argv)
{
    if (argc < 2) {
        std::cout << "nemas tam config\n";
        return 1;
    }
    std::string config_file = argv[1];    // "wlp3s0"

    auto config = load_config({config_file});

    return fuzz(config);
}
