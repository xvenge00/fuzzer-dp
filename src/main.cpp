#include <iostream>
#include <utils/debug.h>
#include "config/config.h"
#include "fuzzer.h"
#include "config/config_loader.h"

int main(int argc, char **argv)
{
    if (argc < 2) {
        std::cout << "nemas tam config\n";
        return 1;
    }
    std::string config_file = argv[1];    // "wlp3s0"

//    const std::array<std::uint8_t, 6>  my_mac = {0x00, 0x23, 0x45, 0x67, 0x89, 0xab};  // random
//    const std::array<std::uint8_t, 6> my_mac = {0x8c, 0xdc, 0x02, 0xd7, 0x35, 0x2b};    // zte router
//    const std::array<std::uint8_t, 6>  target_mac = {0x3c, 0x71 ,0xbf, 0xa6, 0xe6, 0xd0};    // ESP32
//    const std::array<std::uint8_t, 6>  target_mac = {0xd6, 0x10, 0x4e, 0x27, 0xf6, 0xb0};    // mobil

    auto config = load_config({config_file});

    return fuzz(config);
}
