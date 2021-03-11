#include <iostream>
#include "config.h"
#include "fuzzer.h"

int main(int argc, char **argv)
{
    if (argc < 2) {
        std::cout << "nemas tam interface\n";
        return 1;
    }
    std::string interface = argv[1];    // "wlp3s0"

//    const std::array<std::uint8_t, 6>  my_mac = {0x00, 0x23, 0x45, 0x67, 0x89, 0xab};  // random
    const std::array<std::uint8_t, 6> my_mac = {0x8c, 0xdc, 0x02, 0xd7, 0x35, 0x2b};    // zte router
//    const std::array<std::uint8_t, 6>  target_mac = {0x3c, 0x71 ,0xbf, 0xa6, 0xe6, 0xd0};    // ESP32
    const std::array<std::uint8_t, 6>  target_mac = {0xd6, 0x10, 0x4e, 0x27, 0xf6, 0xb0};    // mobil

    Config config{
        .interface = interface,
        .random_seed = 420,
        .src_mac = my_mac,
        .test_device_mac = target_mac,
        .fuzzer_type = DISASS,
        .frame_history_len = 10
    };

    return fuzz(config);
}
