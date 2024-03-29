/*
 * Author: Adam Venger (xvenge00)
 * 2021
 */

#include "int.h"

namespace primitives {

std::vector<std::uint16_t> fuzz_uint16 =
    {0, 1, 2, 3, 16, 255, 256, 32767, 32768, 65535};

std::vector<std::uint16_t> fuzz_uint16_bigger_complement =
    {0, 1, 2, 3, 16, 255, 256, 32767, 32768, 65535, 4, 5, 6, 7, 8, 9, 10, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 254, 257, 511, 512, 513, 1023, 1024, 2047, 2048, 4095, 4096, 8191, 8192, 16383, 16384, 32767};

}

