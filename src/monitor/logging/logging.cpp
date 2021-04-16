#include <boost/circular_buffer.hpp>
#include <iostream>
#include "logging.h"
#include "utils/debug.h"

void dump_frames(boost::circular_buffer<std::vector<std::uint8_t>> frames) {
    int i = frames.size();
    for (auto &f: frames) {
        std::cout << "Frame [current-" << --i << "]\n";
        print_bytes(std::cout, f.data(), f.size());
    }
}

void dump_frames(std::vector<std::vector<std::uint8_t>> frames) {
    int i = frames.size();
    for (auto &f: frames) {
        std::cout << "Frame [current-" << --i << "]\n";
        print_bytes(std::cout, f.data(), f.size());
    }
}
