#ifndef CPP_LOGGING_H
#define CPP_LOGGING_H

#include <boost/circular_buffer.hpp>
#include <iostream>
#include "../debug.h"

void dump_frames(boost::circular_buffer<std::vector<std::uint8_t>> frames) {
    int i = frames.size();
    for (auto &f: frames) {
        std::cout << "Frame [current-" << --i << "]\n";
        print_bytes(std::cout, f.data(), f.size());
    }
}

#endif //CPP_LOGGING_H
