#ifndef CPP_MONITOR_H
#define CPP_MONITOR_H

#include <thread>
#include <iostream>
#include "../logging/ring_buffer.h"
#include "../logging/logging.h"

void monitor(GuardedCircularBuffer<std::vector<std::uint8_t>> &buffer) {
    while(true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5000));

        std::cout << "==============================\n";
        dump_frames(buffer.dump());
        std::cout << "==============================" << std::endl;
    }
}

#endif //CPP_MONITOR_H
