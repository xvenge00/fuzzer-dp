#include <iostream>
#include "monitor.h"
#include "logging/logging.h"

Monitor::Monitor(size_t frame_buff_size):
    frame_buff_(GuardedCircularBuffer(boost::circular_buffer<std::vector<std::uint8_t>>(frame_buff_size))) {}

void Monitor::dump_frames() {
    // TODO to file
    ::dump_frames(frame_buff_.dump());
    std::cout << "==============================" << std::endl;
}

void Monitor::notify() {}

GuardedCircularBuffer<std::vector<std::uint8_t>> &Monitor::frame_buff() {
    return frame_buff_;
}
