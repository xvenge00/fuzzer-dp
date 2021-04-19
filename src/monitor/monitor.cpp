#include <iostream>
#include <utility>
#include "monitor.h"
#include "logging/logging.h"

Monitor::Monitor(
    size_t frame_buff_size,
    std::filesystem::path dump_file
):
    frame_buff_(GuardedCircularBuffer(boost::circular_buffer<std::vector<std::uint8_t>>(frame_buff_size))),
    dump_file(std::move(dump_file)) {}

void Monitor::dump_frames() {
    ::dump_frames(frame_buff_.dump(), dump_file, "=====================");
}

void Monitor::notify() {}

GuardedCircularBuffer<std::vector<std::uint8_t>> &Monitor::frame_buff() {
    return frame_buff_;
}
