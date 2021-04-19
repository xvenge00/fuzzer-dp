#ifndef CPP_MONITOR_H
#define CPP_MONITOR_H

#include <filesystem>
#include "logging/guarded_circular_buffer.h"

struct Monitor {

    explicit Monitor(size_t frame_buff_size, std::filesystem::path dump_file);

    void dump_frames();

    virtual void notify();

    virtual ~Monitor() = default;

    GuardedCircularBuffer<std::vector<std::uint8_t>> &frame_buff();

private:
    GuardedCircularBuffer<std::vector<std::uint8_t>> frame_buff_;
    std::filesystem::path dump_file;
};

#endif //CPP_MONITOR_H
