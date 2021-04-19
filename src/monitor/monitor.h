#ifndef CPP_MONITOR_H
#define CPP_MONITOR_H

#include <atomic>
#include <filesystem>
#include "logging/guarded_circular_buffer.h"

struct Monitor {

    explicit Monitor(size_t frame_buff_size, std::filesystem::path dump_file);

    void dump_frames();

    virtual void notify();

    virtual ~Monitor() = default;

    GuardedCircularBuffer<std::vector<std::uint8_t>> &frame_buff();

    void set_failure();

    bool detected_failure();

private:
    GuardedCircularBuffer<std::vector<std::uint8_t>> frame_buff_;
    std::filesystem::path dump_file;
    std::atomic<bool> failure_detected{false};
};

#endif //CPP_MONITOR_H
