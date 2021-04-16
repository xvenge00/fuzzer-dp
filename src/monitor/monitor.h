#ifndef CPP_MONITOR_H
#define CPP_MONITOR_H

#include "logging/guarded_circular_buffer.h"

struct Monitor {

    explicit Monitor(size_t frame_buff_size);

    void dump_frames();

    virtual ~Monitor() = default;

    GuardedCircularBuffer<std::vector<std::uint8_t>> &frame_buff();

private:
    GuardedCircularBuffer<std::vector<std::uint8_t>> frame_buff_;
};

#endif //CPP_MONITOR_H
