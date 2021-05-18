/*
 * Author: Adam Venger (xvenge00)
 * 2021
 */


#ifndef CPP_GUARDED_CIRCULAR_BUFFER_H
#define CPP_GUARDED_CIRCULAR_BUFFER_H

#include <boost/circular_buffer.hpp>
#include <mutex>

template<typename T>
class GuardedCircularBuffer {
    boost::circular_buffer<T> buffer_;
    std::mutex mutex;

public:
    GuardedCircularBuffer(boost::circular_buffer<T> buff): buffer_(std::move(buff)) {}

    void push_back(T val) {
        std::lock_guard<std::mutex> lock(mutex);
        buffer_.push_back(val);
    }

    std::vector<T> dump() {
        std::lock_guard<std::mutex> lock(mutex);
        return {buffer_.cbegin(), buffer_.cend()};
    }
};

#endif //CPP_GUARDED_CIRCULAR_BUFFER_H
