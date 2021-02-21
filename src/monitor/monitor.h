#ifndef CPP_MONITOR_H
#define CPP_MONITOR_H

#include <thread>
#include <iostream>
#include "logging/ring_buffer.h"
#include "logging/logging.h"
#include "monitor.grpc.pb.h"
#include <grpc++/grpc++.h>

struct MonitorService: public monitor::EspMonitor::Service {
    explicit MonitorService(GuardedCircularBuffer<std::vector<std::uint8_t>> &frame_buff): frame_buff_(frame_buff) {}

    ::grpc::Status Notify(::grpc::ServerContext *context, const ::google::protobuf::Empty *request, ::google::protobuf::Empty *response) override {
        dump_frames(frame_buff_.dump());
        std::cout << "==============================" << std::endl;

        return grpc::Status::OK;
    }

private:
    GuardedCircularBuffer<std::vector<std::uint8_t>> &frame_buff_;
};

void monitor_esp(GuardedCircularBuffer<std::vector<std::uint8_t>> &buffer);

#endif //CPP_MONITOR_H
