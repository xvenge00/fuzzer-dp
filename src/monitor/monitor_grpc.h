#ifndef CPP_MONITOR_GRPC_H
#define CPP_MONITOR_GRPC_H

#include <thread>
#include <iostream>
#include <grpc++/grpc++.h>
#include "monitor.h"
#include "monitor.grpc.pb.h"
#include "logging/guarded_circular_buffer.h"

struct MonitorService: public monitor::EspMonitor::Service {
    explicit MonitorService(GuardedCircularBuffer<std::vector<std::uint8_t>> &frame_buff);

    ::grpc::Status Notify(::grpc::ServerContext *context, const ::google::protobuf::Empty *request, ::google::protobuf::Empty *response) override;

private:
    GuardedCircularBuffer<std::vector<std::uint8_t>> &frame_buff_;
};

struct MonitorESP: public Monitor {
    std::string server_address;
    MonitorService service;
    std::unique_ptr<grpc::Server> server;
    std::unique_ptr<std::thread> th_monitor;

    explicit MonitorESP(GuardedCircularBuffer<std::vector<std::uint8_t>> &buffer);

    ~MonitorESP() override;
};

#endif //CPP_MONITOR_GRPC_H
