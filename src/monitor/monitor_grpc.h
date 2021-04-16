#ifndef CPP_MONITOR_GRPC_H
#define CPP_MONITOR_GRPC_H

#include <thread>
#include <iostream>
#include <grpc++/grpc++.h>
#include "monitor.h"
#include "monitor.grpc.pb.h"
#include "logging/guarded_circular_buffer.h"

struct MonitorGrpcService: public monitor::EspMonitor::Service {
    Monitor &monitor_ref;

    explicit MonitorGrpcService(Monitor &monitor_ref);

    ::grpc::Status Notify(
        ::grpc::ServerContext *context,
        const ::google::protobuf::Empty *request,
        ::google::protobuf::Empty *response
    ) override;
};

struct MonitorESP: public Monitor {
    std::string server_address;
    MonitorGrpcService service;
    std::unique_ptr<grpc::Server> server;
    std::unique_ptr<std::thread> th_monitor;

    explicit MonitorESP(size_t frame_buff_size);

    ~MonitorESP() override;
};

#endif //CPP_MONITOR_GRPC_H
