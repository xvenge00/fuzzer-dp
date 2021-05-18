/*
 * Author: Adam Venger (xvenge00)
 * 2021
 */


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

struct MonitorGRPC: public Monitor {
    std::string server_address;
    MonitorGrpcService service;
    std::unique_ptr<grpc::Server> server;
    std::unique_ptr<std::thread> th_monitor;

    explicit MonitorGRPC(
        size_t frame_buff_size,
        std::filesystem::path dump_file,
        const std::string &server_addr = "0.0.0.0:50051"
    );

    ~MonitorGRPC() override;
};

#endif //CPP_MONITOR_GRPC_H
