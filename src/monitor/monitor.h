#ifndef CPP_MONITOR_H
#define CPP_MONITOR_H

#include <thread>
#include <iostream>
#include "logging/guarded_circular_buffer.h"
#include "logging/logging.h"
#include "monitor.grpc.pb.h"
#include <grpc++/grpc++.h>
#include <spdlog/spdlog.h>

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

struct MonitorESP {
    std::string server_address;
    MonitorService service;
    std::unique_ptr<grpc::Server> server;
    std::unique_ptr<std::thread> th_monitor;

    explicit MonitorESP(GuardedCircularBuffer<std::vector<std::uint8_t>> &buffer): server_address("0.0.0.0:50051"), service(buffer) {

        grpc::ServerBuilder builder;
        builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
        builder.RegisterService(&service);

        server = std::unique_ptr<grpc::Server>{builder.BuildAndStart()};

        spdlog::info("Monitor server listening on {}", server_address);
        th_monitor = std::make_unique<std::thread>(&grpc::Server::Wait, server.get());
    }

    ~MonitorESP() {
        server->Shutdown();
        th_monitor->join();
    }
};

void monitor_esp(GuardedCircularBuffer<std::vector<std::uint8_t>> &buffer);

#endif //CPP_MONITOR_H
