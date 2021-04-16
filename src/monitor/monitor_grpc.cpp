#include "monitor_grpc.h"
#include "logging/logging.h"
#include <spdlog/spdlog.h>

MonitorService::MonitorService(GuardedCircularBuffer<std::vector<std::uint8_t>> &frame_buff): frame_buff_(frame_buff) {}

::grpc::Status MonitorService::Notify(
    ::grpc::ServerContext *context,
    const ::google::protobuf::Empty *request,
    ::google::protobuf::Empty *response
) {
    dump_frames(frame_buff_.dump());
    std::cout << "==============================" << std::endl;

    return grpc::Status::OK;
}

MonitorESP::MonitorESP(GuardedCircularBuffer<std::vector<std::uint8_t>> &buffer):
    server_address("0.0.0.0:50051"),
    service(buffer)
{

    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);

    server = std::unique_ptr<grpc::Server>{builder.BuildAndStart()};

    spdlog::info("Monitor server listening on {}", server_address);
    th_monitor = std::make_unique<std::thread>(&grpc::Server::Wait, server.get());
}


MonitorESP::~MonitorESP() {
    server->Shutdown();
    th_monitor->join();
}