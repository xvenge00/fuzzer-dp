#include "monitor_grpc.h"
#include <spdlog/spdlog.h>


MonitorGrpcService::MonitorGrpcService(
    Monitor &monitor_ref
): monitor_ref(monitor_ref) {}

::grpc::Status MonitorGrpcService::Notify(
    ::grpc::ServerContext *context,
    const ::google::protobuf::Empty *request,
    ::google::protobuf::Empty *response
) {
    monitor_ref.dump_frames();
    return grpc::Status::OK;
}


MonitorESP::MonitorESP(size_t frame_buff_size):
    Monitor(frame_buff_size),
    server_address("0.0.0.0:50051"),    // TODO address
    service(*this)
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