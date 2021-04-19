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
    monitor_ref.set_failure();
    return grpc::Status::OK;
}


MonitorGRPC::MonitorGRPC(
    size_t frame_buff_size,
    std::filesystem::path dump_file,
    const std::string &server_address
):
    Monitor(frame_buff_size, std::move(dump_file)),
    server_address(server_address),
    service(*this)
{
    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);

    server = std::unique_ptr<grpc::Server>{builder.BuildAndStart()};

    spdlog::info("Monitor server listening on {}", server_address);
    th_monitor = std::make_unique<std::thread>(&grpc::Server::Wait, server.get());
}

MonitorGRPC::~MonitorGRPC() {
    server->Shutdown();
    th_monitor->join();
}