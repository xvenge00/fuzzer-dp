#include "monitor.h"

void monitor_esp(GuardedCircularBuffer<std::vector<std::uint8_t>> &buffer) {
    std::string server_address("0.0.0.0:50051");
    MonitorService service{buffer};

    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);


    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    std::cout << "Server listening on " << server_address << std::endl;

    server->Wait();
}