cmake_minimum_required(VERSION 3.17)
project(cpp)

option(GRPC_ENABLED "Enable grpc monitor" OFF) # Disabled by default
if(GRPC_ENABLED)
	message("Building with GRPC monitor support")
	ADD_DEFINITIONS(-DGRPC_ENABLED=1)
else(GRPC_ENABLED)
	message("Building without GRPC monitor support")
endif(GRPC_ENABLED)

set(CMAKE_CXX_STANDARD 20)
add_compile_options(-fcoroutines)

set(CMAKE_CXX_FLAGS_RELEASE "-O3")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(PCAP REQUIRED)
find_package(spdlog REQUIRED)
find_package(Protobuf REQUIRED)
find_package(gRPC REQUIRED)
find_package(yaml-cpp)

add_subdirectory(src)
add_subdirectory(proto)
