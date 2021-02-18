# TODO compile .proto files to sources

add_library(fuzzer-protos STATIC
			${CMAKE_CURRENT_BINARY_DIR}/monitor.grpc.pb.cc
			${CMAKE_CURRENT_BINARY_DIR}/monitor.pb.cc)

target_include_directories(fuzzer-protos PUBLIC "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(fuzzer-protos LINK_INTERFACE_LIBRARIES protobuf::libprotobuf)