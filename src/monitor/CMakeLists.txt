add_library(fuzzer_monitor monitor_grpc.cpp logging/logging.cpp monitor.cpp)

target_link_libraries(
		fuzzer_monitor
		fuzzer_utils
		spdlog::spdlog
		gRPC::grpc++
		gRPC::grpc++_reflection
)

target_include_directories(
		fuzzer_monitor
		PRIVATE ${CMAKE_SOURCE_DIR}/src
		PRIVATE ${CMAKE_SOURCE_DIR}/thirdparty
		PRIVATE "${PROJECT_BINARY_DIR}/proto"
)