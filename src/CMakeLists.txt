set(SOURCES main.cpp)

add_executable(wi_fuzz main.cpp radiotap.cpp)

target_link_libraries(wi_fuzz
					  ${PCAP_LIBRARY}
					  spdlog::spdlog
					  gRPC::grpc++
					  gRPC::grpc++_reflection
					  fuzzer-protos)

target_include_directories(wi_fuzz
						   PRIVATE ${CMAKE_SOURCE_DIR}/thirdparty
						   PRIVATE "${PROJECT_BINARY_DIR}/proto")