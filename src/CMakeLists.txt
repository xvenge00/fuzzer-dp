set(SOURCES main.cpp)

add_subdirectory(fuzzer)
add_subdirectory(utils)

add_library(libwifuzz fuzzer.cpp radiotap.cpp logging/logging.cpp monitor/monitor.cpp)

target_link_libraries(libwifuzz
					  ${PCAP_LIBRARY}
					  frame_fuzzer
					  fuzzer_utils
					  spdlog::spdlog
					  gRPC::grpc++
					  gRPC::grpc++_reflection
					  fuzzer-protos
					  )

target_include_directories(libwifuzz
						   PRIVATE ${CMAKE_SOURCE_DIR}/src
						   PRIVATE ${CMAKE_SOURCE_DIR}/thirdparty
						   PRIVATE "${PROJECT_BINARY_DIR}/proto"
						   )

add_executable(wi_fuzz main.cpp)
target_link_libraries(wi_fuzz libwifuzz)
target_include_directories(wi_fuzz PRIVATE ${CMAKE_SOURCE_DIR}/src)