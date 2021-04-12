add_library(frame_fuzzer frame_factory.cpp beacon_fuzzer.cpp disass_fuzzer.cpp deauth_fuzzer.cpp probe_response.cpp authentication.cpp utils/int.cpp utils/string.cpp)

target_include_directories(frame_fuzzer
						   PRIVATE ${CMAKE_SOURCE_DIR}/src
						   PRIVATE ${CMAKE_SOURCE_DIR}/thirdparty)