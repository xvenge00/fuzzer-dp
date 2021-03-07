add_library(frame_fuzzer fuzzer.cpp prb_resp_fuzzer.cpp beacon_fuzzer.cpp disass_fuzzer.cpp deauth_fuzzer.cpp)

target_include_directories(frame_fuzzer
						   PRIVATE ${CMAKE_SOURCE_DIR}/src
						   PRIVATE ${CMAKE_SOURCE_DIR}/thirdparty)