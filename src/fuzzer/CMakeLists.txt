add_library(frame_fuzzer utils/rt.cpp beacon_fuzzer.cpp disass_fuzzer.cpp deauth_fuzzer.cpp probe_response.cpp authentication.cpp primitives/int.cpp primitives/string.cpp)

target_link_libraries(frame_fuzzer
					  spdlog::spdlog
					  )


target_include_directories(frame_fuzzer
						   PRIVATE ${CMAKE_SOURCE_DIR}/src
						   PRIVATE ${CMAKE_SOURCE_DIR}/thirdparty)