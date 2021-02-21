add_library(frame_fuzzer fuzzer.cpp)

target_include_directories(frame_fuzzer
						   PRIVATE ${CMAKE_SOURCE_DIR}/src
						   PRIVATE ${CMAKE_SOURCE_DIR}/thirdparty)