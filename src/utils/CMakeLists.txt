add_library(fuzzer_utils hash.cpp debug.cpp)

target_include_directories(fuzzer_utils
						   PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})