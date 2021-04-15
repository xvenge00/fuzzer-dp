add_library(fuzzer_utils hash.cpp debug.cpp frame.cpp progress_bar.cpp)

target_include_directories(fuzzer_utils
						   PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})