set(SOURCES main.cpp)

add_subdirectory(fuzzer)
add_subdirectory(utils)
add_subdirectory(monitor)

add_library(libwifuzz fuzzer_control.cpp radiotap.cpp)

target_link_libraries(libwifuzz
					  ${PCAP_LIBRARY}
					  frame_fuzzer
					  fuzzer_utils
					  fuzzer_monitor
					  spdlog::spdlog
					  ${YAML_CPP_LIBRARIES}
					  )

set(WIFUZZ_INCLUDE_DIRS
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/thirdparty
	PRIVATE "${YAML_CPP_INCLUDE_DIRS}"
)

if (GRPC_ENABLED)
	set(WIFUZZ_INCLUDE_DIRS ${WIFUZZ_INCLUDE_DIRS}
		PRIVATE "${PROJECT_BINARY_DIR}/proto"
	)
endif()

target_include_directories(libwifuzz ${WIFUZZ_INCLUDE_DIRS})

add_executable(wi_fuzz main.cpp)
target_link_libraries(wi_fuzz libwifuzz)
target_include_directories(wi_fuzz PRIVATE ${CMAKE_SOURCE_DIR}/src)