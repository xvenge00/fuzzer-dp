add_subdirectory(fuzzer)
add_subdirectory(utils)
add_subdirectory(monitor)

add_library(libwifuzz++ fuzzer_control.cpp radiotap.cpp)

target_link_libraries(libwifuzz++
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

target_include_directories(libwifuzz++ ${WIFUZZ_INCLUDE_DIRS})

add_executable(wifuzz++ main.cpp)
target_link_libraries(wifuzz++ libwifuzz++)
target_include_directories(wifuzz++ PRIVATE ${CMAKE_SOURCE_DIR}/src)