set(MONITOR_SOURCES
	logging/logging.cpp
	monitor.cpp
	monitor_passive.cpp
)
set(MONITOR_LINK_LIBRARIES
	fuzzer_utils
	spdlog::spdlog
)
set(MONITOR_INCLUDE_DIRECTORIES
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/thirdparty
)

if (GRPC_ENABLED)
	set(MONITOR_SOURCES ${MONITOR_SOURCES}
		monitor_grpc.cpp
	)
	set(MONITOR_LINK_LIBRARIES ${MONITOR_LINK_LIBRARIES}
		fuzzer-protos
		gRPC::grpc++
		gRPC::grpc++_reflection
	)
	set(MONITOR_INCLUDE_DIRECTORIES ${MONITOR_INCLUDE_DIRECTORIES}
		PRIVATE "${PROJECT_BINARY_DIR}/proto"
	)
endif()

add_library(fuzzer_monitor ${MONITOR_SOURCES})
target_link_libraries(fuzzer_monitor ${MONITOR_LINK_LIBRARIES})
target_include_directories(fuzzer_monitor ${MONITOR_INCLUDE_DIRECTORIES})