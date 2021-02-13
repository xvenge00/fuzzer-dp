set(SOURCES main.cpp)

add_executable(wi_fuzz main.cpp radiotap.cpp)

target_link_libraries(wi_fuzz ${PCAP_LIBRARY} spdlog::spdlog)

target_include_directories(wi_fuzz PRIVATE ${CMAKE_SOURCE_DIR}/thirdparty)