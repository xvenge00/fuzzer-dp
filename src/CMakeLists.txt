set(SOURCES main.cpp)

add_executable(wi_fuzz main.cpp)

target_link_libraries(wi_fuzz ${PCAP_LIBRARY})
