#include "frame.h"
#include <stdexcept>

std::size_t get_radiotap_size(const std::uint8_t *data, std::size_t len) {
    if (len > 4) {
        return (((uint16_t)*(data+3)) << 4) | *(data+2);    // little endian to big endian
    }

    return 0;
}

const std::uint8_t *get_prb_req_mac(const std::uint8_t *data, std::size_t len) {
    if (len < 16) {
        throw std::runtime_error("frame too small to extract req mac");
    }

    return data + 10;
}

std::uint8_t get_frame_type(const std::uint8_t *packet, std::size_t packet_size) {
    if (packet_size < 2) {
        throw std::runtime_error("too small ieee802 frame");
    }

    return *packet;
}

