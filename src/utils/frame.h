#ifndef CPP_FRAME_H
#define CPP_FRAME_H

#include <cinttypes>

std::size_t get_radiotap_size(const std::uint8_t *data, std::size_t len);

const std::uint8_t *get_src_mac(const std::uint8_t *data, std::size_t len);

std::uint8_t get_frame_type(const std::uint8_t *packet, std::size_t packet_size);


#endif //CPP_FRAME_H
