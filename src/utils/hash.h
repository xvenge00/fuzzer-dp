/*
 * Author: Adam Venger (xvenge00)
 * 2021
 */


#ifndef CPP_HASH_H
#define CPP_HASH_H

#include <cstdint>

std::uint32_t crc32(std::uint32_t bytes_sz, const std::uint8_t *bytes);

std::uint16_t inet_csum(const void *buf, std::size_t hdr_len);

#endif //CPP_HASH_H
