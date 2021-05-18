/*
 * Author: Adam Venger (xvenge00)
 * 2021
 */


#ifndef CPP_DEBUG_H
#define CPP_DEBUG_H

#include <ostream>

void print_mac(const uint8_t *mac);

void print_bytes(std::ostream& out, const unsigned char *data, size_t dataLen, bool format = true);

#endif //CPP_DEBUG_H
