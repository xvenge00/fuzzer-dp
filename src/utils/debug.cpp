#include <iomanip>
#include "debug.h"

void print_mac(const uint8_t *mac) {
    fprintf(stderr, "%02x:%02x:%02x:%02x:%02x:%02x\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_bytes(std::ostream& out, const unsigned char *data, size_t dataLen, bool format) {
    out << std::setfill('0');
    for(size_t i = 0; i < dataLen; ++i) {
        out << std::hex << std::setw(2) << (int)data[i];
        if (format) {
            out << (((i + 1) % 16 == 0) ? "\n" : " ");
        }
    }
    out << std::endl;
}
