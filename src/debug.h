#ifndef CPP_DEBUG_H
#define CPP_DEBUG_H


void print_mac(const uint8_t *mac) {
    fprintf(stderr, "%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

#endif //CPP_DEBUG_H
