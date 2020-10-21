#ifndef CPP_HASH_H
#define CPP_HASH_H

#include <cstdint>


namespace wi_fuzz::hash {

inline std::uint16_t inet_csum(const void *buf, std::size_t hdr_len)
{
    unsigned long sum = 0;
    const uint16_t *ip1;

    ip1 = (const uint16_t *) buf;
    while (hdr_len > 1) {
        sum += *ip1++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        hdr_len -= 2;
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (~sum);
}

} // namespace wi_fuzz::hash

#endif //CPP_HASH_H
