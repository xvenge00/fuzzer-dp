#ifndef CPP_RADIOTAP_UTILS_H
#define CPP_RADIOTAP_UTILS_H

namespace wi_fuzz::radiotap {

constexpr unsigned to_radiotap_flag(unsigned radiotap_type)
{
    return 1u << radiotap_type;
}

constexpr unsigned to_little_endian(unsigned iBigE)
{
    return ((iBigE & 0xFF) << 24) | ((iBigE & 0xFF00) << 8) | ((iBigE >> 8) & 0xFF00) | (iBigE >> 24);
}

}

#endif //CPP_RADIOTAP_UTILS_H
