#ifndef CPP_RADIOTAP_H
#define CPP_RADIOTAP_H

#include <cstdint>


//namespace wi_fuzz {

class RadiotapBase {
    static std::uint8_t base[];
public:
    static constexpr std::uint8_t *get()
    {
        return base;
    }

    static constexpr std::size_t size()
    {
        return 24;  // counted
    }
};

//}

#endif //CPP_RADIOTAP_H
