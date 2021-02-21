#ifndef CPP_LOGGING_H
#define CPP_LOGGING_H

#include <boost/circular_buffer.hpp>

//#include "utils/debug.h"

void dump_frames(boost::circular_buffer<std::vector<std::uint8_t>> frames);

void dump_frames(std::vector<std::vector<std::uint8_t>> frames);

#endif //CPP_LOGGING_H
