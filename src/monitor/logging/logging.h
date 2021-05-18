/*
 * Author: Adam Venger (xvenge00)
 * 2021
 */


#ifndef CPP_LOGGING_H
#define CPP_LOGGING_H

#include <vector>
#include <cinttypes>
#include <ostream>
#include <filesystem>
#include <iostream>

void dump_frames(
    const std::vector<std::vector<std::uint8_t>> &frames,
    std::ostream &ostream = std::cout,
    const std::string &end = "-"
);

void dump_frames(
    const std::vector<std::vector<std::uint8_t>> &frames,
    const std::filesystem::path &path,
    const std::string &end = "-"
);

#endif //CPP_LOGGING_H
