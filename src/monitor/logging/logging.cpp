/*
 * Author: Adam Venger (xvenge00)
 * 2021
 */


#include <fstream>
#include "logging.h"
#include "utils/debug.h"


void dump_frames(
    const std::vector<std::vector<std::uint8_t>> &frames,
    std::ostream &ostream,
    const std::string &end
) {
    int i = frames.size();
    for (auto &f: frames) {
        ostream << "Frame [current-" << --i << "]\n";
        print_bytes(ostream, f.data(), f.size());
    }

    ostream << end << '\n';
}

void dump_frames(
    const std::vector<std::vector<std::uint8_t>> &frames,
    const std::filesystem::path &path,
    const std::string &end
) {
    std::ofstream outfile;
    outfile.open(path, std::ios_base::app); // append

    dump_frames(frames, outfile, end);
}
