#ifndef CPP_FUZZABLE_H
#define CPP_FUZZABLE_H

#include <vector>
#include <cinttypes>
#include "utils/generator.h"

using fuzz_t = std::vector<std::uint8_t>;

struct Fuzzable {
    virtual generator<fuzz_t> get_mutated() = 0;

    virtual size_t num_mutations() = 0;

    virtual ~Fuzzable() = default;
};

#endif //CPP_FUZZABLE_H
