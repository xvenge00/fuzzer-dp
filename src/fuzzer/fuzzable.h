#ifndef CPP_FUZZABLE_H
#define CPP_FUZZABLE_H

#include <vector>
#include <cinttypes>

struct Fuzzable {
    virtual std::vector<uint8_t> get_mutated() = 0;

    virtual size_t num_mutations() = 0;

    virtual ~Fuzzable() = default;
};

#endif //CPP_FUZZABLE_H
