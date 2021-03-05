#ifndef CPP_EXCEPTION_H
#define CPP_EXCEPTION_H

#include <exception>

struct FuzzException : public std::runtime_error {
    FuzzException(): std::runtime_error("Fuzz Exception") {}
};

#endif //CPP_EXCEPTION_H
