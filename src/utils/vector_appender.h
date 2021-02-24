#ifndef CPP_VECTOR_APPENDER_H
#define CPP_VECTOR_APPENDER_H

#include "vector"

// TODO inefficien AF, make better when its a problem
template<typename T>
std::vector<T> operator+(const std::vector<T> &v1, const std::vector<T> &v2) {
    std::vector<T> res{};
    res.reserve(v1.size() + v2.size());

    std::copy(v1.cbegin(), v1.cend(), std::back_inserter(res));
    std::copy(v2.cbegin(), v2.cend(), std::back_inserter(res));

    return res;
}

template<typename T>
std::vector<T> combine_vec(std::initializer_list<std::vector<T>> vec_args) {
    std::vector<T> res{};
    for (auto i: vec_args) {
        res = res + i;
    }
    return res;
}


#endif //CPP_VECTOR_APPENDER_H
