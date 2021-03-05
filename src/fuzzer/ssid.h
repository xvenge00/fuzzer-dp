#ifndef CPP_SSID_H
#define CPP_SSID_H

#include <vector>
#include <cinttypes>
#include <math.h>
#include "exception.h"

//struct FuzzerSSIDLen {
//    void init() {
//        state = 0;
//    }
//
//    std::vector<std::uint8_t> next() {
//        if (state == 0) {
//            ++state;
//
//            return {0};
//        } else if(state <= 8){
//            return {static_cast<std::uint8_t>(pow(2, state++) - 1)};
//        } else {
//            throw FuzzException();
//        }
//    }
//
//int state = 0;
//};
//
//struct FuzzerSSIDName {
//    void init() {
//        state = 0;
//    }
//
//int state = 0;
//};

//struct FuzzerSSID {
//    std::vector<std::uint8_t> next() {
//        size_t max_i = 10;
//        for (int i = 0; i < max_i; ++i) {
//            int curr_len = pow(2, i)-1;
//
//        }
//    }
//};

#endif //CPP_SSID_H
