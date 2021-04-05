#include <iostream>
#include <utils/debug.h>
#include "config/config.h"
#include "fuzzer.h"
#include "config/config_loader.h"

//int main(int argc, char **argv)
//{
//    if (argc < 2) {
//        std::cout << "nemas tam config\n";
//        return 1;
//    }
//    std::string config_file = argv[1];    // "wlp3s0"
//
////    const std::array<std::uint8_t, 6>  my_mac = {0x00, 0x23, 0x45, 0x67, 0x89, 0xab};  // random
////    const std::array<std::uint8_t, 6> my_mac = {0x8c, 0xdc, 0x02, 0xd7, 0x35, 0x2b};    // zte router
////    const std::array<std::uint8_t, 6>  target_mac = {0x3c, 0x71 ,0xbf, 0xa6, 0xe6, 0xd0};    // ESP32
////    const std::array<std::uint8_t, 6>  target_mac = {0xd6, 0x10, 0x4e, 0x27, 0xf6, 0xb0};    // mobil
//
//    auto config = load_config({config_file});
//
//    return fuzz(config);
//}

#include <iostream>
#include <vector>

struct Fuzzable {
    bool is_mutable = true;

    virtual std::vector<uint8_t> get_mutated() = 0;

    virtual size_t num_mutations() = 0;

    virtual ~Fuzzable() = default;
};

struct FuzzableUInt8: public Fuzzable {
    std::vector<uint8_t> get_mutated() override {
        uint8_t res;

        if (is_first) {
            res = 1;
            is_first = false;
        } else if (last_number == 0xff) {
            res = 0;
        } else if  (!(last_number & 0x80u)) {
            res = last_number << 1u;
        } else {
            res = (last_number >> 1u) | 0x80u;
        }

        last_number = res;
        return {res};
    }

    virtual size_t num_mutations() override {
        return 16;
    }

private:
    bool is_first = true;
    uint8_t last_number = 1;
};

struct FuzzableString: public Fuzzable {

    explicit FuzzableString(size_t max_size): max_size_(max_size), lengths_to_fuzz(max_size) {}

    size_t num_mutations() override {
//        return 2 * (max_size_ + 1);
        return 10;
    }

    std::vector<uint8_t> get_mutated() override {
        std::vector<uint8_t> res = {};

//        res = get_printable(max_size_ / len_divisions[i_len_divisions++]);
        res = get_printable(lengths_to_fuzz);

//        if (lengths_to_fuzz > 0) {
        lengths_to_fuzz >>= 1u;
//        }

//        if (i_len_divisions >= len_divisions.size() ) {
//            res = {};
//
//        }
//        if (!fuzzed_all_printable) {
//            res = get_printable(lengths_to_fuzz);
//
//            if (lengths_to_fuzz > max_size_) {
//                fuzzed_all_printable = true;
//                lengths_to_fuzz = 0;
//            }
//
//            ++lengths_to_fuzz;
//        } else if (!fuzzed_all_nulls) {
//            res = get_null(lengths_to_fuzz, max_size_ / 2);
//
//            if (lengths_to_fuzz >= max_size_) {
//                fuzzed_all_printable = true;
//            }
//
//            ++lengths_to_fuzz;
//        }

        // TODO not printable


        return res;
    }

private:
    bool fuzzed_all_printable = false;
    bool fuzzed_all_nulls = false;
    size_t max_size_;
    size_t lengths_to_fuzz;


//    std::array<uint8_t, 9> len_divisions = {1,2,3,4,6,10,16,32,64};
    unsigned i_len_divisions = 0;

    std::vector<uint8_t> get_printable(size_t size) {
        std::vector<uint8_t> res;
        res.reserve(size);
        for(size_t i = 0; i < size; ++i) {
            res.emplace_back('A');
        }
        return res;
    }

    std::vector<uint8_t> get_null(size_t size, uint32_t null_i) {
        std::vector<uint8_t> res;
        res.reserve(size);
        for(size_t i = 0; i < size; ++i) {
            if (i == null_i) {
                res.emplace_back('\0');
            } else {
                res.emplace_back('N');
            }
        }
        return res;
    }
};

struct FuzzableSSID: public Fuzzable {
    size_t num_mutations() override {

    }

    std::vector<uint8_t> get_mutated() override {

    }
};

int main(int argc, char **argv)
{
    auto fuzz_int = FuzzableUInt8{};
    auto fuzz_string = FuzzableString{255*2 - 10};

//    for (int i = 0; i < 32; ++i) {
//        std::cout << (int) fuzz_int.get_mutated()[0] << ',';
//    }

    for (int i = 0; i < fuzz_string.num_mutations(); ++i) {
        auto mutated = fuzz_string.get_mutated();
        for (unsigned char j : mutated) {
            std::cout << j;
        }
        std::cout << '\n';
    }

}