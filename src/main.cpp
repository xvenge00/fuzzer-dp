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
#include <utils/vector_appender.h>

struct Fuzzable {
    bool is_mutable = true;

    virtual std::vector<uint8_t> get_mutated() = 0;

    virtual size_t num_mutations() = 0;

    virtual ~Fuzzable() = default;
};


using namespace std::literals::string_literals;

struct FuzzableSSID: public Fuzzable {
    size_t num_mutations() override {
        return fuzz_lengths.size() + fuzz_dict.size() + 1 + 1;
    }

    std::vector<uint8_t> get_mutated() override {
        std::vector<uint8_t> res {};

        // trying printable chars
        if (i_len_to_try < fuzz_lengths.size()) {
            res.reserve(fuzz_lengths[i_len_to_try] + 1);
            auto ssid_len = std::vector<uint8_t>{fuzz_lengths[i_len_to_try]};
            auto ssid = get_printable(fuzz_lengths[i_len_to_try]);

            res = combine_vec({ssid_len, ssid});

            ++i_len_to_try;
        } else if (i_fuzz_dict < fuzz_dict.size()){     // trying prepared ssids
            auto &str = fuzz_dict[i_fuzz_dict];

            res.reserve(str.length() + 1);
            auto ssid_len = std::vector<uint8_t>{(uint8_t) str.length()};
            auto ssid = std::vector<uint8_t>{str.begin(), str.end()};

            res = combine_vec({ssid_len, ssid});

            ++i_fuzz_dict;
        }   else if (!tried_zero_len) {     // trying zero length string
            auto ssid_len = std::vector<uint8_t>{0};
            auto ssid = get_printable(255);

            res = combine_vec({ssid_len, ssid});

            tried_zero_len = true;
        } else if (!tried_shorter) {   // trying shorter claimed length
            auto ssid_len = std::vector<uint8_t>{32};
            auto ssid = get_printable(255);

            res = combine_vec({ssid_len, ssid});

            tried_shorter = true;
        }

        return res;
    }

private:
    bool tried_zero_len = false;
    bool tried_shorter = false;
    unsigned i_len_to_try = 0;
    const std::array<std::uint8_t, 11> fuzz_lengths{0,1,2,4,8,32,33,64,127,128,255};
    unsigned i_fuzz_dict = 0;
    const std::array<std::string, 23> fuzz_dict {
        "!@#$%%^#$%#$@#$%$$@#$%^^**(()",    // strings riped from boofuz
        "",
        "%00",
        "%00/",
        "%01%02%03%04%0a%0d%0aADSF",
        "%01%02%03@%04%0a%0d%0aADSF",
        "%\xfe\xf0%\x00\xff"s,
        "%xfexf0%x01xff%xfexf0%x01xff%xfexf0%x01xff%xfexf0%x01xff%xfexf0%x01xff%xfexf0%x01xff%xfexf0%x01xff%xfexf0%x01xff%xfexf0%x01xff%xfexf0%x01xff%xfexf0%x01xff%xfexf0%x01xff%xfexf0%x01xff%xfexf0%x01xff%xfexf0%x01xff%xfexf0%x01xff%xfexf0%x01xff%xfexf0%x01xff%xfexf0%x01xff%xfexf0%x01xff",
        "%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n",  // format strings.
        "%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n",
        "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
        "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
        "%u0000",
        "/%00/",
        "\nfoo",
        "foo\n",
        "foo\nfoo",
        "\0foo\0"s,
        "foo\0foo"s,
        "\r\n",
        "\x01\x02\x03\x04",
        "\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE",
        "\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE",
    };

    std::vector<uint8_t> get_printable(size_t size) {
        std::vector<uint8_t> res;
        res.reserve(size);
        for(size_t i = 0; i < size; ++i) {
            res.emplace_back('A');
        }
        return res;
    }
};

int main(int argc, char **argv)
{
    auto fuzz_ssid = FuzzableSSID{};

    for (int i = 0; i < fuzz_ssid.num_mutations(); ++i) {
        auto mutated = fuzz_ssid.get_mutated();
        for (unsigned char j : mutated) {
            std::cout << j;
        }
        std::cout << '\n';
    }

}