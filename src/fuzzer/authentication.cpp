#include <utils/vector_appender.h>
#include "authentication.h"
#include "fuzzer/primitives/int.h"
#include "fuzzer/primitives/string.h"

AuthenticationFuzzer::AuthenticationFuzzer(
    mac_t source_mac,
    mac_t fuzzed_device_mac,
    bool use_bigger_alg_num_set,
    bool use_bigger_trans_num_set,
    bool use_bigger_stat_code_set
):
    Fuzzer(source_mac, fuzzed_device_mac),
    use_bigger_alg_num_set(use_bigger_alg_num_set),
    use_bigger_trans_num_set(use_bigger_trans_num_set),
    use_bigger_stat_code_set(use_bigger_stat_code_set) {}



const std::vector<std::uint16_t> &get_uint16_set(bool use_bigger) {
    return use_bigger ? primitives::fuzz_uint16_bigger_complement : primitives::fuzz_uint16;
}

/*
 * Alg num (2B)
 * Trans num (2B)
 * Status code (2B)
 * Challenge text (variable)
 */
// TODO transaction number fuzzing
generator<fuzz_t> AuthenticationFuzzer::get_mutated() {
    for (auto alg_num: get_uint16_set(use_bigger_alg_num_set)) {
        for (auto status_code: get_uint16_set(use_bigger_stat_code_set)) {

            // fuzz prepared strings
            for (auto &str: primitives::fuzz_strings) {
                auto codes = combine_vec_uint16({alg_num, 0, status_code});
                auto str_vec = std::vector<uint8_t>{(uint8_t) str.length()};

                co_yield combine_vec({codes, str_vec});
            }

            // TODO fuzz long strings
        }
    }
}

size_t AuthenticationFuzzer::num_mutations() {
    return
        get_uint16_set(use_bigger_alg_num_set).size() *
        get_uint16_set(use_bigger_stat_code_set).size() *
        primitives::fuzz_strings.size();

}
