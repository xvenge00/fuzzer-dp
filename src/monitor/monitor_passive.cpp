/*
 * Author: Adam Venger (xvenge00)
 * 2021
 */


#include <spdlog/spdlog.h>
#include "monitor_passive.h"

MonitorPassive::MonitorPassive(
    size_t buff_size,
    const std::chrono::seconds &timeout,
    std::filesystem::path dump_file
):
    Monitor(buff_size, std::move(dump_file)),
    watchdog(timeout, [&]() { this->dump_frames(); this->set_failure(); }) {}

void MonitorPassive::notify() {
    watchdog.pet();
}