#include <spdlog/spdlog.h>
#include "monitor_passive.h"

MonitorPassive::MonitorPassive(
    size_t buff_size,
    const std::chrono::seconds &timeout
):
Monitor(buff_size), watchdog(timeout, [&]() { dump_frames(); }) {}

void MonitorPassive::notify() {
    watchdog.pet();
}