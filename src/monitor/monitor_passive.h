/*
 * Author: Adam Venger (xvenge00)
 * 2021
 */


#ifndef CPP_MONITOR_PASSIVE_H
#define CPP_MONITOR_PASSIVE_H

#include "monitor.h"
#include "watchdog.h"

struct MonitorPassive: public Monitor {

    MonitorPassive(
        size_t buff_size,
        const std::chrono::seconds &timeout,
        std::filesystem::path dump_file
    );

    void notify() override;

private:
    Watchdog watchdog;
};

#endif //CPP_MONITOR_PASSIVE_H
