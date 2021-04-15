#include "progress_bar.h"
#include <iostream>
#include <sys/ioctl.h> //ioctl() and TIOCGWINSZ
#include <unistd.h> // for STDOUT_FILENO

void print_progress_bar(unsigned current, unsigned max) {
    struct winsize size;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &size);

    int bar_width = size.ws_col - 8;

    std::cout << "[";

    if (current < max) {
        float progress = (1.0 * current) / max;
        int pos = bar_width * progress;
        for (int i = 0; i < bar_width; ++i) {
            if (i <= pos) {
                std::cout << "#";
            } else {
                std::cout << " ";
            }
        }

        std::cout << "] " << int(progress * 100.0) << " %\r";
    } else {
        for (int i = 0; i < bar_width; ++i) {
            std::cout << "#";
        }

        std::cout << "] " << 100 << " %\n";
    }



    std::cout.flush();
}
