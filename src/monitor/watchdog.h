#ifndef CPP_WATCHDOG_H
#define CPP_WATCHDOG_H

#include <iostream>
#include <mutex>
#include <atomic>
#include <thread>
#include <exception>
#include <utility>

class Watchdog
{
public:
    using Time_t = std::chrono::time_point<std::chrono::system_clock>;

    explicit Watchdog(
        const std::chrono::seconds &interval_t,
        std::function<void( void )> alarm
    ):
        m_interval(interval_t),
        next_check(std::chrono::system_clock::now() + m_interval),
        alarm(std::move(alarm))
    {
        m_bgThread = std::thread(&Watchdog::bgThread, this);
    }

    void pet() {
        auto next_check_local = std::chrono::time_point_cast<std::chrono::seconds>(
            std::chrono::system_clock::now() + m_interval
        );
        std::lock_guard<std::mutex> lock(m_mutex);

        // set next check to be current time + timeout
        next_check = next_check_local;
        was_expired = false;
        cv.notify_all();
    }

    void done() {
        is_done = true;
        was_expired = false;
        cv.notify_all();
    }

    bool is_expired()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (std::chrono::system_clock::now() > next_check) {
            return !is_done;
        } else {
            return false;
        }
    }

    Time_t get_next_check() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return next_check;
    }

    ~Watchdog()
    {
        done();
        m_bgThread.join();
    }

private:
    const std::chrono::seconds m_interval;
    std::function<void( void )> alarm;

    Time_t next_check;
    std::mutex m_mutex;
    std::thread m_bgThread;
    std::atomic<bool> is_done{false};
    std::atomic<bool> was_expired{false};
    std::mutex cv_mutex;
    std::condition_variable cv;

    void bgThread()
    {
        std::unique_lock<std::mutex> lk(cv_mutex);

        while (!is_done)
        {
            if (is_expired())
            {
                alarm();

                was_expired = true;

                // wait until not released by pet or done or destructor
                cv.wait(lk, [&](){return !was_expired;});
            }

            cv.wait_until(lk, get_next_check());  // it could wake spuriously, but it desn't matter
        }
    }
};

#endif //CPP_WATCHDOG_H
