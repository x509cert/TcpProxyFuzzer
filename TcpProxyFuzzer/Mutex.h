#pragma once
#include <mutex>

#include <mutex>

class SafeMutex {
public:
    // Default constructor uses the system-default mutex type
    SafeMutex() : mutex_(std::mutex()) {}

    // Constructor allows specifying a specific mutex type
    template<typename MutexType>
    SafeMutex(const MutexType& mutex_type) : mutex_(mutex_type) {}

    // Acquires the mutex
    void lock() {
        mutex_.lock();
    }

    // Releases the mutex (unlocks)
    void unlock() {
        mutex_.unlock();
    }

    // Scoped lock acquired during object lifetime
    class ScopedLock {
    public:
        ScopedLock(SafeMutex& mutex) : mutex_(mutex) {
            mutex_.lock();
        }

        ~ScopedLock() {
            mutex_.unlock();
        }

    private:
        SafeMutex& mutex_;
    };

private:
    std::mutex mutex_;
};