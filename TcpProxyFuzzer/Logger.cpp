#include "Logger.h"
#include <chrono>
#include <format>
#include <stdexcept>
#include <iomanip>

Logger::Logger(const std::string& filename) : logFile(filename, std::ios::app) {
    if (!logFile.is_open()) {
        throw std::runtime_error("Unable to open log file: " + filename);
    }
}

Logger::~Logger() {
    if (logFile.is_open()) {
        logFile.close();
    }
}

void Logger::Log(const std::string& message) {

    const auto now = std::chrono::system_clock::now();
    const auto now_time_t = std::chrono::system_clock::to_time_t(now);
    const auto now_ms 
        = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::tm localtime;
    localtime_s(&localtime, &now_time_t);

    logFile << std::put_time(&localtime, "%H:%M:%S") << '.'
        << std::setfill('0') << std::setw(3) << now_ms.count()
        << ": " << message << std::endl;
}

void Logger::Log(int message) {
	Log(std::to_string(message));
}
