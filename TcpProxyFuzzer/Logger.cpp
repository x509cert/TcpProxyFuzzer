#include "Logger.h"
#include <chrono>
#include <format>
#include <stdexcept>
#include <iomanip>
#include <regex>
#include <filesystem>

namespace fs = std::filesystem;

Logger::Logger(const std::string& filename) 
    : _logFile(GenerateNextFilename(filename), std::ios::app) {

    if (!_logFile.is_open()) {
        throw std::runtime_error("Unable to open log file: " + filename);
    }

    _logFile << "----------------------------------------------------------" << std::endl;
}

Logger::~Logger() {
    if (_logFile.is_open()) {
        _logFile.close();
    }
}

void Logger::Log(int indent, const std::string& message) {

    const auto now = std::chrono::system_clock::now();
    const auto now_time_t = std::chrono::system_clock::to_time_t(now);
    const auto now_ms 
        = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::tm localtime;
    localtime_s(&localtime, &now_time_t);

    indent = std::max(0, std::min(indent, static_cast<int>(_indentStrings.size())));

    _logFile << _indentStrings.at(indent) << std::put_time(&localtime, "%H:%M:%S") << '.'
        << std::setfill('0') << std::setw(3) << now_ms.count()
        << ": " << message << std::endl;
}

void Logger::Log(int indent, int message) {
	Log(indent, std::to_string(message));
}

std::string Logger::GenerateNextFilename(const std::string& baseName) {

    const fs::path dirPath = fs::path("fuzzlogs");
    fs::create_directory(dirPath);

    const std::regex pattern(baseName + "-fuzz.(\\d+).log"); 
    std::smatch match{};
    unsigned int maxNumber = 0;

    for (const auto& entry : fs::directory_iterator(dirPath)) {
        const std::string filename = entry.path().filename().string();
        if (std::regex_match(filename, match, pattern)) {
            const unsigned int number = std::stoi(match[1]);
            if (number > maxNumber) {
                maxNumber = number;
            }
        }
    }

    auto path = dirPath.string();
    auto formattedString = std::format("{}\\{}-fuzz.{:04}.log", path, baseName, maxNumber + 1);
    return formattedString;
}
