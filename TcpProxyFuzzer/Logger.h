#pragma once
#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <fstream>
#include <array>
#include <vector>

class Logger {
public:
    Logger(const std::string& filename);
    ~Logger();
    void Log(const int indent, const std::string& message);
    void Log(const int indent, const std::vector<char>&  buf);

private:

    std::string GenerateNextFilename(const std::string& baseName);

    std::ofstream _logFile;
    std::array<std::string,4> _indentStrings = { "", "  ", "    ", "      " };
};

#endif // LOGGER_H