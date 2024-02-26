#pragma once

#include <string>
#include <fstream>
#include <array>
#include <vector>

class Logger {
public:
    Logger(const std::string& filename);
    ~Logger();
    void Log(const int indent, const bool newline, const std::string& message);
    void Log(const int indent, const bool newline, const std::vector<char>&  buf);

    // Unneeded class members, abiding by 'the rule of five'
    // https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#c21-if-you-define-or-delete-any-copy-move-or-destructor-function-define-or-delete-them-all
    Logger(const Logger&) = delete;
    Logger(Logger&&) = delete;
    Logger& operator=(const Logger&) = delete;
    Logger& operator=(Logger&&) = delete;

private:
    std::string GenerateNextFilename(const std::string& baseName);

    std::ofstream _logFile;
    const std::array<std::string,4> _indentStrings = { "", "  ", "    ", "      " };
};
