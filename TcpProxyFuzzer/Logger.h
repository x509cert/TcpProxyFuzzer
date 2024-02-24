#pragma once
#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <fstream>

class Logger {
public:
    Logger(const std::string& filename);
    ~Logger();
    void Log(const std::string& message);
    void Log(int message);

private:
    std::ofstream logFile;
};

#endif // LOGGER_H