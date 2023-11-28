#ifndef RAND_H
#define RAND_H

#include <random>
#include <limits>
#include "gsl/util" // for gsl::narrow_cast

class RandomNumberGenerator {
public:
    RandomNumberGenerator() noexcept
        : gen(nullptr), distUInt(0, std::numeric_limits<unsigned int>::max()),
        distPercent(0, 100), distSmallInt(0, 256) {
    }

    auto generate() {
        init(); // Ensure the generator is initialized
        return distUInt(*gen);
    }

    auto generatePercent() {
        init(); // Ensure the generator is initialized
        return distPercent(*gen);
    }

    auto generateSmallInt() {
        init(); // Ensure the generator is initialized
        return distSmallInt(*gen);
    }

    auto generateChar() {
        init(); // Ensure the generator is initialized
        return gsl::narrow_cast<unsigned char>(distSmallInt(*gen));
    }

    RandomNumberGenerator& setRange(unsigned int min, unsigned int max) {
        const std::uniform_int_distribution<unsigned int>::param_type newRange(min, max - 1);
        distUInt.param(newRange);
        return *this;
    }

private:
    void init() {
        if (!gen) {
            std::random_device rd; // Used to obtain a seed for the random number engine
            gen = std::make_unique<std::mt19937>(rd()); // Initialize upon first use
        }
    }

    std::unique_ptr<std::mt19937> gen; // Mersenne Twister engine, initialized lazily

    // Uniform integer distribution for different ranges
    std::uniform_int_distribution<unsigned int> distUInt;
    std::uniform_int_distribution<unsigned int> distPercent;
    std::uniform_int_distribution<unsigned int> distSmallInt;
};


#endif