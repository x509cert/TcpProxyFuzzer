#ifndef RAND_H
#define RAND_H

#include <random>
#include <algorithm>
#include "gsl/util" 

// High-level RNG wrapper class
// Uses the Mersenne Twister engine and provides various rng distributions
class RandomNumberGenerator {
public:
    RandomNumberGenerator()
        : gen(rd()), dist(0, std::numeric_limits<unsigned int>::max()) {
    }

    // Generate a random number in the current range
    auto generate() {
        return dist(gen);
    }

    // Generate a random number in a specific percentage range (0-100)
    auto generatePercent() {
        return generateInRange(0, 100);
    }

    // Generate a random small integer (0-256)
    auto generateSmallInt() {
        return generateInRange(0, 256);
    }

    // Generate a random character
    auto generateChar() {
        return gsl::narrow_cast<unsigned char>(generateInRange(0, 256));
    }

    // Set the range for random number generation and return *this for chaining
    RandomNumberGenerator& range(unsigned int min, unsigned int max) noexcept {
        dist.param(std::uniform_int_distribution<unsigned int>::param_type(min, max - 1));
        return *this;
    }

    // Generates a normal distribution value with clamping
    double generateNormal(double mu, double sigma, int clamp_bottom, int clamp_top) {
        std::normal_distribution<double> distNormal(mu, sigma);
        return std::clamp(static_cast<int>(std::round(distNormal(gen))), clamp_bottom, clamp_top);
    }

    double generatePoission(double mean) {
		std::poisson_distribution<> distPoisson(mean);
		return distPoisson(gen);
	}

private:
    std::random_device rd;                              // Used to obtain a seed for the random number engine
    std::mt19937 gen;                                   // Mersenne Twister engine
    std::uniform_int_distribution<unsigned int> dist;   // Uniform integer distribution

    // Helper method to generate a number in a specific range
    unsigned int generateInRange(unsigned int min, unsigned int max) {
        const std::uniform_int_distribution<unsigned int>::param_type newRange(min, max - 1);
        dist.param(newRange);
        return dist(gen);
    }
};

#endif