#ifndef RAND_H
#define RAND_H

#include <random>
#include <algorithm>
#include "gsl/util" 

// high-level RNG wrapper class
// uses the Mersenne Twister engine and provides various rng distributions
class RandomNumberGenerator {
public:
    RandomNumberGenerator()
        :   gen(rd()), 
            distUInt(0, std::numeric_limits<unsigned int>::max()),
            distPercent(0, 100), 
            distSmallInt(0, 256) {
    }

    auto generate()           {   return distUInt(gen); }
    auto generatePercent()    {   return distPercent(gen); }
    auto generateSmallInt()   {   return distSmallInt(gen); }
    auto generateChar()       {   return gsl::narrow_cast<unsigned char>(distSmallInt(gen)); }

    // this is so you can chain calls eg; rng.range(0, 10).generate()
    // this creates an RNG in the range [min, max)
    RandomNumberGenerator& range(unsigned int min, unsigned int max) noexcept {
        const std::uniform_int_distribution<unsigned int>::param_type newRange(min, max - 1);
        distUInt.param(newRange);
        return *this;
    }

    const double generateNormal(double mu, double sigma, int clamp_bottom, int clamp_top) {
        std::normal_distribution<double> distNormal(mu, sigma);
        return std::clamp(static_cast<int>(std::round(distNormal(gen))), clamp_bottom, clamp_top);

        return distNormal(gen);
    }

private:
    std::random_device rd;  // Used to obtain a seed for the random number engine
    std::mt19937 gen;       // Mersenne Twister engine

    // Uniform integer distribution for different ranges
    std::uniform_int_distribution<unsigned int> distUInt;
    std::uniform_int_distribution<unsigned int> distPercent;
    std::uniform_int_distribution<unsigned int> distSmallInt;
};

#endif