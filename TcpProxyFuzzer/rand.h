#include <random>
#include "gsl/util" 

// high-level RNG wrapper class
// uses the Mersenne Twister engine and provides various rng distributions
class RandomNumberGenerator {
public:
    RandomNumberGenerator() 
        :   gen(rd()), 
            distUInt(0, std::numeric_limits<unsigned int>::max()),
            distPercent(0, 99), 
            distSmallInt(0, 255) {
    }

    unsigned int generate()           {   return distUInt(gen); }
    unsigned int generatePercent()    {   return distPercent(gen); }
    unsigned int generateSmallInt()   {   return distSmallInt(gen); }
    unsigned char generateChar()      {   return gsl::narrow_cast<unsigned char>(distSmallInt(gen)); }

    // this is so you can chain calls eg; rng.setRange(0, 10).generate()
    // this creates an RNG in the range [min, max)
    RandomNumberGenerator& setRange(unsigned int min, unsigned int max) noexcept {
        const std::uniform_int_distribution<unsigned int>::param_type newRange(min, max-1);
        distUInt.param(newRange);
        return *this;
    }

private:
    std::random_device rd;  // Used to obtain a seed for the random number engine
    std::mt19937 gen;       // Mersenne Twister engine

    // Uniform integer distribution for different ranges
    std::uniform_int_distribution<unsigned int> distUInt;
    std::uniform_int_distribution<unsigned int> distPercent;
    std::uniform_int_distribution<unsigned int> distSmallInt;
};
