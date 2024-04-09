#pragma once
#include <stdint.h>

class crc32 {
public:
    crc32() noexcept {
        uint32_t crc{};
        for (uint32_t i = 0; i < 256; i++) {
            crc = i;
            for (uint32_t j = 8; j > 0; j--) {
                if (crc & 1) {
                    crc = (crc >> 1) ^ 0xEDB88320;
                }
                else {
                    crc >>= 1;
                }
            }

            gsl::at(_crc_table, i) = crc;
        }
    }

    uint32_t calc(const std::vector<char>& buf) const {
        if (buf.empty()) return 0;

        uint32_t crc = 0xFFFFFFFF;
        for (const auto& byte : buf) { 
            const uint8_t index = gsl::narrow_cast<uint8_t>(crc ^ static_cast<uint8_t>(byte));
            crc = (crc >> 8) ^ gsl::at(_crc_table, index);
        }
        return ~crc;
    }

private: 
    uint32_t _crc_table[256]{};
};