#pragma once
#include <stdint.h>

class crc32 {
public:
	crc32() {
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
            _crc_table[i] = crc;
        }
	}

    uint32_t calc(uint8_t* buf, size_t len) const {
        uint32_t crc = 0xFFFFFFFF;
        for (size_t i = 0; i < len; i++) {
            uint8_t index = (uint8_t)(crc ^ buf[i]);
            crc = (crc >> 8) ^ _crc_table[index];
        }
        return ~crc;
    }

private: 
    uint32_t _crc_table[256];
};