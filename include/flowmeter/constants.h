#ifndef FLOWMETER_CONSTANTS_H
#define FLOWMETER_CONSTANTS_H

#include <cstdint>
#include <limits>

uint32_t MAX_DOUBLE_PRECISION = std::numeric_limits<double>::digits10 + 1;
uint32_t BYTE_00 = 0x0;
uint32_t ASCII_START = 0x21;
uint32_t ASCII_END = 0x7E;
uint32_t BYTE_FF = 0xFF;

#endif
