#include <stdint.h>

uint16_t crc_ccitt(uint16_t crc, uint8_t const *buffer, int len);
uint16_t crc16(uint16_t crc, uint8_t const *buffer, int len);
uint16_t crc_ccitt_false(uint16_t crc, uint8_t const *buffer, int len);
