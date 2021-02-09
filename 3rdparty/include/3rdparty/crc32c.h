// crc32c.h -- header for crc32c.c
// Copyright (C) 2015 Mark Adler
// See crc32c.c for the license.

#include <stdint.h>

void crc32c_init(void);

uint32_t crc32c_sw(uint32_t crc, const uint8_t *buf, uint32_t len);
