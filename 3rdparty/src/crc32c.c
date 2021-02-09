#include <3rdparty/crc32c.h>

/*
 * This code has been altered from the original code to support CRC32 in
 * addition to CRC32c
 */

/*
 * CRC32C used by iSCSI, SCTP, SSE4.2, Btrfs, ext4 and Ceph and
 * available in the Linux Kernel.  This is *not* the CRC32 used by
 * Ethernet and zip, gzip, etc.
 *
 * The Linux Kernel implementation is available as:
 *    crytpo_shash_alloc("crc32c")
 *
 * The following polynomial is used, as outlined by Castagnoli:
 *
 *	x^32 +
 *	x^28 +
 *	x^27 + x^26 + x^25 +
 *	x^23 + x^22 + x^20 +
 *	x^19 + x^18 +
 *	x^14 + x^13 +
 *	x^11 + x^10 + x^9 + x^8 +
 *	x^6  +
 *	x^0
 *
 * Normal polynomial vector
 * ------------------------
 *   Bit:         28   24   20   16   12    8    4    0
 *   Binary:    0001 1110 1101 1100 0110 1111 0100 0001
 *   Hex:          1    e    d    c    6    f    4    1  (0x1edc6f41)
 *
 * Reversed polynomial vector
 * --------------------------
 *   Bit:       0    4    8    12   16   20   24   28
 *   Binary:    1000 0010 1111 0110 0011 1011 0111 1000
 *   Hex:          8    2    f    6    3    b    7    8  (0x82f63b78)
 */

enum crc_code {
	CRC32C_POLY_BE = 0x1edc6f41,
	CRC32C_POLY_LE = 0x82f63b78,
};

/* ---- Begin Adler code -------------------------------------*/

/* crc32c.c -- compute CRC-32C using the Intel crc32 instruction
 * Copyright (C) 2013 Mark Adler
 * Version 1.1  1 Aug 2013  Mark Adler
 */

/*
  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the author be held liable for any damages
  arising from the use of this software.
  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:
  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.
  Mark Adler
  madler@alumni.caltech.edu
 */


/* Table for a quadword-at-a-time software crc. */
static uint32_t crc32c_table[8][256];

/* To detect if init has already been called */
static int crc32c_init_once;

/* Construct table */
void crc32c_init(void)
{
	uint32_t n, crc, k;
	enum crc_code crc_code;

    /* Should only call once! */
    if (crc32c_init_once)
        return;

    crc32c_init_once = 1;
    crc_code = CRC32C_POLY_LE;

	for (n = 0; n < 256; n++) {
		crc = n;
		crc = crc & 1 ? (crc >> 1) ^ crc_code : crc >> 1;
		crc = crc & 1 ? (crc >> 1) ^ crc_code : crc >> 1;
		crc = crc & 1 ? (crc >> 1) ^ crc_code : crc >> 1;
		crc = crc & 1 ? (crc >> 1) ^ crc_code : crc >> 1;
		crc = crc & 1 ? (crc >> 1) ^ crc_code : crc >> 1;
		crc = crc & 1 ? (crc >> 1) ^ crc_code : crc >> 1;
		crc = crc & 1 ? (crc >> 1) ^ crc_code : crc >> 1;
		crc = crc & 1 ? (crc >> 1) ^ crc_code : crc >> 1;
		crc32c_table[0][n] = crc;
	}
	for (n = 0; n < 256; n++) {
		crc = crc32c_table[0][n];
		for (k = 1; k < 8; k++) {
			crc = crc32c_table[0][crc & 0xff] ^ (crc >> 8);
			crc32c_table[k][n] = crc;
		}
	}
}

/* Table-driven version -- assumes little-endian integers. */
uint32_t
crc32c_sw(uint32_t crci, const uint8_t *buf, uint32_t len)
{
	const unsigned char *next = (unsigned char const *)buf;
	uint64_t crc;

	crc = crci ^ 0xffffffff;
	while (len && ((uintptr_t)next & 7) != 0) {
		crc = crc32c_table[0][(crc ^ *next++) & 0xff] ^ (crc >> 8);
		len--;
	}
	while (len >= 8) {
		crc ^= *(uint64_t *)next;
		crc = crc32c_table[7][crc & 0xff] ^
			crc32c_table[6][(crc >> 8) & 0xff] ^
			crc32c_table[5][(crc >> 16) & 0xff] ^
			crc32c_table[4][(crc >> 24) & 0xff] ^
			crc32c_table[3][(crc >> 32) & 0xff] ^
			crc32c_table[2][(crc >> 40) & 0xff] ^
			crc32c_table[1][(crc >> 48) & 0xff] ^
			crc32c_table[0][crc >> 56];
		next += 8;
		len -= 8;
	}
	while (len) {
		crc = crc32c_table[0][(crc ^ *next++) & 0xff] ^ (crc >> 8);
		len--;
	}
	return (uint32_t)crc ^ 0xffffffff;
}

/* ---- End Adler code ---------------------------------------*/
