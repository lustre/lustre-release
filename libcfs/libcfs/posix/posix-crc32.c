/*
 *      This file contains part of linux kernel implementation of crc32
 *      kernel version 2.6.32
 */
#include <endian.h>
#include <libcfs/libcfs.h>
#define CRCPOLY_LE      0xedb88320
#define CRC_LE_BITS     8
#define LE_TABLE_SIZE   (1 << CRC_LE_BITS)

static unsigned int crc32table_le[LE_TABLE_SIZE];
/**
 * crc32init_le() - allocate and initialize LE table data
 *
 * crc is the crc of the byte i; other entries are filled in based on the
 * fact that crctable[i^j] = crctable[i] ^ crctable[j].
 *
 */
void crc32init_le(void)
{
	unsigned i, j;
	unsigned int crc = 1;

	crc32table_le[0] = 0;

	for (i = 1 << (CRC_LE_BITS - 1); i; i >>= 1) {
		crc = (crc >> 1) ^ ((crc & 1) ? CRCPOLY_LE : 0);
		for (j = 0; j < LE_TABLE_SIZE; j += 2 * i)
			crc32table_le[i + j] = crc ^ crc32table_le[j];
	}
}

unsigned int crc32_le(unsigned int crc, unsigned char const *p, size_t len)
{
	const unsigned int      *b = (unsigned int *)p;
	const unsigned int      *tab = crc32table_le;

# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define DO_CRC(x) crc = tab[(crc ^ (x)) & 255] ^ (crc>>8)
# else
#  define DO_CRC(x) crc = tab[((crc >> 24) ^ (x)) & 255] ^ (crc<<8)
# endif

	crc = cpu_to_le32(crc);
	/* Align it */
	if (unlikely(((long)b) & 3 && len)) {
		do {
			unsigned char *p = (unsigned char *)b;
			DO_CRC(*p++);
			b = (void *)p;
		} while ((--len) && ((long)b) & 3);
	}
	if (likely(len >= 4)) {
		/* load data 32 bits wide, xor data 32 bits wide. */
		size_t save_len = len & 3;
		len = len >> 2;
		--b; /* use pre increment below(*++b) for speed */
		do {
			crc ^= *++b;
			DO_CRC(0);
			DO_CRC(0);
			DO_CRC(0);
			DO_CRC(0);
		} while (--len);
		b++; /* point to next byte(s) */
		len = save_len;
	}
	/* And the last few bytes */
	if (len) {
		do {
			unsigned char *p = (unsigned char *)b;
			DO_CRC(*p++);
			b = (void *)p;
		} while (--len);
	}

	return le32_to_cpu(crc);
#undef DO_CRC
}
