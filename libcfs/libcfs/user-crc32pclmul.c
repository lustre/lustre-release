/* GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see http://www.gnu.org/licenses
 *
 * Please  visit http://www.xyratex.com/contact if you need additional
 * information or have any questions.
 *
 * GPL HEADER END
 */

/*
 * Copyright 2012 Xyratex Technology Limited
 *
 */

#include <libcfs/libcfs.h>
#include <libcfs/posix/posix-crypto.h>
#include <libcfs/user-crypto.h>

#define CHKSUM_BLOCK_SIZE       1
#define CHKSUM_DIGEST_SIZE	4

#define PCLMUL_MIN_LEN		64L	/* minimum size of buffer
					 * for crc32_pclmul_le_16 */
#define SCALE_F			16L	/* size of xmm register */
#define SCALE_F_MASK		(SCALE_F - 1)

unsigned int crc32_pclmul_le(unsigned int crc, unsigned char const *p,
			     size_t len)
{
	unsigned int iquotient;
	unsigned int iremainder;
	unsigned int prealign;

	if (len < PCLMUL_MIN_LEN + SCALE_F_MASK)
		return crc32_le(crc, p, len);

	if ((long)p & SCALE_F_MASK) {
		/* align p to 16 byte */
		prealign = SCALE_F - ((long)p & SCALE_F_MASK);

		crc = crc32_le(crc, p, prealign);
		len -= prealign;
		p = (unsigned char *)(((unsigned long)p + SCALE_F_MASK) &
				     ~SCALE_F_MASK);
	}
	iquotient = len & (~SCALE_F_MASK);
	iremainder = len & SCALE_F_MASK;

	crc = crc32_pclmul_le_16(p, iquotient, crc);

	if (iremainder)
		crc = crc32_le(crc, p + iquotient, iremainder);

	return crc;
}
#ifndef bit_PCLMUL
#define bit_PCLMUL		(1 << 1)
#endif

int crc32_pclmul_init(void)
{
	unsigned int eax, ebx, ecx, edx, level;

	eax = ebx = ecx = edx = 0;
	level = 1;
	/* get cpuid */
	__asm__ ("xchg{l}\t{%%}ebx, %1\n\t"			     \
		 "cpuid\n\t"					     \
		 "xchg{l}\t{%%}ebx, %1\n\t"			     \
		 : "=a" (eax), "=r" (ebx), "=c" (ecx), "=d" (edx)    \
		 : "0" (level));

	if (ecx & bit_PCLMUL)
		return 1;

	return -1;
}
