/*
 * GPL HEADER START
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
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#define CHUNK (128 * 1024)

void usage(const char *prog, FILE *out)
{
	fprintf(out, "usage: %s allocsize\n", prog);
	fprintf(out, " allocsize is kbytes, or number[KMGP] (P = pages)\n");
	exit(out == stderr);
}

int main(int argc, char *argv[])
{
	long long kbtotal = 0, kballoc;
	int i, j, k, numchunk, alloc, sum, rc = 0;
	char **mem, *tmp;

	if (argc == 2) {
		char *end = NULL;
		kbtotal = strtoull(argv[1], &end, 0);

		switch(*end) {
		case 'g':
		case 'G':
			kbtotal *= 1024;
		case 'm':
		case 'M':
			kbtotal *= 1024;
		case '\0':
		case 'k':
		case 'K':
			break;
		case 'p':
		case 'P':
			kbtotal *= 4;
			break;
		default:
			usage(argv[0], stderr);
			break;
		}
	}

	if (argc != 2 || kbtotal == 0)
		usage(argv[0], stderr);

	numchunk = (kbtotal + CHUNK - 1) / CHUNK;
	mem = calloc(numchunk, sizeof(*mem));
	if (mem == NULL) {
		fprintf(stderr, "error allocating initial chunk array\n");
		exit(-1);
	}

	alloc = CHUNK;
	printf("[%d] allocating %lld kbytes in %u kbyte chunks\n",
	       getpid(), kbtotal, alloc);
	for (i = kballoc = 0; i < numchunk && alloc > 0; i++, kballoc += alloc){
		if (kbtotal - kballoc < alloc)
			alloc = kbtotal - kballoc;

		while (alloc > 0 && (mem[i] = malloc(alloc * 1024)) == NULL) {
			fprintf(stderr, "malloc(%u) failed (%lld/%lld)\n",
				alloc * 1024, kballoc, kbtotal);
			alloc /= 2;
		}
		if (alloc == 0)
			break;

		printf("touching %p ([%lld-%lld]/%lld)\n", mem[i], kballoc,
		       kballoc + alloc - 1, kbtotal);
		for (j = 0, tmp = mem[i]; j < alloc; j += 4) {
			for (k = 0, sum = 0; k < 4095; k++, tmp++)
				sum += *tmp;
			*tmp = sum;
		}
	}
	if (kballoc == 0)
		exit(-2);

	kbtotal = kballoc;
	printf("touched %lld kbytes\n", kballoc);

	alloc = CHUNK;
	printf("verifying %lld kbytes in %u kbyte chunks\n", kbtotal, alloc);
	for (i = kballoc = 0; i < numchunk; i++, kballoc += alloc) {
		if (kbtotal - kballoc < alloc)
			alloc = kbtotal - kballoc;

		tmp = mem[i];
		if (tmp != NULL) {
			printf("verifying %p (%lld/%lld)\n",
			       tmp, kballoc, kbtotal);
			for (j = 0; j < alloc; j += 4) {
				for (k = 0, sum = 0; k < 4095; k++, tmp++)
					sum += *tmp;
				if (*tmp != sum) {
					fprintf(stderr, "sum %x != %x at %p\n",
						*tmp, sum, tmp - 4092);
					rc++;
				}
			}
		}
	}
	printf("verified %lld kbytes\n", kballoc);
	return rc;
}
