/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#include <stdio.h>
#include <errno.h>
#include <sys/utsname.h>
#include <string.h>

struct file_addr {
	char path[256];
	char modname[32];
	unsigned long base; 
};

int print_symbol_address(struct file_addr * fa)
{
        char buffer[4096];
        char cmd[256];
        char func_name[256];
	unsigned long addr;
	char mode[256];
        FILE *file;

	sprintf(cmd, "modprobe -l %s", fa->modname);
        file = popen(cmd, "r");
        if (!file) {
                printf("failed to execute %s:%s\n."
		       "Have you installed modules?\n", 
			cmd, strerror(errno));
		pclose(file);
                return -1;
        }
        if (fgets(buffer, 4095, file) == NULL) {
                printf("failed to get modprobe ouput for %s:%s\n", 
			fa->modname, strerror(errno));
		pclose(file);
                return -1;
	}
	pclose(file);

	sprintf(cmd, "nm -n %s", buffer);
        file = popen(cmd, "r");
        if (!file) {
                printf("failed to execute %s:%s\n."
		       "Have you installed modules?\n", 
			cmd, strerror(errno));
                return -1;
        }

        while (fgets(buffer, 4095, file)) {
        	if (fscanf(file, "%x %s %s\n", &addr, mode, func_name) != 3)
			continue;

		/* only list symbol in text section. */
		if (strcasecmp(mode, "t") == 0) {
			/* skip __init functoin. How to filter others? */
			if (strcmp(func_name, "init_module") != 0)
				printf("%x %s %s\n", fa->base + addr, 
					mode, func_name);
		}
	}
        pclose(file);
        return 0;
}


int generate_symbol_file()
{
        static char* cmd = "lctl modules";
        char         other[4096];
        FILE         *file;
	struct file_addr gfa;

	memset(&gfa, 0, sizeof(gfa));
        file = popen(cmd, "r");
        if (!file) {
                printf("failed to execute %s: %s\n", cmd, strerror(errno));
                return -1;
        }

        while ( fscanf(file, "%s %s %lx\n", other, gfa.path, &gfa.base) == 3) {
		strncpy(gfa.modname, strrchr(gfa.path, '/') + 1, 
			strrchr(gfa.path, '.') - strrchr(gfa.path, '/') - 1);

		 //fprintf(stderr, "%s %s %#x\n", gfa.path, gfa.modname, gfa.base);

		/* continue going without checking result */
		print_symbol_address(&gfa);
		memset(&gfa, 0, sizeof(gfa));
        }
        pclose(file);
	return 0;
}


int main() 
{
	return	generate_symbol_file();
}
