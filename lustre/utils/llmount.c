/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Robert Read <rread@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/mount.h>
#include <mntent.h>

int verbose = 0;
int nomtab = 0;


static void
update_mtab_entry(char *spec, char *node, char *type, char *opts,
		  int flags, int freq, int pass) 
{
        FILE *fp;
        struct mntent mnt;

        mnt.mnt_fsname = spec;
        mnt.mnt_dir = node;
        mnt.mnt_type = type;
        mnt.mnt_opts = opts;
        mnt.mnt_freq = freq;
        mnt.mnt_passno = pass;
      
        /* We get chatty now rather than after the update to mtab since the
           mount succeeded, even if the write to /etc/mtab should fail.  */
//        if (verbose)
//                print_one (&mnt);

        if (!nomtab) {
                if (flags & MS_REMOUNT) {
//                        update_mtab (mnt.mnt_dir, &mnt);
                        ;
                } else {
                        fp = setmntent(MOUNTED, "a+");
                        if (fp == NULL) {
                                fprintf(stderr, "setmntent(%s): %s:", 
                                        MOUNTED,
                                        strerror (errno));
                        } else {
                                if ((addmntent (fp, &mnt)) == 1) {
                                        fprintf(stderr, "addmntent: %s:", 
                                                strerror (errno));
                                }
                                endmntent(fp);
                        }
                }
        }
}

int
main(int argc, char * const argv[])
{
        char * source = argv[1];
        char * target = argv[2];
        char * options = NULL;
        int opt;
        int i;
        int rc;
        
	for (i = 0; i < argc; i++) {
		printf("arg[%d] = %s\n", i, argv[i]);
	}
	while ((opt = getopt(argc, argv, "vno:")) != EOF) {

		switch (opt) {
		case 'v':
                        verbose = 1;
                        break;
		case 'n':
                        nomtab = 1;
			break;
			
		case 'o':
                        options = optarg;
			break;
                default:
                        printf("default\n");
		}
	}
               
        if (optind < argc) {
                printf("optind %d\n", optind);
/*
                while(optind < argc)
*/
        }
        rc = mount(source, target, "lustre_lite", 0, options);
        if (rc) {
                perror("mount.lustre_lite:");
        } else {
                update_mtab_entry(source, target, "lustre_lite", options, 
                                  0, 0, 0);
        }
	return rc;
}
