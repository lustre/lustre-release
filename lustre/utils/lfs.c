/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
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
#include <getopt.h>
#include <string.h>

#include <liblustre.h>
#include <linux/lustre_idl.h>

#include "parser.h"

extern int op_create_file(char *name, long stripe_size, int stripe_offset, 
                int stripe_count);
extern int op_find(char *path, struct obd_uuid *obduuid, int recursive, 
                int verbose, int quiet);

/* all functions */
static int lfs_setstripe(int argc, char **argv);
static int lfs_find(int argc, char **argv);

/* all avaialable commands */
command_t cmdlist[] = {
        {"setstripe", lfs_setstripe, 0,
         "blah...\n"
         "usage: setstripe <filename> <stripe size> <stripe start> <stripe count>\n"
         "\tstripe size:  Number of bytes in each stripe (0 default)\n"
         "\tstripe start: OST index of first stripe (-1 default)\n"
         "\tstripe count: Number of OSTs to stripe over (0 default)"},
        {"find", lfs_find, 0,
         "blah...\n"
         "usage: find [--obd <uuid>] [--quiet | --verbose] [--recursive] <dir|file> ..."},
        {"help", Parser_help, 0, "help"},
        {"exit", Parser_quit, 0, "quit"},
        {"quit", Parser_quit, 0, "quit"},
        { 0, 0, 0, NULL }
};

/* functions */
static int lfs_setstripe(int argc, char **argv)
{	
        int result;
        long st_size;
        int  st_offset, st_count;
	char *end;
        
        if (argc != 5) 
		return CMD_HELP;

	// get the stripe size
	st_size = strtoul(argv[2], &end, 0);
	if (*end != '\0') {
		fprintf(stderr, "error: %s: bad stripe size '%s'\n", 
                                argv[0], argv[2]);
		return CMD_HELP;
	}
	// get the stripe offset
	st_offset = strtoul(argv[3], &end, 0);
	if (*end != '\0') {
		fprintf(stderr, "error: %s: bad stripe offset '%s'\n", 
                                argv[0], argv[3]);
		return CMD_HELP;
	}
	// get the stripe count 
	st_count = strtoul(argv[4], &end, 0);
	if (*end != '\0') {
		fprintf(stderr, "error: %s: bad stripe count '%s'\n", 
                                argv[0], argv[4]);
		return CMD_HELP;
	}

	result = op_create_file(argv[1], st_size, st_offset, st_count);
        if (result)
                fprintf(stderr, "error: %s: create stripe file failed\n",
                                argv[0]);

	return result;
}

static int lfs_find(int argc, char **argv)
{
        struct option long_opts[] = {
                {"obd", 1, 0, 'o'},
                {"quiet", 0, 0, 'q'},
                {"recursive", 0, 0, 'r'},
                {"verbose", 0, 0, 'v'},
                {0, 0, 0, 0}
        };
        char short_opts[] = "ho:qrv";
        int quiet, verbose, recursive, c, rc;
        struct obd_uuid *obduuid = NULL;
	
        optind = 0;
        quiet = verbose = recursive = 0;
        while ((c = getopt_long(argc, argv, short_opts, 
                                        long_opts, NULL)) != -1) {
		switch (c) {
		case 'o':
			if (obduuid) {
				fprintf(stderr, "error: %s: only one obduuid allowed",
                                                argv[0]);
				return CMD_HELP;
			}
			obduuid = (struct obd_uuid *)optarg;
			break;
		case 'q':
			quiet++;
			verbose = 0;
			break;
                case 'r':
                        recursive = 1;
                        break;
		case 'v':
			verbose++;
			quiet = 0;
			break;
		case '?':
                        return CMD_HELP;
                        break;
		default:
			fprintf(stderr, "error: %s: option '%s' unrecognized\n", 
                                        argv[0], argv[optind - 1]);
                        return CMD_HELP;
                        break;
		}
	}

	if (optind >= argc) 
                return CMD_HELP;

        do {
                rc = op_find(argv[optind], obduuid, recursive, verbose, quiet);
        } while (++optind < argc && !rc); 

        if (rc)
                fprintf(stderr, "error: %s: find failed\n", argv[0]);
        return rc;
}


int main(int argc, char **argv)
{
        int rc;

        setlinebuf(stdout);

        Parser_init("lfs > ", cmdlist);

        if (argc > 1) {
                rc = Parser_execarg(argc - 1, argv + 1, cmdlist);
        } else {
                rc = Parser_commands();
        }

        return rc;
}
