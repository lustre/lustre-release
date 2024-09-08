/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * A command line parser.
 */

#ifndef _PARSER_H_
#define _PARSER_H_

#define HISTORY 100
#define MAXARGS 512
#define MAXCMDS 1024

#define CMD_COMPLETE	0
#define CMD_INCOMPLETE	1
#define CMD_NONE	2
#define CMD_AMBIG	3
#define CMD_HELP	4

typedef struct parser_cmd {
	char 	*pc_name;
	int 	(* pc_func)(int, char **);
	struct parser_cmd * pc_sub_cmd;
	char *pc_help;
} command_t;

typedef struct argcmd {
	char    *ac_name;
	int      (*ac_func)(int, char **);
	char     *ac_help;
} argcmd_t;

typedef struct network {
	char	*type;
	char	*server;
	int	port;
} network_t;

int cfs_parser(int argc, char **argv, command_t cmds[]);

#endif
