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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/include/libcfs/util/parser.h
 *
 * A command line parser.
 *
 */

#ifndef _PARSER_H_
#define _PARSER_H_

#define HISTORY	100		/* Don't let history grow unbounded    */
#define MAXARGS 512

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

int Parser_quit(int argc, char **argv);
int Parser_version(int argc, char **argv);
void Parser_init(char *, command_t *);	/* Set prompt and load command list */
int Parser_commands(void);			/* Start the command parser */
void Parser_qhelp(int, char **);	/* Quick help routine */
int Parser_help(int, char **);		/* Detailed help routine */
void Parser_ignore_errors(int ignore);	/* Set the ignore errors flag */
void Parser_printhelp(char *);		/* Detailed help routine */
void Parser_exit(int, char **);		/* Shuts down command parser */
int Parser_execarg(int argc, char **argv, command_t cmds[]);
int execute_line(char * line);
int Parser_list_commands(const command_t *cmdlist, char *buffer,
			 size_t buf_size, const char *parent_cmd,
			 int col_start, int col_num);

/* Converts a string to an integer */
int Parser_int(char *, int *);

/* Prompts for a string, with default values and a maximum length */
char *Parser_getstr(const char *prompt, const char *deft, char *res, 
		    size_t len);

/* Prompts for an integer, with minimum, maximum and default values and base */
int Parser_getint(const char *prompt, long min, long max, long deft,
		  int base);

/* Prompts for a yes/no, with default */
int Parser_getbool(const char *prompt, int deft);

/* Extracts an integer from a string, or prompts if it cannot get one */
long Parser_intarg(const char *inp, const char *prompt, int deft,
		   int min, int max, int base);

/* Extracts a word from the input, or propmts if it cannot get one */
char *Parser_strarg(char *inp, const char *prompt, const char *deft,
		    char *answer, int len);

/* Extracts an integer from a string  with a base */
int Parser_arg2int(const char *inp, long *result, int base);

/* Convert human readable size string to and int; "1k" -> 1000 */
int Parser_size(unsigned long *sizep, char *str);

/* Convert a string boolean to an int; "enable" -> 1 */
int Parser_bool(int *b, char *str);

#endif
