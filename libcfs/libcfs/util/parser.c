// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2001 Cluster File Systems, Inc.
 *
 * Copyright (c) 2014, 2017, Intel Corporation.
 *
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * libcfs/libcfs/parser.c
 *
 * A command line parser.
 *
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <malloc.h>
#ifdef HAVE_LIBREADLINE
# include <readline/history.h>
# include <readline/readline.h>
#endif /* HAVE_LIBREADLINE */
#include <string.h>
#include <unistd.h>

#include <libcfs/util/parser.h>
#include <linux/lustre/lustre_ver.h>

/* Top level of commands */
static command_t top_level[MAXCMDS];
/* Set to 1 if user types exit or quit */
static int done;
/*
 * Normally, the parser will quit when an error occurs in non-interacive
 * mode. Setting this to non-zero will force it to keep buggering on.
 */
static int ignore_errors;

static char *skipwhitespace(char *s);
static char *skiptowhitespace(char *s);
static command_t *find_cmd(char *name, command_t cmds[], char **next);
static int process(char *s, char **next, command_t *lookup, command_t **result,
		   char **prev);
static int line2args(char *line, char **argv, int maxargs);
static int cfs_parser_commands(command_t *cmds);
static int cfs_parser_execarg(int argc, char **argv, command_t cmds[]);
static int cfs_parser_list_commands(const command_t *cmdlist, int line_len,
				int col_num);
static int cfs_parser_list(int argc, char **argv);
static int cfs_parser_help(int argc, char **argv);
static int cfs_parser_quit(int argc, char **argv);
static int cfs_parser_version(int argc, char **argv);
static int cfs_parser_ignore_errors(int argc, char **argv);

command_t override_cmdlist[] = {
	{ .pc_name = "quit", .pc_func = cfs_parser_quit, .pc_help = "quit" },
	{ .pc_name = "exit", .pc_func = cfs_parser_quit, .pc_help = "exit" },
	{ .pc_name = "help", .pc_func = cfs_parser_help,
	  .pc_help = "provide useful information about a command" },
	{ .pc_name = "--help", .pc_func = cfs_parser_help,
	  .pc_help = "provide useful information about a command" },
	{ .pc_name = "version", .pc_func = cfs_parser_version,
	  .pc_help = "show program version" },
	{ .pc_name = "--version", .pc_func = cfs_parser_version,
	  .pc_help = "show program version" },
	{ .pc_name = "list-commands", .pc_func = cfs_parser_list,
	  .pc_help = "list available commands" },
	{ .pc_name = "--list-commands", .pc_func = cfs_parser_list,
	  .pc_help = "list available commands" },
	{ .pc_name = "--ignore_errors", .pc_func = cfs_parser_ignore_errors,
	  .pc_help = "ignore errors that occur during script processing"},
	{ .pc_name = "ignore_errors", .pc_func = cfs_parser_ignore_errors,
	  .pc_help = "ignore errors that occur during script processing"},
	{ .pc_name = 0, .pc_func = NULL, .pc_help = 0 }
};

static char *skipwhitespace(char *s)
{
	char *t;
	int len;

	len = (int)strlen(s);
	for (t = s; t <= s + len && isspace(*t); t++)
		;
	return t;
}

static char *skiptowhitespace(char *s)
{
	char *t;

	for (t = s; *t && !isspace(*t); t++)
		;
	return t;
}

static int line2args(char *line, char **argv, int maxargs)
{
	char *arg;
	int i = 0;

	arg = strtok(line, " \t");
	if (!arg || maxargs < 1)
		return 0;

	argv[i++] = arg;
	while ((arg = strtok(NULL, " \t")) != NULL && i < maxargs)
		argv[i++] = arg;
	return i;
}

/* find a command -- return it if unique otherwise print alternatives */
static command_t *cfs_parser_findargcmd(char *name, command_t cmds[])
{
	command_t *cmd;

	for (cmd = cmds; cmd->pc_name; cmd++) {
		if (strcmp(name, cmd->pc_name) == 0)
			return cmd;
	}
	return NULL;
}

static int cfs_parser_ignore_errors(int argc, char **argv)
{
	(void) argc;
	(void) argv;

	ignore_errors = 1;

	return 0;
}

int cfs_parser(int argc, char **argv, command_t cmds[])
{
	command_t *cmd;
	int rc = 0;
	int i = 0;

	done = 0;

	if (cmds == NULL)
		return -ENOENT;

	for (cmd = override_cmdlist; cmd->pc_name && i < MAXCMDS; cmd++)
		top_level[i++] = *cmd;

	for (cmd = cmds; cmd->pc_name && i < MAXCMDS; cmd++)
		top_level[i++] = *cmd;

	if (argc > 1)
		rc = cfs_parser_execarg(argc - 1, argv + 1, cmds);
	else
		rc = cfs_parser_commands(cmds);

	return rc;
}

static int cfs_parser_execarg(int argc, char **argv, command_t cmds[])
{
	command_t *cmd;

	cmd = cfs_parser_findargcmd(argv[0], override_cmdlist);

	if (!cmd)
		cmd = cfs_parser_findargcmd(argv[0], cmds);

	if (cmd && cmd->pc_func) {
		int rc = cmd->pc_func(argc, argv);

		if (rc == CMD_HELP) {
			fprintf(stdout, "%s\n", cmd->pc_help);
			fflush(stdout);
		}
		return rc;
	}

	fprintf(stderr,
		"%s: '%s' is not a valid command. See '%s --list-commands'.\n",
		program_invocation_short_name, argv[0],
		program_invocation_short_name);

	return -1;
}

/*
 * Returns the command_t * (NULL if not found) corresponding to a
 * _partial_ match with the first token in name.  It sets *next to
 * point to the following token. Does not modify *name.
 */
static command_t *find_cmd(char *name, command_t cmds[], char **next)
{
	int i, len;

	if (!cmds || !name)
		return NULL;

	/*
	 * This sets name to point to the first non-white space character,
	 * and next to the first whitespace after name, len to the length: do
	 * this with strtok
	 */
	name = skipwhitespace(name);
	*next = skiptowhitespace(name);
	len = (int)(*next - name);
	if (len == 0)
		return NULL;

	for (i = 0; cmds[i].pc_name; i++) {
		if (strncasecmp(name, cmds[i].pc_name, len) == 0) {
			*next = skipwhitespace(*next);
			return &cmds[i];
		}
	}
	return NULL;
}

/*
 * Recursively process a command line string s and find the command
 * corresponding to it. This can be ambiguous, full, incomplete,
 * non-existent.
 */
static int process(char *s, char **next, command_t *lookup,
		   command_t **result, char **prev)
{
	static int depth;

	*result = find_cmd(s, lookup, next);
	*prev = s;

	/* non existent */
	if (!*result)
		return CMD_NONE;

	/*
	 * found entry: is it ambigous, i.e. not exact command name and
	 * more than one command in the list matches.  Note that find_cmd
	 * points to the first ambiguous entry
	 */
	if (strncasecmp(s, (*result)->pc_name, strlen((*result)->pc_name))) {
		char *another_next;
		int found_another = 0;

		command_t *another_result = find_cmd(s, (*result) + 1,
						     &another_next);
		while (another_result) {
			if (strncasecmp(s, another_result->pc_name,
					strlen(another_result->pc_name)) == 0) {
				*result = another_result;
				*next = another_next;
				goto got_it;
			}
			another_result = find_cmd(s, another_result + 1,
						  &another_next);
			found_another = 1;

			/*
			 * In some circumstances, process will fail to find a
			 * suitable command. We want to be able to escape both
			 * the while loop and the recursion. So, track the
			 * number of times we've been here and give up if
			 * things start to get out-of-hand.
			 */
			if (depth > 50)
				return CMD_NONE;

			depth++;
		}
		if (found_another)
			return CMD_AMBIG;
	}

got_it:
	/* found a unique command: component or full? */
	if ((*result)->pc_func)
		return CMD_COMPLETE;

	if (**next == '\0')
		return CMD_INCOMPLETE;
	return process(*next, next, (*result)->pc_sub_cmd,
		       result, prev);
}

#ifdef HAVE_LIBREADLINE
static command_t *match_tbl; /* Command completion against this table */
static char *command_generator(const char *text, int state)
{
	static int index, len;
	char *name;

	/* Do we have a match table? */
	if (!match_tbl)
		return NULL;

	/* If this is the first time called on this word, state is 0 */
	if (!state) {
		index = 0;
		len = (int)strlen(text);
	}

	/* Return next name in the command list that paritally matches test */
	while ((name = (match_tbl + index)->pc_name)) {
		index++;

		if (strncasecmp(name, text, len) == 0)
			return strdup(name);
	}

	/* No more matches */
	return NULL;
}

/* probably called by readline */
static char **command_completion(const char *text, int start, int end)
{
	command_t *table;
	char *pos;

	match_tbl = top_level;

	for (table = find_cmd(rl_line_buffer, match_tbl, &pos);
	     table; table = find_cmd(pos, match_tbl, &pos)) {
		if (*(pos - 1) == ' ')
			match_tbl = table->pc_sub_cmd;
	}

	return rl_completion_matches(text, command_generator);
}
#endif

/* take a string and execute the function or print help */
static int execute_line(char *line)
{
	command_t *cmd, *ambig;
	char *prev;
	char *next, *tmp;
	char *argv[MAXARGS];
	int i;
	int rc = 0;

	switch (process(line, &next, top_level, &cmd, &prev)) {
	case CMD_AMBIG:
		fprintf(stderr, "Ambiguous command \'%s\'\nOptions: ", line);
		while ((ambig = find_cmd(prev, cmd, &tmp))) {
			fprintf(stderr, "%s ", ambig->pc_name);
			cmd = ambig + 1;
		}
		fprintf(stderr, "\n");
		break;
	case CMD_NONE:
		fprintf(stderr, "No such command. Try --list-commands to see available commands.\n");
		break;
	case CMD_INCOMPLETE:
		if (cmd == NULL || cmd->pc_sub_cmd == NULL) {
			fprintf(stderr, "'%s' incomplete command.\n", line);
			return rc;
		}

		fprintf(stderr,
			"'%s' incomplete command.  Use '%s x' where x is one of:\n\t",
			line, line);

		for (i = 0; cmd->pc_sub_cmd[i].pc_name; i++)
			fprintf(stderr, "%s ", cmd->pc_sub_cmd[i].pc_name);

		fprintf(stderr, "\n");
		break;
	case CMD_COMPLETE:
		optind = 0;
		i = line2args(line, argv, MAXARGS);
		rc = cmd->pc_func(i, argv);

		if (rc == CMD_HELP) {
			fprintf(stdout, "%s\n", cmd->pc_help);
			fflush(stdout);
		}

		break;
	}

	return rc;
}

#ifdef HAVE_LIBREADLINE
static void noop_int_fn(int unused) { }
static void noop_void_fn(void) { }
#endif

/*
 * just in case you're ever in an airplane and discover you
 * forgot to install readline-dev. :)
 */
static int init_input(void)
{
	int interactive = isatty(fileno(stdin));

#ifdef HAVE_LIBREADLINE
	using_history();
	stifle_history(HISTORY);

	if (!interactive) {
		rl_prep_term_function = noop_int_fn;
		rl_deprep_term_function = noop_void_fn;
	}

	rl_attempted_completion_function = command_completion;
	rl_completion_entry_function = command_generator;
#endif
	return interactive;
}

#ifndef HAVE_LIBREADLINE
#define add_history(s)
static char *readline(char *prompt)
{
	int size = 2048;
	char *line = malloc(size);
	char *ptr = line;
	int c;
	int eof = 0;

	if (!line)
		return NULL;
	if (prompt)
		printf("%s", prompt);

	while (1) {
		if ((c = fgetc(stdin)) != EOF) {
			if (c == '\n')
				goto out;
			*ptr++ = (char)c;

			if (ptr - line >= size - 1) {
				char *tmp;

				size *= 2;
				tmp = malloc(size);
				if (!tmp)
					goto outfree;
				memcpy(tmp, line, ptr - line);
				ptr = tmp + (ptr - line);
				free(line);
				line = tmp;
			}
		} else {
			eof = 1;
			if (ferror(stdin) || feof(stdin))
				goto outfree;
			goto out;
		}
	}
out:
	*ptr = 0;
	if (eof && (strlen(line) == 0)) {
		free(line);
		line = NULL;
	}
	return line;
outfree:
	free(line);
	return NULL;
}
#endif

/* this is the command execution machine */
static int cfs_parser_commands(command_t *cmds)
{
	char *line, *s;
	int rc = 0, save_error = 0;
	int interactive;

	interactive = init_input();

	while (!done) {
		line = readline(interactive ? "> " : NULL);

		if (!line)
			break;

		s = skipwhitespace(line);

		if (*s) {
			add_history(s);
			rc = execute_line(s);
		}
		/* stop on error if not-interactive */
		if (rc != 0 && !interactive) {
			if (save_error == 0)
				save_error = rc;
			if (!ignore_errors)
				done = 1;
		}
		free(line);
	}

	if (save_error)
		rc = save_error;

	return rc;
}

static int cfs_parser_help(int argc, char **argv)
{
	char line[1024];
	char *next, *prev, *tmp;
	command_t *result, *ambig;
	int i;

	if (argc == 1) {
		printf("usage: %s [COMMAND] [OPTIONS]... [ARGS]\n",
			program_invocation_short_name);
		printf("Without any parameters, interactive mode is invoked\n");
		printf("Try '%s help <COMMAND>', or '%s --list-commands' for a list of commands.\n",
			program_invocation_short_name,
			program_invocation_short_name);
		return 0;
	}

	/*
	 * Joining command line arguments without space is not critical here
	 * because of this string is used for search a help topic and assume
	 * that only one argument will be (the name of topic). For example:
	 * lst > help ping run
	 * pingrun: Unknown command.
	 */
	line[0] = '\0';
	for (i = 1;  i < argc; i++) {
		if (strlen(argv[i]) >= sizeof(line) - strlen(line) - 1)
			return -E2BIG;
		/*
		 * The function strlcat() cannot be used here because of
		 * this function is used in LNet utils that is not linked
		 * with libcfs.a.
		 */
		strncat(line, argv[i], sizeof(line) - strlen(line) - 1);
	}

	switch (process(line, &next, top_level, &result, &prev)) {
	case CMD_COMPLETE:
		fprintf(stderr, "%s: %s\n", line, result->pc_help);
		break;
	case CMD_NONE:
		fprintf(stderr, "%s: '%s' is not a valid command. See '%s --list-commands'.\n",
			program_invocation_short_name, line,
			program_invocation_short_name);
		break;
	case CMD_INCOMPLETE:
		fprintf(stderr,
			"'%s' incomplete command.  Use '%s x' where x is one of:\n",
			line, line);
		fprintf(stderr, "\t");
		for (i = 0; result->pc_sub_cmd[i].pc_name; i++)
			fprintf(stderr, "%s ", result->pc_sub_cmd[i].pc_name);
		fprintf(stderr, "\n");
		break;
	case CMD_AMBIG:
		fprintf(stderr, "Ambiguous command \'%s\'\nOptions: ", line);
		while ((ambig = find_cmd(prev, result, &tmp))) {
			fprintf(stderr, "%s ", ambig->pc_name);
			result = ambig + 1;
		}
		fprintf(stderr, "\n");
		break;
	}
	return 0;
}

/**
 * cfs_parser_list_commands() - Output a list of the supported commands.
 * @cmdlist:	  Array of structures describing the commands.
 * @line_len:	  Length of output line.
 * @col_num:	  The number of commands printed in a single row.
 *
 * The commands and subcommands supported by the utility are printed, arranged
 * into several columns for readability.
 *
 * Return: The number of items that were printed.
 */
static int cfs_parser_list_commands(const command_t *cmdlist, int line_len,
				int col_num)
{
	int char_max;
	int count = 0;
	int col = 0;

	int nprinted = 0;
	int offset = 0;

	char_max = line_len / col_num;

	for (; cmdlist->pc_name; cmdlist++) {
		if (!cmdlist->pc_func && !cmdlist->pc_sub_cmd)
			break;
		count++;

		nprinted = fprintf(stdout, "%-*s ", char_max - offset - 1,
				   cmdlist->pc_name);
		/*
		 * when a column is too wide, save offset so subsequent columns
		 * can be aligned properly
		 */
		offset = offset + nprinted - char_max;
		offset = offset > 0 ? offset : 0;

		col++;
		if (col >= col_num) {
			fprintf(stdout, "\n");
			col = 0;
			offset = 0;
		}
	}
	if (col != 0)
		fprintf(stdout, "\n");
	return count;
}

static int cfs_parser_quit(int argc, char **argv)
{
	(void) argc;
	(void) argv;

	done = 1;

	return 0;
}

static int cfs_parser_version(int argc, char **argv)
{
	(void) argc;
	(void) argv;

	fprintf(stdout, "%s %s\n", program_invocation_short_name,
		LUSTRE_VERSION_STRING);

	return 0;
}

static int cfs_parser_list(int argc, char **argv)
{
	command_t *cmd;
	int num_cmds_listed;

	(void) argc;
	(void) argv;

	cmd = top_level;
	while (cmd->pc_name != NULL) {
		if (!cmd->pc_func) {
			/*
			 * print the command category
			 */
			printf("\n%s\n", cmd->pc_name);
			cmd++;
		}
		num_cmds_listed = cfs_parser_list_commands(cmd, 80, 4);
		cmd += num_cmds_listed;
	}

	return 0;
}
