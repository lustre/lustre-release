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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <sys/wait.h>

#define DEBUG 0

#ifndef NGROUPS_MAX
#define NGROUPS_MAX 32
#endif

static const char usage[] =
"Usage: %s -u user_id [-g grp_id] [-v euid] [-j egid] [-G[gid0,gid1,...]] command\n"
"  -u user_id           switch to UID user_id\n"
"  -g grp_id            switch to GID grp_id\n"
"  -v euid              switch euid to UID\n"
"  -j egid              switch egid to GID\n"
"  -G[gid0,gid1,...]    set supplementary groups\n";

void Usage_and_abort(const char *name)
{
	fprintf(stderr, usage, name);
	exit(-1);
}

int main(int argc, char **argv)
{
	char **my_argv, *name = argv[0], *grp;
	int status, c, i;
	int gid_is_set = 0, uid_is_set = 0, num_supp = -1;
	uid_t user_id = 0;
	gid_t grp_id = 0, supp_groups[NGROUPS_MAX] = { 0 };
	int euid_is_set = 0, egid_is_set = 0;
	uid_t euid = 0;
	gid_t egid = 0;

	if (argc == 1) {
		fprintf(stderr, "No parameter count\n");
		Usage_and_abort(name);
	}

	/* get UID and GID */
	while ((c = getopt(argc, argv, "+u:g:v:j:hG::")) != -1) {
		switch (c) {
		case 'u':
			if (!isdigit(optarg[0])) {
				struct passwd *pw = getpwnam(optarg);

				if (!pw) {
					fprintf(stderr, "parameter '%s' bad\n",
						optarg);
					Usage_and_abort(name);
				}
				user_id = pw->pw_uid;
			} else {
				user_id = (uid_t)atoi(optarg);
			}
			uid_is_set = 1;
			if (!gid_is_set)
				grp_id = user_id;
			break;

		case 'g':
			if (!isdigit(optarg[0])) {
				struct group *gr = getgrnam(optarg);

				if (!gr) {
					fprintf(stderr, "getgrname %s failed\n",
						optarg);
					Usage_and_abort(name);
				}
				grp_id = gr->gr_gid;
			} else {
				grp_id = (gid_t)atoi(optarg);
			}
			gid_is_set = 1;
			break;

		case 'v':
			if (!isdigit(optarg[0])) {
				struct passwd *pw = getpwnam(optarg);

				if (!pw) {
					fprintf(stderr, "parameter '%s' bad\n",
						optarg);
					Usage_and_abort(name);
				}
				euid = pw->pw_uid;
			} else {
				euid = (uid_t)atoi(optarg);
			}
			euid_is_set = 1;
			break;

		case 'j':
			if (!isdigit(optarg[0])) {
				struct group *gr = getgrnam(optarg);

				if (!gr) {
					fprintf(stderr, "getgrname %s failed\n",
						optarg);
					Usage_and_abort(name);
				}
				egid = gr->gr_gid;
			} else {
				egid = (gid_t)atoi(optarg);
			}
			egid_is_set = 1;
			break;

		case 'G':
			num_supp = 0;
			if (!optarg || !isdigit(optarg[0]))
				break;
			while ((grp = strsep(&optarg, ",")) != NULL) {
				printf("adding supp group %d\n", atoi(grp));
				supp_groups[num_supp++] = atoi(grp);
				if (num_supp >= NGROUPS_MAX)
					break;
			}
			break;

		default:
		case 'h':
			Usage_and_abort(name);
			break;
		}
	}

	if (!uid_is_set) {
		fprintf(stderr, "Must specify uid to run.\n");
		Usage_and_abort(name);
	}

	if (optind == argc) {
		fprintf(stderr, "Must specify command to run.\n");
		Usage_and_abort(name);
	}

	/* assemble the command */
	my_argv = (char **)malloc(sizeof(char *) * (argc + 1 - optind));
	if (!my_argv) {
		fprintf(stderr, "Error in allocating memory. (%s)\n",
			strerror(errno));
		exit(-1);
	}

	for (i = optind; i < argc; i++)
		my_argv[i - optind] = argv[i];

	my_argv[i - optind] = NULL;

#if DEBUG
	system("whoami");
#endif

	/* set GID */
	if (!egid_is_set)
		egid = grp_id;
	status = setregid(grp_id, egid);
	if (status == -1) {
		fprintf(stderr, "Cannot change gid to %d/%d, errno=%d (%s)\n",
			grp_id, egid, errno, strerror(errno));
		exit(-1);
	}

	if (num_supp >= 0) {
		status = setgroups(num_supp, supp_groups);
		if (status == -1) {
			perror("setting supplementary groups");
			exit(-1);
		}
	}

	/* set UID */
	if (!euid_is_set)
		euid = user_id;
	status = setreuid(user_id, euid);
	if (status == -1) {
		fprintf(stderr, "Cannot change uid to %d/%d, errno=%d (%s)\n",
			user_id, euid, errno, strerror(errno));
		exit(-1);
	}

	fprintf(stderr, "running as uid/gid/euid/egid %d/%d/%d/%d, groups:",
		user_id, grp_id, euid, egid);
	for (i = 0; i < num_supp; i++)
		fprintf(stderr, " %d", supp_groups[i]);
	fprintf(stderr, "\n");

	for (i = 0; i < argc - optind; i++)
		fprintf(stderr, " [%s]", my_argv[i]);

	fprintf(stderr, "\n");
	fflush(stderr);

	/* The command to be run */
	execvp(my_argv[0], my_argv);
	fprintf(stderr, "execvp fails running %s (%d): %s\n", my_argv[0],
		errno, strerror(errno));
	exit(-1);
}
