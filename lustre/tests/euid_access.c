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
 * Copyright (c) 2020, Whamcloud.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>

void print_groups(int num_groups, gid_t *groups)
{
	int i;

	fprintf(stdout, "\tGroups ");
	for (i = 0; i < num_groups; i++) {
		struct group *gr = getgrgid(groups[i]);

		if (gr == NULL)
			perror("getgrgid");
		fprintf(stdout, "%6d - %s, ", gr->gr_gid, gr->gr_name);
	}
	fprintf(stdout, "\n");
}

char usage[] =
"Usage: %s <user to switch euid to> <path to file to access>\n";

int main(int argc, char **argv)
{
	char *user_to_euid;
	char *filename;
	struct passwd *user_pwd;
	char *user_name;
	int num_groups = 0;
	gid_t *groups;
	struct passwd *switch_pwd;
	uid_t switch_uid, switch_gid;
	int switch_num_groups = 0;
	gid_t *switch_groups;
	int final_num_groups = 0;
	gid_t *final_groups;
	int fd = 0;
	int save_errno;
	int rc;

	if (argc != 3) {
		fprintf(stderr, usage, argv[0]);
		exit(1);
	}

	user_to_euid = argv[1];
	filename = argv[2];

	user_pwd = getpwuid(getuid());
	if (!user_pwd) {
		if (errno) {
			save_errno = errno;
			perror("getpwuid");
		} else {
			save_errno = 1;
			fprintf(stderr, "Cannot find user in passwd db\n");
		}
		exit(save_errno);
	}
	user_name = user_pwd->pw_name;

	fprintf(stdout, "Initially %s ruid:rgid %d:%d, euid:egid %d:%d\n",
		user_name, getuid(), getgid(), geteuid(), getegid());

	num_groups = getgroups(0, NULL);
	if (num_groups) {
		groups = malloc(sizeof(gid_t) * num_groups);
		if (!groups) {
			save_errno = errno;
			perror("groups");
			exit(save_errno);
		}
		rc = getgrouplist(user_name, getgid(), groups, &num_groups);
		if (rc == -1) {
			save_errno = errno;
			free(groups);
			perror("groups list");
			exit(save_errno);
		}
		print_groups(num_groups, groups);
		free(groups);
	}

	/* lookup information about switch_user provided */
	switch_pwd = getpwnam(user_to_euid);
	if (!switch_pwd) {
		if (errno) {
			save_errno = errno;
			perror("getpwnam");
		} else {
			save_errno = 1;
			fprintf(stderr, "Cannot find user %s in passwd db\n",
				user_to_euid);
		}
		exit(save_errno);
	}
	switch_uid = switch_pwd->pw_uid;
	switch_gid = switch_pwd->pw_gid;

	fprintf(stdout, "To switch to effective %s uid:gid %d:%d\n",
		user_to_euid, switch_uid, switch_gid);

	rc = setegid(switch_gid);
	if (rc == -1) {
		save_errno = errno;
		perror("setegid");
		exit(save_errno);
	}

	getgrouplist(user_to_euid, switch_gid, NULL, &switch_num_groups);
	if (switch_num_groups) {
		switch_groups = malloc(sizeof(gid_t) * switch_num_groups);
		if (!switch_groups) {
			save_errno = errno;
			perror("switch_groups");
			exit(save_errno);
		}
		rc = getgrouplist(user_to_euid, switch_gid,
				  switch_groups, &switch_num_groups);
		if (rc == -1) {
			save_errno = errno;
			free(switch_groups);
			perror("switch_groups list");
			exit(save_errno);
		}
		print_groups(switch_num_groups, switch_groups);
		rc = setgroups(switch_num_groups, switch_groups);
		save_errno = errno;
		free(switch_groups);
		if (rc == -1) {
			perror("setgroups");
			exit(save_errno);
		}
	}

	rc = seteuid(switch_uid);
	if (rc == -1) {
		save_errno = errno;
		perror("seteuid");
		exit(save_errno);
	}

	fprintf(stdout, "Now %s ruid:rgid %d:%d, euid:egid %d:%d\n",
		user_name, getuid(), getgid(), geteuid(), getegid());

	final_num_groups = getgroups(0, NULL);
	final_groups = malloc(sizeof(gid_t) * final_num_groups);
	if (!final_groups) {
		save_errno = errno;
		perror("final_groups");
		exit(save_errno);
	}
	rc = getgroups(final_num_groups, final_groups);
	if (rc == -1) {
		save_errno = errno;
		free(final_groups);
		perror("final_groups list");
		exit(save_errno);
	}
	print_groups(final_num_groups, final_groups);
	free(final_groups);

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0666);
	if (fd == -1) {
		save_errno = errno;
		perror("open");
		exit(save_errno);
	}
	rc = write(fd, "test", 5);
	if (rc == -1) {
		save_errno = errno;
		perror("write");
		exit(save_errno);
	}
	close(fd);
	fprintf(stdout, "File %s successfully written\n", filename);

	exit(0);
}

