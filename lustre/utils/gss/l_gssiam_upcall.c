// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google
 * Userspace upcall for GSSIAM token retrieval.
 *
 * This program is called by the kernel (upcall_cache) when a GSSIAM token
 * is needed for a user.
 *
 * Arguments: [-d] [-p <principal>] [-l <loginuid>] <key>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#include <linux/types.h>
#include <linux/lustre/lustre_user.h>
#include <libcfs/util/param.h>
#include "lstddef.h"
#include "err_util.h"

static int send_downcall(const struct gssiam_downcall_data *data,
			 size_t data_size)
{
	glob_t path;
	ssize_t ret;
	int fd;
	int rc;

	rc = cfs_get_param_paths(&path, "sptlrpc/gssiam/gssiam_downcall");
	if (rc) {
		logmsg(LL_ERR, "Failed to get param path for gssiam: %s\n",
		       strerror(errno));
		return EXIT_FAILURE;
	}

	fd = open(path.gl_pathv[0], O_WRONLY);
	if (fd < 0) {
		logmsg(LL_ERR, "Failed to open %s: %s\n", path.gl_pathv[0],
		       strerror(errno));
		cfs_free_param_data(&path);
		return EXIT_FAILURE;
	}

	ret = write(fd, data, data_size);
	if (ret < 0 || (size_t)ret != data_size) {
		logmsg(LL_ERR, "Failed to write downcall data: %s\n",
		       strerror(errno));
		rc = EXIT_FAILURE;
	} else {
		rc = (data->idd_err != 0) ? EXIT_FAILURE : 0;
	}

	close(fd);
	cfs_free_param_data(&path);
	return rc;
}

static int send_error_downcall(__u64 key, int err, __u32 loginuid,
			       const char *principal)
{
	struct gssiam_downcall_data *err_data;
	size_t principal_len = principal ? strlen(principal) + 1 : 0;
	size_t data_size = sizeof(*err_data) + principal_len;
	int rc;

	err_data = calloc(1, data_size);
	if (!err_data)
		return EXIT_FAILURE;

	err_data->idd_magic = GSSIAM_DOWNCALL_MAGIC;
	err_data->idd_err = err;
	err_data->idd_key = key;
	err_data->idd_loginuid = loginuid;
	err_data->idd_token_len = 0;
	err_data->idd_principal_len = principal_len;
	if (principal)
		memcpy(idd_principal(err_data), principal, principal_len);

	rc = send_downcall(err_data, data_size);
	free(err_data);
	return rc;
}

int main(int argc, char **argv)
{
	char *key_str = NULL;
	char *principal = NULL;
	char *loginuid_str = NULL;
	char *endptr = NULL;
	int opt;
	int debug = 0;
	__u64 key = 0;
	__u32 loginuid = (__u32)-1;
	struct gssiam_downcall_data *data;
	int data_size;
	int rc = 0;
	/* Reference implementation: return mock token for testing.
	 * Production deployments should replace this with a lookup in
	 * the local enterprise IAM credential cache.
	 */
	const char *token = "mock_gssiam_token";

	static struct option long_opts[] = {
		{ .val = 'd', .name = "debug",	.has_arg = no_argument },
		{ .val = 'l', .name = "loginuid",
		  .has_arg = required_argument },
		{ .val = 'p', .name = "principal",
		  .has_arg = required_argument },
		{ .name = NULL }
	};

	while ((opt = getopt_long(argc, argv, "dl:p:", long_opts,
				  NULL)) != -1) {
		switch (opt) {
		case 'd':
			debug = 1;
			lgss_set_loglevel(LL_TRACE);
			break;
		case 'l':
			loginuid_str = optarg;
			break;
		case 'p':
			principal = optarg;
			break;
		default:
			logmsg(LL_ERR,
			       "Usage: %s [-d] [-p <principal>] [-l <loginuid>] <key>\n",
			       argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (optind >= argc) {
		logmsg(LL_ERR, "Missing key\n");
		return EXIT_FAILURE;
	}

	key_str = argv[optind];
	errno = 0;
	key = strtoull(key_str, &endptr, 10);
	if (errno != 0 || *endptr != '\0') {
		logmsg(LL_ERR, "Invalid key '%s'\n", key_str);
		return EXIT_FAILURE;
	}

	if (loginuid_str) {
		errno = 0;
		loginuid = strtoul(loginuid_str, &endptr, 10);
		if (errno != 0 || *endptr != '\0') {
			logmsg(LL_ERR, "Invalid loginuid '%s'\n", loginuid_str);
			send_error_downcall(key, -EINVAL, (__u32)-1, principal);
			return EXIT_FAILURE;
		}
	}

	/* Get token from remote GSSIAM server by principal */

	/* Generate mock data */
	data_size = sizeof(*data) + round_up(strlen(token), 8) +
		    (principal ? strlen(principal) + 1 : 0);
	data = malloc(data_size);
	if (!data) {
		logmsg(LL_ERR, "Failed to allocate memory\n");
		send_error_downcall(key, -ENOMEM, loginuid, principal);
		return EXIT_FAILURE;
	}

	memset(data, 0, data_size);
	data->idd_magic = GSSIAM_DOWNCALL_MAGIC;
	data->idd_err = 0;
	data->idd_key = key;
	data->idd_loginuid = loginuid;
	data->idd_token_len = strlen(token);
	data->idd_principal_len = principal ? strlen(principal) + 1 : 0;

	memcpy(idd_token(data), token, data->idd_token_len);
	if (principal)
		memcpy(idd_principal(data), principal, data->idd_principal_len);

	if (debug) {
		fprintf(stdout, "key: %llu\ntoken: %s\n", key, token);
		if (principal)
			fprintf(stdout, "principal: %s\n", principal);
		if (loginuid_str)
			fprintf(stdout, "loginuid: %s\n", loginuid_str);
		goto out_free;
	}

	rc = send_downcall(data, data_size);

out_free:
	free(data);
	return rc;
}
