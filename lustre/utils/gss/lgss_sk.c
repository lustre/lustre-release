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
 * Copyright (C) 2015, Trustees of Indiana University
 *
 * Author: Jeremy Filizetti <jfilizet@iu.edu>
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <lnet/nidstr.h>
#include <lustre/lustre_idl.h>

#include "sk_utils.h"
#include "err_util.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* One week default expiration */
#define SK_DEFAULT_EXPIRE 604800
#define SK_DEFAULT_SK_KEYLEN 256
#define SK_DEFAULT_DH_KEYLEN 1024
#define SK_DEFAULT_NODEMAP "default"

/* Names match up with openssl enc and dgst commands */
char *sk_crypt2name[] = {
	[SK_CRYPT_EMPTY] = "NONE",
	[SK_CRYPT_AES256_CTR] = "AES-256-CTR",
};

char *sk_hmac2name[] = {
	[SK_HMAC_EMPTY] = "NONE",
	[SK_HMAC_SHA256] = "SHA256",
	[SK_HMAC_SHA512] = "SHA512",
};

int sk_name2crypt(char *name)
{
	int i;

	for (i = 0; i < SK_CRYPT_MAX; i++) {
		if (strcasecmp(name, sk_crypt2name[i]) == 0)
			return i;
	}

	return SK_CRYPT_INVALID;
}

int sk_name2hmac(char *name)
{
	int i;

	for (i = 0; i < SK_HMAC_MAX; i++) {
		if (strcasecmp(name, sk_hmac2name[i]) == 0)
			return i;
	}

	return SK_HMAC_INVALID;
}

void usage(FILE *fp, char *program)
{
	int i;

	fprintf(fp, "Usage %s [OPTIONS] -l <file> | -m <file> | "
		"-r <file> | -w <file>\n", program);
	fprintf(fp, "-l|--load    <file>	Load key from file into user's "
		"session keyring\n");
	fprintf(fp, "-m|--modify  <file>	Modify a file's key "
		"attributes\n");
	fprintf(fp, "-r|--read    <file>	Show file's key attributes\n");
	fprintf(fp, "-w|--write   <file>	Generate key file\n\n");
	fprintf(fp, "Load Options:\n");
	fprintf(fp, "-t|--type    <type>	Key type (mgs, server, "
		"client)\n\n");
	fprintf(fp, "Modify/Write Options:\n");
	fprintf(fp, "-c|--crypt   <num>	Cipher for encryption "
		"(Default: AES Counter mode)\n");
	for (i = 0; i < SK_CRYPT_MAX; i++)
		fprintf(fp, "                        %s\n", sk_crypt2name[i]);

	fprintf(fp, "-h|--hmac    <num>	Hash alg for HMAC "
		"(Default: SHA256)\n");
	for (i = 0; i < SK_HMAC_MAX; i++)
		fprintf(fp, "                        %s\n", sk_hmac2name[i]);

	fprintf(fp, "-e|--expire  <num>	Seconds before contexts from "
		"key expire (Default: %d seconds)\n", SK_DEFAULT_EXPIRE);
	fprintf(fp, "-f|--fsname  <name>	File system name for key\n");
	fprintf(fp, "-g|--mgsnids <nids>	Comma seperated list of MGS "
		"NIDs.  Only required when mgssec is used (Default: "
		"\"\")\n");
	fprintf(fp, "-n|--nodemap <name>	Nodemap name for key "
		"(Default: \"%s\")\n", SK_DEFAULT_NODEMAP);
	fprintf(fp, "-s|--session <len>	DHKE Public key length in bits "
		"(Default: %d)\n", SK_DEFAULT_DH_KEYLEN);
	fprintf(fp, "-k|--shared  <len>	Shared key length in bits "
		"(Default: %d)\n", SK_DEFAULT_SK_KEYLEN);
	fprintf(fp, "-d|--data    <file>	Shared key data source "
		"(Default: /dev/random)\n\n");
	fprintf(fp, "Other Options:\n");
	fprintf(fp, "-v|--verbose           Increase verbosity for "
		"errors\n");
	exit(EXIT_FAILURE);
}

ssize_t get_key_data(char *src, void *buffer, size_t bits)
{
	char *ptr = buffer;
	size_t remain;
	ssize_t rc;
	int fd;

	/* convert bits to minimum number of bytes */
	remain = (bits + 7) / 8;

	fd = open(src, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s: %s\n", src,
			strerror(errno));
		return -errno;
	}

	while (remain > 0) {
		rc = read(fd, ptr, remain);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "Error reading from %s: %s\n", src,
				strerror(errno));
			rc = -errno;
			goto out;

		} else if (rc == 0) {
			fprintf(stderr, "Key source too short for key size\n");
			rc = -ENODATA;
			goto out;
		}
		ptr += rc;
		remain -= rc;
	}
	rc = 0;

out:
	close(fd);
	return rc;
}

int write_config_file(char *output_file, struct sk_keyfile_config *config,
		      bool overwrite)
{
	size_t rc;
	int fd;
	int flags = O_WRONLY | O_CREAT;

	if (!overwrite)
		flags |= O_EXCL;

	sk_config_cpu_to_disk(config);

	fd = open(output_file, flags, 0400);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s: %s\n", output_file,
			strerror(errno));
		return -errno;
	}

	rc = write(fd, config, sizeof(*config));
	if (rc < 0) {
		fprintf(stderr, "Error writing to %s: %s\n", output_file,
			strerror(errno));
		rc = -errno;

	} else if (rc != sizeof(*config)) {
		fprintf(stderr, "Short write to %s\n", output_file);
		rc = -ENOSPC;

	} else {
		rc = 0;
	}

	close(fd);
	return rc;
}

int print_config(char *filename)
{
	struct sk_keyfile_config *config;
	int i;

	config = sk_read_file(filename);
	if (!config)
		return EXIT_FAILURE;

	if (sk_validate_config(config)) {
		fprintf(stderr, "Key configuration failed validation\n");
		free(config);
		return EXIT_FAILURE;
	}

	printf("Version:        %u\n", config->skc_version);
	printf("HMAC alg:       %s\n", sk_hmac2name[config->skc_hmac_alg]);
	printf("Crypt alg:      %s\n", sk_crypt2name[config->skc_crypt_alg]);
	printf("Ctx Expiration: %u seconds\n", config->skc_expire);
	printf("Shared keylen:  %u bits\n", config->skc_shared_keylen);
	printf("Session keylen: %u bits\n", config->skc_session_keylen);
	printf("File system:    %s\n", config->skc_fsname);
	printf("MGS NIDs:       ");
	for (i = 0; i < MAX_MGSNIDS; i++) {
		if (config->skc_mgsnids[i] == LNET_NID_ANY)
			continue;
		printf("%s ", libcfs_nid2str(config->skc_mgsnids[i]));
	}
	printf("\n");
	printf("Nodemap name:   %s\n", config->skc_nodemap);
	printf("Shared key:\n");
	print_hex(0, config->skc_shared_key, config->skc_shared_keylen / 8);

	free(config);
	return EXIT_SUCCESS;
}

int parse_mgsnids(char *mgsnids, struct sk_keyfile_config *config)
{
	lnet_nid_t nid;
	char *ptr;
	char *sep;
	char *end;
	int rc = 0;
	int i;

	/* replace all old values */
	for (i = 0; i < MAX_MGSNIDS; i++)
		config->skc_mgsnids[i] = LNET_NID_ANY;

	i = 0;
	end = mgsnids + strlen(mgsnids);
	ptr = mgsnids;
	while (ptr < end && i < MAX_MGSNIDS) {
		sep = strstr(ptr, ",");
		if (sep != NULL)
			*sep = '\0';

		nid = libcfs_str2nid(ptr);
		if (nid == LNET_NID_ANY) {
			fprintf(stderr, "Invalid MGS NID: %s\n", ptr);
			rc = -EINVAL;
			break;
		}

		config->skc_mgsnids[i++] = nid;
		ptr += strlen(ptr) + 1;
	}

	if (i == MAX_MGSNIDS) {
		fprintf(stderr, "Too many MGS NIDs provided\n");
		rc = -E2BIG;
	}

	return rc;
}

int main(int argc, char **argv)
{
	struct sk_keyfile_config *config;
	char *data = NULL;
	char *input = NULL;
	char *load = NULL;
	char *modify = NULL;
	char *output = NULL;
	char *mgsnids = NULL;
	char *nodemap = NULL;
	char *fsname = NULL;
	int type = SK_TYPE_INVALID;
	int crypt = SK_CRYPT_EMPTY;
	int hmac = SK_HMAC_EMPTY;
	int expire = -1;
	int shared_keylen = -1;
	int session_keylen = -1;
	int verbose = 0;
	int i;
	int opt;

	static struct option long_opt[] = {
		{"crypt", 1, 0, 'c'},
		{"data", 1, 0, 'd'},
		{"expire", 1, 0, 'e'},
		{"fsname", 1, 0, 'f'},
		{"mgsnids", 1, 0, 'g'},
		{"hmac", 1, 0, 'h'},
		{"load", 1, 0, 'l'},
		{"modify", 1, 0, 'm'},
		{"nodemap", 1, 0, 'n'},
		{"read", 1, 0, 'r'},
		{"session", 1, 0, 's'},
		{"shared", 1, 0, 'k'},
		{"type", 1, 0, 't'},
		{"write", 1, 0, 'w'},
		{"verbose", 0, 0, 'v'},
		{"help", 0, 0, 'p'},
		{0, 0, 0, 0},
	};

	while ((opt = getopt_long(argc, argv, "c:d:e:f:g:h:l:m:n:pr:s:k:t:w:v",
				  long_opt, NULL)) != EOF) {
		switch (opt) {
		case 'c':
			crypt = sk_name2crypt(optarg);
			break;
		case 'd':
			data = optarg;
			break;
		case 'e':
			expire = atoi(optarg);
			if (expire < 60)
				fprintf(stderr, "WARNING: Using a short key "
					"expiration may cause issues during "
					"key renegotiation\n");
			break;
		case 'f':
			fsname = optarg;
			if (strlen(fsname) > MTI_NAME_MAXLEN) {
				fprintf(stderr, "File system name too long\n");
				return EXIT_FAILURE;
			}
			break;
		case 'g':
			mgsnids = optarg;
			break;
		case 'h':
			hmac = sk_name2hmac(optarg);
			break;
		case 'l':
			load = optarg;
			break;
		case 'n':
			nodemap = optarg;
			if (strlen(nodemap) > LUSTRE_NODEMAP_NAME_LENGTH) {
				fprintf(stderr, "Nodemap name too long\n");
				return EXIT_FAILURE;
			}
			break;
		case 'm':
			modify = optarg;
			break;
		case 'p':
			usage(stdout, argv[0]);
			break;
		case 'r':
			input = optarg;
			break;
		case 's':
			session_keylen = atoi(optarg);
			break;
		case 'k':
			shared_keylen = atoi(optarg);
			break;
		case 't':
			if (!strcasecmp(optarg, "server")) {
				type = SK_TYPE_SERVER;
			} else if (!strcasecmp(optarg, "mgs")) {
				type = SK_TYPE_MGS;
			} else if (!strcasecmp(optarg, "client")) {
				type = SK_TYPE_CLIENT;
			} else {
				fprintf(stderr, "type must be mgs, server, or "
					"client\n");
				return EXIT_FAILURE;
			}
			break;
		case 'w':
			output = optarg;
			break;
		case 'v':
			verbose++;
			break;
		default:
			fprintf(stderr, "Unknown option: %c\n", opt);
			return EXIT_FAILURE;
			break;
		}
	}

	if (optind != argc) {
		fprintf(stderr, "Extraneous arguments provided, check usage\n");
		return EXIT_FAILURE;
	}

	if (!input && !output && !load && !modify) {
		usage(stderr, argv[0]);
		return EXIT_FAILURE;
	}

	/* init gss logger for foreground (no syslog) which prints to stderr */
	initerr(NULL, verbose, 1);

	if (input)
		return print_config(input);

	if (load) {
		if (type == SK_TYPE_INVALID) {
			fprintf(stderr, "type must be specified when loading "
				"a key\n");
			return EXIT_FAILURE;
		}

		if (sk_load_keyfile(load, type))
			return EXIT_FAILURE;
		return EXIT_SUCCESS;
	}

	if (crypt == SK_CRYPT_INVALID) {
		fprintf(stderr, "Invalid crypt algorithm specified\n");
		return EXIT_FAILURE;
	}
	if (hmac == SK_HMAC_INVALID) {
		fprintf(stderr, "Invalid HMAC algorithm specified\n");
		return EXIT_FAILURE;
	}

	if (modify) {
		config = sk_read_file(modify);
		if (!config)
			return EXIT_FAILURE;

		if (crypt != SK_CRYPT_EMPTY)
			config->skc_crypt_alg = crypt;
		if (hmac != SK_HMAC_EMPTY)
			config->skc_hmac_alg = hmac;
		if (expire != -1)
			config->skc_expire = expire;
		if (shared_keylen != -1)
			config->skc_shared_keylen = shared_keylen;
		if (session_keylen != -1)
			config->skc_session_keylen = session_keylen;
		if (fsname)
			strncpy(config->skc_fsname, fsname, strlen(fsname));
		if (nodemap)
			strncpy(config->skc_nodemap, nodemap, strlen(nodemap));
		if (mgsnids && parse_mgsnids(mgsnids, config))
			goto error;
		if (data && get_key_data(data, config->skc_shared_key,
		    config->skc_shared_keylen)) {
			fprintf(stderr, "Failure getting data for key\n");
			goto error;
		}

		if (sk_validate_config(config)) {
			fprintf(stderr, "Key configuration failed "
				"validation\n");
			goto error;
		}

		if (write_config_file(modify, config, true))
			goto error;

		return EXIT_SUCCESS;
	}

	/* write mode for a new key */
	if (!fsname && !mgsnids) {
		fprintf(stderr, "Must provide --fsname, "
			"--mgsnids, or both\n");
		return EXIT_FAILURE;
	}

	config = malloc(sizeof(*config));
	if (!config)
		return EXIT_FAILURE;

	/* Set the defaults */
	memset(config, 0, sizeof(*config));
	config->skc_version = SK_CONF_VERSION;
	config->skc_expire = SK_DEFAULT_EXPIRE;
	config->skc_shared_keylen = SK_DEFAULT_SK_KEYLEN;
	config->skc_session_keylen = SK_DEFAULT_DH_KEYLEN;
	config->skc_crypt_alg = SK_CRYPT_AES256_CTR;
	config->skc_hmac_alg = SK_HMAC_SHA256;
	for (i = 0; i < MAX_MGSNIDS; i++)
		config->skc_mgsnids[i] = LNET_NID_ANY;

	if (crypt != SK_CRYPT_EMPTY)
		config->skc_crypt_alg = crypt;
	if (hmac != SK_HMAC_EMPTY)
		config->skc_hmac_alg = hmac;
	if (expire != -1)
		config->skc_expire = expire;
	if (shared_keylen != -1)
		config->skc_shared_keylen = shared_keylen;
	if (session_keylen != -1)
		config->skc_session_keylen = session_keylen;
	if (fsname)
		strncpy(config->skc_fsname, fsname, strlen(fsname));
	if (nodemap)
		strncpy(config->skc_nodemap, nodemap, strlen(nodemap));
	else
		strncpy(config->skc_nodemap, SK_DEFAULT_NODEMAP,
			strlen(SK_DEFAULT_NODEMAP));

	if (mgsnids && parse_mgsnids(mgsnids, config))
		goto error;
	if (!data)
		data = "/dev/random";
	if (get_key_data(data, config->skc_shared_key,
	    config->skc_shared_keylen)) {
		fprintf(stderr, "Failure getting data for key\n");
		goto error;
	}

	if (sk_validate_config(config)) {
		fprintf(stderr, "Key configuration failed validation\n");
		goto error;
	}

	if (write_config_file(output, config, false))
		goto error;

	return EXIT_SUCCESS;

error:
	if (config)
		free(config);
	return EXIT_FAILURE;
}
