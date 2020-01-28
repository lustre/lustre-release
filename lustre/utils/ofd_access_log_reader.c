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
 *
 * Copyright 2020, DataDirect Networks Storage.
 *
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: John L. Hammond <jhammond@whamcloud.com>
 *
 * lustre/utils/ofd_access_log_reader.c
 *
 * Sample utility to discover and read Lustre (ofd) access logs.
 *
 * This demonstrates the discovery and reading of Lustre access logs
 * (see linux/lustre/lustre_access_log.h and
 * lustre/ofd/ofd_access_log.c.). By default it opens the control
 * device, discovers and opens all access log devices, and consumes
 * all access log entries. If invoked with the --list option then it
 * prints information about all available devices to stdout and exits.
 *
 * Structured trace points (when --trace is used) are added to permit
 * testing of the access log functionality (see test_165* in
 * lustre/tests/sanity.sh).
 */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <malloc.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <linux/types.h>
#include <linux/lustre/lustre_user.h>
#include <linux/lustre/lustre_access_log.h>
#include "lstddef.h"

/* TODO fsname filter */

static FILE *debug_file;
static FILE *trace_file;

#define DEBUG(fmt, args...)						\
	do {								\
		if (debug_file != NULL)					\
			fprintf(debug_file, "DEBUG %s:%d: "fmt, __func__, __LINE__, ##args); \
	} while (0)

#define TRACE(fmt, args...)						\
	do {								\
		if (trace_file != NULL)					\
			fprintf(trace_file, "TRACE "fmt, ##args);	\
	} while (0)

#define DEBUG_D(x) DEBUG("%s = %d\n", #x, x)
#define DEBUG_P(x) DEBUG("%s = %p\n", #x, x)
#define DEBUG_S(x) DEBUG("%s = '%s'\n", #x, x)
#define DEBUG_U(x) DEBUG("%s = %u\n", #x, x)
#define DEBUG_U32(x) DEBUG("%s = %"PRIu32"\n", #x, x)
#define DEBUG_U64(x) DEBUG("%s = %"PRIu64"\n", #x, x)

#define ERROR(fmt, args...) \
	fprintf(stderr, "%s: "fmt, program_invocation_short_name, ##args)

#define FATAL(fmt, args...)			\
	do {					\
		ERROR("FATAL: "fmt, ##args);	\
		exit(EXIT_FAILURE);		\
	} while (0)

enum {
	ALR_EXIT_SUCCESS = INT_MIN + EXIT_SUCCESS,
	ALR_EXIT_FAILURE = INT_MIN + EXIT_FAILURE,
	ALR_ERROR = -1,
	ALR_EOF = 0,
	ALR_OK = 1,
};

struct alr_dev {
	char *alr_name;
	int (*alr_io)(int /* epoll_fd */, struct alr_dev * /* this */, unsigned int /* mask */);
	void (*alr_destroy)(struct alr_dev *);
	int alr_fd;
};

struct alr_log {
	struct alr_dev alr_dev;
	char *alr_buf;
	size_t alr_buf_size;
	size_t alr_entry_size;
	dev_t alr_rdev;
};

static struct alr_log *alr_log[1 << 20]; /* 20 == MINORBITS */
static int oal_version; /* FIXME ... major version, minor version */
static unsigned int oal_log_major;
static unsigned int oal_log_minor_max;

#define D_ALR_DEV "%s %d"
#define P_ALR_DEV(ad) \
	(ad)->alr_name, (ad)->alr_fd

#define D_ALR_LOG D_ALR_DEV" %u:%u"
#define P_ALR_LOG(al) \
	P_ALR_DEV(&(al)->alr_dev), major((al)->alr_rdev), minor((al)->alr_rdev)

static void alr_dev_free(int epoll_fd, struct alr_dev *ad)
{
	TRACE("alr_dev_free %s\n", ad->alr_name);

	if (!(ad->alr_fd < 0))
		epoll_ctl(epoll_fd, EPOLL_CTL_DEL, ad->alr_fd, NULL);

	if (ad->alr_destroy != NULL)
		(*ad->alr_destroy)(ad);

	if (!(ad->alr_fd < 0))
		close(ad->alr_fd);

	free(ad->alr_name);
	free(ad);
}

static struct alr_log **alr_log_lookup(dev_t rdev)
{
	assert(major(rdev) == oal_log_major);

	if (!(minor(rdev) < ARRAY_SIZE(alr_log)))
		return NULL;

	return &alr_log[minor(rdev)];
}

static const char *alr_flags_to_str(unsigned int flags)
{
	switch (flags & (OFD_ACCESS_READ | OFD_ACCESS_WRITE)) {
	default:
		return "0";
	case OFD_ACCESS_READ:
		return "r";
	case OFD_ACCESS_WRITE:
		return "w";
	case OFD_ACCESS_READ | OFD_ACCESS_WRITE:
		return "rw";
	}
}

/* /dev/lustre-access-log/scratch-OST0000 device poll callback: read entries
 * from log and print. */
static int alr_log_io(int epoll_fd, struct alr_dev *ad, unsigned int mask)
{
	struct alr_log *al = container_of(ad, struct alr_log, alr_dev);
	ssize_t i, count;

	TRACE("alr_log_io %s\n", ad->alr_name);
	DEBUG_U(mask);

	assert(al->alr_entry_size != 0);
	assert(al->alr_buf_size != 0);
	assert(al->alr_buf != NULL);

	count = read(ad->alr_fd, al->alr_buf, al->alr_buf_size);
	if (count < 0) {
		ERROR("cannot read events from '%s': %s\n", ad->alr_name, strerror(errno));
		return ALR_ERROR;
	}

	if (count == 0) {
		TRACE("alr_log_eof %s\n", ad->alr_name);
		return ALR_EOF;
	}

	if (count % al->alr_entry_size != 0) {
		ERROR("invalid read from "D_ALR_LOG": entry_size = %zu, count = %zd\n",
			P_ALR_LOG(al), al->alr_entry_size, count);
		return ALR_ERROR;
	}

	DEBUG("read "D_ALR_LOG", count = %zd\n", P_ALR_LOG(al), count);

	for (i = 0; i < count; i += al->alr_entry_size) {
		struct ofd_access_entry_v1 *oae =
			(struct ofd_access_entry_v1 *)&al->alr_buf[i];

		TRACE("alr_log_entry %s "DFID" %lu %lu %lu %u %u %s\n",
			ad->alr_name,
			PFID(&oae->oae_parent_fid),
			(unsigned long)oae->oae_begin,
			(unsigned long)oae->oae_end,
			(unsigned long)oae->oae_time,
			(unsigned int)oae->oae_size,
			(unsigned int)oae->oae_segment_count,
			alr_flags_to_str(oae->oae_flags));
	}

	return ALR_OK;
}

static void alr_log_destroy(struct alr_dev *ad)
{
	struct alr_log *al = container_of(ad, struct alr_log, alr_dev);
	struct alr_log **pal;

	TRACE("alr_log_free %s\n", ad->alr_name);
	assert(major(al->alr_rdev) == oal_log_major);

	pal = alr_log_lookup(al->alr_rdev);
	if (pal != NULL && *pal == al)
		*pal = NULL;

	free(al->alr_buf);
	al->alr_buf = NULL;
	al->alr_buf_size = 0;
}

/* Add an access log (identified by path) to the epoll set. */
static int alr_log_add(int epoll_fd, const char *path)
{
	struct alr_log **pal, *al = NULL;
	struct stat st;
	int fd = -1;
	int rc;

	fd = open(path, O_RDONLY|O_NONBLOCK|O_CLOEXEC);
	if (fd < 0) {
		ERROR("cannot open device '%s': %s\n", path, strerror(errno));
		rc = (errno == ENOENT ? 0 : -1); /* Possible race. */
		goto out;
	}

	/* Revalidate rdev in case of race. */
	rc = fstat(fd, &st);
	if (rc < 0) {
		ERROR("cannot stat '%s': %s\n", path, strerror(errno));
		goto out;
	}

	if (major(st.st_rdev) != oal_log_major)
		goto out;

	pal = alr_log_lookup(st.st_rdev);
	if (pal == NULL) {
		ERROR("no device slot available for '%s' with minor %u\n",
			path, minor(st.st_rdev));
		goto out;
	}

	if (*pal != NULL)
		goto out; /* We already have this device. */

	struct lustre_access_log_info_v1 lali;

	memset(&lali, 0, sizeof(lali));

	rc = ioctl(fd, LUSTRE_ACCESS_LOG_IOCTL_INFO, &lali);
	if (rc < 0) {
		ERROR("cannot get info for device '%s': %s\n",
			path, strerror(errno));
		goto out;
	}

	if (lali.lali_type != LUSTRE_ACCESS_LOG_TYPE_OFD) {
		rc = 0;
		goto out;
	}

	al = calloc(1, sizeof(*al));
	if (al == NULL)
		FATAL("cannot allocate struct alr_dev of size %zu: %s\n",
			sizeof(*al), strerror(errno));

	al->alr_dev.alr_io = &alr_log_io;
	al->alr_dev.alr_destroy = &alr_log_destroy;
	al->alr_dev.alr_fd = fd;
	fd = -1;

	al->alr_rdev = st.st_rdev;

	al->alr_dev.alr_name = strdup(lali.lali_name);
	if (al->alr_dev.alr_name == NULL)
		FATAL("cannot copy name of size %zu: %s\n",
			strlen(lali.lali_name), strerror(errno));

	al->alr_buf_size = lali.lali_log_size;
	al->alr_entry_size = lali.lali_entry_size;

	if (al->alr_entry_size == 0) {
		ERROR("device '%s' has zero entry size\n", path);
		rc = -1;
		goto out;
	}

	if (al->alr_buf_size == 0)
		al->alr_buf_size = 1048576;

	al->alr_buf_size = roundup(al->alr_buf_size, al->alr_entry_size);

	al->alr_buf = malloc(al->alr_buf_size);
	if (al->alr_buf == NULL)
		FATAL("cannot allocate log buffer for '%s' of size %zu: %s\n",
			path, al->alr_buf_size, strerror(errno));

	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLHUP,
		.data.ptr = &al->alr_dev,
	};

	rc = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, al->alr_dev.alr_fd, &ev);
	if (rc < 0) {
		ERROR("cannot add device '%s' to epoll set: %s\n",
			path, strerror(errno));
		goto out;
	}

	TRACE("alr_log_add %s\n", al->alr_dev.alr_name);

	if (oal_log_minor_max < minor(al->alr_rdev))
		oal_log_minor_max = minor(al->alr_rdev);

	assert(*pal == NULL);
	*pal = al;
	al = NULL;
	rc = 0;
out:
	if (al != NULL)
		alr_dev_free(epoll_fd, &al->alr_dev);

	if (!(fd < 0))
		close(fd);

	return rc;
}

/* Scan /dev/lustre-access-log/ for new access log devices and add to
 * epoll set. */
static int alr_scan(int epoll_fd)
{
	const char dir_path[] = "/dev/"LUSTRE_ACCESS_LOG_DIR_NAME;
	DIR *dir;
	int dir_fd;
	struct dirent *d;
	int rc;

	dir = opendir(dir_path);
	if (dir == NULL) {
		ERROR("cannot open '%s' for scanning: %s\n", dir_path, strerror(errno));
		return ALR_EXIT_FAILURE;
	}

	dir_fd = dirfd(dir);

	/* Scan /dev for devices with major equal to oal_log_major and add
	 * any new devices. */
	while ((d = readdir(dir)) != NULL) {
		char path[6 + PATH_MAX];
		struct alr_log **pal;
		struct stat st;

		if (d->d_type != DT_CHR)
			continue;

		rc = fstatat(dir_fd, d->d_name, &st, 0);
		if (rc < 0) {
			ERROR("cannot stat '%s/%s' while scanning: %s\n",
				dir_path, d->d_name, strerror(errno));
			continue;
		}

		if (!S_ISCHR(st.st_mode))
			continue;

		if (major(st.st_rdev) != oal_log_major)
			continue;

		pal = alr_log_lookup(st.st_rdev);
		if (pal == NULL) {
			ERROR("no device slot available for '%s/%s' with minor %u\n",
				dir_path, d->d_name, minor(st.st_rdev));
			continue;
		}

		if (*pal != NULL)
			continue; /* We already have this device. */

		snprintf(path, sizeof(path), "%s/%s", dir_path, d->d_name);

		alr_log_add(epoll_fd, path);
	}

	closedir(dir);

	return ALR_OK;
}

/* /dev/lustre-access-log/control device poll callback: call prescan
 * ioctl and scan /dev/lustre-access-log/ for new access log
 * devices. */
static int alr_ctl_io(int epoll_fd, struct alr_dev *cd, unsigned int mask)
{
	int rc;

	TRACE("%s\n", __func__);
	DEBUG_U(mask);

	if (mask & EPOLLERR)
		return ALR_EXIT_FAILURE;

	if (mask & EPOLLHUP)
		return ALR_EXIT_SUCCESS;

	rc = ioctl(cd->alr_fd, LUSTRE_ACCESS_LOG_IOCTL_PRESCAN);
	if (rc < 0) {
		ERROR("cannot start scanning: %s\n", strerror(errno));
		return ALR_EXIT_FAILURE;
	}

	return alr_scan(epoll_fd);
}

/* signalfd epoll callback. Handle SIGINT and SIGTERM by breaking from
 * the epoll loop and exiting normally.*/
static int alr_signal_io(int epoll_fd, struct alr_dev *sd, unsigned int mask)
{
	struct signalfd_siginfo ssi;
	ssize_t rc;

	TRACE("%s\n", __func__);
	DEBUG_U(mask);

	rc = read(sd->alr_fd, &ssi, sizeof(ssi));
	if (rc <= 0)
		return ALR_OK;

	DEBUG_U32(ssi.ssi_signo);
	switch (ssi.ssi_signo) {
	case SIGINT:
	case SIGTERM:
		return ALR_EXIT_SUCCESS;
	default:
		return ALR_OK;
	}
}

/* Call LUSTRE_ACCESS_LOG_IOCTL_INFO to get access log info and print
 * YAML formatted info to stdout. */
static int alr_log_info(struct alr_log *al)
{
	struct lustre_access_log_info_v1 lali;
	int rc;

	rc = ioctl(al->alr_dev.alr_fd, LUSTRE_ACCESS_LOG_IOCTL_INFO, &lali);
	if (rc < 0) {
		ERROR("cannot get info for device '%s': %s\n",
			al->alr_dev.alr_name, strerror(errno));
		return -1;
	}

	printf("- name: %s\n"
	       "  version: %#x\n"
	       "  type: %#x\n"
	       "  log_size: %u\n"
	       "  entry_size: %u\n"
	       "  _head: %u\n"
	       "  _tail: %u\n"
	       "  _entry_space: %u\n"
	       "  _entry_count: %u\n"
	       "  _drop_count: %u\n"
	       "  _is_closed: %u\n",
	       lali.lali_name,
	       lali.lali_version,
	       lali.lali_type,
	       lali.lali_log_size,
	       lali.lali_entry_size,
	       lali._lali_head,
	       lali._lali_tail,
	       lali._lali_entry_space,
	       lali._lali_entry_count,
	       lali._lali_drop_count,
	       lali._lali_is_closed);

	return 0;
}

static struct alr_dev *alr_dev_create(int epoll_fd, int fd, const char *name,
			int (*io)(int, struct alr_dev *, unsigned int),
			void (*destroy)(struct alr_dev *))
{
	struct alr_dev *alr;
	int rc;

	alr = calloc(1, sizeof(*alr));
	if (alr == NULL)
		return NULL;

	alr->alr_name = strdup(name);
	if (alr->alr_name == NULL) {
		free(alr);
		return NULL;
	}
	alr->alr_io = io;
	alr->alr_destroy = destroy;
	alr->alr_fd = fd;

	struct epoll_event event = {
		.events = EPOLLIN | EPOLLHUP,
		.data.ptr = alr,
	};

	rc = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, alr->alr_fd, &event);
	if (rc < 0) {
		free(alr);
		return NULL;
	}

	return alr;
}

int main(int argc, char *argv[])
{
	const char ctl_path[] = "/dev/"LUSTRE_ACCESS_LOG_DIR_NAME"/control";
	struct alr_dev *alr_signal = NULL;
	struct alr_dev *alr_ctl = NULL;
	unsigned int m;
	int list_info = 0;
	int epoll_fd = -1;
	int signal_fd = -1;
	int ctl_fd = -1;
	int exit_status;
	int rc;
	int c;

	static struct option options[] = {
		{ .name = "debug", .has_arg = optional_argument, .val = 'd', },
		{ .name = "help", .has_arg = no_argument, .val = 'h', },
		{ .name = "list", .has_arg = no_argument, .val = 'l', },
		{ .name = "trace", .has_arg = optional_argument, .val = 't', },
		{ .name = NULL, },
	};

	while ((c = getopt_long(argc, argv, "d::hlt::", options, NULL)) != -1) {
		switch (c) {
		case 'd':
			if (optarg == NULL) {
				debug_file = stderr;
			} else if (strcmp(optarg, "-") == 0) {
				debug_file = stdout;
			} else {
				debug_file = fopen(optarg, "a");
				if (debug_file == NULL)
					FATAL("cannot open debug file '%s': %s\n",
						optarg, strerror(errno));
			}

			break;
		case 'h':
			/* ... */
			exit(EXIT_SUCCESS);
		case 'l':
			list_info = 1;
			break;
		case 't':
			if (optarg == NULL) {
				trace_file = stderr;
			} else if (strcmp(optarg, "-") == 0) {
				trace_file = stdout;
			} else {
				trace_file = fopen(optarg, "a");
				if (debug_file == NULL)
					FATAL("cannot open debug file '%s': %s\n",
						optarg, strerror(errno));
			}

			break;
		case '?':
			/* Try ... for more ... */
			exit(EXIT_FAILURE);
		}
	}

	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd < 0)
		FATAL("cannot create epoll set: %s\n", strerror(errno));

	/* Setup signal FD and add to epoll set. */
	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	sigaddset(&signal_mask, SIGINT);
	sigaddset(&signal_mask, SIGTERM);
	rc = sigprocmask(SIG_BLOCK, &signal_mask, NULL);
	if (rc < 0)
		FATAL("cannot set process signal mask: %s\n", strerror(errno));

	signal_fd = signalfd(-1, &signal_mask, SFD_NONBLOCK|SFD_CLOEXEC);
	if (signal_fd < 0)
		FATAL("cannot create signalfd: %s\n", strerror(errno));

	alr_signal = alr_dev_create(epoll_fd, signal_fd, "signal", &alr_signal_io, NULL);
	if (alr_signal == NULL)
		FATAL("cannot register signalfd: %s\n", strerror(errno));

	signal_fd = -1;

	/* Open control device. */
	ctl_fd = open(ctl_path, O_RDONLY|O_NONBLOCK|O_CLOEXEC);
	if (ctl_fd < 0)
		FATAL("cannot open '%s': %s\n", ctl_path, strerror(errno));

	/* Get and print interface version. */
	oal_version = ioctl(ctl_fd, LUSTRE_ACCESS_LOG_IOCTL_VERSION);
	if (oal_version < 0)
		FATAL("cannot get ofd access log interface version: %s\n", strerror(errno));

	DEBUG_D(oal_version);

	/* Get and print device major used for access log devices. */
	oal_log_major = ioctl(ctl_fd, LUSTRE_ACCESS_LOG_IOCTL_MAJOR);
	if (oal_log_major < 0)
		FATAL("cannot get ofd access log major: %s\n", strerror(errno));

	DEBUG_D(oal_log_major);

	/* Add control device to epoll set. */
	alr_ctl = alr_dev_create(epoll_fd, ctl_fd, "control", &alr_ctl_io, NULL);
	if (alr_ctl == NULL)
		FATAL("cannot register control device: %s\n", strerror(errno));

	ctl_fd = -1;

	do {
		struct epoll_event ev[32];
		int timeout = (list_info ? 0 : -1);
		int i, ev_count;

		ev_count = epoll_wait(epoll_fd, ev, ARRAY_SIZE(ev), timeout);
		if (ev_count < 0) {
			if (errno == EINTR) /* Signal or timeout. */
				continue;

			ERROR("cannot wait on epoll set: %s\n", strerror(errno));
			exit_status = EXIT_FAILURE;
			goto out;
		}

		DEBUG_D(ev_count);

		for (i = 0; i < ev_count; i++) {
			struct alr_dev *ad = ev[i].data.ptr;
			unsigned int mask = ev[i].events;

			rc = (*ad->alr_io)(epoll_fd, ad, mask);
			switch (rc) {
			case ALR_EXIT_FAILURE:
				exit_status = EXIT_FAILURE;
				goto out;
			case ALR_EXIT_SUCCESS:
				exit_status = EXIT_SUCCESS;
				goto out;
			case ALR_ERROR:
			case ALR_EOF:
				alr_dev_free(epoll_fd, ad);
				break;
			case ALR_OK:
			default:
				break;
			}
		}
	} while (!list_info);

	exit_status = EXIT_SUCCESS;
out:
	assert(oal_log_minor_max < ARRAY_SIZE(alr_log));

	for (m = 0; m <= oal_log_minor_max; m++) {
		if (alr_log[m] == NULL)
			continue;

		if (list_info) {
			rc = alr_log_info(alr_log[m]);
			if (rc < 0)
				exit_status = EXIT_FAILURE;
		}

		alr_dev_free(epoll_fd, &alr_log[m]->alr_dev);
	}

	alr_dev_free(epoll_fd, alr_ctl);
	alr_dev_free(epoll_fd, alr_signal);
	close(epoll_fd);

	DEBUG_D(exit_status);

	return exit_status;
}
