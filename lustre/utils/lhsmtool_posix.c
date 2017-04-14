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
 * http://www.gnu.org/licenses/gpl-2.0.htm
 *
 * GPL HEADER END
 */
/*
 * (C) Copyright 2012 Commissariat a l'energie atomique et aux energies
 *     alternatives
 *
 * Copyright (c) 2013, 2016, Intel Corporation.
 */
/* HSM copytool program for POSIX filesystem-based HSM's.
 *
 * An HSM copytool daemon acts on action requests from Lustre to copy files
 * to and from an HSM archive system. This one in particular makes regular
 * POSIX filesystem calls to a given path, where an HSM is presumably mounted.
 *
 * This particular tool can also import an existing HSM archive.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <libcfs/util/string.h>
#include <linux/lustre_fid.h>
#include <lustre/lustreapi.h>

/* Progress reporting period */
#define REPORT_INTERVAL_DEFAULT 30
/* HSM hash subdir permissions */
#define DIR_PERM S_IRWXU
/* HSM hash file permissions */
#define FILE_PERM (S_IRUSR | S_IWUSR)

#define ONE_MB 0x100000

#ifndef NSEC_PER_SEC
# define NSEC_PER_SEC 1000000000UL
#endif

enum ct_action {
	CA_IMPORT = 1,
	CA_REBIND,
	CA_MAXSEQ,
};

struct options {
	int			 o_copy_attrs;
	int			 o_daemonize;
	int			 o_dry_run;
	int			 o_abort_on_error;
	int			 o_shadow_tree;
	int			 o_verbose;
	int			 o_copy_xattrs;
	int			 o_archive_cnt;
	int			 o_archive_id[LL_HSM_MAX_ARCHIVE];
	int			 o_report_int;
	unsigned long long	 o_bandwidth;
	size_t			 o_chunk_size;
	enum ct_action		 o_action;
	char			*o_event_fifo;
	char			*o_mnt;
	int			 o_mnt_fd;
	char			*o_hsm_root;
	char			*o_src; /* for import, or rebind */
	char			*o_dst; /* for import, or rebind */
};

/* everything else is zeroed */
struct options opt = {
	.o_copy_attrs = 1,
	.o_shadow_tree = 1,
	.o_verbose = LLAPI_MSG_INFO,
	.o_copy_xattrs = 1,
	.o_report_int = REPORT_INTERVAL_DEFAULT,
	.o_chunk_size = ONE_MB,
};

/* hsm_copytool_private will hold an open FD on the lustre mount point
 * for us. Additionally open one on the archive FS root to make sure
 * it doesn't drop out from under us (and remind the admin to shutdown
 * the copytool before unmounting). */

static int arc_fd = -1;

static int err_major;
static int err_minor;

static char cmd_name[PATH_MAX];
static char fs_name[MAX_OBD_NAME + 1];

static struct hsm_copytool_private *ctdata;

static inline double ct_now(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	return tv.tv_sec + 0.000001 * tv.tv_usec;
}

#define CT_ERROR(_rc, _format, ...)					\
	llapi_error(LLAPI_MSG_ERROR, _rc,				\
		    "%f %s[%ld]: "_format,				\
		    ct_now(), cmd_name, syscall(SYS_gettid), ## __VA_ARGS__)

#define CT_DEBUG(_format, ...)						\
	llapi_error(LLAPI_MSG_DEBUG | LLAPI_MSG_NO_ERRNO, 0,		\
		    "%f %s[%ld]: "_format,				\
		    ct_now(), cmd_name, syscall(SYS_gettid), ## __VA_ARGS__)

#define CT_WARN(_format, ...) \
	llapi_error(LLAPI_MSG_WARN | LLAPI_MSG_NO_ERRNO, 0,		\
		    "%f %s[%ld]: "_format,				\
		    ct_now(), cmd_name, syscall(SYS_gettid), ## __VA_ARGS__)

#define CT_TRACE(_format, ...)						\
	llapi_error(LLAPI_MSG_INFO | LLAPI_MSG_NO_ERRNO, 0,		\
		    "%f %s[%ld]: "_format,				\
		    ct_now(), cmd_name, syscall(SYS_gettid), ## __VA_ARGS__)

static void usage(const char *name, int rc)
{
	fprintf(stdout,
	" Usage: %s [options]... <mode> <lustre_mount_point>\n"
	"The Lustre HSM Posix copy tool can be used as a daemon or "
	"as a command line tool\n"
	"The Lustre HSM daemon acts on action requests from Lustre\n"
	"to copy files to and from an HSM archive system.\n"
	"This POSIX-flavored daemon makes regular POSIX filesystem calls\n"
	"to an HSM mounted at a given hsm_root.\n"
	"   --daemon            Daemon mode, run in background\n"
	" Options:\n"
	"   --no-attr           Don't copy file attributes\n"
	"   --no-shadow         Don't create shadow namespace in archive\n"
	"   --no-xattr          Don't copy file extended attributes\n"
	"The Lustre HSM tool performs administrator-type actions\n"
	"on a Lustre HSM archive.\n"
	"This POSIX-flavored tool can link an existing HSM namespace\n"
	"into a Lustre filesystem.\n"
	" Usage:\n"
	"   %s [options] --import <src> <dst> <lustre_mount_point>\n"
	"      import an archived subtree from\n"
	"       <src> (FID or relative path to hsm_root) into the Lustre\n"
	"             filesystem at\n"
	"       <dst> (absolute path)\n"
	"   %s [options] --rebind <old_FID> <new_FID> <lustre_mount_point>\n"
	"      rebind an entry in the HSM to a new FID\n"
	"       <old_FID> old FID the HSM entry is bound to\n"
	"       <new_FID> new FID to bind the HSM entry to\n"
	"   %s [options] --rebind <list_file> <lustre_mount_point>\n"
	"      perform the rebind operation for all FID in the list file\n"
	"       each line of <list_file> consists of <old_FID> <new_FID>\n"
	"   %s [options] --max-sequence <fsname>\n"
	"       return the max fid sequence of archived files\n"
	"   --abort-on-error          Abort operation on major error\n"
	"   -A, --archive <#>         Archive number (repeatable)\n"
	"   -b, --bandwidth <bw>      Limit I/O bandwidth (unit can be used\n,"
	"                             default is MB)\n"
	"   --dry-run                 Don't run, just show what would be done\n"
	"   -c, --chunk-size <sz>     I/O size used during data copy\n"
	"                             (unit can be used, default is MB)\n"
	"   -f, --event-fifo <path>   Write events stream to fifo\n"
	"   -p, --hsm-root <path>     Target HSM mount point\n"
	"   -q, --quiet               Produce less verbose output\n"
	"   -u, --update-interval <s> Interval between progress reports sent\n"
	"                             to Coordinator\n"
	"   -v, --verbose             Produce more verbose output\n",
	cmd_name, cmd_name, cmd_name, cmd_name, cmd_name);

	exit(rc);
}

static int ct_parseopts(int argc, char * const *argv)
{
	struct option long_opts[] = {
	{ .val = 1,	.name = "abort-on-error",
	  .flag = &opt.o_abort_on_error,	.has_arg = no_argument },
	{ .val = 1,	.name = "abort_on_error",
	  .flag = &opt.o_abort_on_error,	.has_arg = no_argument },
	{ .val = 'A',	.name = "archive",	.has_arg = required_argument },
	{ .val = 'b',	.name = "bandwidth",	.has_arg = required_argument },
	{ .val = 'c',	.name = "chunk-size",	.has_arg = required_argument },
	{ .val = 'c',	.name = "chunk_size",	.has_arg = required_argument },
	{ .val = 1,	.name = "daemon",	.has_arg = no_argument,
	  .flag = &opt.o_daemonize },
	{ .val = 'f',	.name = "event-fifo",	.has_arg = required_argument },
	{ .val = 'f',	.name = "event_fifo",	.has_arg = required_argument },
	{ .val = 1,	.name = "dry-run",	.has_arg = no_argument,
	  .flag = &opt.o_dry_run },
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .val = 'i',	.name = "import",	.has_arg = no_argument },
	{ .val = 'M',	.name = "max-sequence",	.has_arg = no_argument },
	{ .val = 'M',	.name = "max_sequence",	.has_arg = no_argument },
	{ .val = 0,	.name = "no-attr",	.has_arg = no_argument,
	  .flag = &opt.o_copy_attrs },
	{ .val = 0,	.name = "no_attr",	.has_arg = no_argument,
	  .flag = &opt.o_copy_attrs },
	{ .val = 0,	.name = "no-shadow",	.has_arg = no_argument,
	  .flag = &opt.o_shadow_tree },
	{ .val = 0,	.name = "no_shadow",	.has_arg = no_argument,
	  .flag = &opt.o_shadow_tree },
	{ .val = 0,	.name = "no-xattr",	.has_arg = no_argument,
	  .flag = &opt.o_copy_xattrs },
	{ .val = 0,	.name = "no_xattr",	.has_arg = no_argument,
	  .flag = &opt.o_copy_xattrs },
	{ .val = 'p',	.name = "hsm-root",	.has_arg = required_argument },
	{ .val = 'p',	.name = "hsm_root",	.has_arg = required_argument },
	{ .val = 'q',	.name = "quiet",	.has_arg = no_argument },
	{ .val = 'r',	.name = "rebind",	.has_arg = no_argument },
	{ .val = 'u',	.name = "update-interval",
						.has_arg = required_argument },
	{ .val = 'u',	.name = "update_interval",
						.has_arg = required_argument },
	{ .val = 'v',	.name = "verbose",	.has_arg = no_argument },
	{ .name = NULL } };
	int			 c, rc;
	unsigned long long	 value;
	unsigned long long	 unit;

	optind = 0;
	while ((c = getopt_long(argc, argv, "A:b:c:f:hiMp:qru:v",
				long_opts, NULL)) != -1) {
		switch (c) {
		case 'A':
			if ((opt.o_archive_cnt >= LL_HSM_MAX_ARCHIVE) ||
			    (atoi(optarg) >= LL_HSM_MAX_ARCHIVE)) {
				rc = -E2BIG;
				CT_ERROR(rc, "archive number must be less"
					 "than %zu", LL_HSM_MAX_ARCHIVE);
				return rc;
			}
			opt.o_archive_id[opt.o_archive_cnt] = atoi(optarg);
			opt.o_archive_cnt++;
			break;
		case 'b': /* -b and -c have both a number with unit as arg */
		case 'c':
			unit = ONE_MB;
			if (llapi_parse_size(optarg, &value, &unit, 0) < 0) {
				rc = -EINVAL;
				CT_ERROR(rc, "bad value for -%c '%s'", c,
					 optarg);
				return rc;
			}
			if (c == 'c')
				opt.o_chunk_size = value;
			else
				opt.o_bandwidth = value;
			break;
		case 'f':
			opt.o_event_fifo = optarg;
			break;
		case 'h':
			usage(argv[0], 0);
		case 'i':
			opt.o_action = CA_IMPORT;
			break;
		case 'M':
			opt.o_action = CA_MAXSEQ;
			break;
		case 'p':
			opt.o_hsm_root = optarg;
			break;
		case 'q':
			opt.o_verbose--;
			break;
		case 'r':
			opt.o_action = CA_REBIND;
			break;
		case 'u':
			opt.o_report_int = atoi(optarg);
			if (opt.o_report_int < 0) {
				rc = -EINVAL;
				CT_ERROR(rc, "bad value for -%c '%s'", c,
					 optarg);
				return rc;
			}
			break;
		case 'v':
			opt.o_verbose++;
			break;
		case 0:
			break;
		default:
			return -EINVAL;
		}
	}

	switch (opt.o_action) {
	case CA_IMPORT:
		/* src dst mount_point */
		if (argc != optind + 3) {
			rc = -EINVAL;
			CT_ERROR(rc, "--import requires 2 arguments");
			return rc;
		}
		opt.o_src = argv[optind++];
		opt.o_dst = argv[optind++];
		break;
	case CA_REBIND:
		/* FID1 FID2 mount_point or FILE mount_point */
		if (argc == optind + 2) {
			opt.o_src = argv[optind++];
			opt.o_dst = NULL;
		} else if (argc == optind + 3) {
			opt.o_src = argv[optind++];
			opt.o_dst = argv[optind++];
		} else {
			rc = -EINVAL;
			CT_ERROR(rc, "--rebind requires 1 or 2 arguments");
			return rc;
		}
		break;
	case CA_MAXSEQ:
	default:
		/* just mount point */
		break;
	}

	if (argc != optind + 1) {
		rc = -EINVAL;
		CT_ERROR(rc, "no mount point specified");
		return rc;
	}

	opt.o_mnt = argv[optind];
	opt.o_mnt_fd = -1;

	CT_TRACE("action=%d src=%s dst=%s mount_point=%s",
		 opt.o_action, opt.o_src, opt.o_dst, opt.o_mnt);

	if (opt.o_hsm_root == NULL) {
		rc = -EINVAL;
		CT_ERROR(rc, "must specify a root directory for the backend");
		return rc;
	}

	if (opt.o_action == CA_IMPORT) {
		if (opt.o_src && opt.o_src[0] == '/') {
			rc = -EINVAL;
			CT_ERROR(rc,
				 "source path must be relative to HSM root");
			return rc;
		}

		if (opt.o_dst && opt.o_dst[0] != '/') {
			rc = -EINVAL;
			CT_ERROR(rc, "destination path must be absolute");
			return rc;
		}
	}

	return 0;
}

/* mkdir -p path */
static int ct_mkdir_p(const char *path)
{
	char	*saved, *ptr;
	int	 rc;

	ptr = strdup(path);
	if (ptr == NULL)
		return -errno;

	saved = ptr;
	while (*ptr == '/')
		ptr++;

	while ((ptr = strchr(ptr, '/')) != NULL) {
		*ptr = '\0';
		rc = mkdir(saved, DIR_PERM);
		*ptr = '/';
		if (rc < 0 && errno != EEXIST) {
			rc = -errno;
			CT_ERROR(rc, "cannot mkdir '%s'", path);
			free(saved);
			return rc;
		}
		ptr++;
	}

	free(saved);

	return 0;
}

static int ct_save_stripe(int src_fd, const char *src, const char *dst)
{
	char			 lov_file[PATH_MAX];
	char			 lov_buf[XATTR_SIZE_MAX];
	struct lov_user_md	*lum;
	int			 rc;
	int			 fd;
	ssize_t			 xattr_size;

	snprintf(lov_file, sizeof(lov_file), "%s.lov", dst);
	CT_TRACE("saving stripe info of '%s' in %s", src, lov_file);

	xattr_size = fgetxattr(src_fd, XATTR_LUSTRE_LOV, lov_buf,
			       sizeof(lov_buf));
	if (xattr_size < 0) {
		rc = -errno;
		CT_ERROR(rc, "cannot get stripe info on '%s'", src);
		return rc;
	}

	lum = (struct lov_user_md *)lov_buf;

	if (lum->lmm_magic == LOV_USER_MAGIC_V1 ||
	    lum->lmm_magic == LOV_USER_MAGIC_V3) {
		/* Set stripe_offset to -1 so that it is not interpreted as a
		 * hint on restore. */
		lum->lmm_stripe_offset = -1;
	}

	fd = open(lov_file, O_TRUNC | O_CREAT | O_WRONLY, FILE_PERM);
	if (fd < 0) {
		rc = -errno;
		CT_ERROR(rc, "cannot open '%s'", lov_file);
		goto err_cleanup;
	}

	rc = write(fd, lum, xattr_size);
	if (rc < 0) {
		rc = -errno;
		CT_ERROR(rc, "cannot write %zd bytes to '%s'",
			 xattr_size, lov_file);
		close(fd);
		goto err_cleanup;
	}

	rc = close(fd);
	if (rc < 0) {
		rc = -errno;
		CT_ERROR(rc, "cannot close '%s'", lov_file);
		goto err_cleanup;
	}

	return 0;

err_cleanup:
	unlink(lov_file);

	return rc;
}

static int ct_load_stripe(const char *src, void *lovea, size_t *lovea_size)
{
	char	 lov_file[PATH_MAX];
	int	 rc;
	int	 fd;

	snprintf(lov_file, sizeof(lov_file), "%s.lov", src);
	CT_TRACE("reading stripe rules from '%s' for '%s'", lov_file, src);

	fd = open(lov_file, O_RDONLY);
	if (fd < 0) {
		CT_ERROR(errno, "cannot open '%s'", lov_file);
		return -ENODATA;
	}

	rc = read(fd, lovea, *lovea_size);
	if (rc < 0) {
		CT_ERROR(errno, "cannot read %zu bytes from '%s'",
			 *lovea_size, lov_file);
		close(fd);
		return -ENODATA;
	}

	*lovea_size = rc;
	close(fd);

	return 0;
}

static int ct_restore_stripe(const char *src, const char *dst, int dst_fd,
			     const void *lovea, size_t lovea_size)
{
	int	rc;

	rc = fsetxattr(dst_fd, XATTR_LUSTRE_LOV, lovea, lovea_size,
		       XATTR_CREATE);
	if (rc < 0) {
		rc = -errno;
		CT_ERROR(rc, "cannot set lov EA on '%s'", dst);
	}

	return rc;
}

static int ct_copy_data(struct hsm_copyaction_private *hcp, const char *src,
			const char *dst, int src_fd, int dst_fd,
			const struct hsm_action_item *hai, long hal_flags)
{
	struct hsm_extent	 he;
	__u64			 offset = hai->hai_extent.offset;
	struct stat		 src_st;
	struct stat		 dst_st;
	char			*buf = NULL;
	__u64			 write_total = 0;
	__u64			 length = hai->hai_extent.length;
	time_t			 last_report_time;
	int			 rc = 0;
	double			 start_ct_now = ct_now();
	/* Bandwidth Control */
	time_t			start_time;
	time_t			now;
	time_t			last_bw_print;

	if (fstat(src_fd, &src_st) < 0) {
		rc = -errno;
		CT_ERROR(rc, "cannot stat '%s'", src);
		return rc;
	}

	if (!S_ISREG(src_st.st_mode)) {
		rc = -EINVAL;
		CT_ERROR(rc, "'%s' is not a regular file", src);
		return rc;
	}

	if (hai->hai_extent.offset > (__u64)src_st.st_size) {
		rc = -EINVAL;
		CT_ERROR(rc, "Trying to start reading past end (%ju > "
			 "%jd) of '%s' source file",
			 (uintmax_t)hai->hai_extent.offset,
			 (intmax_t)src_st.st_size, src);
		return rc;
	}

	if (fstat(dst_fd, &dst_st) < 0) {
		rc = -errno;
		CT_ERROR(rc, "cannot stat '%s'", dst);
		return rc;
	}

	if (!S_ISREG(dst_st.st_mode)) {
		rc = -EINVAL;
		CT_ERROR(rc, "'%s' is not a regular file", dst);
		return rc;
	}

	/* Don't read beyond a given extent */
	if (length > src_st.st_size - hai->hai_extent.offset)
		length = src_st.st_size - hai->hai_extent.offset;

	start_time = last_bw_print = last_report_time = time(NULL);

	he.offset = offset;
	he.length = 0;
	rc = llapi_hsm_action_progress(hcp, &he, length, 0);
	if (rc < 0) {
		/* Action has been canceled or something wrong
		 * is happening. Stop copying data. */
		CT_ERROR(rc, "progress ioctl for copy '%s'->'%s' failed",
			 src, dst);
		goto out;
	}

	errno = 0;

	buf = malloc(opt.o_chunk_size);
	if (buf == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	CT_TRACE("start copy of %ju bytes from '%s' to '%s'",
		 (uintmax_t)length, src, dst);

	while (write_total < length) {
		ssize_t	rsize;
		ssize_t	wsize;
		int	chunk = (length - write_total > opt.o_chunk_size) ?
				 opt.o_chunk_size : length - write_total;

		rsize = pread(src_fd, buf, chunk, offset);
		if (rsize == 0)
			/* EOF */
			break;

		if (rsize < 0) {
			rc = -errno;
			CT_ERROR(rc, "cannot read from '%s'", src);
			break;
		}

		wsize = pwrite(dst_fd, buf, rsize, offset);
		if (wsize < 0) {
			rc = -errno;
			CT_ERROR(rc, "cannot write to '%s'", dst);
			break;
		}

		write_total += wsize;
		offset += wsize;

		now = time(NULL);
		/* sleep if needed, to honor bandwidth limits */
		if (opt.o_bandwidth != 0) {
			unsigned long long write_theory;

			write_theory = (now - start_time) * opt.o_bandwidth;

			if (write_theory < write_total) {
				unsigned long long	excess;
				struct timespec		delay;

				excess = write_total - write_theory;

				delay.tv_sec = excess / opt.o_bandwidth;
				delay.tv_nsec = (excess % opt.o_bandwidth) *
					NSEC_PER_SEC / opt.o_bandwidth;

				if (now >= last_bw_print + opt.o_report_int) {
					CT_TRACE("bandwith control: %lluB/s "
						 "excess=%llu sleep for "
						 "%lld.%09lds",
						 opt.o_bandwidth, excess,
						 (long long)delay.tv_sec,
						 delay.tv_nsec);
					last_bw_print = now;
				}

				do {
					rc = nanosleep(&delay, &delay);
				} while (rc < 0 && errno == EINTR);
				if (rc < 0) {
					CT_ERROR(errno, "delay for bandwidth "
						 "control failed to sleep: "
						 "residual=%lld.%09lds",
						 (long long)delay.tv_sec,
						 delay.tv_nsec);
					rc = 0;
				}
			}
		}

		now = time(NULL);
		if (now >= last_report_time + opt.o_report_int) {
			last_report_time = now;
			CT_TRACE("%%%ju ", (uintmax_t)(100 * write_total / length));
			/* only give the length of the write since the last
			 * progress report */
			he.length = offset - he.offset;
			rc = llapi_hsm_action_progress(hcp, &he, length, 0);
			if (rc < 0) {
				/* Action has been canceled or something wrong
				 * is happening. Stop copying data. */
				CT_ERROR(rc, "progress ioctl for copy"
					 " '%s'->'%s' failed", src, dst);
				goto out;
			}
			he.offset = offset;
		}
		rc = 0;
	}

out:
	/*
	 * truncate restored file
	 * size is taken from the archive this is done to support
	 * restore after a force release which leaves the file with the
	 * wrong size (can big bigger than the new size)
	 */
	if ((hai->hai_action == HSMA_RESTORE) &&
	    (src_st.st_size < dst_st.st_size)) {
		/*
		 * make sure the file is on disk before reporting success.
		 */
		rc = ftruncate(dst_fd, src_st.st_size);
		if (rc < 0) {
			rc = -errno;
			CT_ERROR(rc, "cannot truncate '%s' to size %jd",
				 dst, (intmax_t)src_st.st_size);
			err_major++;
		}
	}

	if (buf != NULL)
		free(buf);

	CT_TRACE("copied %ju bytes in %f seconds",
		 (uintmax_t)length, ct_now() - start_ct_now);

	return rc;
}

/* Copy file attributes from file src to file dest */
static int ct_copy_attr(const char *src, const char *dst, int src_fd,
			int dst_fd)
{
	struct stat	st;
	struct timeval	times[2];
	int		rc;

	if (fstat(src_fd, &st) < 0) {
		rc = -errno;
		CT_ERROR(rc, "cannot stat '%s'", src);
		return rc;
	}

	times[0].tv_sec = st.st_atime;
	times[0].tv_usec = 0;
	times[1].tv_sec = st.st_mtime;
	times[1].tv_usec = 0;
	if (fchmod(dst_fd, st.st_mode) < 0 ||
	    fchown(dst_fd, st.st_uid, st.st_gid) < 0 ||
	    futimes(dst_fd, times) < 0) {
		rc = -errno;
		CT_ERROR(rc, "cannot set attributes of '%s'", src);
		return rc;
	}

	return 0;
}

static int ct_copy_xattr(const char *src, const char *dst, int src_fd,
			 int dst_fd, bool is_restore)
{
	char	 list[XATTR_LIST_MAX];
	char	 value[XATTR_SIZE_MAX];
	char	*name;
	ssize_t	 list_len;
	int	 rc;

	list_len = flistxattr(src_fd, list, sizeof(list));
	if (list_len < 0)
		return -errno;

	name = list;
	while (name < list + list_len) {
		rc = fgetxattr(src_fd, name, value, sizeof(value));
		if (rc < 0)
			return -errno;

		/* when we restore, we do not restore lustre xattr */
		if (!is_restore ||
		    (strncmp(XATTR_TRUSTED_PREFIX, name,
			     sizeof(XATTR_TRUSTED_PREFIX) - 1) != 0)) {
			rc = fsetxattr(dst_fd, name, value, rc, 0);
			CT_TRACE("fsetxattr of '%s' on '%s' rc=%d (%s)",
				 name, dst, rc, strerror(errno));
			/* lustre.* attrs aren't supported on other FS's */
			if (rc < 0 && errno != EOPNOTSUPP) {
				rc = -errno;
				CT_ERROR(rc, "cannot set extended attribute"
					 " '%s' of '%s'",
					 name, dst);
				return rc;
			}
		}
		name += strlen(name) + 1;
	}

	return 0;
}

static int ct_path_lustre(char *buf, int sz, const char *mnt,
			  const lustre_fid *fid)
{
	return snprintf(buf, sz, "%s/%s/fid/"DFID_NOBRACE, mnt,
			dot_lustre_name, PFID(fid));
}

static int ct_path_archive(char *buf, int sz, const char *archive_dir,
			   const lustre_fid *fid)
{
	return snprintf(buf, sz, "%s/%04x/%04x/%04x/%04x/%04x/%04x/"
			DFID_NOBRACE, archive_dir,
			(fid)->f_oid       & 0xFFFF,
			(fid)->f_oid >> 16 & 0xFFFF,
			(unsigned int)((fid)->f_seq       & 0xFFFF),
			(unsigned int)((fid)->f_seq >> 16 & 0xFFFF),
			(unsigned int)((fid)->f_seq >> 32 & 0xFFFF),
			(unsigned int)((fid)->f_seq >> 48 & 0xFFFF),
			PFID(fid));
}

static bool ct_is_retryable(int err)
{
	return err == -ETIMEDOUT;
}

static int ct_begin_restore(struct hsm_copyaction_private **phcp,
			    const struct hsm_action_item *hai,
			    int mdt_index, int open_flags)
{
	char	 src[PATH_MAX];
	int	 rc;

	rc = llapi_hsm_action_begin(phcp, ctdata, hai, mdt_index, open_flags,
				    false);
	if (rc < 0) {
		ct_path_lustre(src, sizeof(src), opt.o_mnt, &hai->hai_fid);
		CT_ERROR(rc, "llapi_hsm_action_begin() on '%s' failed", src);
	}

	return rc;
}

static int ct_begin(struct hsm_copyaction_private **phcp,
		    const struct hsm_action_item *hai)
{
	/* Restore takes specific parameters. Call the same function w/ default
	 * values for all other operations. */
	return ct_begin_restore(phcp, hai, -1, 0);
}

static int ct_fini(struct hsm_copyaction_private **phcp,
		   const struct hsm_action_item *hai, int hp_flags, int ct_rc)
{
	struct hsm_copyaction_private	*hcp;
	char				 lstr[PATH_MAX];
	int				 rc;

	CT_TRACE("Action completed, notifying coordinator "
		 "cookie=%#jx, FID="DFID", hp_flags=%d err=%d",
		 (uintmax_t)hai->hai_cookie, PFID(&hai->hai_fid),
		 hp_flags, -ct_rc);

	ct_path_lustre(lstr, sizeof(lstr), opt.o_mnt, &hai->hai_fid);

	if (phcp == NULL || *phcp == NULL) {
		rc = llapi_hsm_action_begin(&hcp, ctdata, hai, -1, 0, true);
		if (rc < 0) {
			CT_ERROR(rc, "llapi_hsm_action_begin() on '%s' failed",
				 lstr);
			return rc;
		}
		phcp = &hcp;
	}

	rc = llapi_hsm_action_end(phcp, &hai->hai_extent, hp_flags, abs(ct_rc));
	if (rc == -ECANCELED)
		CT_ERROR(rc, "completed action on '%s' has been canceled: "
			 "cookie=%#jx, FID="DFID, lstr,
			 (uintmax_t)hai->hai_cookie, PFID(&hai->hai_fid));
	else if (rc < 0)
		CT_ERROR(rc, "llapi_hsm_action_end() on '%s' failed", lstr);
	else
		CT_TRACE("llapi_hsm_action_end() on '%s' ok (rc=%d)",
			 lstr, rc);

	return rc;
}

static int ct_archive(const struct hsm_action_item *hai, const long hal_flags)
{
	struct hsm_copyaction_private	*hcp = NULL;
	char				 src[PATH_MAX];
	char				 dst[PATH_MAX] = "";
	int				 rc;
	int				 rcf = 0;
	bool				 rename_needed = false;
	int				 hp_flags = 0;
	int				 open_flags;
	int				 src_fd = -1;
	int				 dst_fd = -1;

	rc = ct_begin(&hcp, hai);
	if (rc < 0)
		goto fini_major;

	/* we fill archive so:
	 * source = data FID
	 * destination = lustre FID
	 */
	ct_path_lustre(src, sizeof(src), opt.o_mnt, &hai->hai_dfid);
	ct_path_archive(dst, sizeof(dst), opt.o_hsm_root, &hai->hai_fid);
	if (hai->hai_extent.length == -1) {
		/* whole file, write it to tmp location and atomically
		 * replace old archived file */
		strlcat(dst, "_tmp", sizeof(dst));
		/* we cannot rely on the same test because ct_copy_data()
		 * updates hai_extent.length */
		rename_needed = true;
	}

	CT_TRACE("archiving '%s' to '%s'", src, dst);

	if (opt.o_dry_run) {
		rc = 0;
		goto fini_major;
	}

	rc = ct_mkdir_p(dst);
	if (rc < 0) {
		CT_ERROR(rc, "mkdir_p '%s' failed", dst);
		goto fini_major;
	}

	src_fd = llapi_hsm_action_get_fd(hcp);
	if (src_fd < 0) {
		rc = src_fd;
		CT_ERROR(rc, "cannot open '%s' for read", src);
		goto fini_major;
	}

	open_flags = O_WRONLY | O_NOFOLLOW;
	/* If extent is specified, don't truncate an old archived copy */
	open_flags |= ((hai->hai_extent.length == -1) ? O_TRUNC : 0) | O_CREAT;

	dst_fd = open(dst, open_flags, FILE_PERM);
	if (dst_fd == -1) {
		rc = -errno;
		CT_ERROR(rc, "cannot open '%s' for write", dst);
		goto fini_major;
	}

	/* saving stripe is not critical */
	rc = ct_save_stripe(src_fd, src, dst);
	if (rc < 0)
		CT_ERROR(rc, "cannot save file striping info of '%s' in '%s'",
			 src, dst);

	rc = ct_copy_data(hcp, src, dst, src_fd, dst_fd, hai, hal_flags);
	if (rc < 0) {
		CT_ERROR(rc, "data copy failed from '%s' to '%s'", src, dst);
		goto fini_major;
	}

	rc = fsync(dst_fd);
	if (rc < 0) {
		rc = -errno;
		CT_ERROR(rc, "cannot flush '%s' archive file '%s'", src, dst);
		goto fini_major;
	}

	CT_TRACE("data archiving for '%s' to '%s' done", src, dst);

	/* attrs will remain on the MDS; no need to copy them, except possibly
	  for disaster recovery */
	if (opt.o_copy_attrs) {
		rc = ct_copy_attr(src, dst, src_fd, dst_fd);
		if (rc < 0) {
			CT_ERROR(rc, "cannot copy attr of '%s' to '%s'",
				 src, dst);
			rcf = rc;
		}
		CT_TRACE("attr file for '%s' saved to archive '%s'",
			 src, dst);
	}

	/* xattrs will remain on the MDS; no need to copy them, except possibly
	 for disaster recovery */
	if (opt.o_copy_xattrs) {
		rc = ct_copy_xattr(src, dst, src_fd, dst_fd, false);
		if (rc < 0) {
			CT_ERROR(rc, "cannot copy xattr of '%s' to '%s'",
				 src, dst);
			rcf = rcf ? rcf : rc;
		}
		CT_TRACE("xattr file for '%s' saved to archive '%s'",
			 src, dst);
	}

	if (rename_needed == true) {
		char	 tmp_src[PATH_MAX];
		char	 tmp_dst[PATH_MAX];

		/* atomically replace old archived file */
		ct_path_archive(src, sizeof(src), opt.o_hsm_root,
				&hai->hai_fid);
		rc = rename(dst, src);
		if (rc < 0) {
			rc = -errno;
			CT_ERROR(rc, "cannot rename '%s' to '%s'", dst, src);
			goto fini_major;
		}
		/* rename lov file */
		snprintf(tmp_src, sizeof(tmp_src), "%s.lov", src);
		snprintf(tmp_dst, sizeof(tmp_dst), "%s.lov", dst);
		rc = rename(tmp_dst, tmp_src);
		if (rc < 0)
			CT_ERROR(errno, "cannot rename '%s' to '%s'",
				 tmp_dst, tmp_src);
	}

	if (opt.o_shadow_tree) {
		/* Create a namespace of softlinks that shadows the original
		 * Lustre namespace.  This will only be current at
		 * time-of-archive (won't follow renames).
		 * WARNING: release won't kill these links; a manual
		 * cleanup of dead links would be required.
		 */
		char		 buf[PATH_MAX];
		long long	 recno = -1;
		int		 linkno = 0;
		char		*ptr;
		int		 depth = 0;
		ssize_t		 sz;

		sprintf(buf, DFID, PFID(&hai->hai_fid));
		sprintf(src, "%s/shadow/", opt.o_hsm_root);

		ptr = opt.o_hsm_root;
		while (*ptr)
			(*ptr++ == '/') ? depth-- : 0;

		rc = llapi_fid2path(opt.o_mnt, buf, src + strlen(src),
				    sizeof(src) - strlen(src), &recno, &linkno);
		if (rc < 0) {
			CT_ERROR(rc, "cannot get FID of '%s'", buf);
			rcf = rcf ? rcf : rc;
			goto fini_minor;
		}

		/* Figure out how many parent dirs to symlink back */
		ptr = src;
		while (*ptr)
			(*ptr++ == '/') ? depth++ : 0;
		sprintf(buf, "..");
		while (--depth > 1)
			strcat(buf, "/..");

		ct_path_archive(dst, sizeof(dst), buf, &hai->hai_fid);

		if (ct_mkdir_p(src)) {
			CT_ERROR(errno, "mkdir_p '%s' failed", src);
			rcf = rcf ? rcf : -errno;
			goto fini_minor;
		}
		/* symlink already exists ? */
		sz = readlink(src, buf, sizeof(buf));
		/* detect truncation */
		if (sz == sizeof(buf)) {
			rcf = rcf ? rcf : -E2BIG;
			CT_ERROR(rcf, "readlink '%s' truncated", src);
			goto fini_minor;
		}
		if (sz >= 0) {
			buf[sz] = '\0';
			if (sz == 0 || strncmp(buf, dst, sz) != 0) {
				if (unlink(src) && errno != ENOENT) {
					CT_ERROR(errno,
						 "cannot unlink symlink '%s'",
						 src);
					rcf = rcf ? rcf : -errno;
					goto fini_minor;
				/* unlink old symlink done */
				CT_TRACE("remove old symlink '%s' pointing"
					 " to '%s'", src, buf);
				}
			} else {
				/* symlink already ok */
				CT_TRACE("symlink '%s' already pointing"
					 " to '%s'", src, dst);
				rcf = 0;
				goto fini_minor;
			}
		}
		if (symlink(dst, src)) {
			CT_ERROR(errno, "cannot symlink '%s' to '%s'",
				 src, dst);
			rcf = rcf ? rcf : -errno;
			goto fini_minor;
		}
		CT_TRACE("symlink '%s' to '%s' done", src, dst);
	}
fini_minor:
	if (rcf)
		err_minor++;
	goto out;


fini_major:
	err_major++;

	unlink(dst);
	if (ct_is_retryable(rc))
		hp_flags |= HP_FLAG_RETRY;

	rcf = rc;

out:
	if (!(src_fd < 0))
		close(src_fd);

	if (!(dst_fd < 0))
		close(dst_fd);

	rc = ct_fini(&hcp, hai, hp_flags, rcf);

	return rc;
}

static int ct_restore(const struct hsm_action_item *hai, const long hal_flags)
{
	struct hsm_copyaction_private	*hcp = NULL;
	char				 src[PATH_MAX];
	char				 dst[PATH_MAX];
	char				 lov_buf[XATTR_SIZE_MAX];
	size_t				 lov_size = sizeof(lov_buf);
	int				 rc;
	int				 hp_flags = 0;
	int				 src_fd = -1;
	int				 dst_fd = -1;
	int				 mdt_index = -1;
	int				 open_flags = 0;
	bool				 set_lovea;
	struct lu_fid			 dfid;
	/* we fill lustre so:
	 * source = lustre FID in the backend
	 * destination = data FID = volatile file
	 */

	/* build backend file name from released file FID */
	ct_path_archive(src, sizeof(src), opt.o_hsm_root, &hai->hai_fid);

	rc = llapi_get_mdt_index_by_fid(opt.o_mnt_fd, &hai->hai_fid,
					&mdt_index);
	if (rc < 0) {
		CT_ERROR(rc, "cannot get mdt index "DFID"",
			 PFID(&hai->hai_fid));
		return rc;
	}
	/* restore loads and sets the LOVEA w/o interpreting it to avoid
	 * dependency on the structure format. */
	rc = ct_load_stripe(src, lov_buf, &lov_size);
	if (rc < 0) {
		CT_WARN("cannot get stripe rules for '%s' (%s), use default",
			src, strerror(-rc));
		set_lovea = false;
	} else {
		open_flags |= O_LOV_DELAY_CREATE;
		set_lovea = true;
	}

	rc = ct_begin_restore(&hcp, hai, mdt_index, open_flags);
	if (rc < 0)
		goto fini;

	/* get the FID of the volatile file */
	rc = llapi_hsm_action_get_dfid(hcp, &dfid);
	if (rc < 0) {
		CT_ERROR(rc, "restoring "DFID
			 ", cannot get FID of created volatile file",
			 PFID(&hai->hai_fid));
		goto fini;
	}

	/* build volatile "file name", for messages */
	snprintf(dst, sizeof(dst), "{VOLATILE}="DFID, PFID(&dfid));

	CT_TRACE("restoring data from '%s' to '%s'", src, dst);

	if (opt.o_dry_run) {
		rc = 0;
		goto fini;
	}

	src_fd = open(src, O_RDONLY | O_NOATIME | O_NOFOLLOW);
	if (src_fd < 0) {
		rc = -errno;
		CT_ERROR(rc, "cannot open '%s' for read", src);
		goto fini;
	}

	dst_fd = llapi_hsm_action_get_fd(hcp);
	if (dst_fd < 0) {
		rc = dst_fd;
		CT_ERROR(rc, "cannot open '%s' for write", dst);
		goto fini;
	}

	if (set_lovea) {
		/* the layout cannot be allocated through .fid so we have to
		 * restore a layout */
		rc = ct_restore_stripe(src, dst, dst_fd, lov_buf, lov_size);
		if (rc < 0) {
			CT_ERROR(rc, "cannot restore file striping info"
				 " for '%s' from '%s'", dst, src);
			err_major++;
			goto fini;
		}
	}

	rc = ct_copy_data(hcp, src, dst, src_fd, dst_fd, hai, hal_flags);
	if (rc < 0) {
		CT_ERROR(rc, "cannot copy data from '%s' to '%s'",
			 src, dst);
		err_major++;
		if (ct_is_retryable(rc))
			hp_flags |= HP_FLAG_RETRY;
		goto fini;
	}

	CT_TRACE("data restore from '%s' to '%s' done", src, dst);

fini:
	rc = ct_fini(&hcp, hai, hp_flags, rc);

	/* object swaping is done by cdt at copy end, so close of volatile file
	 * cannot be done before */
	if (!(src_fd < 0))
		close(src_fd);

	if (!(dst_fd < 0))
		close(dst_fd);

	return rc;
}

static int ct_remove(const struct hsm_action_item *hai, const long hal_flags)
{
	struct hsm_copyaction_private	*hcp = NULL;
	char				 dst[PATH_MAX];
	int				 rc;

	rc = ct_begin(&hcp, hai);
	if (rc < 0)
		goto fini;

	ct_path_archive(dst, sizeof(dst), opt.o_hsm_root, &hai->hai_fid);

	CT_TRACE("removing file '%s'", dst);

	if (opt.o_dry_run) {
		rc = 0;
		goto fini;
	}

	rc = unlink(dst);
	if (rc < 0) {
		rc = -errno;
		CT_ERROR(rc, "cannot unlink '%s'", dst);
		err_minor++;
		goto fini;
	}

	strlcat(dst, ".lov", sizeof(dst));
	rc = unlink(dst);
	if (rc < 0) {
		rc = -errno;
		CT_ERROR(rc, "cannot unlink '%s'", dst);
		err_minor++;
		goto fini;
	}

fini:
	rc = ct_fini(&hcp, hai, 0, rc);

	return rc;
}

static int ct_process_item(struct hsm_action_item *hai, const long hal_flags)
{
	int	rc = 0;

	if (opt.o_verbose >= LLAPI_MSG_INFO || opt.o_dry_run) {
		/* Print the original path */
		char		fid[128];
		char		path[PATH_MAX];
		long long	recno = -1;
		int		linkno = 0;

		sprintf(fid, DFID, PFID(&hai->hai_fid));
		CT_TRACE("'%s' action %s reclen %d, cookie=%#jx",
			 fid, hsm_copytool_action2name(hai->hai_action),
			 hai->hai_len, (uintmax_t)hai->hai_cookie);
		rc = llapi_fid2path(opt.o_mnt, fid, path,
				    sizeof(path), &recno, &linkno);
		if (rc < 0)
			CT_ERROR(rc, "cannot get path of FID %s", fid);
		else
			CT_TRACE("processing file '%s'", path);
	}

	switch (hai->hai_action) {
	/* set err_major, minor inside these functions */
	case HSMA_ARCHIVE:
		rc = ct_archive(hai, hal_flags);
		break;
	case HSMA_RESTORE:
		rc = ct_restore(hai, hal_flags);
		break;
	case HSMA_REMOVE:
		rc = ct_remove(hai, hal_flags);
		break;
	case HSMA_CANCEL:
		CT_TRACE("cancel not implemented for file system '%s'",
			 opt.o_mnt);
		/* Don't report progress to coordinator for this cookie:
		 * the copy function will get ECANCELED when reporting
		 * progress. */
		err_minor++;
		return 0;
		break;
	default:
		rc = -EINVAL;
		CT_ERROR(rc, "unknown action %d, on '%s'", hai->hai_action,
			 opt.o_mnt);
		err_minor++;
		ct_fini(NULL, hai, 0, rc);
	}

	return 0;
}

struct ct_th_data {
	long			 hal_flags;
	struct hsm_action_item	*hai;
};

static void *ct_thread(void *data)
{
	struct ct_th_data *cttd = data;
	int rc;

	rc = ct_process_item(cttd->hai, cttd->hal_flags);

	free(cttd->hai);
	free(cttd);
	pthread_exit((void *)(intptr_t)rc);
}

static int ct_process_item_async(const struct hsm_action_item *hai,
				 long hal_flags)
{
	pthread_attr_t		 attr;
	pthread_t		 thread;
	struct ct_th_data	*data;
	int			 rc;

	data = malloc(sizeof(*data));
	if (data == NULL)
		return -ENOMEM;

	data->hai = malloc(hai->hai_len);
	if (data->hai == NULL) {
		free(data);
		return -ENOMEM;
	}

	memcpy(data->hai, hai, hai->hai_len);
	data->hal_flags = hal_flags;

	rc = pthread_attr_init(&attr);
	if (rc != 0) {
		CT_ERROR(rc, "pthread_attr_init failed for '%s' service",
			 opt.o_mnt);
		free(data->hai);
		free(data);
		return -rc;
	}

	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	rc = pthread_create(&thread, &attr, ct_thread, data);
	if (rc != 0)
		CT_ERROR(rc, "cannot create thread for '%s' service",
			 opt.o_mnt);

	pthread_attr_destroy(&attr);
	return 0;
}

static int ct_import_one(const char *src, const char *dst)
{
	char		newarc[PATH_MAX];
	lustre_fid	fid;
	struct stat	st;
	int		rc;

	CT_TRACE("importing '%s' from '%s'", dst, src);

	if (stat(src, &st) < 0) {
		rc = -errno;
		CT_ERROR(rc, "cannot stat '%s'", src);
		return rc;
	}

	if (opt.o_dry_run)
		return 0;

	rc = llapi_hsm_import(dst,
			      opt.o_archive_cnt ? opt.o_archive_id[0] : 0,
			      &st, 0, 0, 0, 0, NULL, &fid);
	if (rc < 0) {
		CT_ERROR(rc, "cannot import '%s' from '%s'", dst, src);
		return rc;
	}

	ct_path_archive(newarc, sizeof(newarc), opt.o_hsm_root, &fid);

	rc = ct_mkdir_p(newarc);
	if (rc < 0) {
		CT_ERROR(rc, "mkdir_p '%s' failed", newarc);
		err_major++;
		return rc;

	}

	/* Lots of choices now: mv, ln, ln -s ? */
	rc = link(src, newarc); /* hardlink */
	if (rc < 0) {
		rc = -errno;
		CT_ERROR(rc, "cannot link '%s' to '%s'", newarc, src);
		err_major++;
		return rc;
	}
	CT_TRACE("imported '%s' from '%s'=='%s'", dst, newarc, src);

	return 0;
}

static char *path_concat(const char *dirname, const char *basename)
{
	char	*result;
	int	 rc;

	rc = asprintf(&result, "%s/%s", dirname, basename);
	if (rc < 0)
		return NULL;

	return result;
}

static int ct_import_fid(const lustre_fid *import_fid)
{
	char	fid_path[PATH_MAX];
	int	rc;

	ct_path_lustre(fid_path, sizeof(fid_path), opt.o_mnt, import_fid);
	rc = access(fid_path, F_OK);
	if (rc == 0 || errno != ENOENT) {
		rc = (errno == 0) ? -EEXIST : -errno;
		CT_ERROR(rc, "cannot import '"DFID"'", PFID(import_fid));
		return rc;
	}

	ct_path_archive(fid_path, sizeof(fid_path), opt.o_hsm_root,
			import_fid);

	CT_TRACE("Resolving "DFID" to %s", PFID(import_fid), fid_path);

	return ct_import_one(fid_path, opt.o_dst);
}

static int ct_import_recurse(const char *relpath)
{
	DIR		*dir;
	struct dirent	*ent;
	char		*srcpath, *newpath;
	lustre_fid	 import_fid;
	int		 rc;

	if (relpath == NULL)
		return -EINVAL;

	/* Is relpath a FID? In which case SFID should expand to three
	 * elements. */
	rc = sscanf(relpath, SFID, RFID(&import_fid));
	if (rc == 3)
		return ct_import_fid(&import_fid);

	srcpath = path_concat(opt.o_hsm_root, relpath);
	if (srcpath == NULL) {
		err_major++;
		return -ENOMEM;
	}

	dir = opendir(srcpath);
	if (dir == NULL) {
		/* Not a dir, or error */
		if (errno == ENOTDIR) {
			/* Single regular file case, treat o_dst as absolute
			   final location. */
			rc = ct_import_one(srcpath, opt.o_dst);
		} else {
			rc = -errno;
			CT_ERROR(rc, "cannot opendir '%s'", srcpath);
			err_major++;
		}
		free(srcpath);
		return rc;
	}
	free(srcpath);

	while ((ent = readdir(dir)) != NULL) {
		if (!strcmp(ent->d_name, ".") ||
		    !strcmp(ent->d_name, ".."))
			continue;

		/* New relative path */
		newpath = path_concat(relpath, ent->d_name);
		if (newpath == NULL) {
			err_major++;
			rc = -ENOMEM;
			goto out;
		}

		if (ent->d_type == DT_DIR) {
			rc = ct_import_recurse(newpath);
		} else {
			char src[PATH_MAX];
			char dst[PATH_MAX];

			sprintf(src, "%s/%s", opt.o_hsm_root, newpath);
			sprintf(dst, "%s/%s", opt.o_dst, newpath);
			/* Make the target dir in the Lustre fs */
			rc = ct_mkdir_p(dst);
			if (rc == 0) {
				/* Import the file */
				rc = ct_import_one(src, dst);
			} else {
				CT_ERROR(rc, "ct_mkdir_p '%s' failed", dst);
				err_major++;
			}
		}

		if (rc != 0) {
			CT_ERROR(rc, "cannot import '%s'", newpath);
			if (err_major && opt.o_abort_on_error) {
				free(newpath);
				goto out;
			}
		}
		free(newpath);
	}

	rc = 0;
out:
	closedir(dir);
	return rc;
}

static int ct_rebind_one(const lustre_fid *old_fid, const lustre_fid *new_fid)
{
	char	src[PATH_MAX];
	char	dst[PATH_MAX];
	int	rc;

	CT_TRACE("rebind "DFID" to "DFID, PFID(old_fid), PFID(new_fid));

	ct_path_archive(src, sizeof(src), opt.o_hsm_root, old_fid);
	ct_path_archive(dst, sizeof(dst), opt.o_hsm_root, new_fid);

	if (!opt.o_dry_run) {
		ct_mkdir_p(dst);
		if (rename(src, dst)) {
			rc = -errno;
			CT_ERROR(rc, "cannot rename '%s' to '%s'", src, dst);
			return -errno;
		}
		/* rename lov file */
		strlcat(src, ".lov", sizeof(src));
		strlcat(dst, ".lov", sizeof(dst));
		if (rename(src, dst))
			CT_ERROR(errno, "cannot rename '%s' to '%s'", src, dst);

	}
	return 0;
}

static bool fid_is_file(lustre_fid *fid)
{
	return fid_is_norm(fid) || fid_is_igif(fid);
}

static bool should_ignore_line(const char *line)
{
	int	i;

	for (i = 0; line[i] != '\0'; i++) {
		if (isspace(line[i]))
			continue;
		else if (line[i] == '#')
			return true;
		else
			return false;
	}

	return true;
}

static int ct_rebind_list(const char *list)
{
	int		 rc;
	FILE		*filp;
	ssize_t		 r;
	char		*line = NULL;
	size_t		 line_size = 0;
	unsigned int	 nl = 0;
	unsigned int	 ok = 0;

	filp = fopen(list, "r");
	if (filp == NULL) {
		rc = -errno;
		CT_ERROR(rc, "cannot open '%s'", list);
		return rc;
	}

	/* each line consists of 2 FID */
	while ((r = getline(&line, &line_size, filp)) != -1) {
		lustre_fid	old_fid;
		lustre_fid	new_fid;

		/* Ignore empty and commented out ('#...') lines. */
		if (should_ignore_line(line))
			continue;

		nl++;

		rc = sscanf(line, SFID" "SFID, RFID(&old_fid), RFID(&new_fid));
		if (rc != 6 || !fid_is_file(&old_fid) ||
		    !fid_is_file(&new_fid)) {
			CT_ERROR(EINVAL,
				 "'%s' FID expected near '%s', line %u",
				 list, line, nl);
			err_major++;
			continue;
		}

		if (ct_rebind_one(&old_fid, &new_fid))
			err_major++;
		else
			ok++;
	}

	fclose(filp);

	if (line)
		free(line);

	/* return 0 if all rebinds were successful */
	CT_TRACE("%u lines read from '%s', %u rebind successful", nl, list, ok);

	return ok == nl ? 0 : -1;
}

static int ct_rebind(void)
{
	int	rc;

	if (opt.o_dst) {
		lustre_fid	old_fid;
		lustre_fid	new_fid;

		if (sscanf(opt.o_src, SFID, RFID(&old_fid)) != 3 ||
		    !fid_is_file(&old_fid)) {
			rc = -EINVAL;
			CT_ERROR(rc, "'%s' invalid FID format", opt.o_src);
			return rc;
		}

		if (sscanf(opt.o_dst, SFID, RFID(&new_fid)) != 3 ||
		    !fid_is_file(&new_fid)) {
			rc = -EINVAL;
			CT_ERROR(rc, "'%s' invalid FID format", opt.o_dst);
			return rc;
		}

		rc = ct_rebind_one(&old_fid, &new_fid);

		return rc;
	}

	/* o_src is a list file */
	rc = ct_rebind_list(opt.o_src);

	return rc;
}

static int ct_dir_level_max(const char *dirpath, __u16 *sub_seqmax)
{
	DIR		*dir;
	int		 rc;
	__u16		 sub_seq;
	struct dirent *ent;

	*sub_seqmax = 0;

	dir = opendir(dirpath);
	if (dir == NULL) {
		rc = -errno;
		CT_ERROR(rc, "cannot open directory '%s'", opt.o_hsm_root);
		return rc;
	}

	do {
		errno = 0;
		ent = readdir(dir);
		if (ent == NULL) {
			/* end of directory.
			 * rc is 0 and seqmax contains the max value. */
			rc = -errno;
			if (rc)
				CT_ERROR(rc, "cannot readdir '%s'", dirpath);
			goto out;
		}

		if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
			continue;

		if (sscanf(ent->d_name, "%hx", &sub_seq) != 1) {
			CT_TRACE("'%s' has an unexpected dirname format, "
				 "skip entry", ent->d_name);
			continue;
		}
		if (sub_seq > *sub_seqmax)
			*sub_seqmax = sub_seq;
	} while (1);
out:
	closedir(dir);
	return rc;
}

static int ct_max_sequence(void)
{
	int	rc, i;
	char	path[PATH_MAX];
	__u64	seq = 0;
	__u16	subseq;

	strlcpy(path, opt.o_hsm_root, sizeof(path));
	/* FID sequence is stored in top-level directory names:
	 * hsm_root/16bits (high weight)/16 bits/16 bits/16 bits (low weight).
	 */
	for (i = 0; i < 4; i++) {
		size_t path_len;

		rc = ct_dir_level_max(path, &subseq);
		if (rc != 0)
			return rc;
		seq |= ((__u64)subseq << ((3 - i) * 16));
		path_len = strlen(path);
		rc = snprintf(path + path_len, sizeof(path) - path_len,
			      "/%04x", subseq);
		if (rc >= (sizeof(path) - path_len))
			return -E2BIG;
		path[sizeof(path) - 1] = '\0';
	}

	printf("max_sequence: %#jx\n", (uintmax_t)seq);

	return 0;
}

static void handler(int signal)
{
	psignal(signal, "exiting");
	/* If we don't clean up upon interrupt, umount thinks there's a ref
	 * and doesn't remove us from mtab (EINPROGRESS). The lustre client
	 * does successfully unmount and the mount is actually gone, but the
	 * mtab entry remains. So this just makes mtab happier. */
	llapi_hsm_copytool_unregister(&ctdata);

	/* Also remove fifo upon signal as during normal/error exit */
	if (opt.o_event_fifo != NULL)
		llapi_hsm_unregister_event_fifo(opt.o_event_fifo);
	_exit(1);
}

/* Daemon waits for messages from the kernel; run it in the background. */
static int ct_run(void)
{
	struct sigaction cleanup_sigaction;
	int rc;

	if (opt.o_daemonize) {
		rc = daemon(1, 1);
		if (rc < 0) {
			rc = -errno;
			CT_ERROR(rc, "cannot daemonize");
			return rc;
		}
	}

	setbuf(stdout, NULL);

	if (opt.o_event_fifo != NULL) {
		rc = llapi_hsm_register_event_fifo(opt.o_event_fifo);
		if (rc < 0) {
			CT_ERROR(rc, "failed to register event fifo");
			return rc;
		}
		llapi_error_callback_set(llapi_hsm_log_error);
	}

	rc = llapi_hsm_copytool_register(&ctdata, opt.o_mnt,
					 opt.o_archive_cnt,
					 opt.o_archive_id, 0);
	if (rc < 0) {
		CT_ERROR(rc, "cannot start copytool interface");
		return rc;
	}

	memset(&cleanup_sigaction, 0, sizeof(cleanup_sigaction));
	cleanup_sigaction.sa_handler = handler;
	sigemptyset(&cleanup_sigaction.sa_mask);
	sigaction(SIGINT, &cleanup_sigaction, NULL);
	sigaction(SIGTERM, &cleanup_sigaction, NULL);

	while (1) {
		struct hsm_action_list *hal;
		struct hsm_action_item *hai;
		int msgsize;
		int i = 0;

		CT_TRACE("waiting for message from kernel");

		rc = llapi_hsm_copytool_recv(ctdata, &hal, &msgsize);
		if (rc == -ESHUTDOWN) {
			CT_TRACE("shutting down");
			break;
		} else if (rc < 0) {
			CT_WARN("cannot receive action list: %s",
				strerror(-rc));
			err_major++;
			if (opt.o_abort_on_error)
				break;
			else
				continue;
		}

		CT_TRACE("copytool fs=%s archive#=%d item_count=%d",
			 hal->hal_fsname, hal->hal_archive_id, hal->hal_count);

		if (strcmp(hal->hal_fsname, fs_name) != 0) {
			rc = -EINVAL;
			CT_ERROR(rc, "'%s' invalid fs name, expecting: %s",
				 hal->hal_fsname, fs_name);
			err_major++;
			if (opt.o_abort_on_error)
				break;
			else
				continue;
		}

		hai = hai_first(hal);
		while (++i <= hal->hal_count) {
			if ((char *)hai - (char *)hal > msgsize) {
				rc = -EPROTO;
				CT_ERROR(rc,
					 "'%s' item %d past end of message!",
					 opt.o_mnt, i);
				err_major++;
				break;
			}
			rc = ct_process_item_async(hai, hal->hal_flags);
			if (rc < 0)
				CT_ERROR(rc, "'%s' item %d process",
					 opt.o_mnt, i);
			if (opt.o_abort_on_error && err_major)
				break;
			hai = hai_next(hai);
		}

		if (opt.o_abort_on_error && err_major)
			break;
	}

	llapi_hsm_copytool_unregister(&ctdata);
	if (opt.o_event_fifo != NULL)
		llapi_hsm_unregister_event_fifo(opt.o_event_fifo);

	return rc;
}

static int ct_setup(void)
{
	int	rc;

	/* set llapi message level */
	llapi_msg_set_level(opt.o_verbose);

	arc_fd = open(opt.o_hsm_root, O_RDONLY);
	if (arc_fd < 0) {
		rc = -errno;
		CT_ERROR(rc, "cannot open archive at '%s'", opt.o_hsm_root);
		return rc;
	}

	rc = llapi_search_fsname(opt.o_mnt, fs_name);
	if (rc < 0) {
		CT_ERROR(rc, "cannot find a Lustre filesystem mounted at '%s'",
			 opt.o_mnt);
		return rc;
	}

	opt.o_mnt_fd = open(opt.o_mnt, O_RDONLY);
	if (opt.o_mnt_fd < 0) {
		rc = -errno;
		CT_ERROR(rc, "cannot open mount point at '%s'",
			 opt.o_mnt);
		return rc;
	}

	return rc;
}

static int ct_cleanup(void)
{
	int	rc;

	if (opt.o_mnt_fd >= 0) {
		rc = close(opt.o_mnt_fd);
		if (rc < 0) {
			rc = -errno;
			CT_ERROR(rc, "cannot close mount point");
			return rc;
		}
	}

	if (arc_fd >= 0) {
		rc = close(arc_fd);
		if (rc < 0) {
			rc = -errno;
			CT_ERROR(rc, "cannot close archive root directory");
			return rc;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	int	rc;

	strlcpy(cmd_name, basename(argv[0]), sizeof(cmd_name));
	rc = ct_parseopts(argc, argv);
	if (rc < 0) {
		CT_WARN("try '%s --help' for more information", cmd_name);
		return -rc;
	}

	rc = ct_setup();
	if (rc < 0)
		goto error_cleanup;

	switch (opt.o_action) {
	case CA_IMPORT:
		rc = ct_import_recurse(opt.o_src);
		break;
	case CA_REBIND:
		rc = ct_rebind();
		break;
	case CA_MAXSEQ:
		rc = ct_max_sequence();
		break;
	default:
		rc = ct_run();
		break;
	}

	if (opt.o_action != CA_MAXSEQ)
		CT_TRACE("process finished, errs: %d major, %d minor,"
			 " rc=%d (%s)", err_major, err_minor, rc,
			 strerror(-rc));

error_cleanup:
	ct_cleanup();

	return -rc;
}

