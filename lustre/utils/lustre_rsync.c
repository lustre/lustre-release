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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/utils/lustre_rsync.c
 *
 * Author: Kalpak Shah <Kalpak.Shah@Sun.COM>
 * Author: Manoj Joseph <Manoj.Joseph@Sun.COM>
 */

/*
 * - lustre_rsync is a tool for replicating a lustre filesystem.
 *
 * - The source-fs is a live lustre filesystem. It is not a
 * snapshot. It is mounted and undergoing changes
 *
 * - The target-fs is a copy of the source-fs from the past. Let's
 * call this point, the 'sync point'.
 *
 * - There is a changelog of all metadata operations that happened on
 * the filesystem since the 'sync point'.
 *
 * - lustre_rsync replicates all the operations saved in the changelog
 * on to the target filesystem to make it identical to the source.
 *
 * To facilitate replication, the lustre filesystem provides
 *    a) a way to get the current filesystem path of a given FID
 *    b) a way to open files by specifying its FID
 *
 * The changelog only has a limited amount of information.
 *  tfid - The FID of the target file
 *  pfid - The FID of the parent of the target file (at the time of
 *         the operation)
 *  sfid - The FID of the source file
 *  spfid - The FID of the parent of the source file
 *  name - The name of the target file (at the time of the operation), the name
 *         of the source file is appended (delimited with '\0') if this
 *         operation involves a source
 *
 * With just this information, it is not alwasy possible to determine
 * the file paths for each operation. For instance, if pfid does not
 * exist on the source-fs (due to a subsequent deletion), its path
 * cannot be queried. In such cases, lustre_rsync keeps the files in a
 * special directory ("/.lustrerepl"). Once all the operations in a
 * changelog are replayed, all the files in this special directory
 * will get moved to the location as in the source-fs.
 *
 * Shorthand used: f2p(fid) = fid2path(fid)
 *
 * The following are the metadata operations of interest.
 * 1. creat
 *    If tfid is absent on the source-fs, ignore this operation
 *    If pfid is absent on the source-fs [or]
 *    if f2p(pfid) is not present on target-fs [or]
 *    if f2p(pfid)+name != f2p(tfid)
 *      creat .lustrerepl/tfid
 *      track [pfid,tfid,name]
 *    Else
 *      creat f2p[tfid]
 *
 * 2. remove
 *    If .lustrerepl/[tfid] is present on the target
 *      rm .lustrerepl/[tfid]
 *    Else if pfid is present on the source-fs,
 *      if f2p(pfid)+name is present,
 *        rm f2p(pfid)+name
 *
 * 3. move (spfid,sname) to (pfid,name)
 *    If pfid is present
 *      if spfid is also present, mv (spfid,sname) to (pfid,name)
 *      else mv .lustrerepl/[sfid] to (pfid,name)
 *    Else if pfid is not present,
 *      if spfid is present, mv (spfid,sname) .lustrerepl/[sfid]
 *    If moving out of .lustrerepl
 *      move out all its children in .lustrerepl.
 *      [pfid,tfid,name] tracked from (1) is used for this.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <stdarg.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <limits.h>
#include <utime.h>
#include <time.h>
#include <sys/xattr.h>
#include <linux/types.h>
#include <linux/lustre_ioctl.h>

#include <libcfs/libcfs_debug.h>
#include <libcfs/util/ioctl.h>
#include <libcfs/util/string.h>
#include <libcfs/util/parser.h>
#include <lustre/lustreapi.h>
#include "lustre_rsync.h"

#define REPLICATE_STATUS_VER 1
#define CLEAR_INTERVAL 100
#define DEFAULT_RSYNC_THRESHOLD 0xA00000 /* 10 MB */

#define TYPE_STR_LEN 16

#define DEFAULT_MDT "-MDT0000"
#define SPECIAL_DIR ".lustrerepl"
#define RSYNC "rsync"
#define TYPE "type"

/* Debug flags */
#define DINFO 1
#define DTRACE 2

/* Not used; declared for fulfilling obd.c's dependency. */
command_t cmdlist[0];
extern int obd_initialize(int argc, char **argv);

/* Information for processing a changelog record. This structure is
   allocated on the heap instead of allocating large variables on the
   stack. */
struct lr_info {
        long long recno;
        int target_no;
	unsigned int is_extended:1;
        enum changelog_rec_type type;
	char tfid[LR_FID_STR_LEN];
	char pfid[LR_FID_STR_LEN];
	char sfid[LR_FID_STR_LEN];
	char spfid[LR_FID_STR_LEN];
	char sname[NAME_MAX + 1];
	char name[NAME_MAX + 1];
        char src[PATH_MAX + 1];
        char dest[PATH_MAX + 1];
        char path[PATH_MAX + 1];
        char savedpath[PATH_MAX + 1];
        char link[PATH_MAX + 1];
        char linktmp[PATH_MAX + 1];
        char cmd[PATH_MAX];
        int bufsize;
        char *buf;

        /* Variables for querying the xattributes */
        char *xlist;
        size_t xsize;
        char *xvalue;
        size_t xvsize;
};

struct lr_parent_child_list {
        struct lr_parent_child_log pc_log;
        struct lr_parent_child_list *pc_next;
};

struct lustre_rsync_status *status;
char *statuslog;  /* Name of the status log file */
int logbackedup;
int noxattr;    /* Flag to turn off replicating xattrs */
int noclear;    /* Flag to turn off clearing changelogs */
int debug;      /* Flag to turn debugging information on and off */
int verbose;    /* Verbose output */
long long rec_count; /* No of changelog records that were processed */
int errors;
int dryrun;
int use_rsync;  /* Flag to turn on use of rsync to copy data */
long long rsync_threshold = DEFAULT_RSYNC_THRESHOLD;
int quit;       /* Flag to stop processing the changelog; set on the
                   receipt of a signal */
int abort_on_err = 0;

char rsync[PATH_MAX];
char rsync_ver[PATH_MAX];
struct lr_parent_child_list *parents;

FILE *debug_log;

/* Command line options */
struct option long_opts[] = {
        {"source",      required_argument, 0, 's'},
        {"target",      required_argument, 0, 't'},
        {"mdt",         required_argument, 0, 'm'},
        {"user",        required_argument, 0, 'u'},
        {"statuslog",   required_argument, 0, 'l'},
        {"verbose",     no_argument,       0, 'v'},
        {"xattr",       required_argument, 0, 'x'},
        {"dry-run",     no_argument,       0, 'z'},
        /* Undocumented options follow */
        {"cl-clear",    required_argument, 0, 'c'},
        {"use-rsync",   no_argument,       0, 'r'},
        {"rsync-threshold", required_argument, 0, 'y'},
        {"start-recno", required_argument, 0, 'n'},
        {"abort-on-err",no_argument,       0, 'a'},
        {"debug",       required_argument, 0, 'd'},
	{"debuglog",	required_argument, 0, 'D'},
	{0, 0, 0, 0}
};

/* Command line usage */
void lr_usage()
{
        fprintf(stderr, "\tlustre_rsync -s <lustre_root_path> -t <target_path> "
                "-m <mdt> -r <user id> -l <status log>\n"
                "lustre_rsync can also pick up parameters from a "
                "status log created earlier.\n"
                "\tlustre_rsync -l <log_file>\n"
                "options:\n"
                "\t--xattr <yes|no> replicate EAs\n"
                "\t--abort-on-err   abort at first err\n"
                "\t--verbose\n"
                "\t--dry-run        don't write anything\n");
}

#define DEBUG_ENTRY(info)						       \
	lr_debug(D_TRACE, "***** Start %lld %s (%d) %s %s %s *****\n",         \
		 (info)->recno, changelog_type2str((info)->type),	       \
		 (info)->type, (info)->tfid, (info)->pfid, (info)->name);

#define DEBUG_EXIT(info, rc)						       \
	lr_debug(D_TRACE, "##### End %lld %s (%d) %s %s %s rc=%d #####\n",     \
		 (info)->recno, changelog_type2str((info)->type),	       \
		 (info)->type, (info)->tfid, (info)->pfid, (info)->name, rc);

/* Print debug information. This is controlled by the value of the
   global variable 'debug' */
void lr_debug(int level, const char *fmt, ...)
{
	va_list ap;

	if (level > debug)
		return;

	va_start(ap, fmt);
	if (debug_log != NULL)
		vfprintf(debug_log, fmt, ap);
	else
		vfprintf(stdout, fmt, ap);
	va_end(ap);
}


void * lr_grow_buf(void *buf, int size)
{
        void *ptr;

        ptr = realloc(buf, size);
        if (ptr == NULL)
                free(buf);
        return ptr;
}


/* Use rsync to replicate file data */
int lr_rsync_data(struct lr_info *info)
{
        int rc;
        struct stat st_src, st_dest;
        char cmd[PATH_MAX];

        lr_debug(DTRACE, "Syncing data%s\n", info->tfid);

        rc = stat(info->src, &st_src);
        if (rc == -1) {
                fprintf(stderr, "Error: Unable to stat src=%s %s\n",
                        info->src, info->name);
                if (errno == ENOENT)
                        return 0;
                else
                        return -errno;
        }
        rc = stat(info->dest, &st_dest);
        if (rc == -1) {
                fprintf(stderr, "Error: Unable to stat dest=%s\n",
                        info->dest);
                return -errno;
        }

        if (st_src.st_mtime != st_dest.st_mtime ||
            st_src.st_size != st_dest.st_size) {
                /* XXX spawning off an rsync for every data sync and
                 * waiting synchronously is bad for performance.
                 * librsync could possibly used here. But it does not
                 * seem to be of production grade. Multi-threaded
                 * replication is also to be considered.
                 */
                int status;
                snprintf(cmd, PATH_MAX, "%s --inplace %s %s", rsync, info->src,
                        info->dest);
                lr_debug(DTRACE, "\t%s %s\n", cmd, info->tfid);
                status = system(cmd);
                if (status == -1) {
                        rc = -errno;
                } else if (WIFEXITED(status)) {
                        status = WEXITSTATUS(status);
                        if (!status)
                                rc = 0;
                        else if (status == 23 || status == 24)
                                /* Error due to vanished source files;
                                   Ignore this error*/
                                rc = 0;
                        else
                                rc = -EINVAL;
                        if (status)
                                lr_debug(DINFO, "rsync %s exited with %d %d\n",
                                         info->src, status, rc);
                } else {
                        rc = -EINTR;
                }
        } else {
                lr_debug(DTRACE, "Not syncing %s and %s %s\n", info->src,
                         info->dest, info->tfid);
        }

        return rc;
}

int lr_copy_data(struct lr_info *info)
{
        int fd_src = -1;
        int fd_dest = -1;
        int bufsize;
        int rsize;
        int rc = 0;
        struct stat st_src;
        struct stat st_dest;

        fd_src = open(info->src, O_RDONLY);
        if (fd_src == -1)
                return -errno;
        if (fstat(fd_src, &st_src) == -1 ||
            stat(info->dest, &st_dest) == -1)
                goto out;

        if (st_src.st_mtime == st_dest.st_mtime &&
            st_src.st_size == st_dest.st_size)
                goto out;

        if (st_src.st_size > rsync_threshold && rsync[0] != '\0') {
                /* It is more efficient to use rsync to replicate
                   large files. Any file larger than rsync_threshold
                   is handed off to rsync. */
                lr_debug(DTRACE, "Using rsync to replicate %s\n", info->tfid);
                rc = lr_rsync_data(info);
                goto out;
        }

        fd_dest = open(info->dest, O_WRONLY | O_TRUNC, st_src.st_mode);
        if (fd_dest == -1) {
                rc = -errno;
                goto out;
        }
        bufsize = st_dest.st_blksize;

        if (info->bufsize < bufsize) {
                /* Grow buffer */
                info->buf = lr_grow_buf(info->buf, bufsize);
                if (info->buf == NULL) {
                        rc = -ENOMEM;
                        goto out;
                }
                info->bufsize = bufsize;
        }

	while (1) {
		char *buf;
		int wsize;

		buf = info->buf;
		rsize = read(fd_src, buf, bufsize);
		if (rsize == 0) {
			rc = 0;
			break;
		}
		if (rsize < 0) {
			rc = -errno;
			break;
		}
		do {
			wsize = write(fd_dest, buf, rsize);
			if (wsize <= 0) {
				rc = -errno;
				break;
			}
			rsize -= wsize;
			buf += wsize;
		} while (rsize > 0);
	}
	fsync(fd_dest);

out:
	if (fd_src != -1)
		close(fd_src);
	if (fd_dest != -1)
		close(fd_dest);

	return rc;
}

/* Copy data from source to destination */
int lr_sync_data(struct lr_info *info)
{
        if (use_rsync)
                return lr_rsync_data(info);
        else
                return lr_copy_data(info);
}

/* Copy all attributes from file src to file dest */
int lr_copy_attr(char *src, char *dest)
{
        struct stat st;
        struct utimbuf time;

        if (stat(src, &st) == -1 ||
            chmod(dest, st.st_mode) == -1 ||
            chown(dest, st.st_uid, st.st_gid) == -1)
                return -errno;

        time.actime = st.st_atime;
        time.modtime = st.st_mtime;
        if (utime(dest, &time) == -1)
                return -errno;
        return 0;
}

/* Copy all xattrs from file info->src to info->dest */
int lr_copy_xattr(struct lr_info *info)
{
        size_t size = info->xsize;
        int start;
        int len;
        int rc;

        if (noxattr)
                return 0;

        errno = 0;
        rc = llistxattr(info->src, info->xlist, size);
        lr_debug(DTRACE, "llistxattr(%s,%p) returned %d, errno=%d\n",
                 info->src, info->xlist, rc, errno);
        if ((rc > 0 && info->xlist == NULL) || errno == ERANGE) {
                size = rc > PATH_MAX ? rc : PATH_MAX;
                info->xlist = lr_grow_buf(info->xlist, size);
                if (info->xlist == NULL)
                        return -ENOMEM;
                info->xsize = size;
                rc = llistxattr(info->src, info->xlist, size);
                lr_debug(DTRACE, "llistxattr %s returned %d, errno=%d\n",
                         info->src, rc, errno);
        }
        if (rc < 0)
                return rc;

        len = rc;
        start = 0;
        while (start < len) {
                size = info->xvsize;
                rc = lgetxattr(info->src, info->xlist + start,
                               info->xvalue, size);
                if (info->xvalue == NULL || errno == ERANGE) {
                        size = rc > PATH_MAX ? rc : PATH_MAX;
                        info->xvalue = lr_grow_buf(info->xvalue, size);
                        if (info->xvalue == NULL)
                                return -ENOMEM;
                        info->xvsize = size;
                        rc = lgetxattr(info->src, info->xlist + start,
                                       info->xvalue, size);
                }
                lr_debug(DTRACE, "\t(%s,%d) rc=%p\n", info->xlist + start,
                         info->xvalue, rc);
                if (rc > 0) {
                        size = rc;
                        rc = lsetxattr(info->dest, info->xlist + start,
                                       info->xvalue, size, 0);
                        lr_debug(DTRACE, "\tlsetxattr(), rc=%d, errno=%d\n",
                                 rc, errno);
                        if (rc == -1) {
                                if (errno != ENOTSUP) {
                                        fprintf(stderr, "Error replicating "
                                                " xattr for %s: %d\n",
                                                info->dest, errno);
                                        errors++;
                                }
                                rc = 0;
                        }
                }
                start += strlen(info->xlist + start) + 1;
        }

        lr_debug(DINFO, "setxattr: %s %s\n", info->src, info->dest);

        return rc;
}

/* Retrieve the filesystem path for a given FID and a given
   linkno. The path is returned in info->path */
int lr_get_path_ln(struct lr_info *info, char *fidstr, int linkno)
{
        long long recno = -1;
        int rc;

        rc = llapi_fid2path(status->ls_source, fidstr, info->path,
                            PATH_MAX, &recno, &linkno);
        if (rc < 0 && rc != -ENOENT) {
                fprintf(stderr, "fid2path error: (%s, %s) %d %s\n",
                        status->ls_source, fidstr, -rc, strerror(errno = -rc));
        }

        return rc;
}

/* Retrieve the filesystem path for a given FID. The path is returned
   in info->path */
int lr_get_path(struct lr_info *info, char *fidstr)
{
        return lr_get_path_ln(info, fidstr, 0);
}

/* Generate the path for opening by FID */
void lr_get_FID_PATH(char *mntpt, char *fidstr, char *buf, int bufsize)
{
        /* Open-by-FID path is <mntpt>/.lustre/fid/[SEQ:OID:VER] */
        snprintf(buf, bufsize, "%s/%s/fid/%s", mntpt, dot_lustre_name,
                 fidstr);
        return;
}

/* Read the symlink information into 'info->link' */
int lr_get_symlink(struct lr_info *info)
{
        int rc;
        char *link;

        lr_get_FID_PATH(status->ls_source, info->tfid, info->src, PATH_MAX);
        rc = readlink(info->src, info->linktmp, PATH_MAX);
        if (rc > 0)
                info->linktmp[rc] = '\0';
        else
                return rc;
        lr_debug(DTRACE, "symlink: readlink returned %s\n", info->linktmp);

        if (strncmp(info->linktmp, status->ls_source,
                    strlen(status->ls_source)) == 0) {
                /* Strip source fs path and replace with target fs path. */
                link = info->linktmp + strlen(status->ls_source);
                snprintf(info->src, PATH_MAX, "%s%s",
                         status->ls_targets[info->target_no], link);
                link = info->src;
        } else {
                link = info->linktmp;
        }
	strlcpy(info->link, link, sizeof(info->link));

	return rc;
}

/* Create file/directory/device file/symlink. */
int lr_mkfile(struct lr_info *info)
{
        struct stat st;
        int rc = 0;

        errno = 0;
        lr_debug(DINFO, "mkfile(%d) %s \n", info->type, info->dest);
        if (info->type == CL_MKDIR) {
                rc = mkdir(info->dest, 0777);
        } else if (info->type == CL_SOFTLINK) {
                lr_get_symlink(info);
                rc = symlink(info->link, info->dest);
        } else if (info->type == CL_MKNOD) {
                lr_get_FID_PATH(status->ls_source, info->tfid,
                                    info->src, PATH_MAX);
                rc = stat(info->src, &st);
                if (rc == -1) {
                        if (errno == ENOENT)
                                return 0;
                        else
                                return -errno;
                }
                rc = mknod(info->dest, st.st_mode, st.st_rdev);
        } else {
                rc = mknod(info->dest, S_IFREG | 0777, 0);
        }

	if (rc < 0) {
		if (errno == EEXIST)
			rc = 0;
		else
			return -errno;
	}

        /* Sync data and attributes */
        if (info->type == CL_CREATE || info->type == CL_MKDIR) {
                lr_debug(DTRACE, "Syncing data and attributes %s\n",
                         info->tfid);
                (void) lr_copy_xattr(info);
                if (info->type == CL_CREATE)
                        rc = lr_sync_data(info);
                if (!rc)
                        rc = lr_copy_attr(info->src, info->dest);

                if (rc == -ENOENT)
                        /* Source file has disappeared. Not an error. */
                        rc = 0;
        } else {
                lr_debug(DTRACE, "Not syncing data and attributes %s\n",
                         info->tfid);
        }

        return rc;
}

int lr_add_pc(const char *pfid, const char *tfid, const char *name)
{
	struct lr_parent_child_list *p;
	size_t len;

	p = calloc(1, sizeof(*p));
	if (p == NULL)
		return -ENOMEM;
	len = strlcpy(p->pc_log.pcl_pfid, pfid, sizeof(p->pc_log.pcl_pfid));
	if (len >= sizeof(p->pc_log.pcl_pfid))
		goto out_err;
	len = strlcpy(p->pc_log.pcl_tfid, tfid, sizeof(p->pc_log.pcl_tfid));
	if (len >= sizeof(p->pc_log.pcl_tfid))
		goto out_err;
	len = strlcpy(p->pc_log.pcl_name, name, sizeof(p->pc_log.pcl_name));
	if (len >= sizeof(p->pc_log.pcl_name))
		goto out_err;

	p->pc_next = parents;
	parents = p;
	return 0;

out_err:
	free(p);
	return -E2BIG;
}

void lr_cascade_move(const char *fid, const char *dest, struct lr_info *info)
{
        struct lr_parent_child_list *curr, *prev;
        char *d;
        int rc;

        d = calloc(1, PATH_MAX + 1);
        prev = curr = parents;
        while (curr) {
                if (strcmp(curr->pc_log.pcl_pfid, fid) == 0) {
                        snprintf(d, PATH_MAX, "%s/%s", dest,
                                 curr->pc_log.pcl_name);
                        snprintf(info->src, PATH_MAX, "%s/%s/%s",
                                status->ls_targets[info->target_no],
                                SPECIAL_DIR, curr->pc_log.pcl_tfid);
                        rc = rename(info->src, d);
                        if (rc == -1) {
                                fprintf(stderr, "Error renaming file "
                                        " %s to %s: %d\n",
                                        info->src, d, errno);
                                errors++;
                        }
                        if (curr == parents)
                                parents = curr->pc_next;
                        else
                                prev->pc_next = curr->pc_next;
			lr_cascade_move(curr->pc_log.pcl_tfid, d, info);
                        free(curr);
                        prev = curr = parents;

                } else {
                        prev = curr;
                        curr = curr->pc_next;
                }
        }

        free(d);
}

/* remove [info->spfid, info->sfid] from parents */
int lr_remove_pc(const char *pfid, const char *tfid)
{
        struct lr_parent_child_list *curr, *prev;

        for (prev = curr = parents; curr; prev = curr, curr = curr->pc_next) {
                if (strcmp(curr->pc_log.pcl_pfid, pfid) == 0 &&
                    strcmp(curr->pc_log.pcl_tfid, tfid) == 0) {
                        if (curr == parents)
                                parents = curr->pc_next;
                        else
                                prev->pc_next = curr->pc_next;
                        free(curr);
                        break;
                }
        }
        return 0;
}

/* Create file under SPECIAL_DIR with its tfid as its name. */
int lr_mk_special(struct lr_info *info)
{
        int rc;

        snprintf(info->dest, PATH_MAX, "%s/%s/%s",
                status->ls_targets[info->target_no], SPECIAL_DIR,
                info->tfid);

        rc = lr_mkfile(info);
        if (rc)
                return rc;

        rc = lr_add_pc(info->pfid, info->tfid, info->name);
        return rc;
}

/* Remove a file or directory */
int lr_rmfile(struct lr_info *info)
{
        int rc;

        if (info->type == CL_RMDIR)
                rc = rmdir(info->dest);
        else
                rc = unlink(info->dest);
        if (rc == -1)
                rc = -errno;
        return rc;
}

/* Recursively remove directory and its contents */
int lr_rm_recursive(struct lr_info *info)
{
        int rc;

        snprintf(info->cmd, PATH_MAX, "rm -rf %s", info->dest);
        rc = system(info->cmd);
        if (rc == -1)
                rc = -errno;

        return rc;
}

/* Remove a file under SPECIAL_DIR with its tfid as its name. */
int lr_rm_special(struct lr_info *info)
{
        int rc;

        snprintf(info->dest, PATH_MAX, "%s/%s/%s",
                 status->ls_targets[info->target_no], SPECIAL_DIR,
                 info->tfid);
        rc = lr_rmfile(info);

        if (rc)
                lr_debug(DINFO, "remove: %s; rc=%d, errno=%d\n",
                         info->dest, rc, errno);
        return rc;
}

/* Replicate file and directory create events */
int lr_create(struct lr_info *info)
{
        int len;
        int rc1 = 0;
        int rc;
        int mkspecial = 0;

        /* Is target FID present on the source? */
        rc = lr_get_path(info, info->tfid);
        if (rc == -ENOENT) {
                /* Source file has disappeared. Not an error. */
                lr_debug(DINFO, "create: tfid %s not found on"
                         "source-fs\n", info->tfid);
                return 0;
        } else if (rc) {
                return rc;
        }
        strcpy(info->savedpath, info->path);

        /* Is parent FID present on the source */
        rc = lr_get_path(info, info->pfid);
        if (rc == -ENOENT) {
                lr_debug(DINFO, "create: pfid %s not found on source-fs\n",
                         info->tfid);
                mkspecial = 1;
        } else if (rc < 0) {
                return rc;
        }

        /* Is f2p(pfid)+name != f2p(tfid)? If not the file has moved. */
        len = strlen(info->path);
	if (len == 1 && info->path[0] == '/')
		snprintf(info->dest, PATH_MAX, "%s", info->name);
	else if (len - 1 > 0 && info->path[len - 1] == '/')
                snprintf(info->dest, PATH_MAX, "%s%s", info->path, info->name);
        else
                snprintf(info->dest, PATH_MAX, "%s/%s", info->path, info->name);

        lr_debug(DTRACE, "dest = %s; savedpath = %s\n", info->dest,
                 info->savedpath);
        if (strncmp(info->dest, info->savedpath, PATH_MAX) != 0) {
                lr_debug(DTRACE, "create: file moved (%s). %s != %s\n",
                         info->tfid, info->dest, info->savedpath);
                mkspecial = 1;
        }

        /* Is f2p(pfid) present on the target? If not, the parent has
           moved */
        if (!mkspecial) {
		snprintf(info->dest, PATH_MAX, "%s/%s", status->ls_targets[0],
			info->path);
		if (access(info->dest, F_OK) != 0) {
			lr_debug(DTRACE, "create: parent %s not found\n",
				info->dest);
			mkspecial = 1;
		}
        }
        for (info->target_no = 0; info->target_no < status->ls_num_targets;
             info->target_no++) {
                snprintf(info->dest, PATH_MAX, "%s/%s",
                        status->ls_targets[info->target_no], info->savedpath);
                lr_get_FID_PATH(status->ls_source, info->tfid, info->src,
                                    PATH_MAX);

                if (!mkspecial)
                        rc1 = lr_mkfile(info);
                if (mkspecial || rc1 == -ENOENT) {
                        rc1 = lr_mk_special(info);
                }
                if (rc1)
                        rc = rc1;
        }
	return rc;
}

/* Replicate a file remove (rmdir/unlink) operation */
int lr_remove(struct lr_info *info)
{
        int rc = 0;
        int rc1;

        for (info->target_no = 0; info->target_no < status->ls_num_targets;
             info->target_no++) {

                rc1 = lr_rm_special(info);
                if (!rc1)
                        continue;

                rc1 = lr_get_path(info, info->pfid);
                if (rc1 == -ENOENT) {
                        lr_debug(DINFO, "remove: pfid %s not found\n",
                                 info->pfid);
                        continue;
                }
                if (rc1) {
                        rc = rc1;
                        continue;
                }
                snprintf(info->dest, PATH_MAX, "%s/%s/%s",
                        status->ls_targets[info->target_no], info->path,
                        info->name);

                rc1 = lr_rmfile(info);
                lr_debug(DINFO, "remove: %s; rc1=%d, errno=%d\n",
                         info->dest, rc1, errno);
                if (rc1 == -ENOTEMPTY)
                        rc1 = lr_rm_recursive(info);

                if (rc1) {
                        rc = rc1;
                        continue;
                }
        }
	return rc;
}

/* Replicate a rename/move operation. */
int lr_move(struct lr_info *info)
{
        int rc = 0;
        int rc1;
        int rc_dest, rc_src;
        int special_src = 0;
        int special_dest = 0;
	char srcpath[PATH_MAX + 1] = "";

	assert(info->is_extended);

	rc_src = lr_get_path(info, info->spfid);
	if (rc_src < 0 && rc_src != -ENOENT)
		return rc_src;
	memcpy(srcpath, info->path, strlen(info->path));

	rc_dest = lr_get_path(info, info->pfid);
	if (rc_dest < 0 && rc_dest != -ENOENT)
		return rc_dest;

        for (info->target_no = 0; info->target_no < status->ls_num_targets;
             info->target_no++) {

                if (!rc_dest) {
                        snprintf(info->dest, PATH_MAX, "%s/%s",
                                status->ls_targets[info->target_no],
				info->path);
                        if (access(info->dest, F_OK) != 0) {
                                rc_dest = -errno;
                        } else {
                                snprintf(info->dest, PATH_MAX, "%s/%s/%s",
                                        status->ls_targets[info->target_no],
					info->path, info->name);
                        }
			lr_debug(DINFO, "dest path %s rc_dest=%d\n", info->dest,
				 rc_dest);
                }
                if (rc_dest == -ENOENT) {
                        snprintf(info->dest, PATH_MAX, "%s/%s/%s",
                                status->ls_targets[info->target_no],
				SPECIAL_DIR, info->sfid);
                        special_dest = 1;
			lr_debug(DINFO, "special dest %s\n", info->dest);
                }

		if (!rc_src) {
			snprintf(info->src, PATH_MAX, "%s/%s/%s",
				status->ls_targets[info->target_no],
				srcpath, info->sname);
			lr_debug(DINFO, "src path %s rc_src=%d\n", info->src,
				 rc_src);
		}
                if (rc_src == -ENOENT || (access(info->src, F_OK) != 0 &&
                                          errno == ENOENT)) {
                        snprintf(info->src, PATH_MAX, "%s/%s/%s",
                                status->ls_targets[info->target_no],
				SPECIAL_DIR, info->sfid);
                        special_src = 1;
			lr_debug(DINFO, "special src %s\n", info->src);
                }

                rc1 = 0;
		errno = 0;
                if (strcmp(info->src, info->dest) != 0) {
                        rc1 = rename(info->src, info->dest);
                        if (rc1 == -1)
                                rc1 = -errno;
			lr_debug(DINFO, "rename returns %d\n", rc1);
                }

		if (special_src)
			rc1 = lr_remove_pc(info->spfid, info->sfid);

		if (!special_dest)
			lr_cascade_move(info->sfid, info->dest, info);
		else
			rc1 = lr_add_pc(info->pfid, info->sfid, info->name);

                lr_debug(DINFO, "move: %s [to] %s rc1=%d, errno=%d\n",
                         info->src, info->dest, rc1, errno);
                if (rc1)
                        rc = rc1;
        }
	return rc;
}

/* Replicate a hard link */
int lr_link(struct lr_info *info)
{
        int i;
        int rc;
        int rc1;
        struct stat st;

        lr_get_FID_PATH(status->ls_source, info->tfid, info->src, PATH_MAX);
        rc = stat(info->src, &st);
        if (rc == -1)
                return -errno;

        for (info->target_no = 0; info->target_no < status->ls_num_targets;
             info->target_no++) {

		info->src[0] = 0;
		info->dest[0] = 0;
		rc1 = 0;

		/*
		 * The changelog record has the new parent directory FID and
		 * name of the target file. So info->dest can be constructed
		 * by getting the path of the new parent directory and
		 * appending the target file name.
		 */
		rc1 = lr_get_path(info, info->pfid);
		lr_debug(rc1 ? 0 : DTRACE, "\tparent fid2path %s, %s, rc=%d\n",
			 info->path, info->name, rc1);

		if (rc1 == 0) {
			snprintf(info->dest, sizeof(info->dest), "%s/%s/%s",
				 status->ls_targets[info->target_no],
				 info->path, info->name);
			lr_debug(DINFO, "link destination is %s\n", info->dest);
		}

		/* Search through the hardlinks to get the src */
		for (i = 0; i < st.st_nlink && info->src[0] == 0; i++) {
                        rc1 = lr_get_path_ln(info, info->tfid, i);
                        lr_debug(rc1 ? 0:DTRACE, "\tfid2path %s, %s, %d rc=%d\n",
                                 info->path, info->name, i, rc1);
                        if (rc1)
                                break;

			/*
			 * Compare the path of target FID with info->dest
			 * to find out info->src.
			 */
			char srcpath[PATH_MAX];

			snprintf(srcpath, sizeof(srcpath), "%s/%s",
				 status->ls_targets[info->target_no],
				 info->path);

			if (strcmp(srcpath, info->dest) != 0) {
				strlcpy(info->src, srcpath, sizeof(info->src));
				lr_debug(DINFO, "link source is %s\n",
					 info->src);
			}
		}

                if (rc1) {
                        rc = rc1;
                        continue;
                }

                if (info->src[0] == 0)
                        snprintf(info->src, PATH_MAX, "%s/%s/%s",
                                status->ls_targets[info->target_no],
                                SPECIAL_DIR, info->tfid);
                else if (info->dest[0] == 0)
                        snprintf(info->dest, PATH_MAX, "%s/%s/%s",
                                status->ls_targets[info->target_no],
                                SPECIAL_DIR, info->tfid);

		rc1 = link(info->src, info->dest);
		lr_debug(DINFO, "link: %s [to] %s; rc1=%d %s\n",
			 info->src, info->dest, rc1,
			 strerror(rc1 ? errno : 0));

                if (rc1)
                        rc = rc1;
        }
	return rc;
}

/* Replicate file attributes */
int lr_setattr(struct lr_info *info)
{
        int rc1;
        int rc;

        lr_get_FID_PATH(status->ls_source, info->tfid, info->src, PATH_MAX);

        rc = lr_get_path(info, info->tfid);
        if (rc == -ENOENT)
                lr_debug(DINFO, "setattr: %s not present on source-fs\n",
                         info->src);
        if (rc)
                return rc;

        for (info->target_no = 0; info->target_no < status->ls_num_targets;
             info->target_no++) {

                snprintf(info->dest, PATH_MAX, "%s/%s",
                         status->ls_targets[info->target_no], info->path);
                lr_debug(DINFO, "setattr: %s %s %s", info->src, info->dest,
                         info->tfid);

                rc1 = lr_sync_data(info);
                if (!rc1)
                        rc1 = lr_copy_attr(info->src, info->dest);
                if (rc1)
                        rc = rc1;
        }
	return rc;
}

/* Replicate xattrs */
int lr_setxattr(struct lr_info *info)
{
        int rc, rc1;

        lr_get_FID_PATH(status->ls_source, info->tfid, info->src, PATH_MAX);

        rc = lr_get_path(info, info->tfid);
        if (rc == -ENOENT)
                lr_debug(DINFO, "setxattr: %s not present on source-fs\n",
                         info->src);
        if (rc)
                return rc;

        for (info->target_no = 0; info->target_no < status->ls_num_targets;
             info->target_no++) {

                snprintf(info->dest, PATH_MAX, "%s/%s",
                        status->ls_targets[info->target_no], info->path);
                lr_debug(DINFO, "setxattr: %s %s %s\n", info->src, info->dest,
                         info->tfid);

                rc1 = lr_copy_xattr(info);
                if (rc1)
                        rc = rc1;
        }

	return rc;
}

/* Parse a line of changelog entry */
int lr_parse_line(void *priv, struct lr_info *info)
{
	struct changelog_rec		*rec;
	struct changelog_ext_rename	*rnm;
	size_t				 namelen;
	size_t				 copylen = sizeof(info->name);

	if (llapi_changelog_recv(priv, &rec) != 0)
		return -1;

	info->is_extended = !!(rec->cr_flags & CLF_RENAME);
	info->recno = rec->cr_index;
	info->type = rec->cr_type;
	snprintf(info->tfid, sizeof(info->tfid), DFID, PFID(&rec->cr_tfid));
	snprintf(info->pfid, sizeof(info->pfid), DFID, PFID(&rec->cr_pfid));

	namelen = strnlen(changelog_rec_name(rec), rec->cr_namelen);
	if (copylen > namelen + 1)
		copylen = namelen + 1;
	strlcpy(info->name, changelog_rec_name(rec), copylen);

	/* Don't use rnm if CLF_RENAME isn't set */
	rnm = changelog_rec_rename(rec);
	if (rec->cr_flags & CLF_RENAME && !fid_is_zero(&rnm->cr_sfid)) {
		copylen = sizeof(info->sname);

		snprintf(info->sfid, sizeof(info->sfid), DFID,
			 PFID(&rnm->cr_sfid));
		snprintf(info->spfid, sizeof(info->spfid), DFID,
			 PFID(&rnm->cr_spfid));
		namelen = changelog_rec_snamelen(rec);
		if (copylen > namelen + 1)
			copylen = namelen + 1;
		strlcpy(info->sname, changelog_rec_sname(rec), copylen);

		if (verbose > 1)
			printf("Rec %lld: %d %s %s\n", info->recno, info->type,
				info->name, info->sname);
	} else {
		if (verbose > 1)
			printf("Rec %lld: %d %s\n", info->recno, info->type,
				info->name);
	}

        llapi_changelog_free(&rec);

        rec_count++;
        return 0;
}

/* Initialize the replication parameters */
int lr_init_status()
{
        size_t size = sizeof(struct lustre_rsync_status) + PATH_MAX + 1;

        if (status != NULL)
                return 0;
        status = calloc(size, 1);
        if (status == NULL)
                return -ENOMEM;
        status->ls_version = REPLICATE_STATUS_VER;
        status->ls_size = size;
        status->ls_last_recno = -1;
        return 0;
}

/* Make a backup of the statuslog */
void lr_backup_log()
{
        char backupfile[PATH_MAX];

        if (logbackedup)
                return;
        snprintf(backupfile, PATH_MAX, "%s.old", statuslog);
        (void) rename(statuslog, backupfile);
        logbackedup = 1;

        return;
}

/* Save replication parameters to a statuslog. */
int lr_write_log()
{
        int fd;
        size_t size;
        size_t write_size = status->ls_size;
        struct lr_parent_child_list *curr;
        int rc = 0;

        if (statuslog == NULL)
                return 0;

        lr_backup_log();

        fd = open(statuslog, O_WRONLY | O_CREAT | O_SYNC,
                             S_IRUSR | S_IWUSR);
        if (fd == -1) {
                fprintf(stderr, "Error opening log file for writing (%s)\n",
                        statuslog);
                return -1;
        }
        errno = 0;
        size = write(fd, status, write_size);
        if (size != write_size) {
                fprintf(stderr, "Error writing to log file (%s) %d\n",
                        statuslog, errno);
                close(fd);
                return -1;
        }

        for (curr = parents; curr; curr = curr->pc_next) {
                size = write(fd, &curr->pc_log, sizeof(curr->pc_log));
                if (size != sizeof(curr->pc_log)) {
                        fprintf(stderr, "Error writing to log file (%s) %d\n",
                                statuslog, errno);
                        rc = -1;
                        break;
                }
        }
        close(fd);
        return rc;
}

/* Read statuslog and populate the replication parameters.  Command
 * line parameters take precedence over parameters in the log file.*/
int lr_read_log()
{
        struct lr_parent_child_list *tmp;
        struct lr_parent_child_log rec;
        struct lustre_rsync_status *s;
        int fd = -1;
        size_t size;
        size_t read_size = sizeof(struct lustre_rsync_status) + PATH_MAX + 1;
        int rc = 0;

        if (statuslog == NULL)
                return 0;

        s = calloc(1, read_size);
	if (s == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	fd = open(statuslog, O_RDONLY);
	if (fd == -1) {
		rc = -errno;
		goto out;
	}

	size = read(fd, s, read_size);
	if (size != read_size) {
		rc = -EINVAL;
		goto out;
	}

	if (read_size < s->ls_size) {
		read_size = s->ls_size;
		s = lr_grow_buf(s, read_size);
		if (s == NULL) {
			rc = -ENOMEM;
			goto out;
		}

		if (lseek(fd, 0, SEEK_SET) == -1) {
			rc = -ENOMEM;
			goto out;
		}

		size = read(fd, s, read_size);
		if (size != read_size) {
			rc = -EINVAL;
			goto out;
		}
	}

	while (read(fd, &rec, sizeof(rec)) != 0) {
		tmp = calloc(1, sizeof(*tmp));
		if (!tmp) {
			rc = -ENOMEM;
			goto out;
		}

                tmp->pc_log = rec;
                tmp->pc_next = parents;
                parents = tmp;
        }

        /* copy uninitialized fields to status */
        if (status->ls_num_targets == 0) {
                if (status->ls_size != s->ls_size) {
                        status = lr_grow_buf(status, s->ls_size);
			if (status == NULL) {
				rc = -ENOMEM;
				goto out;
			}

                        status->ls_size = s->ls_size;
                }
                status->ls_num_targets = s->ls_num_targets;
                memcpy(status->ls_targets, s->ls_targets,
                       (PATH_MAX + 1) * s->ls_num_targets);
        }
        if (status->ls_last_recno == -1)
                status->ls_last_recno = s->ls_last_recno;

	if (status->ls_registration[0] == '\0')
		strlcpy(status->ls_registration, s->ls_registration,
			sizeof(status->ls_registration));

	if (status->ls_mdt_device[0] == '\0')
		strlcpy(status->ls_mdt_device, s->ls_mdt_device,
			sizeof(status->ls_mdt_device));

	if (status->ls_source_fs[0] == '\0')
		strlcpy(status->ls_source_fs, s->ls_source_fs,
			sizeof(status->ls_source_fs));

	if (status->ls_source[0] == '\0')
		strlcpy(status->ls_source, s->ls_source,
			sizeof(status->ls_source));

 out:
        if (fd != -1)
                close(fd);
        if (s)
                free(s);
        return rc;
}

/* Clear changelogs every CLEAR_INTERVAL records or at the end of
   processing. */
int lr_clear_cl(struct lr_info *info, int force)
{
	char		mdt_device[LR_NAME_MAXLEN + 1];
	long long	rec;
	int		rc = 0;

        if (force || info->recno > status->ls_last_recno + CLEAR_INTERVAL) {
                if (info->type == CL_RENAME)
                        rec = info->recno + 1;
                else
                        rec = info->recno;
                if (!noclear && !dryrun) {
                        /* llapi_changelog_clear modifies the mdt
                         * device name so make a copy of it until this
                         * is fixed.
                        */
			strlcpy(mdt_device, status->ls_mdt_device,
				sizeof(mdt_device));
                        rc = llapi_changelog_clear(mdt_device,
                                                   status->ls_registration,
                                                   rec);
                        if (rc)
                                printf("Changelog clear (%s, %s, %lld) "
                                       "returned %d\n", status->ls_mdt_device,
                                       status->ls_registration, rec, rc);
                }
                if (!rc && !dryrun) {
                        status->ls_last_recno = rec;
                        lr_write_log();

                }
        }

        return rc;
}

/* Locate a usable version of rsync. At this point we'll use any
   version. */
int lr_locate_rsync()
{
        FILE *fp;
        int len;

        /* Locate rsync */
        snprintf(rsync, PATH_MAX, "%s -p %s", TYPE, RSYNC);
        fp = popen(rsync, "r");
        if (fp == NULL)
                return -1;

        if (fgets(rsync, PATH_MAX, fp) == NULL) {
                fclose(fp);
                return -1;
        }

        len = strlen(rsync);
        if (len > 0 && rsync[len - 1] == '\n')
                rsync[len - 1] = '\0';
        fclose(fp);

        /* Determine the version of rsync */
        snprintf(rsync_ver, PATH_MAX, "%s --version", rsync);
        fp = popen(rsync_ver, "r");
        if (fp == NULL)
                return -1;

        if (fgets(rsync_ver, PATH_MAX, fp) == NULL) {
                fclose(fp);
                return -1;
        }
        len = strlen(rsync_ver);
        if (len > 0 && rsync_ver[len - 1] == '\n')
                rsync_ver[len - 1] = '\0';
        fclose(fp);

        return 0;

}

/* Print the replication parameters */
void lr_print_status(struct lr_info *info)
{
        int i;

        if (!verbose)
                return;

        printf("Lustre filesystem: %s\n", status->ls_source_fs);
        printf("MDT device: %s\n", status->ls_mdt_device);
        printf("Source: %s\n", status->ls_source);
        for (i = 0; i < status->ls_num_targets; i++)
                printf("Target: %s\n", status->ls_targets[i]);
        if (statuslog != NULL)
                printf("Statuslog: %s\n", statuslog);
        printf("Changelog registration: %s\n", status->ls_registration);
	printf("Starting changelog record: %jd\n",
	       (uintmax_t)status->ls_last_recno);
        if (noxattr)
                printf("Replicate xattrs: no\n");
        if (noclear)
                printf("Clear changelog after use: no\n");
        if (use_rsync)
                printf("Using rsync: %s (%s)\n", rsync, rsync_ver);
}

void lr_print_failure(struct lr_info *info, int rc)
{
        fprintf(stderr, "Replication of operation failed(%d):"
                " %lld %s (%d) %s %s %s\n", rc, info->recno,
                changelog_type2str(info->type), info->type, info->tfid,
                info->pfid, info->name);
}

/* Replicate filesystem operations from src_path to target_path */
int lr_replicate()
{
        void *changelog_priv;
        struct lr_info *info;
	struct lr_info *ext = NULL;
        time_t start;
        int xattr_not_supp;
        int i;
        int rc;

        start = time(NULL);

        info = calloc(1, sizeof(struct lr_info));
        if (info == NULL)
                return -ENOMEM;

        rc = llapi_search_fsname(status->ls_source, status->ls_source_fs);
        if (rc) {
                fprintf(stderr, "Source path is not a valid Lustre client "
                        "mountpoint.\n");
		goto out;
        }
        if (status->ls_mdt_device[0] == '\0')
                snprintf(status->ls_mdt_device, LR_NAME_MAXLEN, "%s%s",
                        status->ls_source_fs, DEFAULT_MDT);

        ext = calloc(1, sizeof(struct lr_info));
	if (ext == NULL) {
		rc = -ENOMEM;
		goto out;
	}

        for (i = 0, xattr_not_supp = 0; i < status->ls_num_targets; i++) {
                snprintf(info->dest, PATH_MAX, "%s/%s", status->ls_targets[i],
                        SPECIAL_DIR);
                rc = mkdir(info->dest, 0777);
                if (rc == -1 && errno != EEXIST) {
                        fprintf(stderr, "Error writing to target path %s.\n",
                                status->ls_targets[i]);
			rc = -errno;
			goto out;
                }
                rc = llistxattr(info->src, info->xlist, info->xsize);
                if (rc == -1 && errno == ENOTSUP) {
                        fprintf(stderr, "xattrs not supported on %s\n",
                                status->ls_targets[i]);
                        xattr_not_supp++;
                }
        }
        if (xattr_not_supp == status->ls_num_targets)
                /* None of the targets support xattrs. */
                noxattr = 1;

        lr_print_status(info);

	/* Open changelogs for consumption*/
	rc = llapi_changelog_start(&changelog_priv,
				CHANGELOG_FLAG_BLOCK | CHANGELOG_FLAG_JOBID,
				status->ls_mdt_device, status->ls_last_recno);
        if (rc < 0) {
                fprintf(stderr, "Error opening changelog file for fs %s.\n",
                        status->ls_source_fs);
		goto out;
        }

        while (!quit && lr_parse_line(changelog_priv, info) == 0) {
                rc = 0;
		if (info->type == CL_RENAME && !info->is_extended) {
			/* Newer rename operations extends changelog to store
			 * source file information, but old changelog has
			 * another record.
			 */
			if (lr_parse_line(changelog_priv, ext) != 0)
				break;
			memcpy(info->sfid, info->tfid, sizeof(info->sfid));
			memcpy(info->spfid, info->pfid, sizeof(info->spfid));
			memcpy(info->tfid, ext->tfid, sizeof(info->tfid));
			memcpy(info->pfid, ext->pfid, sizeof(info->pfid));
			strlcpy(info->sname, info->name, sizeof(info->sname));
			strlcpy(info->name, ext->name, sizeof(info->name));
			info->is_extended = 1;
		}

                if (dryrun)
                        continue;

		DEBUG_ENTRY(info);

                switch(info->type) {
                case CL_CREATE:
                case CL_MKDIR:
                case CL_MKNOD:
                case CL_SOFTLINK:
                        rc = lr_create(info);
                        break;
                case CL_RMDIR:
                case CL_UNLINK:
                        rc = lr_remove(info);
                        break;
                case CL_RENAME:
			rc = lr_move(info);
                        break;
                case CL_HARDLINK:
                        rc = lr_link(info);
                        break;
                case CL_TRUNC:
                case CL_SETATTR:
                        rc = lr_setattr(info);
                        break;
                case CL_XATTR:
                        rc = lr_setxattr(info);
                        break;
		case CL_CLOSE:
		case CL_EXT:
		case CL_OPEN:
		case CL_LAYOUT:
		case CL_MARK:
			/* Nothing needs to be done for these entries */
			/* fallthrough */
		default:
			break;
		}
		DEBUG_EXIT(info, rc);
                if (rc && rc != -ENOENT) {
                        lr_print_failure(info, rc);
                        errors++;
                        if (abort_on_err)
                                break;
                }
                lr_clear_cl(info, 0);
                if (debug) {
                        bzero(info, sizeof(struct lr_info));
                        bzero(ext, sizeof(struct lr_info));
                }
        }

        llapi_changelog_fini(&changelog_priv);

        if (errors || verbose)
                printf("Errors: %d\n", errors);

        /* Clear changelog records used so far */
        lr_clear_cl(info, 1);

        if (verbose) {
                printf("lustre_rsync took %ld seconds\n", time(NULL) - start);
                printf("Changelog records consumed: %lld\n", rec_count);
        }

	rc = 0;

out:
	if (info != NULL)
		free(info);
	if (ext != NULL)
		free(ext);

	return rc;
}

void
termination_handler (int signum)
{
        /* Set a flag for the replicator to gracefully shutdown */
        quit = 1;
        printf("lustre_rsync halting.\n");
}

int main(int argc, char *argv[])
{
        int newsize;
        int numtargets = 0;
        int rc = 0;

        if ((rc = lr_init_status()) != 0)
                return rc;

	while ((rc = getopt_long(argc, argv, "as:t:m:u:l:vx:zc:ry:n:d:D:",
				 long_opts, NULL)) >= 0) {
                switch (rc) {
                case 'a':
                        /* Assume absolute paths */
                        abort_on_err++;
                        break;
                case 's':
                        /* Assume absolute paths */
			strlcpy(status->ls_source, optarg,
				sizeof(status->ls_source));
                        break;
                case 't':
                        status->ls_num_targets++;
                        numtargets++;
                        if (numtargets != status->ls_num_targets) {
                                /* Targets were read from a log
                                   file. The ones specified on the
                                   command line take precedence. The
                                   ones from the log file will be
                                   ignored. */
                                status->ls_num_targets = numtargets;
                        }
                        newsize = sizeof (struct lustre_rsync_status) +
                                (status->ls_num_targets * (PATH_MAX + 1));
                        if (status->ls_size != newsize) {
                                status->ls_size = newsize;
                                status = lr_grow_buf(status, newsize);
                                if (status == NULL)
                                        return -ENOMEM;
                        }
			strlcpy(status->ls_targets[status->ls_num_targets - 1],
				optarg, sizeof(status->ls_targets[0]));
			break;
		case 'm':
			strlcpy(status->ls_mdt_device, optarg,
				sizeof(status->ls_mdt_device));
			break;
		case 'u':
			strlcpy(status->ls_registration, optarg,
				sizeof(status->ls_registration));
                        break;
                case 'l':
                        statuslog = optarg;
                        (void) lr_read_log();
                        break;
                case 'v':
                        verbose++;
                        break;
                case 'x':
                        if (strcmp("no", optarg) == 0) {
                                noxattr = 1;
                        } else if (strcmp("yes", optarg) != 0) {
                                printf("Invalid parameter %s. "
                                       "Specify --xattr=no or --xattr=yes\n",
                                       optarg);
                                return -1;
                        }
                        break;
                case 'z':
                        dryrun = 1;
                        break;
                case 'c':
                        /* Undocumented option cl-clear */
                        if (strcmp("no", optarg) == 0) {
                                noclear = 1;
                        } else if (strcmp("yes", optarg) != 0) {
                                printf("Invalid parameter %s. "
                                       "Specify --cl-clear=no "
                                       "or --cl-clear=yes\n",
                                       optarg);
                                return -1;
                        }
                        break;
                case 'r':
                        /* Undocumented option use-rsync */
                        use_rsync = 1;
                        break;
                case 'y':
                        /* Undocumented option rsync-threshold */
                        rsync_threshold = atol(optarg);
                        break;
                case 'n':
                        /* Undocumented option start-recno */
                        status->ls_last_recno = atol(optarg);
                        break;
                case 'd':
                        /* Undocumented option debug */
                        debug = atoi(optarg);
                        if (debug < 0 || debug > 2)
                                debug = 0;
                        break;
		case 'D':
			/* Undocumented option debug log file */
			if (debug_log != NULL)
				fclose(debug_log);
			debug_log = fopen(optarg, "a");
			if (debug_log == NULL) {
				printf("Cannot open %s for debug log\n",
				       optarg);
				return -1;
			}
			break;
                default:
                        fprintf(stderr, "error: %s: option '%s' "
                                "unrecognized.\n", argv[0], argv[optind - 1]);
                        lr_usage();
                        return -1;
                }
        }

        if (status->ls_last_recno == -1)
                status->ls_last_recno = 0;
        if (strnlen(status->ls_registration, LR_NAME_MAXLEN) == 0) {
                /* No registration ID was passed in. */
                printf("Please specify changelog consumer registration id.\n");
                lr_usage();
                return -1;
        }
        if (strnlen(status->ls_source, PATH_MAX) == 0) {
                fprintf(stderr, "Please specify the source path.\n");
                lr_usage();
                return -1;
        }
        if (strnlen(status->ls_targets[0], PATH_MAX) == 0) {
                fprintf(stderr, "Please specify the target path.\n");
                lr_usage();
                return -1;
        }

        /* This plumbing is needed for some of the ioctls behind
           llapi calls to work. */
	register_ioc_dev(OBD_DEV_ID, OBD_DEV_PATH);

        rc = lr_locate_rsync();
        if (use_rsync && rc != 0) {
                fprintf(stderr, "Error: unable to locate %s.\n", RSYNC);
                exit(-1);
        }

        signal(SIGINT, termination_handler);
        signal(SIGHUP, termination_handler);
        signal(SIGTERM, termination_handler);

        rc = lr_replicate();

	if (debug_log != NULL)
		fclose(debug_log);
	return rc;
}
