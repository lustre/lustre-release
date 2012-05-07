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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef __TEST_COMMON__H
#define __TEST_COMMON__H

#define ENV_LUSTRE_MNTPNT               "LIBLUSTRE_MOUNT_POINT"
#define ENV_LUSTRE_MNTTGT               "LIBLUSTRE_MOUNT_TARGET"
#define ENV_LUSTRE_TIMEOUT              "LIBLUSTRE_TIMEOUT"
#define ENV_LUSTRE_DUMPFILE             "LIBLUSTRE_DUMPFILE"

extern int exit_on_err;

#include <utime.h> /* for utimbuf */

void t_touch(const char *path);
void t_create(const char *path);
void t_link(const char *src, const char *dst);
void t_unlink(const char *path);
void t_mkdir(const char *path);
void t_rmdir(const char *path);
void t_symlink(const char *src, const char *new);
void t_mknod(const char *path, mode_t mode, int major, int minor);
void t_chmod_raw(const char *path, mode_t mode);
void t_chmod(const char *path, const char *format, ...);
void t_rename(const char *oldpath, const char *newpath);
int t_open_readonly(const char *path);
int t_open(const char *path);
int t_chdir(const char *path);
int t_utime(const char *path, const struct utimbuf *buf);
int t_opendir(const char *path);
void t_close(int fd);
int t_check_stat(const char *name, struct stat *buf);
int t_check_stat_fail(const char *name);
void t_echo_create(const char *path, const char *str);
void t_grep(const char *path, char *str);
void t_grep_v(const char *path, char *str);
void t_ls(int fd, char *buf, int size);
int t_fcntl(int fd, int cmd, ...);

char *safe_strncpy(char *dst, char *src, int max_size);

#endif
