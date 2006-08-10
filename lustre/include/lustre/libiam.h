/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  libiam.h
 *  iam user level library
 *
 *   Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Wang Di <wangdi@clusterfs.com>
 *   Author: Nikita Danilov <nikita@clusterfs.com>
 *   Author: Fan Yong <fanyong@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

/*
 *  lustre/libiam.h
 */

#ifndef __IAM_ULIB_H__
#define __IAM_ULIB_H__


#define SET_DEFAULT     -1
#define DX_FMT_NAME_LEN 16

enum iam_fmt_t {
        FMT_LFIX,
        FMT_LVAR
};

struct iam_uapi_info {
        __u16 iui_keysize;
        __u16 iui_recsize;
        __u16 iui_ptrsize;
        __u16 iui_height;
        char  iui_fmt_name[DX_FMT_NAME_LEN];
};

/*
 * Creat an iam file, but do NOT open it.
 * Return 0 if success, else -1.
 */
int iam_creat(char *filename, enum iam_fmt_t fmt,
              int blocksize, int keysize, int recsize, int ptrsize);

/*
 * Open an iam file, but do NOT creat it if the file doesn't exist.
 * Please use iam_creat for creating the file before use iam_open.
 * Return file id (fd) if success, else -1.
 */
int iam_open(char *filename, struct iam_uapi_info *ua);

/*
 * Close file opened by iam_open. 
 */
int iam_close(int fd);

/*
 * Please use iam_open before use this function.
 */
int iam_insert(int fd, struct iam_uapi_info *ua,
               int key_need_convert, char *keybuf,
               int rec_need_convert, char *recbuf);

/*
 * Please use iam_open before use this function.
 */
int iam_lookup(int fd, struct iam_uapi_info *ua,
               int key_need_convert, char *key_buf,
               int *keysize, char *save_key,
               int rec_need_convert, char *rec_buf,
               int *recsize, char *save_rec);

/*
 * Please use iam_open before use this function.
 */
int iam_delete(int fd, struct iam_uapi_info *ua,
               int key_need_convert, char *keybuf,
               int rec_need_convert, char *recbuf);

/*
 * Please use iam_open before use this function.
 */
int iam_it_start(int fd, struct iam_uapi_info *ua,
                 int key_need_convert, char *key_buf,
                 int *keysize, char *save_key,
                 int rec_need_convert, char *rec_buf,
                 int *recsize, char *save_rec);

/*
 * Please use iam_open before use this function.
 */
int iam_it_next(int fd, struct iam_uapi_info *ua,
                int key_need_convert, char *key_buf,
                int *keysize, char *save_key,
                int rec_need_convert, char *rec_buf,
                int *recsize, char *save_rec);

/*
 * Please use iam_open before use this function.
 */
int iam_it_stop(int fd, struct iam_uapi_info *ua,
                int key_need_convert, char *keybuf,
                int rec_need_convert, char *recbuf);

/*
 * Change iam file mode.
 */
int iam_polymorph(char *filename, unsigned long mode);


#endif
