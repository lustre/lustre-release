/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/dmu-osd/udmu.h
 *
 * Author: Alex Tomas <alex@clusterfs.com>
 * Author: Atul Vidwansa <atul.vidwansa@sun.com>
 * Author: Manoj Joseph <manoj.joseph@sun.com>
 */

#ifndef _DMU_H
#define _DMU_H

#ifdef  __cplusplus
extern "C" {
#endif

#define LUSTRE_ZPL_VERSION 1ULL

#ifndef DMU_AT_TYPE
#define DMU_AT_TYPE    0x0001
#define DMU_AT_MODE    0x0002
#define DMU_AT_UID     0x0004
#define DMU_AT_GID     0x0008
#define DMU_AT_FSID    0x0010
#define DMU_AT_NODEID  0x0020
#define DMU_AT_NLINK   0x0040
#define DMU_AT_SIZE    0x0080
#define DMU_AT_ATIME   0x0100
#define DMU_AT_MTIME   0x0200
#define DMU_AT_CTIME   0x0400
#define DMU_AT_RDEV    0x0800
#define DMU_AT_BLKSIZE 0x1000
#define DMU_AT_NBLOCKS 0x2000
#define DMU_AT_SEQ     0x8000
#endif

#if 0
#define ACCESSED                (DMU_AT_ATIME)
#define STATE_CHANGED           (DMU_AT_CTIME)
#define CONTENT_MODIFIED        (DMU_AT_MTIME | DMU_AT_CTIME)
#endif

#define LOOKUP_DIR              0x01    /* want parent dir vp */
#define LOOKUP_XATTR            0x02    /* lookup up extended attr dir */
#define CREATE_XATTR_DIR        0x04    /* Create extended attr dir */

#define S_IFDOOR        0xD000  /* door */
#define S_IFPORT        0xE000  /* event port */

struct statfs64;

/* Data structures required for Solaris ZFS compatability */
#if !defined(__sun__)

#ifndef _SPL_TYPES_H
typedef struct timespec timestruc_t;
#endif

#endif

#ifndef _SPL_VNODE_H
typedef enum vtype {
        VNON    = 0,
        VREG    = 1,
        VDIR    = 2,
        VBLK    = 3,
        VCHR    = 4,
        VLNK    = 5,
        VFIFO   = 6,
        VDOOR   = 7,
        VPROC   = 8,
        VSOCK   = 9,
        VPORT   = 10,
        VBAD    = 11
} vtype_t;
#endif

typedef struct vnattr {
        unsigned int    va_mask;        /* bit-mask of attributes */
        enum vtype      va_type;        /* vnode type (for create) */
        mode_t          va_mode;        /* file access mode */
        uid_t           va_uid;         /* owner user id */
        gid_t           va_gid;         /* owner group id */
        dev_t           va_fsid;        /* file system id (dev for now) */
        unsigned long long va_nodeid;   /* node id */
        nlink_t         va_nlink;       /* number of references to file */
        off_t           va_size;        /* file size in bytes */
        timestruc_t     va_atime;       /* time of last access */
        timestruc_t     va_mtime;       /* time of last modification */
        timestruc_t     va_ctime;       /* time of last status change */
        dev_t           va_rdev;        /* device the file represents */
        unsigned int    va_blksize;     /* fundamental block size */
        unsigned int    va_blkbits;
        unsigned long long va_nblocks;  /* # of blocks allocated */
        unsigned int    va_seq;         /* sequence number */
} vnattr_t;

typedef struct udmu_objset {
        struct objset *os;
        struct zilog *zilog;
        uint64_t root;  /* id of root znode */
        uint64_t unlinkedobj;
} udmu_objset_t;


/* definitions from dmu.h */
#ifndef _SYS_DMU_H

typedef struct objset objset_t;
typedef struct dmu_tx dmu_tx_t;
typedef struct dmu_buf dmu_buf_t;
typedef struct zap_cursor zap_cursor_t;

#define DMU_NEW_OBJECT  (-1ULL)
#define DMU_OBJECT_END  (-1ULL)

#endif

#ifndef _SYS_TXG_H
#define TXG_WAIT        1ULL
#define TXG_NOWAIT      2ULL
#endif

#define ZFS_DIRENT_MAKE(type, obj) (((uint64_t)type << 60) | obj)

#define FTAG ((char *)__func__)

void udmu_init(void);

void udmu_fini(void);

void udmu_debug(int level);

/* udmu object-set API */

int udmu_objset_open(char *osname, char *import_dir, int import, int force, udmu_objset_t *uos);

void udmu_objset_close(udmu_objset_t *uos, int export_pool);

int udmu_objset_statfs(udmu_objset_t *uos, struct statfs64 *statp);

int udmu_objset_root(udmu_objset_t *uos, dmu_buf_t **dbp, void *tag);

void udmu_wait_synced(udmu_objset_t *uos, dmu_tx_t *tx);

/* udmu ZAP API */

int udmu_zap_lookup(udmu_objset_t *uos, dmu_buf_t *zap_db, const char *name,
                    void *value, int value_size, int intsize);

void udmu_zap_create(udmu_objset_t *uos, dmu_buf_t **zap_dbp, dmu_tx_t *tx, void *tag);

int udmu_zap_insert(udmu_objset_t *uos, dmu_buf_t *zap_db, dmu_tx_t *tx,
                    const char *name, void *value, int len);

int udmu_zap_delete(udmu_objset_t *uos, dmu_buf_t *zap_db, dmu_tx_t *tx,
                    const char *name);

/* zap cursor apis */
int udmu_zap_cursor_init(zap_cursor_t **zc, udmu_objset_t *uos, uint64_t zapobj);

void udmu_zap_cursor_fini(zap_cursor_t *zc);

int udmu_zap_cursor_retrieve_key(zap_cursor_t *zc, char *key);

int udmu_zap_cursor_retrieve_value(zap_cursor_t *zc,  char *buf,
                int buf_size, int *bytes_read);

void udmu_zap_cursor_advance(zap_cursor_t *zc);

uint64_t udmu_zap_cursor_serialize(zap_cursor_t *zc);

int udmu_zap_cursor_move_to_key(zap_cursor_t *zc, const char *name);

void udmu_zap_cursor_init_serialized(zap_cursor_t *zc, udmu_objset_t *uos,
                            uint64_t zapobj, uint64_t serialized);

/* udmu object API */

void udmu_object_create(udmu_objset_t *uos, dmu_buf_t **dbp, dmu_tx_t *tx, void *tag);

int udmu_object_get_dmu_buf(udmu_objset_t *uos, uint64_t object,
                            dmu_buf_t **dbp, void *tag);

void udmu_object_put_dmu_buf(dmu_buf_t *db, void *tag);

uint64_t udmu_object_get_id(dmu_buf_t *db);

int udmu_object_read(udmu_objset_t *uos, dmu_buf_t *db, uint64_t offset,
                     uint64_t size, void *buf);

void udmu_object_write(udmu_objset_t *uos, dmu_buf_t *db, struct dmu_tx *tx,
                      uint64_t offset, uint64_t size, void *buf);

void udmu_object_getattr(dmu_buf_t *db, vnattr_t *vap);

void udmu_object_setattr(dmu_buf_t *db, dmu_tx_t *tx, vnattr_t *vap);

void udmu_object_punch(udmu_objset_t *uos, dmu_buf_t *db, dmu_tx_t *tx,
                      uint64_t offset, uint64_t len);

int udmu_object_delete(udmu_objset_t *uos, dmu_buf_t **db, dmu_tx_t *tx, void *tag);

/*udmu transaction API */

dmu_tx_t *udmu_tx_create(udmu_objset_t *uos);

void udmu_tx_hold_write(dmu_tx_t *tx, uint64_t object, uint64_t off, int len);

void udmu_tx_hold_free(dmu_tx_t *tx, uint64_t object, uint64_t off,
    uint64_t len);

void udmu_tx_hold_zap(dmu_tx_t *tx, uint64_t object, int add, char *name);

void udmu_tx_hold_bonus(dmu_tx_t *tx, uint64_t object);

void udmu_tx_abort(dmu_tx_t *tx);

int udmu_tx_assign(dmu_tx_t *tx, uint64_t txg_how);

void udmu_tx_wait(dmu_tx_t *tx);

int udmu_indblk_overhead(dmu_buf_t *db, unsigned long *used,
                         unsigned long *overhead);

void udmu_tx_commit(dmu_tx_t *tx);

void * udmu_tx_cb_create(size_t bytes);

int udmu_tx_cb_add(dmu_tx_t *tx, void *func, void *data);

int udmu_tx_cb_destroy(void *data);

int udmu_object_is_zap(dmu_buf_t *);

int udmu_indblk_overhead(dmu_buf_t *db, unsigned long *used, unsigned 
                                long *overhead);

int udmu_get_blocksize(dmu_buf_t *db, long *blksz);

uint64_t udmu_object_get_links(dmu_buf_t *db);
void udmu_object_links_inc(dmu_buf_t *db, dmu_tx_t *tx);
void udmu_object_links_dec(dmu_buf_t *db, dmu_tx_t *tx);

int udmu_get_xattr(dmu_buf_t *db, void *val, int vallen, const char *name);
int udmu_set_xattr(dmu_buf_t *db, void *val, int vallen,
                   const char *name, dmu_tx_t *tx);
int udmu_del_xattr(dmu_buf_t *db, const char *name, dmu_tx_t *tx);
int udmu_list_xattr(dmu_buf_t *db, void *val, int vallen);

#ifdef  __cplusplus
}
#endif

#endif /* _DMU_H */
