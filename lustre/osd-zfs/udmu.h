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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2012, Intel Corporation.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osd-zfs/udmu.h
 *
 * Author: Alex Tomas <alex@clusterfs.com>
 * Author: Atul Vidwansa <atul.vidwansa@sun.com>
 * Author: Manoj Joseph <manoj.joseph@sun.com>
 */

#ifndef _DMU_H
#define _DMU_H

#include <sys/zap.h>
#include <sys/vnode.h>
#include <sys/mode.h>
#include <sys/sa.h>

#include <lustre/lustre_user.h>

typedef struct udmu_objset {
	struct objset	*os;
	uint64_t	root;  /* id of root znode */
	spinlock_t	lock;  /* protects objects below */
	uint64_t	objects; /* in-core counter of objects */
	/* SA attr mapping->id,
	 * name is the same as in ZFS to use defines SA_ZPL_...*/
	sa_attr_type_t *z_attr_table;
} udmu_objset_t;

#ifndef _SYS_TXG_H
#define TXG_WAIT        1ULL
#define TXG_NOWAIT      2ULL
#endif

#define ZFS_DIRENT_MAKE(type, obj) (((uint64_t)type << 60) | obj)

/* Statfs space reservation for grant, fragmentation, and unlink space. */
#define OSD_STATFS_RESERVED_BLKS  (1ULL << (22 - SPA_MAXBLOCKSHIFT)) /* 4MB */
#define OSD_STATFS_RESERVED_SHIFT (7)         /* reserve 0.78% of all space */

/* Statfs {minimum, safe estimate, and maximum} dnodes per block */
#define OSD_DNODE_MIN_BLKSHIFT (SPA_MAXBLOCKSHIFT - DNODE_SHIFT) /* 17-9 =8 */
#define OSD_DNODE_EST_BLKSHIFT (SPA_MAXBLOCKSHIFT - 12)          /* 17-12=5 */
#define OSD_DNODE_EST_COUNT    1024

#define OSD_GRANT_FOR_LOCAL_OIDS (2ULL << 20) /* 2MB for last_rcvd, ... */

void udmu_init(void);
void udmu_fini(void);

/* udmu object-set API */
int udmu_objset_open(char *osname, udmu_objset_t *uos);
void udmu_objset_close(udmu_objset_t *uos);
int udmu_objset_statfs(udmu_objset_t *uos, struct obd_statfs *osfs);
uint64_t udmu_objset_user_iused(udmu_objset_t *uos, uint64_t uidbytes);
int udmu_objset_root(udmu_objset_t *uos, dmu_buf_t **dbp, void *tag);
uint64_t udmu_get_txg(udmu_objset_t *uos, dmu_tx_t *tx);
int udmu_blk_insert_cost(void);

/* zap cursor apis */
int udmu_zap_cursor_init(zap_cursor_t **zc, udmu_objset_t *uos,
		uint64_t zapobj, uint64_t hash);

void udmu_zap_cursor_fini(zap_cursor_t *zc);

void udmu_zap_cursor_advance(zap_cursor_t *zc);

uint64_t udmu_zap_cursor_serialize(zap_cursor_t *zc);

int udmu_zap_cursor_move_to_key(zap_cursor_t *zc, const char *name);

/* Commit callbacks */
int udmu_object_is_zap(dmu_buf_t *);

#endif /* _DMU_H */
