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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/include/libcfs/curproc.h
 *
 * Lustre curproc API declaration
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#ifndef __LIBCFS_CURPROC_H__
#define __LIBCFS_CURPROC_H__

#if !defined(HAVE_UIDGID_HEADER) || !defined(__KERNEL__)

#ifndef _LINUX_UIDGID_H
#define _LINUX_UIDGID_H

typedef uid_t kuid_t;
typedef gid_t kgid_t;

#define INVALID_UID	-1
#define INVALID_GID	-1

#define GLOBAL_ROOT_UID	 0
#define GLOBAL_ROOT_GID	 0

#ifndef __KERNEL__
struct user_namespace {
	unsigned int pad;
};

extern struct user_namespace init_user_ns;
#endif

static inline uid_t __kuid_val(kuid_t uid)
{
	return uid;
}

static inline gid_t __kgid_val(kgid_t gid)
{
	return gid;
}

static inline kuid_t make_kuid(struct user_namespace *from, uid_t uid)
{
	return uid;
}

static inline kgid_t make_kgid(struct user_namespace *from, gid_t gid)
{
	return gid;
}

static inline uid_t from_kuid(struct user_namespace *to, kuid_t uid)
{
	return uid;
}

static inline gid_t from_kgid(struct user_namespace *to, kgid_t gid)
{
	return gid;
}

static inline bool uid_eq(kuid_t left, kuid_t right)
{
	return left == right;
}

static inline bool uid_valid(kuid_t uid)
{
	return uid != (typeof(uid))INVALID_UID;
}

static inline bool gid_valid(kgid_t gid)
{
	return gid != (typeof(gid))INVALID_GID;
}
#endif /* _LINUX_UIDGID_H */

#endif

int cfs_get_environ(const char *key, char *value, int *val_len);

typedef __u32 cfs_cap_t;

#define CFS_CAP_CHOWN                   0
#define CFS_CAP_DAC_OVERRIDE            1
#define CFS_CAP_DAC_READ_SEARCH         2
#define CFS_CAP_FOWNER                  3
#define CFS_CAP_FSETID                  4
#define CFS_CAP_LINUX_IMMUTABLE         9
#define CFS_CAP_SYS_ADMIN              21
#define CFS_CAP_SYS_BOOT               23
#define CFS_CAP_SYS_RESOURCE           24

#define CFS_CAP_FS_MASK ((1 << CFS_CAP_CHOWN) |                 \
                         (1 << CFS_CAP_DAC_OVERRIDE) |          \
                         (1 << CFS_CAP_DAC_READ_SEARCH) |       \
                         (1 << CFS_CAP_FOWNER) |                \
                         (1 << CFS_CAP_FSETID ) |               \
                         (1 << CFS_CAP_LINUX_IMMUTABLE) |       \
                         (1 << CFS_CAP_SYS_ADMIN) |             \
                         (1 << CFS_CAP_SYS_BOOT) |              \
                         (1 << CFS_CAP_SYS_RESOURCE))

void cfs_cap_raise(cfs_cap_t cap);
void cfs_cap_lower(cfs_cap_t cap);
int cfs_cap_raised(cfs_cap_t cap);
cfs_cap_t cfs_curproc_cap_pack(void);
void cfs_curproc_cap_unpack(cfs_cap_t cap);
int cfs_capable(cfs_cap_t cap);

/* __LIBCFS_CURPROC_H__ */
#endif
/*
 * Local variables:
 * c-indentation-style: "K&R"
 * c-basic-offset: 8
 * tab-width: 8
 * fill-column: 80
 * scroll-step: 1
 * End:
 */
