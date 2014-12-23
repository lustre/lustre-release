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
 */
/*
 * Copyright (c) 2012, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/lustre/include/lustre_idmap.h
 *
 * MDS data structures.
 * See also lustre_idl.h for wire formats of requests.
 */

#ifndef _LUSTRE_EACL_H
#define _LUSTRE_EACL_H

/** \defgroup eacl eacl
 *
 * @{
 */

#ifdef CONFIG_FS_POSIX_ACL
# include <linux/fs.h>
# include <linux/posix_acl_xattr.h>

typedef struct {
        __u16                   e_tag;
        __u16                   e_perm;
        __u32                   e_id;
        __u32                   e_stat;
} ext_acl_xattr_entry;

typedef struct {
        __u32                   a_count;
        ext_acl_xattr_entry     a_entries[0];
} ext_acl_xattr_header;

#define CFS_ACL_XATTR_SIZE(count, prefix) \
        (sizeof(prefix ## _header) + (count) * sizeof(prefix ## _entry))

#define CFS_ACL_XATTR_COUNT(size, prefix) \
        (((size) - sizeof(prefix ## _header)) / sizeof(prefix ## _entry))

#ifdef HAVE_SERVER_SUPPORT
struct lu_ucred;
struct lu_attr;
struct lustre_idmap_table;

extern int lustre_posix_acl_permission(struct lu_ucred *mu,
					const struct lu_attr *la, int want,
					posix_acl_xattr_entry *entry,
					int count);
extern int lustre_posix_acl_chmod_masq(posix_acl_xattr_entry *entry,
                                       __u32 mode, int count);
extern int lustre_posix_acl_create_masq(posix_acl_xattr_entry *entry,
                                        __u32 *pmode, int count);
extern int lustre_posix_acl_equiv_mode(posix_acl_xattr_entry *entry, mode_t *mode_p,
				       int count);

extern int
lustre_posix_acl_xattr_id2client(struct lu_ucred *mu,
				 struct lustre_idmap_table *t,
				 posix_acl_xattr_header *header,
				 int size, int flags);

extern int
lustre_ext_acl_xattr_id2server(struct lu_ucred *mu,
			       struct lustre_idmap_table *t,
			       ext_acl_xattr_header *header);
#endif /* HAVE_SERVER_SUPPORT */

extern ext_acl_xattr_header *
lustre_posix_acl_xattr_2ext(posix_acl_xattr_header *header, int size);
extern int
lustre_posix_acl_xattr_filter(posix_acl_xattr_header *header, int size,
			      posix_acl_xattr_header **out);
extern void
lustre_posix_acl_xattr_free(posix_acl_xattr_header *header, int size);
extern void
lustre_ext_acl_xattr_free(ext_acl_xattr_header *header);
extern int
lustre_acl_xattr_merge2posix(posix_acl_xattr_header *posix_header, int size,
                             ext_acl_xattr_header *ext_header,
                             posix_acl_xattr_header **out);
extern ext_acl_xattr_header *
lustre_acl_xattr_merge2ext(posix_acl_xattr_header *posix_header, int size,
                           ext_acl_xattr_header *ext_header);

#endif /* CONFIG_FS_POSIX_ACL */

/** @} eacl */

#endif
