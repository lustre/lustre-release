/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   This file is part of Lustre, http://www.lustre.org
 *
 * MDS data structures.
 * See also lustre_idl.h for wire formats of requests.
 */

#ifndef _LUSTRE_ACL_H
#define _LUSTRE_ACL_H

#ifdef __KERNEL__
# include <linux/fs.h>
# include <linux/dcache.h>
# ifdef CONFIG_FS_POSIX_ACL
# include <linux/xattr_acl.h>
# endif
#endif

/* ACL */
#ifdef CONFIG_FS_POSIX_ACL
#define LUSTRE_POSIX_ACL_MAX_ENTRIES    (32)
#define LUSTRE_POSIX_ACL_MAX_SIZE       \
        (sizeof(xattr_acl_header) + 32 * sizeof(xattr_acl_entry))
#else
#define LUSTRE_POSIX_ACL_MAX_SIZE       0
#endif


#endif
