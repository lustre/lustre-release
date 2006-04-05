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
#include <linux/lustre_handles.h>
#include <libcfs/kp30.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_log.h>
#include <linux/lustre_export.h>

#ifdef CONFIG_FS_POSIX_ACL
#define LUSTRE_POSIX_ACL_MAX_ENTRIES    (32)
#define LUSTRE_POSIX_ACL_MAX_SIZE       \
                (xattr_acl_size(LUSTRE_POSIX_ACL_MAX_ENTRIES))
#else
#define LUSTRE_POSIX_ACL_MAX_SIZE       0
#endif

#endif
