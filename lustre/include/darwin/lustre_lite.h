/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lustre lite cluster file system
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * Copyright (C) 2002 Cluster File Systems, Inc. <info@clusterfs.com>
 */



#ifndef _DARWIN_LL_H
#define _DARWIN_LL_H

#ifndef _LL_H
#error Do not #include this file directly. #include <lustre_lite.h> instead
#endif

#include <libcfs/libcfs.h>

#ifdef __KERNEL__

struct iattr {
        unsigned int    ia_valid;
        umode_t         ia_mode;
        uid_t           ia_uid;
        gid_t           ia_gid;
        loff_t          ia_size;
        time_t          ia_atime;
        time_t          ia_mtime;
        time_t          ia_ctime;
        unsigned int    ia_attr_flags;
};

/*
 * intent data-structured. For Linux they are defined in
 * linux/include/linux/dcache.h
 */
#define IT_OPEN     0x0001
#define IT_CREAT    0x0002
#define IT_READDIR  0x0004
#define IT_GETATTR  0x0008
#define IT_LOOKUP   0x0010
#define IT_UNLINK   0x0020
#define IT_GETXATTR 0x0040
#define IT_EXEC     0x0080
#define IT_PIN      0x0100

#define IT_FL_LOCKED   0x0001
#define IT_FL_FOLLOWED 0x0002 /* set by vfs_follow_link */

#define INTENT_MAGIC 0x19620323 /* Happy birthday! */

struct lustre_intent_data {
        int     it_disposition;
        int     it_status;
        __u64   it_lock_handle;
        void    *it_data;
        int     it_lock_mode;
};

/*
 * Liang: We keep the old lookup_intent struct in XNU 
 * to avoid unnecessary allocate/free. 
 */
#define LUSTRE_IT(it) ((struct lustre_intent_data *)(&(it)->d.lustre))

struct lookup_intent {
	int     it_magic;
	void    (*it_op_release)(struct lookup_intent *);
	int     it_op;
	int     it_flags;
	int     it_create_mode;
	union {
                struct lustre_intent_data lustre;
		void *fs_data;
	} d;
};

struct super_operations{
};
#endif

#endif
