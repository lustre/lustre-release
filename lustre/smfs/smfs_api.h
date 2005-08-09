/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc. <info@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *   smfs data structures.
 *   See also lustre_idl.h for wire formats of requests.
 *
 */

#ifndef __SMFS_API_H
#define __SMFS_API_H

#include <linux/lustre_audit.h>

/* SMFS plugin stuff */
#define SMFS_PLG_KML    0x0001L
#define SMFS_PLG_LRU    0x0004L
#define SMFS_PLG_COW    0x0020L
#define SMFS_PLG_UNDO   0x0100L
#define SMFS_PLG_AUDIT  0x0200L
#define SMFS_PLG_DUMMY  0x1000L
#define SMFS_PLG_ALL    (~0L)

#define SMFS_SET(flags, mask) (flags |= mask)
#define SMFS_IS(flags, mask) (flags & mask)
#define SMFS_CLEAR(flags, mask) (flags &= ~mask)

typedef enum { 
        HOOK_CREATE = 1,
        HOOK_LOOKUP,
        HOOK_LINK,
        HOOK_UNLINK,
        HOOK_SYMLINK,
        HOOK_READLINK,
        HOOK_MKDIR,
        HOOK_RMDIR,
        HOOK_MKNOD,
        HOOK_RENAME,
        HOOK_SETATTR,
        HOOK_GETATTR,
        HOOK_WRITE,
        HOOK_READ,
        HOOK_READDIR,
        HOOK_F_SETATTR,
        HOOK_SETXATTR,
        HOOK_GETXATTR,
        HOOK_REMOVEXATTR,
        HOOK_LISTXATTR,
        HOOK_F_SETXATTR,
        HOOK_SI_READ,
        HOOK_SI_WRITE,
        HOOK_SPECIAL,
        HOOK_MAX
} hook_op;

typedef int (*smfs_plg_hook)(hook_op hook_code, struct inode *,
                             void *arg, int rc, void * priv);
typedef int (*smfs_plg_func)(int help_code, struct super_block *,
                             void *arg, void * priv);

struct smfs_plugin {
        struct list_head plg_list;
        int              plg_type;

        smfs_plg_hook    plg_pre_op;
        smfs_plg_hook    plg_post_op;
        smfs_plg_func    plg_helper;
        void *           plg_private;
        int (* plg_exit)(struct super_block *, void *);
};
/* KML plugin stuff */
#define KML_LOG_NAME    "smfs_kml"

struct kml_priv {
        /* llog pack function */
        int (*pack_fn)(int, char *, struct dentry *,
                        struct inode *, void *, void *);
};

struct audit_priv {
        struct llog_ctxt *audit_ctxt;
        void * audit_get_record;
        void * au_id2name;
        int result;
        __u64 a_mask;
};
typedef int (*audit_get_op)(struct inode *, void *, struct audit_priv *,
                            char *, __u32*);

struct hook_msg {
        struct dentry * dentry;

};

struct hook_link_msg {
        struct dentry * dentry;
        struct dentry * new_dentry;
};
struct hook_unlink_msg {
        struct dentry * dentry;
        int mode;
};

struct hook_symlink_msg {
        struct dentry * dentry;
        int tgt_len;
        char * symname;
};

struct hook_rename_msg {
        struct dentry * dentry;
        struct inode * old_dir;
        struct inode * new_dir;
        struct dentry * new_dentry;
};

struct hook_readdir_msg {
        struct dentry * dentry;
        struct file * filp;
        void * dirent;
        filldir_t filldir;
};

struct hook_write_msg {
        struct dentry * dentry;
        size_t count;
        loff_t pos;
};

struct hook_attr_msg {
        struct dentry * dentry;
        struct iattr *attr;
};

struct hook_xattr_msg {
        char * name;
        char *buffer;
	int  buffer_size;
};

struct hook_rw_msg {
        int write;
        struct lustre_id *id;
};

void smfs_pre_hook (struct inode*, hook_op, void*);
void smfs_post_hook(struct inode*, hook_op, void*, int);

#define SMFS_PRE_HOOK(inode, op, msg) smfs_pre_hook (inode, op, msg)
#define SMFS_POST_HOOK(inode, op, msg, rc) smfs_post_hook(inode, op, msg, rc)

#define PLG_EXIT        0
#define PLG_TRANS_SIZE  1
#define PLG_TEST_INODE  2
#define PLG_SET_INODE   3
#define PLG_START       4
#define PLG_STOP        5
#define PLG_SET_INFO    6
#define PLG_HELPER_MAX  7

struct plg_hmsg {
        __u32 data;
        __u32 result;        
};

struct plg_info_msg {
        char * key;
        void * val;
};
int smfs_helper (struct super_block *, int, void *);
#define SMFS_PLG_HELP(sb, op, data) smfs_helper(sb, op, data)

int smfs_register_plugin(struct super_block *, struct smfs_plugin *);
struct smfs_plugin * smfs_deregister_plugin(struct super_block *, int);

int smfs_init_dummy(struct super_block *);
int smfs_init_kml(struct super_block *);
int smfs_init_lru(struct super_block *);
int smfs_init_cow(struct super_block *);
int smfs_init_audit(struct super_block *);
//int audit_mds_op(hook_op, struct inode *, void *, struct audit_priv *);
int audit_client_log(struct super_block*, struct audit_msg *);
int audit_mds_setup(struct obd_device *, struct super_block *, struct audit_priv *);
int audit_ost_setup(struct obd_device *, struct super_block *, struct audit_priv *);
int smfs_set_audit(struct super_block *, struct inode *, __u64 *);
int smfs_get_audit(struct super_block *, struct inode *,
                   struct inode *,  __u64 *);

static inline int audit_rec_from_id (char **pbuf, struct lustre_id * id)
{
        struct audit_id_record * rec = (void*)(*pbuf);
        int len = sizeof(*rec);

        rec->au_num = id_ino(id);
        rec->au_fid = id_fid(id);
        rec->au_gen = id_gen(id);
        rec->au_type = id_type(id);
        rec->au_mds = id_group(id);
        
        *pbuf += len;
        return len;
}

static inline int audit_fill_name_rec (char **pbuf, const char * name, int nlen) 
{
        struct audit_name_record * n_rec = (void*)(*pbuf);
        int len = sizeof(*n_rec) + nlen;
        
        memcpy(n_rec->name, name, nlen);
        n_rec->name_len = nlen;

        *pbuf += len;
        return len;
}

#endif
