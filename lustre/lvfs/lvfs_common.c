/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2003 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org/
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
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/obd.h>
#include <linux/lvfs.h>

struct dentry *lvfs_fid2dentry(struct lvfs_run_ctxt *ctxt, __u64 id,
                               __u32 gen, __u64 gr, void *data)
{
        return ctxt->cb_ops.l_fid2dentry(id, gen, gr, data);
}
EXPORT_SYMBOL(lvfs_fid2dentry);

static struct list_head lvfs_context_list;

void lvfs_mount_list_init(void)
{
        INIT_LIST_HEAD(&lvfs_context_list);
}

void lvfs_mount_list_cleanup(void)
{
        struct list_head *tmp;

        if (list_empty(&lvfs_context_list))
                return;

        list_for_each(tmp, &lvfs_context_list) {
                struct lvfs_obd_ctxt *data = 
                       list_entry(tmp, struct lvfs_obd_ctxt, loc_list);
                CERROR("device %s still mounted with refcount %d\n",
                        data->loc_name, atomic_read(&data->loc_refcount));
        }
}

static inline
struct lvfs_obd_ctxt *get_lvfs_mount(struct lvfs_obd_ctxt *lvfs_ctxt)
{
        atomic_inc(&lvfs_ctxt->loc_refcount);
        return lvfs_ctxt;
}

static struct lvfs_obd_ctxt *add_lvfs_mount(struct vfsmount *mnt, char *name)
{
        struct lvfs_obd_ctxt *lvfs_ctxt;
        ENTRY;

        OBD_ALLOC(lvfs_ctxt, sizeof(*lvfs_ctxt));
        if (!lvfs_ctxt) {
                CERROR("No Memory\n");
                RETURN(NULL);
        }

        if (name) {
                int length = strlen(name) + 1;

                OBD_ALLOC(lvfs_ctxt->loc_name, length);
                if (!lvfs_ctxt->loc_name) {
                        CERROR("No Memory\n");
                        OBD_FREE(lvfs_ctxt, sizeof(*lvfs_ctxt));
                        RETURN(NULL);
                }
                memcpy(lvfs_ctxt->loc_name, name, length);
        }
        lvfs_ctxt->loc_mnt = mnt;
        list_add(&lvfs_ctxt->loc_list, &lvfs_context_list);
        atomic_set(&lvfs_ctxt->loc_refcount, 1);
        RETURN(lvfs_ctxt);
}

void lvfs_umount_fs(struct lvfs_obd_ctxt *lvfs_ctxt)
{
        if (lvfs_ctxt && atomic_dec_and_test(&lvfs_ctxt->loc_refcount)) {
                struct vfsmount *mnt = lvfs_ctxt->loc_mnt;

                list_del(&lvfs_ctxt->loc_list);
                if (atomic_read(&mnt->mnt_count) > 2)
                       CERROR("mount busy, mnt %p mnt_count %d != 2\n", mnt,
                               atomic_read(&mnt->mnt_count));
                
                mntput(mnt);
                
                if (lvfs_ctxt->loc_name)
                        OBD_FREE(lvfs_ctxt->loc_name, 
                                 strlen(lvfs_ctxt->loc_name) + 1);
                OBD_FREE(lvfs_ctxt, sizeof(*lvfs_ctxt));
                dev_clear_rdonly(2);
        }
}
EXPORT_SYMBOL(lvfs_umount_fs);

int lvfs_mount_fs(char *name, char *fstype, char *options, int flags,
                  struct lvfs_obd_ctxt **lvfs_ctxt)
{
        struct vfsmount *mnt = NULL;
        struct list_head *tmp;
        int rc = 0;
        ENTRY;

        list_for_each(tmp, &lvfs_context_list) {
                struct lvfs_obd_ctxt *data =
                               list_entry(tmp, struct lvfs_obd_ctxt, loc_list);
                if (strcmp(data->loc_name, name) == 0) {
                       *lvfs_ctxt = get_lvfs_mount(data);
                       RETURN(0);
                }
        }
        mnt = do_kern_mount(fstype, flags, name, options);

        if (IS_ERR(mnt)) {
                rc = PTR_ERR(mnt);
                CERROR("do_kern_mount failed: rc = %d\n", rc);
                GOTO(out, rc);
        }
        CDEBUG(D_SUPER, "%s: mnt = %p\n", name, mnt);
        /*add this lvfs context to the lvfs_mount_list*/
        *lvfs_ctxt = add_lvfs_mount(mnt, name);
        if (!*lvfs_ctxt) {
                mntput(mnt);
                CERROR("add_lvfs_mount failed\n");
                GOTO(out, rc = -EINVAL);
        }
out:
        RETURN(rc);
}
EXPORT_SYMBOL(lvfs_mount_fs);
