/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002, 2003 Cluster File Systems, Inc.
 *   Author: Hariharan Thantry <thantry@users.sourceforge.net>
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
 */

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_CLASS
#ifdef __KERNEL__
#include <linux/config.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/types.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#include <asm/statfs.h>
#endif

#else
#include <liblustre.h>
#endif

#include <linux/obd_class.h>
#include <linux/lprocfs_status.h>

#ifdef LPROCFS

struct proc_dir_entry *lprocfs_srch(struct proc_dir_entry *head,
                                    const char *name)
{
        struct proc_dir_entry* temp;

        if (!head)
                return NULL;

        temp = head->subdir;
        while (temp != NULL) {
                if (!strcmp(temp->name, name))
                        return temp;

                temp = temp->next;
        }
        return NULL;
}

/* lprocfs API calls */

int lprocfs_add_vars(struct proc_dir_entry *root, struct lprocfs_vars *list,
                     void *data)
{
        if ((root == NULL) || (list == NULL))
                return -EINVAL;

        while (list->name) {
                struct proc_dir_entry *cur_root, *proc;
                char *pathcopy, *cur, *next;
                int pathsize = strlen(list->name)+1;

                proc = NULL;
                cur_root = root;

                /* need copy of path for strsep */
                OBD_ALLOC(pathcopy, pathsize);
                if (!pathcopy)
                        return -ENOMEM;

                next = pathcopy;
                strcpy(pathcopy, list->name);

                while (cur_root && (cur = strsep(&next, "/"))) {
                        if (*cur =='\0') /* skip double/trailing "/" */
                                continue;

                        proc = lprocfs_srch(cur_root, cur);
                        CDEBUG(D_OTHER, "cur_root=%s, cur=%s, next=%s, (%s)\n",
                               cur_root->name, cur, next,
                               (proc ? "exists" : "new"));
                        if (next)
                                cur_root = (proc ? proc :
                                                   proc_mkdir(cur, cur_root));
                        else if (!proc)
                                proc = create_proc_entry(cur, 0444, cur_root);
                }

                OBD_FREE(pathcopy, pathsize);

                if ((cur_root==NULL) || (proc==NULL)) {
                        CERROR("LprocFS: No memory to create /proc entry %s",
                               list->name);
                        return -ENOMEM;
                }

                proc->read_proc = list->read_fptr;
                proc->write_proc = list->write_fptr;
                proc->data = (list->data ? list->data : data);
                list++;
        }
        return 0;
}

void lprocfs_remove(struct proc_dir_entry* root)
{
        struct proc_dir_entry *temp = root;
        struct proc_dir_entry *rm_entry;
        struct proc_dir_entry *parent;

        LASSERT(root != NULL);
        parent = root->parent;
        LASSERT(parent != NULL);

        while (1) {
                while (temp->subdir)
                        temp = temp->subdir;

                rm_entry = temp;
                temp = temp->parent;
                remove_proc_entry(rm_entry->name, rm_entry->parent);
                if (temp == parent)
                        break;
        }
}

struct proc_dir_entry *lprocfs_register(const char *name,
                                        struct proc_dir_entry *parent,
                                        struct lprocfs_vars *list, void *data)
{
        struct proc_dir_entry *newchild;

        newchild = lprocfs_srch(parent, name);
        if (newchild) {
                CERROR(" Lproc: Attempting to register %s more than once \n",
                       name);
                return ERR_PTR(-EALREADY);
        }

        newchild = proc_mkdir(name, parent);
        if (newchild && list) {
                int rc = lprocfs_add_vars(newchild, list, data);
                if (rc) {
                        lprocfs_remove(newchild);
                        return ERR_PTR(rc);
                }
        }
        return newchild;
}

/* Generic callbacks */

int lprocfs_rd_u64(char *page, char **start, off_t off,
                   int count, int *eof, void *data)
{
        LASSERT(data != NULL);
        *eof = 1;
        return snprintf(page, count, LPU64"\n", *(__u64 *)data);
}

int lprocfs_rd_uuid(char* page, char **start, off_t off, int count,
                    int *eof, void *data)
{
        struct obd_device* dev = (struct obd_device*)data;

        LASSERT(dev != NULL);
        *eof = 1;
        return snprintf(page, count, "%s\n", dev->obd_uuid.uuid);
}

int lprocfs_rd_name(char *page, char **start, off_t off, int count,
                    int *eof, void *data)
{
        struct obd_device* dev = (struct obd_device *)data;

        LASSERT(dev != NULL);
        LASSERT(dev->obd_name != NULL);
        *eof = 1;
        return snprintf(page, count, "%s\n", dev->obd_name);
}

int lprocfs_rd_blksize(char* page, char **start, off_t off, int count,
                       int *eof, struct statfs *sfs)
{
        LASSERT(sfs != NULL);
        *eof = 1;
        return snprintf(page, count, "%lu\n", sfs->f_bsize);
}

int lprocfs_rd_kbytestotal(char* page, char **start, off_t off, int count,
                           int *eof, struct statfs *sfs)
{
        __u32 blk_size;
        __u64 result;

        LASSERT(sfs != NULL);
        blk_size = sfs->f_bsize >> 10;
        result = sfs->f_blocks;

        while (blk_size >>= 1)
                result <<= 1;

        *eof = 1;
        return snprintf(page, count, LPU64"\n", result);
}

int lprocfs_rd_kbytesfree(char* page, char **start, off_t off, int count,
                          int *eof, struct statfs *sfs)
{
        __u32 blk_size;
        __u64 result;

        LASSERT(sfs != NULL);
        blk_size = sfs->f_bsize >> 10;
        result = sfs->f_bfree;

        while (blk_size >>= 1)
                result <<= 1;

        *eof = 1;
        return snprintf(page, count, LPU64"\n", result);
}

int lprocfs_rd_filestotal(char* page, char **start, off_t off, int count,
                          int *eof, struct statfs *sfs)
{
        LASSERT(sfs != NULL);
        *eof = 1;
        return snprintf(page, count, "%ld\n", sfs->f_files);
}

int lprocfs_rd_filesfree(char* page, char **start, off_t off, int count,
                         int *eof, struct statfs *sfs)
{
        LASSERT(sfs != NULL);
        *eof = 1;
        return snprintf(page, count, "%ld\n", sfs->f_ffree);
}

int lprocfs_rd_filegroups(char* page, char **start, off_t off, int count,
                          int *eof, struct statfs *sfs)
{
        *eof = 1;
        return snprintf(page, count, "unimplemented\n");
}

int lprocfs_rd_server_uuid(char* page, char **start, off_t off, int count,
                           int *eof, void *data)
{
        struct obd_device* obd = (struct obd_device*)data;
        struct client_obd* cli;

        LASSERT(obd != NULL);
        cli = &obd->u.cli;
        *eof = 1;
        return snprintf(page, count, "%s\n", cli->cl_target_uuid.uuid);
}

int lprocfs_rd_conn_uuid(char *page, char **start, off_t off, int count,
                         int *eof,  void *data)
{
        struct obd_device *obd = (struct obd_device*)data;
        struct ptlrpc_connection *conn;

        LASSERT(obd != NULL);
        conn = obd->u.cli.cl_import.imp_connection;
        LASSERT(conn != NULL);
        *eof = 1;
        return snprintf(page, count, "%s\n", conn->c_remote_uuid.uuid);
}

int lprocfs_rd_numrefs(char *page, char **start, off_t off, int count,
                       int *eof, void *data)
{
        struct obd_type* class = (struct obd_type*) data;

        LASSERT(class != NULL);
        *eof = 1;
        return snprintf(page, count, "%d\n", class->typ_refcnt);
}

int lprocfs_obd_attach(struct obd_device *dev, struct lprocfs_vars *list)
{
        int rc = 0;

        LASSERT(dev != NULL);
        LASSERT(dev->obd_type != NULL);
        LASSERT(dev->obd_type->typ_procroot != NULL);

        dev->obd_proc_entry = lprocfs_register(dev->obd_name,
                                               dev->obd_type->typ_procroot,
                                               list, dev);
        if (IS_ERR(dev->obd_proc_entry)) {
                rc = PTR_ERR(dev->obd_proc_entry);
                dev->obd_proc_entry = NULL;
        }
        return rc;
}

int lprocfs_obd_detach(struct obd_device *dev)
{
        if (dev && dev->obd_proc_entry) {
                lprocfs_remove(dev->obd_proc_entry);
                dev->obd_proc_entry = NULL;
        }
        return 0;
}

#endif /* LPROCFS*/

EXPORT_SYMBOL(lprocfs_register);
EXPORT_SYMBOL(lprocfs_remove);
EXPORT_SYMBOL(lprocfs_add_vars);
EXPORT_SYMBOL(lprocfs_obd_attach);
EXPORT_SYMBOL(lprocfs_obd_detach);

EXPORT_SYMBOL(lprocfs_rd_u64);
EXPORT_SYMBOL(lprocfs_rd_uuid);
EXPORT_SYMBOL(lprocfs_rd_name);
EXPORT_SYMBOL(lprocfs_rd_server_uuid);
EXPORT_SYMBOL(lprocfs_rd_conn_uuid);
EXPORT_SYMBOL(lprocfs_rd_numrefs);

EXPORT_SYMBOL(lprocfs_rd_blksize);
EXPORT_SYMBOL(lprocfs_rd_kbytestotal);
EXPORT_SYMBOL(lprocfs_rd_kbytesfree);
EXPORT_SYMBOL(lprocfs_rd_filestotal);
EXPORT_SYMBOL(lprocfs_rd_filesfree);
EXPORT_SYMBOL(lprocfs_rd_filegroups);
