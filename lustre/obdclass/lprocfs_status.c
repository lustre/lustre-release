/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
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
 *   Author: Hariharan Thantry thantry@users.sourceforge.net
 */
#define EXPORT_SYMTAB
#include <linux/config.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/types.h>

#define DEBUG_SUBSYSTEM S_CLASS
#include <linux/obd_class.h>
#include <linux/lprocfs_status.h>

#ifdef LPROCFS

struct proc_dir_entry* lprocfs_srch(struct proc_dir_entry* head,
                                    const char* name)
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

int lprocfs_add_vars(struct proc_dir_entry* root, 
                     struct lprocfs_vars* list,
                     void* data)
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
                        CDEBUG(D_OTHER, 
                               "cur_root=%s, cur=%s, next=%s, (%s)\n", 
                               cur_root->name, cur, next,
                               (proc ? "exists" : "new" ));
                        if (next)
                                cur_root = (proc ? proc : proc_mkdir(cur, cur_root));
                        else
                                if (!proc) 
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
        struct proc_dir_entry *parent = root->parent;

        while (1) {
                while (temp->subdir)
                        temp = temp->subdir;

                rm_entry = temp;
                temp = temp->parent;
                remove_proc_entry(rm_entry->name, rm_entry->parent);
                if (temp == parent) break;
        }
}

struct proc_dir_entry * lprocfs_register(const char* name,
                                         struct proc_dir_entry *parent, 
                                         struct lprocfs_vars *list,
                                         void *data)
{
        struct proc_dir_entry *newchild;

        newchild = lprocfs_srch(parent, name);
        if (newchild) /* return what already exists */
                return newchild;

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
        int rc = snprintf(page, count, LPU64"\n", *(__u64 *)data);
        *eof = 1;
        return rc;
}

int lprocfs_rd_uuid(char* page, char **start, off_t off, int count,
                    int *eof, void *data)
{
        struct obd_device* dev = (struct obd_device*)data;
        int rc = snprintf(page, count, "%s\n", dev->obd_uuid);
        *eof = 1;
        return rc;
}

int lprocfs_rd_name(char* page, char **start, off_t off, int count,
                    int *eof, void *data)
{
        struct obd_device* dev = (struct obd_device*)data;
        int rc = snprintf(page, count, "%s\n", dev->obd_name);
        *eof = 1;
        return rc;
}

int lprocfs_rd_blksize(char* page, char **start, off_t off, int count,
                       int *eof, struct statfs *sfs)
{
        int rc = snprintf(page, count, "%lu\n", sfs->f_bsize);
        *eof = 1;
        return rc;
}
        
int lprocfs_rd_kbytestotal(char* page, char **start, off_t off, int count,
                           int *eof, struct statfs *sfs)
{
        int rc;
        __u32 blk_size;
        __u64 result;

        blk_size = sfs->f_bsize;
        blk_size >>= 10;
        result = sfs->f_blocks;
        while (blk_size >>= 1)
                result <<= 1;

        rc = snprintf(page, count, LPU64"\n", result); 

        *eof = 1;
        return rc;
}

int lprocfs_rd_kbytesfree(char* page, char **start, off_t off, int count,
                          int *eof, struct statfs *sfs)
{
        int rc;
        __u32 blk_size;
        __u64 result;

        blk_size = sfs->f_bsize;
        blk_size >>= 10;
        result = sfs->f_bfree;
        while (blk_size >>= 1)
                result <<= 1;

        rc = snprintf(page, count, LPU64"\n", result); 
        
        *eof = 1;
        return rc;
}

int lprocfs_rd_filestotal(char* page, char **start, off_t off, int count,
                          int *eof, struct statfs *sfs)
{
        int rc = snprintf(page, count, "%ld\n", sfs->f_files); 
        *eof = 1;
        return rc;
}

int lprocfs_rd_filesfree(char* page, char **start, off_t off, int count,
                         int *eof, struct statfs *sfs)
{
        int rc= snprintf(page, count, "%ld\n", sfs->f_ffree);
        *eof = 1;
        return rc;
}

int lprocfs_rd_filegroups(char* page, char **start, off_t off, int count,
                          int *eof, struct statfs *sfs)
{
        int rc = snprintf(page, count, "unimplemented\n");
        *eof = 1;
        return rc;
}

int lprocfs_rd_server_uuid(char* page, char **start, off_t off, int count,
                           int *eof, void *data)
{

        struct obd_device* obd = (struct obd_device*)data;
        struct client_obd* cli = &obd->u.cli;
        return snprintf(page, count, "%s\n", cli->cl_target_uuid);   
}

int lprocfs_rd_conn_uuid(char* page, char **start, off_t off, int count,
                         int *eof,  void *data)
{
        struct obd_device* obd = (struct obd_device*)data;
        struct client_obd* cli = &obd->u.cli;
        struct obd_import* imp = &cli->cl_import;
        int rc;

        rc = snprintf(page, count, "%s\n", 
                      imp->imp_connection->c_remote_uuid);   
        *eof = 1;
        return rc;
}

int lprocfs_rd_numrefs(char* page, char **start, off_t off, int count,
                       int *eof, void *data)
{
        struct obd_type* class = (struct obd_type*) data;
        int rc;

        rc = snprintf(page, count, "%d\n", class->typ_refcnt);
        *eof = 1;
        return rc;
}

int lprocfs_obd_attach(struct obd_device *dev, struct lprocfs_vars *list)
{
        int rc = 0;
        dev->obd_proc_entry = lprocfs_register(dev->obd_name,
                                               dev->obd_type->typ_procroot, 
                                               list,
                                               dev);
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



