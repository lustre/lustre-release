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
#include <linux/seq_file.h>

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

                if ((cur_root == NULL) || (proc == NULL)) {
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
        struct obd_device *obd = (struct obd_device *)data;
        struct client_obd *cli;

        LASSERT(obd != NULL);
        cli = &obd->u.cli;
        *eof = 1;
        return snprintf(page, count, "%s\n",
                        cli->cl_import->imp_target_uuid.uuid);
}

int lprocfs_rd_conn_uuid(char *page, char **start, off_t off, int count,
                         int *eof,  void *data)
{
        struct obd_device *obd = (struct obd_device*)data;
        struct ptlrpc_connection *conn;

        LASSERT(obd != NULL);
        conn = obd->u.cli.cl_import->imp_connection;
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

struct lprocfs_counters* lprocfs_alloc_counters(unsigned int num)
{
        struct lprocfs_counters* cntrs;
        int csize;
        if (num == 0)
                return NULL;

        csize = offsetof(struct lprocfs_counters, cntr[num]);
        OBD_ALLOC(cntrs, csize);
        if (cntrs != NULL) {
                cntrs->num = num;
        }
        return cntrs;
}

void lprocfs_free_counters(struct lprocfs_counters* cntrs)
{
        if (cntrs != NULL) {
                int csize = offsetof(struct lprocfs_counters, cntr[cntrs->num]);                OBD_FREE(cntrs, csize);
        }
}

/* Reset counter under lock */
int lprocfs_counter_write(struct file *file, const char *buffer,
                          unsigned long count, void *data)
{
        struct lprocfs_counters *cntrs = (struct lprocfs_counters*) data;
        unsigned int i;
        LASSERT(cntrs != NULL);

        for (i = 0; i < cntrs->num; i++) {
                struct lprocfs_counter *cntr = &(cntrs->cntr[i]);
                spinlock_t *lock = (cntr->config & LPROCFS_CNTR_EXTERNALLOCK) ?
                        cntr->l.external : &cntr->l.internal;

                spin_lock(lock);
                cntr->count     = 0;
                cntr->sum       = 0;
                cntr->min       = (~(__u64)0);
                cntr->max       = 0;
                cntr->sumsquare = 0;
                spin_unlock(lock);
        }
        return 0;
}

static void *lprocfs_counters_seq_start(struct seq_file *p, loff_t *pos)
{
        struct lprocfs_counters *cntrs = p->private;
        return (*pos >= cntrs->num) ? NULL : (void*) &cntrs->cntr[*pos];
}

static void lprocfs_counters_seq_stop(struct seq_file *p, void *v)
{
}

static void *lprocfs_counters_seq_next(struct seq_file *p, void *v,
                                       loff_t *pos)
{
        struct lprocfs_counters *cntrs = p->private;
        ++*pos;
        return (*pos >= cntrs->num) ? NULL : (void*) &(cntrs->cntr[*pos]);
}

/* seq file export of one lprocfs counter */
static int lprocfs_counters_seq_show(struct seq_file *p, void *v)
{
       struct lprocfs_counters *cntrs = p->private;
       struct lprocfs_counter  *cntr = v;
       spinlock_t              *lock;
       struct lprocfs_counter  c;
       int rc = 0;

       if (cntr == &(cntrs->cntr[0])) {
               struct timeval now;
               do_gettimeofday(&now);
               rc = seq_printf(p, "%-25s %lu.%lu secs.usecs\n",
                               "snapshot_time", now.tv_sec, now.tv_usec);
               if (rc < 0)
                       return rc;
       }

       /* Take a snapshot of the counter under lock */
       lock = (cntr->config & LPROCFS_CNTR_EXTERNALLOCK) ?
               cntr->l.external : &cntr->l.internal;
       spin_lock(lock);

       c.count = cntr->count;
       c.sum = cntr->sum;
       c.min = cntr->min;
       c.max = cntr->max;
       c.sumsquare = cntr->sumsquare;

       spin_unlock(lock);

       rc = seq_printf(p, "%-25s "LPU64" samples [%s]", cntr->name, c.count,
                       cntr->units);
       if (rc < 0)
               goto out;

       if ((cntr->config & LPROCFS_CNTR_AVGMINMAX) && (c.count > 0)) {
               rc = seq_printf(p, " "LPU64" "LPU64" "LPU64, c.min,c.max,c.sum);
               if (rc < 0)
                       goto out;
               if (cntr->config & LPROCFS_CNTR_STDDEV)
                       rc = seq_printf(p, " "LPU64, c.sumsquare);
               if (rc < 0)
                       goto out;
       }
       rc = seq_printf(p, "\n");
 out:
       return (rc < 0) ? rc : 0;
}

struct seq_operations lprocfs_counters_seq_sops = {
        .start = lprocfs_counters_seq_start,
        .stop = lprocfs_counters_seq_stop,
        .next = lprocfs_counters_seq_next,
        .show = lprocfs_counters_seq_show,
};

static int lprocfs_counters_seq_open(struct inode *inode, struct file *file)
{
        struct proc_dir_entry *dp = inode->u.generic_ip;
        struct seq_file *seq;
        int rc;

        rc = seq_open(file, &lprocfs_counters_seq_sops);
        if (rc)
                return rc;
        seq = file->private_data;
        seq->private = dp->data;
        return 0;
}

struct file_operations lprocfs_counters_seq_fops = {
        .open    = lprocfs_counters_seq_open,
        .read    = seq_read,
        .llseek  = seq_lseek,
        .release = seq_release,
};

int lprocfs_register_counters(struct proc_dir_entry *root, const char* name,
                              struct lprocfs_counters *cntrs)
{
        struct proc_dir_entry *entry;
        LASSERT(root != NULL);

        entry = create_proc_entry(name, 0444, root);
        if (entry == NULL)
                return -ENOMEM;
        entry->proc_fops = &lprocfs_counters_seq_fops;
        entry->data = (void*) cntrs;
        entry->write_proc = lprocfs_counter_write;
        return 0;
}

#define LPROCFS_OBD_OP_INIT(base, cntrs, op)                               \
do {                                                                       \
        unsigned int coffset = base + OBD_COUNTER_OFFSET(op);              \
        LASSERT(coffset < cntrs->num);                                     \
        LPROCFS_COUNTER_INIT(&cntrs->cntr[coffset], 0, NULL, #op, "reqs"); \
} while (0)


int lprocfs_alloc_obd_counters(struct obd_device *obddev,
                               unsigned int num_private_counters)
{
        struct lprocfs_counters* obdops_cntrs;
        unsigned int num_counters;
        int rc, i;

        LASSERT(obddev->counters == NULL);
        LASSERT(obddev->obd_proc_entry != NULL);
        LASSERT(obddev->cntr_base == 0);

        num_counters = 1 + OBD_COUNTER_OFFSET(san_preprw)+num_private_counters;
        obdops_cntrs = lprocfs_alloc_counters(num_counters);
        if (!obdops_cntrs)
                return -ENOMEM;

        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, iocontrol);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, get_info);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, set_info);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, attach);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, detach);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, setup);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, cleanup);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, connect);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, disconnect);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, statfs);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, syncfs);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, packmd);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, unpackmd);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, preallocate);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, create);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, destroy);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, setattr);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, getattr);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, getattr_async);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, open);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, close);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, brw);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, brw_async);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, punch);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, sync);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, migrate);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, copy);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, iterate);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, preprw);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, commitrw);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, enqueue);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, match);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, cancel);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, cancel_unused);
        LPROCFS_OBD_OP_INIT(num_private_counters, obdops_cntrs, san_preprw);

        for (i = num_private_counters; i < num_counters; i++) {
                /* If this assertion failed, it is likely that an obd
                 * operation was added to struct obd_ops in
                 * <linux/obd.h>, and that the corresponding line item
                 * LPROCFS_OBD_OP_INIT(.., .., opname)
                 * is missing from the list above. */
                LASSERT(obdops_cntrs->cntr[i].name != NULL);
        }
        rc = lprocfs_register_counters(obddev->obd_proc_entry, "obd_stats",
                                       obdops_cntrs);
        if (rc < 0) {
                lprocfs_free_counters(obdops_cntrs);
        } else {
                obddev->counters  = obdops_cntrs;
                obddev->cntr_base = num_private_counters;
        }
        return rc;
}

void lprocfs_free_obd_counters(struct obd_device *obddev)
{
        struct lprocfs_counters* obdops_cntrs = obddev->counters;
        if (obdops_cntrs != NULL) {
                obddev->counters = NULL;
                lprocfs_free_counters(obdops_cntrs);
        }
}

#endif /* LPROCFS*/

EXPORT_SYMBOL(lprocfs_register);
EXPORT_SYMBOL(lprocfs_remove);
EXPORT_SYMBOL(lprocfs_add_vars);
EXPORT_SYMBOL(lprocfs_obd_attach);
EXPORT_SYMBOL(lprocfs_obd_detach);
EXPORT_SYMBOL(lprocfs_alloc_counters);
EXPORT_SYMBOL(lprocfs_free_counters);
EXPORT_SYMBOL(lprocfs_register_counters);
EXPORT_SYMBOL(lprocfs_alloc_obd_counters);
EXPORT_SYMBOL(lprocfs_free_obd_counters);

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
