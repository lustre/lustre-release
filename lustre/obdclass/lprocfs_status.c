/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002, 2003 Cluster File Systems, Inc.
 *   Author: Hariharan Thantry <thantry@users.sourceforge.net>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_CLASS

#ifndef __KERNEL__
# include <liblustre.h>
#endif

#include <obd_class.h>
#include <lprocfs_status.h>
#include <lustre_fsfilt.h>

#if defined(LPROCFS)

struct proc_dir_entry *lprocfs_srch(struct proc_dir_entry *head,
                                    const char *name)
{
        struct proc_dir_entry *temp;

        if (head == NULL)
                return NULL;

        temp = head->subdir;
        while (temp != NULL) {
                if (strcmp(temp->name, name) == 0)
                        return temp;

                temp = temp->next;
        }
        return NULL;
}

/* lprocfs API calls */

int lprocfs_add_vars(struct proc_dir_entry *root, struct lprocfs_vars *list,
                     void *data)
{
        if (root == NULL || list == NULL)
                return -EINVAL;

        while (list->name != NULL) {
                struct proc_dir_entry *cur_root, *proc;
                char *pathcopy, *cur, *next, pathbuf[64];
                int pathsize = strlen(list->name) + 1;

                proc = NULL;
                cur_root = root;

                /* need copy of path for strsep */
                if (strlen(list->name) > sizeof(pathbuf) - 1) {
                        OBD_ALLOC(pathcopy, pathsize);
                        if (pathcopy == NULL)
                                return -ENOMEM;
                } else {
                        pathcopy = pathbuf;
                }

                next = pathcopy;
                strcpy(pathcopy, list->name);

                while (cur_root != NULL && (cur = strsep(&next, "/"))) {
                        if (*cur =='\0') /* skip double/trailing "/" */
                                continue;

                        proc = lprocfs_srch(cur_root, cur);
                        CDEBUG(D_OTHER, "cur_root=%s, cur=%s, next=%s, (%s)\n",
                               cur_root->name, cur, next,
                               (proc ? "exists" : "new"));
                        if (next != NULL) {
                                cur_root = (proc ? proc :
                                            proc_mkdir(cur, cur_root));
                        } else if (proc == NULL) {
                                mode_t mode = 0;
                                if (list->read_fptr)
                                        mode = 0444;
                                if (list->write_fptr)
                                        mode |= 0200;
                                proc = create_proc_entry(cur, mode, cur_root);
                        }
                }

                if (pathcopy != pathbuf)
                        OBD_FREE(pathcopy, pathsize);

                if (cur_root == NULL || proc == NULL) {
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

void lprocfs_remove(struct proc_dir_entry *root)
{
        struct proc_dir_entry *temp = root;
        struct proc_dir_entry *rm_entry;
        struct proc_dir_entry *parent;

        LASSERT(root != NULL);
        parent = root->parent;
        LASSERT(parent != NULL);
 
        while (1) {
                while (temp->subdir != NULL)
                        temp = temp->subdir;

                rm_entry = temp;
                temp = temp->parent;

                /* Memory corruption once caused this to fail, and
                   without this LASSERT we would loop here forever. */
                LASSERTF(strlen(rm_entry->name) == rm_entry->namelen,
                         "0x%p  %s/%s len %d\n", rm_entry, temp->name,
                         rm_entry->name, (int)strlen(rm_entry->name));

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
        if (newchild != NULL) {
                CERROR(" Lproc: Attempting to register %s more than once \n",
                       name);
                return ERR_PTR(-EALREADY);
        }

        newchild = proc_mkdir(name, parent);
        if (newchild != NULL && list != NULL) {
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

int lprocfs_rd_atomic(char *page, char **start, off_t off,
                   int count, int *eof, void *data)
{
        atomic_t *atom = (atomic_t *)data;
        LASSERT(atom != NULL);
        *eof = 1;
        return snprintf(page, count, "%d\n", atomic_read(atom));
}

int lprocfs_rd_uuid(char *page, char **start, off_t off, int count,
                    int *eof, void *data)
{
        struct obd_device *obd = (struct obd_device*)data;

        LASSERT(obd != NULL);
        *eof = 1;
        return snprintf(page, count, "%s\n", obd->obd_uuid.uuid);
}

int lprocfs_rd_name(char *page, char **start, off_t off, int count,
                    int *eof, void* data)
{
        struct obd_device *dev = (struct obd_device *)data;

        LASSERT(dev != NULL);
        LASSERT(dev->obd_name != NULL);
        *eof = 1;
        return snprintf(page, count, "%s\n", dev->obd_name);
}

int lprocfs_rd_fstype(char *page, char **start, off_t off, int count, int *eof,
                      void *data)
{
        struct obd_device *obd = (struct obd_device *)data;

        LASSERT(obd != NULL);
        LASSERT(obd->obd_fsops != NULL);
        LASSERT(obd->obd_fsops->fs_type != NULL);
        return snprintf(page, count, "%s\n", obd->obd_fsops->fs_type);
}

int lprocfs_rd_blksize(char *page, char **start, off_t off, int count,
                       int *eof, void *data)
{
        struct obd_statfs osfs;
        int rc = obd_statfs(data, &osfs, get_jiffies_64() - HZ);
        if (!rc) {
                *eof = 1;
                rc = snprintf(page, count, "%u\n", osfs.os_bsize);
        }
        return rc;
}

int lprocfs_rd_kbytestotal(char *page, char **start, off_t off, int count,
                           int *eof, void *data)
{
        struct obd_statfs osfs;
        int rc = obd_statfs(data, &osfs, get_jiffies_64() - HZ);
        if (!rc) {
                __u32 blk_size = osfs.os_bsize >> 10;
                __u64 result = osfs.os_blocks;

                while (blk_size >>= 1)
                        result <<= 1;

                *eof = 1;
                rc = snprintf(page, count, LPU64"\n", result);
        }
        return rc;
}

int lprocfs_rd_kbytesfree(char *page, char **start, off_t off, int count,
                          int *eof, void *data)
{
        struct obd_statfs osfs;
        int rc = obd_statfs(data, &osfs, get_jiffies_64() - HZ);
        if (!rc) {
                __u32 blk_size = osfs.os_bsize >> 10;
                __u64 result = osfs.os_bfree;

                while (blk_size >>= 1)
                        result <<= 1;

                *eof = 1;
                rc = snprintf(page, count, LPU64"\n", result);
        }
        return rc;
}

int lprocfs_rd_kbytesavail(char *page, char **start, off_t off, int count,
                           int *eof, void *data)
{
        struct obd_statfs osfs;
        int rc = obd_statfs(data, &osfs, get_jiffies_64() - HZ);
        if (!rc) {
                __u32 blk_size = osfs.os_bsize >> 10;
                __u64 result = osfs.os_bavail;

                while (blk_size >>= 1)
                        result <<= 1;

                *eof = 1;
                rc = snprintf(page, count, LPU64"\n", result);
        }
        return rc;
}

int lprocfs_rd_filestotal(char *page, char **start, off_t off, int count,
                          int *eof, void *data)
{
        struct obd_statfs osfs;
        int rc = obd_statfs(data, &osfs, get_jiffies_64() - HZ);
        if (!rc) {
                *eof = 1;
                rc = snprintf(page, count, LPU64"\n", osfs.os_files);
        }

        return rc;
}

int lprocfs_rd_filesfree(char *page, char **start, off_t off, int count,
                         int *eof, void *data)
{
        struct obd_statfs osfs;
        int rc = obd_statfs(data, &osfs, get_jiffies_64() - HZ);
        if (!rc) {
                *eof = 1;
                rc = snprintf(page, count, LPU64"\n", osfs.os_ffree);
        }
        return rc;
}

int lprocfs_rd_server_uuid(char *page, char **start, off_t off, int count,
                           int *eof, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        struct obd_import *imp;
        char *imp_state_name = NULL;

        LASSERT(obd != NULL);
        imp = obd->u.cli.cl_import;
        imp_state_name = ptlrpc_import_state_name(imp->imp_state);
        *eof = 1;
        return snprintf(page, count, "%s\t%s%s\n",
                        obd2cli_tgt(obd), imp_state_name,
                        imp->imp_deactive ? "\tDEACTIVATED" : "");
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

static const char *obd_connect_names[] = {
        "read_only",
        "lov_index",
        "unused",
        "write_grant",
        "server_lock",
        "version",
        "request_portal",
        "acl",
        "xattr",
        "create_on_write",
        "truncate_lock",
        "initial_transno",
        "inode_bit_locks",
        "join_file",
        "getattr_by_fid",
        "no_oh_for_devices",
        NULL
};

int lprocfs_rd_connect_flags(char *page, char **start, off_t off,
                             int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        __u64 mask = 1, flags;
        int i, ret;

        if (obd == NULL)
                return 0;

        flags = obd->u.cli.cl_import->imp_connect_data.ocd_connect_flags;
        ret = snprintf(page, count, "flags="LPX64"\n", flags);
        for (i = 0; obd_connect_names[i] != NULL; i++, mask <<= 1) {
                if (flags & mask)
                        ret += snprintf(page + ret, count - ret, "%s\n",
                                        obd_connect_names[i]);
        }
        if (flags & ~(mask - 1))
                ret += snprintf(page + ret, count - ret,
                                "unknown flags "LPX64"\n", flags & ~(mask - 1));

        return ret;
}
EXPORT_SYMBOL(lprocfs_rd_connect_flags);

int lprocfs_rd_num_exports(char *page, char **start, off_t off, int count,
                           int *eof,  void *data)
{
        struct obd_device *obd = (struct obd_device*)data;

        LASSERT(obd != NULL);
        *eof = 1;
        return snprintf(page, count, "%u\n", obd->obd_num_exports);
}

int lprocfs_rd_numrefs(char *page, char **start, off_t off, int count,
                       int *eof, void *data)
{
        struct obd_type *class = (struct obd_type*) data;

        LASSERT(class != NULL);
        *eof = 1;
        return snprintf(page, count, "%d\n", class->typ_refcnt);
}

int lprocfs_obd_setup(struct obd_device *obd, struct lprocfs_vars *list)
{
        int rc = 0;

        LASSERT(obd != NULL);
        LASSERT(obd->obd_magic == OBD_DEVICE_MAGIC);
        LASSERT(obd->obd_type->typ_procroot != NULL);

        obd->obd_proc_entry = lprocfs_register(obd->obd_name,
                                               obd->obd_type->typ_procroot,
                                               list, obd);
        if (IS_ERR(obd->obd_proc_entry)) {
                rc = PTR_ERR(obd->obd_proc_entry);
                CERROR("error %d setting up lprocfs for %s\n",rc,obd->obd_name);
                obd->obd_proc_entry = NULL;
        }
        return rc;
}

int lprocfs_obd_cleanup(struct obd_device *obd)
{
        if (obd && obd->obd_proc_entry) {
                lprocfs_remove(obd->obd_proc_entry);
                obd->obd_proc_entry = NULL;
        }
        return 0;
}

struct lprocfs_stats *lprocfs_alloc_stats(unsigned int num)
{
        struct lprocfs_stats *stats;
        struct lprocfs_percpu *percpu;
        unsigned int percpusize;
        unsigned int i;

        if (num == 0)
                return NULL;

        OBD_ALLOC(stats, offsetof(typeof(*stats), ls_percpu[num_online_cpus()]));
        if (stats == NULL)
                return NULL;

        percpusize = L1_CACHE_ALIGN(offsetof(typeof(*percpu), lp_cntr[num]));
        stats->ls_percpu_size = num_online_cpus() * percpusize;
        OBD_ALLOC(stats->ls_percpu[0], stats->ls_percpu_size);
        if (stats->ls_percpu[0] == NULL) {
                OBD_FREE(stats, offsetof(typeof(*stats),
                                         ls_percpu[num_online_cpus()]));
                return NULL;
        }

        stats->ls_num = num;
        for (i = 1; i < num_online_cpus(); i++)
                stats->ls_percpu[i] = (void *)(stats->ls_percpu[i - 1]) +
                        percpusize;

        return stats;
}

void lprocfs_free_stats(struct lprocfs_stats *stats)
{
        if (stats->ls_num == 0)
                return;

        OBD_FREE(stats->ls_percpu[0], stats->ls_percpu_size);
        OBD_FREE(stats, offsetof(typeof(*stats), ls_percpu[num_online_cpus()]));
}

/* Reset counter under lock */
int lprocfs_counter_write(struct file *file, const char *buffer,
                          unsigned long count, void *data)
{
        /* not supported */
        return 0;
}

static void *lprocfs_stats_seq_start(struct seq_file *p, loff_t *pos)
{
        struct lprocfs_stats *stats = p->private;
        /* return 1st cpu location */
        return (*pos >= stats->ls_num) ? NULL :
                &(stats->ls_percpu[0]->lp_cntr[*pos]);
}

static void lprocfs_stats_seq_stop(struct seq_file *p, void *v)
{
}

static void *lprocfs_stats_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
        struct lprocfs_stats *stats = p->private;
        ++*pos;
        return (*pos >= stats->ls_num) ? NULL :
                &(stats->ls_percpu[0]->lp_cntr[*pos]);
}

/* seq file export of one lprocfs counter */
static int lprocfs_stats_seq_show(struct seq_file *p, void *v)
{
       struct lprocfs_stats *stats = p->private;
       struct lprocfs_counter  *cntr = v;
       struct lprocfs_counter  t, ret = { .lc_min = ~(__u64)0 };
       int i, idx, rc;

       if (cntr == &(stats->ls_percpu[0])->lp_cntr[0]) {
               struct timeval now;
               do_gettimeofday(&now);
               rc = seq_printf(p, "%-25s %lu.%lu secs.usecs\n",
                               "snapshot_time", now.tv_sec, now.tv_usec);
               if (rc < 0)
                       return rc;
       }
       idx = cntr - &(stats->ls_percpu[0])->lp_cntr[0];

       for (i = 0; i < num_online_cpus(); i++) {
               struct lprocfs_counter *percpu_cntr =
                       &(stats->ls_percpu[i])->lp_cntr[idx];
               int centry;

               do {
                       centry = atomic_read(&percpu_cntr->lc_cntl.la_entry);
                       t.lc_count = percpu_cntr->lc_count;
                       t.lc_sum = percpu_cntr->lc_sum;
                       t.lc_min = percpu_cntr->lc_min;
                       t.lc_max = percpu_cntr->lc_max;
                       t.lc_sumsquare = percpu_cntr->lc_sumsquare;
               } while (centry != atomic_read(&percpu_cntr->lc_cntl.la_entry) &&
                        centry != atomic_read(&percpu_cntr->lc_cntl.la_exit));
               ret.lc_count += t.lc_count;
               ret.lc_sum += t.lc_sum;
               if (t.lc_min < ret.lc_min)
                       ret.lc_min = t.lc_min;
               if (t.lc_max > ret.lc_max)
                       ret.lc_max = t.lc_max;
               ret.lc_sumsquare += t.lc_sumsquare;
       }

       rc = seq_printf(p, "%-25s "LPU64" samples [%s]", cntr->lc_name,
                       ret.lc_count, cntr->lc_units);
       if (rc < 0)
               goto out;

       if ((cntr->lc_config & LPROCFS_CNTR_AVGMINMAX) && (ret.lc_count > 0)) {
               rc = seq_printf(p, " "LPU64" "LPU64" "LPU64,
                               ret.lc_min, ret.lc_max, ret.lc_sum);
               if (rc < 0)
                       goto out;
               if (cntr->lc_config & LPROCFS_CNTR_STDDEV)
                       rc = seq_printf(p, " "LPU64, ret.lc_sumsquare);
               if (rc < 0)
                       goto out;
       }
       rc = seq_printf(p, "\n");
 out:
       return (rc < 0) ? rc : 0;
}

struct seq_operations lprocfs_stats_seq_sops = {
        start: lprocfs_stats_seq_start,
        stop:  lprocfs_stats_seq_stop,
        next:  lprocfs_stats_seq_next,
        show:  lprocfs_stats_seq_show,
};

static int lprocfs_stats_seq_open(struct inode *inode, struct file *file)
{
        struct proc_dir_entry *dp = PDE(inode);
        struct seq_file *seq;
        int rc;

        rc = seq_open(file, &lprocfs_stats_seq_sops);
        if (rc)
                return rc;
        seq = file->private_data;
        seq->private = dp->data;
        return 0;
}

struct file_operations lprocfs_stats_seq_fops = {
        .owner   = THIS_MODULE,
        .open    = lprocfs_stats_seq_open,
        .read    = seq_read,
        .llseek  = seq_lseek,
        .release = seq_release,
};

int lprocfs_register_stats(struct proc_dir_entry *root, const char *name,
                           struct lprocfs_stats *stats)
{
        struct proc_dir_entry *entry;
        LASSERT(root != NULL);

        entry = create_proc_entry(name, 0444, root);
        if (entry == NULL)
                return -ENOMEM;
        entry->proc_fops = &lprocfs_stats_seq_fops;
        entry->data = (void *)stats;
        entry->write_proc = lprocfs_counter_write;
        return 0;
}

void lprocfs_counter_init(struct lprocfs_stats *stats, int index,
                          unsigned conf, const char *name, const char *units)
{
        struct lprocfs_counter *c;
        int i;

        LASSERT(stats != NULL);
        for (i = 0; i < num_online_cpus(); i++) {
                c = &(stats->ls_percpu[i]->lp_cntr[index]);
                c->lc_config = conf;
                c->lc_min = ~(__u64)0;
                c->lc_name = name;
                c->lc_units = units;
        }
}
EXPORT_SYMBOL(lprocfs_counter_init);

#define LPROCFS_OBD_OP_INIT(base, stats, op)                               \
do {                                                                       \
        unsigned int coffset = base + OBD_COUNTER_OFFSET(op);              \
        LASSERT(coffset < stats->ls_num);                                  \
        lprocfs_counter_init(stats, coffset, 0, #op, "reqs");              \
} while (0)

int lprocfs_alloc_obd_stats(struct obd_device *obd, unsigned num_private_stats)
{
        struct lprocfs_stats *stats;
        unsigned int num_stats;
        int rc, i;

        LASSERT(obd->obd_stats == NULL);
        LASSERT(obd->obd_proc_entry != NULL);
        LASSERT(obd->obd_cntr_base == 0);

        num_stats = (sizeof(*obd->obd_type->typ_ops) / sizeof(void *)) +
                num_private_stats - 1 /* o_owner */;
        stats = lprocfs_alloc_stats(num_stats);
        if (stats == NULL)
                return -ENOMEM;

        LPROCFS_OBD_OP_INIT(num_private_stats, stats, iocontrol);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, get_info);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, set_info_async);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, attach);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, detach);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, setup);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, precleanup);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, cleanup);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, process_config);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, postrecov);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, add_conn);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, del_conn);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, connect);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, reconnect);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, disconnect);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, statfs);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, statfs_async);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, packmd);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, unpackmd);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, checkmd);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, preallocate);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, create);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, destroy);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, setattr);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, setattr_async);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, getattr);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, getattr_async);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, brw);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, brw_async);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, prep_async_page);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, queue_async_io);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, queue_group_io);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, trigger_group_io);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, set_async_flags);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, teardown_async_page);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, merge_lvb);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, adjust_kms);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, punch);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, sync);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, migrate);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, copy);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, iterate);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, preprw);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, commitrw);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, enqueue);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, match);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, change_cbdata);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, cancel);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, cancel_unused);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, join_lru);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, san_preprw);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, init_export);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, destroy_export);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, extent_calc);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, llog_init);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, llog_finish);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, pin);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, unpin);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, import_event);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, notify);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, health_check);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, quotacheck);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, quotactl);
        LPROCFS_OBD_OP_INIT(num_private_stats, stats, ping);

        for (i = num_private_stats; i < num_stats; i++) {
                /* If this LBUGs, it is likely that an obd
                 * operation was added to struct obd_ops in
                 * <obd.h>, and that the corresponding line item
                 * LPROCFS_OBD_OP_INIT(.., .., opname)
                 * is missing from the list above. */
                LASSERTF(stats->ls_percpu[0]->lp_cntr[i].lc_name != NULL,
                         "Missing obd_stat initializer obd_op "
                         "operation at offset %d.\n", i - num_private_stats);
        }
        rc = lprocfs_register_stats(obd->obd_proc_entry, "stats", stats);
        if (rc < 0) {
                lprocfs_free_stats(stats);
        } else {
                obd->obd_stats  = stats;
                obd->obd_cntr_base = num_private_stats;
        }
        return rc;
}

void lprocfs_free_obd_stats(struct obd_device *obd)
{
        struct lprocfs_stats *stats = obd->obd_stats;

        if (stats != NULL) {
                obd->obd_stats = NULL;
                lprocfs_free_stats(stats);
        }
}

int lprocfs_write_helper(const char *buffer, unsigned long count,
                         int *val)
{
        return lprocfs_write_frac_helper(buffer, count, val, 1);
}

int lprocfs_write_frac_helper(const char *buffer, unsigned long count,
                              int *val, int mult)
{
        char kernbuf[20], *end, *pbuf;

        if (count > (sizeof(kernbuf) - 1))
                return -EINVAL;

        if (copy_from_user(kernbuf, buffer, count))
                return -EFAULT;

        kernbuf[count] = '\0';
        pbuf = kernbuf;
        if (*pbuf == '-') {
                mult = -mult;
                pbuf++;
        }

        *val = (int)simple_strtoul(pbuf, &end, 10) * mult;
        if (pbuf == end)
                return -EINVAL;

        if (end != NULL && *end == '.') {
                int temp_val, pow = 1;
                int i;

                pbuf = end + 1;
                if (strlen(pbuf) > 5)
                        pbuf[5] = '\0'; /*only allow 5bits fractional*/

                temp_val = (int)simple_strtoul(pbuf, &end, 10) * mult;

                if (pbuf < end) {
                        for (i = 0; i < (end - pbuf); i++)
                                pow *= 10;

                        *val += temp_val / pow;
                }
        }
        return 0;
}

int lprocfs_read_frac_helper(char *buffer, unsigned long count, long val, int mult)
{
        long decimal_val,frac_val;
        int prtn;

        if (count < 10)
                return -EINVAL;

        decimal_val =val / mult;
        prtn = snprintf(buffer, count, "%ld", decimal_val);
        frac_val = val % mult;

        if (prtn < (count - 4) && frac_val > 0) {
                long temp_frac;
                int i, temp_mult = 1, frac_bits = 0;

                temp_frac = frac_val * 10;
                buffer[prtn++] = '.';
                while (frac_bits < 2 && (temp_frac / mult) < 1 ) { /*only reserved 2bits fraction*/
                        buffer[prtn++] ='0';
                        temp_frac *= 10;
                        frac_bits++;
                }
                /*
                  Need to think these cases :
                        1. #echo x.00 > /proc/xxx       output result : x
                        2. #echo x.0x > /proc/xxx       output result : x.0x
                        3. #echo x.x0 > /proc/xxx       output result : x.x
                        4. #echo x.xx > /proc/xxx       output result : x.xx
                        Only reserved 2bits fraction.       
                 */
                for (i = 0; i < (5 - prtn); i++)
                        temp_mult *= 10;

                frac_bits = min((int)count - prtn, 3 - frac_bits);
                prtn += snprintf(buffer + prtn, frac_bits, "%ld", frac_val * temp_mult / mult);

                prtn--;
                while(buffer[prtn] < '1' || buffer[prtn] > '9') {
                        prtn--;
                        if (buffer[prtn] == '.') {
                                prtn--;
                                break;
                        }
                }
                prtn++;
        }
        buffer[prtn++] ='\n';
        return prtn;
}

int lprocfs_write_u64_helper(const char *buffer, unsigned long count,__u64 *val)
{
        return lprocfs_write_frac_u64_helper(buffer, count, val, 1);
}

int lprocfs_write_frac_u64_helper(const char *buffer, unsigned long count,
                              __u64 *val, int mult)
{
        char kernbuf[22], *end, *pbuf;

        if (count > (sizeof(kernbuf) - 1) )
                return -EINVAL;

        if (copy_from_user(kernbuf, buffer, count))
                return -EFAULT;

        kernbuf[count] = '\0';
        pbuf = kernbuf;
        if (*pbuf == '-') {
                mult = -mult;
                pbuf++;
        }

        *val = simple_strtoull(pbuf, &end, 10) * mult;
        if (pbuf == end)
                return -EINVAL;

        if (end != NULL && *end == '.') {
                int temp_val;
                int i, pow = 1;

                pbuf = end + 1;
                if (strlen(pbuf) > 10)
                        pbuf[10] = '\0';

                temp_val = (int)simple_strtoull(pbuf, &end, 10) * mult;

                if (pbuf < end) {
                        for (i = 0; i < (end - pbuf); i++)
                                pow *= 10;

                        *val += (__u64)(temp_val / pow);
                }
        }
        return 0;
}

int lprocfs_obd_seq_create(struct obd_device *dev, char *name, mode_t mode,
                           struct file_operations *seq_fops, void *data)
{
        struct proc_dir_entry *entry;
        ENTRY;

        entry = create_proc_entry(name, mode, dev->obd_proc_entry);
        if (entry == NULL)
                RETURN(-ENOMEM);
        entry->proc_fops = seq_fops;
        entry->data = data;

        RETURN(0);
}
EXPORT_SYMBOL(lprocfs_obd_seq_create);

void lprocfs_oh_tally(struct obd_histogram *oh, unsigned int value)
{
        if (value >= OBD_HIST_MAX)
                value = OBD_HIST_MAX - 1;

        spin_lock(&oh->oh_lock);
        oh->oh_buckets[value]++;
        spin_unlock(&oh->oh_lock);
}
EXPORT_SYMBOL(lprocfs_oh_tally);

void lprocfs_oh_tally_log2(struct obd_histogram *oh, unsigned int value)
{
        unsigned int val;

        for (val = 0; ((1 << val) < value) && (val <= OBD_HIST_MAX); val++)
                ;

        lprocfs_oh_tally(oh, val);
}
EXPORT_SYMBOL(lprocfs_oh_tally_log2);

unsigned long lprocfs_oh_sum(struct obd_histogram *oh)
{
        unsigned long ret = 0;
        int i;

        for (i = 0; i < OBD_HIST_MAX; i++)
                ret +=  oh->oh_buckets[i];
        return ret;
}
EXPORT_SYMBOL(lprocfs_oh_sum);

void lprocfs_oh_clear(struct obd_histogram *oh)
{
        spin_lock(&oh->oh_lock);
        memset(oh->oh_buckets, 0, sizeof(oh->oh_buckets));
        spin_unlock(&oh->oh_lock);
}
EXPORT_SYMBOL(lprocfs_oh_clear);

int lprocfs_obd_rd_recovery_status(char *page, char **start, off_t off,
                                          int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        int len = 0, n,
                connected = obd->obd_connected_clients,
                max_recoverable = obd->obd_max_recoverable_clients,
                recoverable = obd->obd_recoverable_clients,
                completed = max_recoverable - recoverable,
                queue_len = obd->obd_requests_queued_for_recovery,
                replayed = obd->obd_replayed_requests;
        __u64 next_transno = obd->obd_next_recovery_transno;

        LASSERT(obd != NULL);
        *eof = 1;

        n = snprintf(page, count, "status: ");
        page += n; len += n; count -= n;
        if (obd->obd_max_recoverable_clients == 0) {
                n = snprintf(page, count, "INACTIVE\n");
                return len + n;
        }

        /* sampled unlocked, but really... */
        if (obd->obd_recovering == 0) {
                n = snprintf(page, count, "COMPLETE\n");
                page += n; len += n; count -= n;

                n = snprintf(page, count, "recovery_start: %lu\n",
                             obd->obd_recovery_start);
                page += n; len += n; count -= n;
                n = snprintf(page, count, "recovery_end: %lu\n",
                             obd->obd_recovery_end);
                page += n; len += n; count -= n;
                n = snprintf(page, count, "recovered_clients: %d\n",
                             completed);
                page += n; len += n; count -= n;
                n = snprintf(page, count, "unrecovered_clients: %d\n",
                             obd->obd_recoverable_clients);
                page += n; len += n; count -= n;
                n = snprintf(page, count, "last_transno: "LPD64"\n",
                             next_transno - 1);
                page += n; len += n; count -= n;
                n = snprintf(page, count, "replayed_requests: %d\n", replayed);
                return len + n;
        }

        n = snprintf(page, count, "RECOVERING\n");
        page += n; len += n; count -= n;
        n = snprintf(page, count, "recovery_start: %lu\n",
                     obd->obd_recovery_start);
        page += n; len += n; count -= n;
        n = snprintf(page, count, "time remaining: %lu\n",
                     CURRENT_SECONDS >= obd->obd_recovery_end ? 0 : 
                     obd->obd_recovery_end - CURRENT_SECONDS);
        page += n; len += n; count -= n;
        n = snprintf(page, count, "connected_clients: %d/%d\n",
                     connected, max_recoverable);
        page += n; len += n; count -= n;
        n = snprintf(page, count, "completed_clients: %d/%d\n",
                     completed, max_recoverable);
        page += n; len += n; count -= n;
        n = snprintf(page, count, "replayed_requests: %d/??\n", replayed);
        page += n; len += n; count -= n;
        n = snprintf(page, count, "queued_requests: %d\n", queue_len);
        page += n; len += n; count -= n;
        n = snprintf(page, count, "next_transno: "LPD64"\n", next_transno);
        return len + n;
}
EXPORT_SYMBOL(lprocfs_obd_rd_recovery_status);

EXPORT_SYMBOL(lprocfs_register);
EXPORT_SYMBOL(lprocfs_srch);
EXPORT_SYMBOL(lprocfs_remove);
EXPORT_SYMBOL(lprocfs_add_vars);
EXPORT_SYMBOL(lprocfs_obd_setup);
EXPORT_SYMBOL(lprocfs_obd_cleanup);
EXPORT_SYMBOL(lprocfs_alloc_stats);
EXPORT_SYMBOL(lprocfs_free_stats);
EXPORT_SYMBOL(lprocfs_register_stats);
EXPORT_SYMBOL(lprocfs_alloc_obd_stats);
EXPORT_SYMBOL(lprocfs_free_obd_stats);

EXPORT_SYMBOL(lprocfs_rd_u64);
EXPORT_SYMBOL(lprocfs_rd_atomic);
EXPORT_SYMBOL(lprocfs_rd_uuid);
EXPORT_SYMBOL(lprocfs_rd_name);
EXPORT_SYMBOL(lprocfs_rd_fstype);
EXPORT_SYMBOL(lprocfs_rd_server_uuid);
EXPORT_SYMBOL(lprocfs_rd_conn_uuid);
EXPORT_SYMBOL(lprocfs_rd_num_exports);
EXPORT_SYMBOL(lprocfs_rd_numrefs);

EXPORT_SYMBOL(lprocfs_rd_blksize);
EXPORT_SYMBOL(lprocfs_rd_kbytestotal);
EXPORT_SYMBOL(lprocfs_rd_kbytesfree);
EXPORT_SYMBOL(lprocfs_rd_kbytesavail);
EXPORT_SYMBOL(lprocfs_rd_filestotal);
EXPORT_SYMBOL(lprocfs_rd_filesfree);

EXPORT_SYMBOL(lprocfs_write_helper);
EXPORT_SYMBOL(lprocfs_write_frac_helper);
EXPORT_SYMBOL(lprocfs_read_frac_helper);
EXPORT_SYMBOL(lprocfs_write_u64_helper);
EXPORT_SYMBOL(lprocfs_write_frac_u64_helper);
#endif /* LPROCFS*/
