/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/smfs/audit_transfer.c
 *
 *  Copyright (C) 2004 Cluster File Systems, Inc.
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
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#define DEBUG_SUBSYSTEM S_SM

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/obd_class.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_smfs.h>
#include <linux/lustre_audit.h>
#include <linux/lustre_log.h>
#include "smfs_internal.h"

struct transfer_item {
        struct llog_handle      *ti_llh;
        struct list_head        ti_link;
        void * id2name;
};

#define TRANSFERD_STOP          0
struct transferd_ctl {
        unsigned long           tc_flags;
        wait_queue_head_t       tc_waitq;
        struct completion       tc_starting;
        struct completion       tc_stopping;

        struct list_head        tc_list;
        spinlock_t              tc_lock;
};

static struct transferd_ctl transferd_tc;
static DECLARE_MUTEX(transferd_sem);
static int transferd_users = 0;
char *buf = NULL;

int audit_notify(struct llog_handle *llh, void * arg)
{
        struct transfer_item *ti;
        ENTRY;

        down(&transferd_sem);
        if (transferd_users == 0) {
                up(&transferd_sem);
                RETURN(0);
        }
        up(&transferd_sem);

        if (test_bit(TRANSFERD_STOP, &transferd_tc.tc_flags)) {
                CDEBUG(D_INFO, "transfer daemon stopped\n");
                RETURN(0);
        }

        OBD_ALLOC(ti, sizeof(*ti));
        if (ti == NULL)
                RETURN(-ENOMEM);
        
        INIT_LIST_HEAD(&ti->ti_link);
        ti->ti_llh = llh;
        ti->id2name = arg;

        spin_lock(&transferd_tc.tc_lock);
        list_add_tail(&ti->ti_link, &transferd_tc.tc_list);
        spin_unlock(&transferd_tc.tc_lock);

        wake_up(&transferd_tc.tc_waitq);

        RETURN(0);
}
                                                                                                                                               
const char *opstr[AUDIT_MAX] = {
        [AUDIT_NONE]     "null",
        [AUDIT_CREATE]   "create",
        [AUDIT_LINK]     "link",
        [AUDIT_UNLINK]   "unlink",
        [AUDIT_SYMLINK]  "symlink",
        [AUDIT_RENAME]   "rename",
        [AUDIT_SETATTR]  "setattr",
        [AUDIT_WRITE]    "write",
        [AUDIT_READ]     "read",
        [AUDIT_OPEN]     "open",
        [AUDIT_STAT]     "stat",
        [AUDIT_MMAP]     "mmap",
        [AUDIT_READLINK] "readlink",
        [AUDIT_READDIR]  "readdir",
};

#define construct_header(buf, size, rec, id_rec)                        \
        snprintf(buf, size, "AUDIT:"LPX64":%u/%u:%s:%d:"DLID4":",       \
        rec->nid, rec->uid, rec->gid, opstr[rec->opcode], (__s16)rec->result,\
        (unsigned long)id_rec->au_fid, (unsigned long)id_rec->au_mds, \
        (unsigned long)id_rec->au_num, (unsigned long)id_rec->au_gen);

#define REC2ID(rec, id) {                                       \
        id_ino(id) = rec->au_num;                               \
        id_gen(id) = rec->au_gen;                               \
        id_type(id) = rec->au_type;                             \
        id_fid(id) = rec->au_fid;                               \
        id_group(id) = rec->au_mds;                             \
}

static int 
transfer_record(struct obd_device *obd, struct audit_record *rec, int type, void * data)
{
        struct audit_id_record *id_rec = 
                (struct audit_id_record *)((char *)rec + sizeof(*rec));
        struct audit_name_record *name_rec = NULL;
        int (*audit_id2name)(struct obd_device *obd, char **name, 
                     int *namelen, struct lustre_id *id) = data;

        int n, rc = 0;
        ENTRY;

        CDEBUG(D_INFO, "transfer %s\n", opstr[rec->opcode]);

        memset(buf, 0, PAGE_SIZE);
        n = construct_header(buf, PAGE_SIZE, rec, id_rec);
        if (n < 0)
                RETURN(n);
        
        switch (rec->opcode)
        {
                case AUDIT_UNLINK:
                        if (type != SMFS_AUDIT_NAME_REC)
                                break;
                case AUDIT_LINK:
                case AUDIT_RENAME:
                        id_rec++;
                default:
                        break;
        }
                
        if (audit_id2name) {
                char *name = NULL;
                struct lustre_id id;
                int namelen = 0;
        
                REC2ID(id_rec, &id);
                rc = audit_id2name(obd, &name, &namelen, &id);
                if (rc < 0) {
                        strncat(buf, "unknown", PAGE_SIZE - n);
                        n += strlen("unknown");
                } else if (namelen == 0) {
                        //root itself
                        if (type != SMFS_AUDIT_NAME_REC)
                                strcat(buf, "/");
                } else {
                        strncat(buf, name, PAGE_SIZE - n);
                        n += namelen;
                        OBD_FREE(name, namelen);
                } 
        }
        
        if (type == SMFS_AUDIT_NAME_REC) {
                name_rec = (struct audit_name_record *)((char *)(++id_rec));
                strncat(buf, "/", 1);
                n += 1;
                strncat(buf, name_rec->name, PAGE_SIZE - n);
        }
        
        CDEBUG(D_INFO, "%s\n", buf);

        printk("%s\n", buf);

        RETURN(0);
}

static int transfer_cb(struct llog_handle *llh, struct llog_rec_hdr *rec,
                       void *data)
{
        struct obd_device *obd = llh->lgh_ctxt->loc_obd;
        struct audit_record *ad_rec;
        struct llog_cookie cookie;
        ENTRY;
        
        if (!(le32_to_cpu(llh->lgh_hdr->llh_flags) & LLOG_F_IS_PLAIN)) {
                CERROR("log is not plain\n");
                RETURN(-EINVAL);
        }
        if (rec->lrh_type != cpu_to_le32(SMFS_AUDIT_GEN_REC) &&
            rec->lrh_type != cpu_to_le32(SMFS_AUDIT_NAME_REC)) {
                CERROR("log record type error\n");
                RETURN(-EINVAL);
        }

        ad_rec = (struct audit_record *)((char *)rec + sizeof(*rec));
        
        LASSERT(ad_rec->opcode < AUDIT_MAX);

        cookie.lgc_lgl = llh->lgh_id;
        cookie.lgc_subsys = LLOG_AUDIT_ORIG_CTXT;
        cookie.lgc_index = le32_to_cpu(rec->lrh_index);

        transfer_record(obd, ad_rec, rec->lrh_type, data);
        
        llog_cancel(llh->lgh_ctxt, 1, &cookie, 0, NULL);

        RETURN(0);
}

static int audit_transfer(struct transfer_item *ti)
{
        struct llog_handle *llh = ti->ti_llh;
        int rc = 0;
        ENTRY;

        rc = llog_cat_process(llh, (llog_cb_t)&transfer_cb, ti->id2name);
        if (rc)
                CERROR("process catalog log failed: rc(%d)\n", rc);

        RETURN(0);
}

static int transferd_check(struct transferd_ctl *tc)
{
        int rc = 0;
        ENTRY;
        
        if (test_bit(TRANSFERD_STOP, &tc->tc_flags))
                RETURN(1);
        
        spin_lock(&tc->tc_lock);
        rc = list_empty(&tc->tc_list) ? 0 : 1;
        spin_unlock(&tc->tc_lock);
        
        RETURN(rc);
}
                
static int transferd(void *arg)
{
        struct transferd_ctl *tc = arg;
        unsigned long flags;
        struct list_head *pos, *tmp;
        struct transfer_item *ti = NULL;
        ENTRY;

        lock_kernel();
        
        /* ptlrpc_daemonize() */
        exit_mm(current);
        lustre_daemonize_helper();
        exit_files(current);
        reparent_to_init();
        
        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);
        THREAD_NAME(current->comm, sizeof(current->comm) - 1, "%s", 
                    "audit_transferd");
        unlock_kernel();

        complete(&tc->tc_starting);

        LASSERT(buf == NULL);
        OBD_ALLOC(buf, PAGE_SIZE);
        LASSERT(buf != NULL);

        while (1) {
                struct l_wait_info lwi = { 0 };
                
                l_wait_event(tc->tc_waitq, transferd_check(tc), &lwi);
                
                if (test_bit(TRANSFERD_STOP, &tc->tc_flags))
                        break;
                
                spin_lock(&tc->tc_lock);
                LASSERT(!list_empty(&tc->tc_list));
                ti = list_entry(tc->tc_list.next, struct transfer_item, ti_link);
                list_del_init(&ti->ti_link);
                spin_unlock(&tc->tc_lock);
                
                audit_transfer(ti);
                OBD_FREE(ti, sizeof(*ti));

        }

        OBD_FREE(buf, PAGE_SIZE);

        spin_lock(&tc->tc_lock);
        list_for_each_safe(pos, tmp, &tc->tc_list) {
                ti = list_entry(pos, struct transfer_item, ti_link);
                list_del_init(&ti->ti_link);
                OBD_FREE(ti, sizeof(*ti));
        }
        spin_unlock(&tc->tc_lock);

        complete(&tc->tc_stopping);
        RETURN(0);
}

int audit_start_transferd()
{
        int rc = 0;
        ENTRY;
        
        down(&transferd_sem);
        if (++transferd_users != 1)
                GOTO(out, rc = 0);

        memset(&transferd_tc, 0, sizeof(transferd_tc));
        init_completion(&transferd_tc.tc_starting);
        init_completion(&transferd_tc.tc_stopping);
        init_waitqueue_head(&transferd_tc.tc_waitq);
        transferd_tc.tc_flags = 0;
        INIT_LIST_HEAD(&transferd_tc.tc_list);
        spin_lock_init(&transferd_tc.tc_lock);
        
        if (kernel_thread(transferd, &transferd_tc, 0) < 0) {
                transferd_users--;
                GOTO(out, rc = -ECHILD);
        }

        wait_for_completion(&transferd_tc.tc_starting);
out:
        up(&transferd_sem);
        RETURN(rc);
}

int audit_stop_transferd(void)
{
        int rc = 0;
        ENTRY;

        down(&transferd_sem);
        if (--transferd_users > 0)
                GOTO(out, rc = 0);

        set_bit(TRANSFERD_STOP, &transferd_tc.tc_flags);
        wake_up(&transferd_tc.tc_waitq);
        wait_for_completion(&transferd_tc.tc_stopping);
out:
        up(&transferd_sem);
        RETURN(rc);
}
