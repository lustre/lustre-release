/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/fs/obdfilter/filter.c
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
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

/*
 * Invariant: Get O/R i_sem for lookup, if needed, before any journal ops
 *            (which need to get journal_lock, may block if journal full).
 *
 * Invariant: Call filter_start_transno() before any journal ops to avoid the
 *            same deadlock problem.  We can (and want) to get rid of the
 *            transno sem in favour of the dir/inode i_sem to avoid single
 *            threaded operation on the OST.
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/config.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/init.h>
#include <linux/version.h>
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
# include <linux/mount.h>
# include <linux/buffer_head.h>
#endif

#include <linux/obd_class.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lprocfs_status.h>
#include <linux/lustre_log.h>
#include <linux/lustre_commit_confd.h>

#include "filter_internal.h"

#define S_SHIFT 12
static char *obd_type_by_mode[S_IFMT >> S_SHIFT] = {
        [0]                     NULL,
        [S_IFREG >> S_SHIFT]    "R",
        [S_IFDIR >> S_SHIFT]    "D",
        [S_IFCHR >> S_SHIFT]    "C",
        [S_IFBLK >> S_SHIFT]    "B",
        [S_IFIFO >> S_SHIFT]    "F",
        [S_IFSOCK >> S_SHIFT]   "S",
        [S_IFLNK >> S_SHIFT]    "L"
};

static inline const char *obd_mode_to_type(int mode)
{
        return obd_type_by_mode[(mode & S_IFMT) >> S_SHIFT];
}

static void filter_ffd_addref(void *ffdp)
{
        struct filter_file_data *ffd = ffdp;

        atomic_inc(&ffd->ffd_refcount);
        CDEBUG(D_INFO, "GETting ffd %p : new refcount %d\n", ffd,
               atomic_read(&ffd->ffd_refcount));
}

static struct filter_file_data *filter_ffd_new(void)
{
        struct filter_file_data *ffd;

        OBD_ALLOC(ffd, sizeof *ffd);
        if (ffd == NULL) {
                CERROR("out of memory\n");
                return NULL;
        }

        atomic_set(&ffd->ffd_refcount, 2);

        INIT_LIST_HEAD(&ffd->ffd_handle.h_link);
        class_handle_hash(&ffd->ffd_handle, filter_ffd_addref);

        return ffd;
}

static struct filter_file_data *filter_handle2ffd(struct lustre_handle *handle)
{
        struct filter_file_data *ffd = NULL;
        ENTRY;
        LASSERT(handle != NULL);
        ffd = class_handle2object(handle->cookie);
        if (ffd != NULL)
                LASSERT(ffd->ffd_file->private_data == ffd);
        RETURN(ffd);
}

static void filter_ffd_put(struct filter_file_data *ffd)
{
        CDEBUG(D_INFO, "PUTting ffd %p : new refcount %d\n", ffd,
               atomic_read(&ffd->ffd_refcount) - 1);
        LASSERT(atomic_read(&ffd->ffd_refcount) > 0 &&
                atomic_read(&ffd->ffd_refcount) < 0x5a5a);
        if (atomic_dec_and_test(&ffd->ffd_refcount)) {
                LASSERT(list_empty(&ffd->ffd_handle.h_link));
                OBD_FREE(ffd, sizeof *ffd);
        }
}

static void filter_ffd_destroy(struct filter_file_data *ffd)
{
        class_handle_unhash(&ffd->ffd_handle);
        filter_ffd_put(ffd);
}

static void filter_commit_cb(struct obd_device *obd, __u64 transno,
                             void *cb_data, int error)
{
        obd_transno_commit_cb(obd, transno, error);
}

static int filter_client_log_cancel(struct lustre_handle *conn,
                                    struct lov_stripe_md *lsm, int count,
                                    struct llog_cookie *cookies, int flags)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct llog_commit_data *llcd;
        struct filter_obd *filter = &obd->u.filter;
        int rc = 0;
        ENTRY;

        if (count == 0 || cookies == NULL) {
                down(&filter->fo_sem);
                if (filter->fo_llcd == NULL || !(flags & OBD_LLOG_FL_SENDNOW))
                        GOTO(out, rc);

                llcd = filter->fo_llcd;
                GOTO(send_now, rc);
        }

        down(&filter->fo_sem);
        llcd = filter->fo_llcd;
        if (llcd == NULL) {
                llcd = llcd_grab();
                if (llcd == NULL) {
                        CERROR("couldn't get an llcd - dropped "LPX64":%x+%u\n",
                               cookies->lgc_lgl.lgl_oid,
                               cookies->lgc_lgl.lgl_ogen, cookies->lgc_index);
                        GOTO(out, rc = -ENOMEM);
                }
                llcd->llcd_import = filter->fo_mdc_imp;
                filter->fo_llcd = llcd;
        }

        memcpy(llcd->llcd_cookies + llcd->llcd_cookiebytes, cookies,
               sizeof(*cookies));
        llcd->llcd_cookiebytes += sizeof(*cookies);

        GOTO(send_now, rc);
send_now:
        if ((PAGE_SIZE - llcd->llcd_cookiebytes < sizeof(*cookies) ||
             flags & OBD_LLOG_FL_SENDNOW)) {
                filter->fo_llcd = NULL;
                llcd_send(llcd);
        }
out:
        up(&filter->fo_sem);

        return rc;
}

/* When this (destroy) operation is committed, return the cancel cookie */
static void filter_cancel_cookies_cb(struct obd_device *obd, __u64 transno,
                                     void *cb_data, int error)
{
        filter_client_log_cancel(&obd->u.filter.fo_mdc_conn, NULL, 1,
                                 cb_data, OBD_LLOG_FL_SENDNOW);
        OBD_FREE(cb_data, sizeof(struct llog_cookie));
}

/* Assumes caller has already pushed us into the kernel context. */
int filter_finish_transno(struct obd_export *exp, struct obd_trans_info *oti,
                          int rc)
{
        struct filter_obd *filter = &exp->exp_obd->u.filter;
        struct filter_export_data *fed = &exp->exp_filter_data;
        struct filter_client_data *fcd = fed->fed_fcd;
        __u64 last_rcvd;
        loff_t off;
        ssize_t written;

        /* Propagate error code. */
        if (rc)
                RETURN(rc);

        if (!exp->exp_obd->obd_replayable)
                RETURN(rc);

        /* we don't allocate new transnos for replayed requests */
        if (oti != NULL && oti->oti_transno == 0) {
                spin_lock(&filter->fo_translock);
                last_rcvd = le64_to_cpu(filter->fo_fsd->fsd_last_transno) + 1;
                filter->fo_fsd->fsd_last_transno = cpu_to_le64(last_rcvd);
                spin_unlock(&filter->fo_translock);
                oti->oti_transno = last_rcvd;
                fcd->fcd_last_rcvd = cpu_to_le64(last_rcvd);
                fcd->fcd_mount_count = filter->fo_fsd->fsd_mount_count;

                /* could get xid from oti, if it's ever needed */
                fcd->fcd_last_xid = 0;

                off = fed->fed_lr_off;
                fsfilt_set_last_rcvd(exp->exp_obd, last_rcvd, oti->oti_handle,
                                     filter_commit_cb, NULL);
                written = fsfilt_write_record(exp->exp_obd,
                                              filter->fo_rcvd_filp, (char *)fcd,
                                              sizeof(*fcd), &off);
                CDEBUG(D_HA, "wrote trans #"LPD64" for client %s at #%d: "
                       "written = "LPSZ"\n", last_rcvd, fcd->fcd_uuid,
                       fed->fed_lr_idx, written);

                if (written == sizeof(*fcd))
                        RETURN(0);
                CERROR("error writing to %s: rc = %d\n", LAST_RCVD,
                       (int)written);
                if (written >= 0)
                        RETURN(-ENOSPC);
                RETURN(written);
        }

        RETURN(0);
}

void f_dput(struct dentry *dentry)
{
        /* Can't go inside filter_ddelete because it can block */
        CDEBUG(D_INODE, "putting %s: %p, count = %d\n",
               dentry->d_name.name, dentry, atomic_read(&dentry->d_count) - 1);
        LASSERT(atomic_read(&dentry->d_count) > 0);

        dput(dentry);
}

/* Not racy w.r.t. others, because we are the only user of this dentry */
static void filter_drelease(struct dentry *dentry)
{
        if (dentry->d_fsdata)
                OBD_FREE(dentry->d_fsdata, sizeof(struct filter_dentry_data));
}

struct dentry_operations filter_dops = {
        d_release: filter_drelease,
};

/* Add client data to the FILTER.  We use a bitmap to locate a free space
 * in the last_rcvd file if cl_idx is -1 (i.e. a new client).
 * Otherwise, we have just read the data from the last_rcvd file and
 * we know its offset. */
static int filter_client_add(struct obd_device *obd, struct filter_obd *filter,
                             struct filter_export_data *fed, int cl_idx)
{
        unsigned long *bitmap = filter->fo_last_rcvd_slots;
        int new_client = (cl_idx == -1);
        ENTRY;

        LASSERT(bitmap != NULL);

        /* XXX if fcd_uuid were a real obd_uuid, I could use obd_uuid_equals */
        if (!strcmp(fed->fed_fcd->fcd_uuid, "OBD_CLASS_UUID"))
                RETURN(0);

        /* the bitmap operations can handle cl_idx > sizeof(long) * 8, so
         * there's no need for extra complication here
         */
        if (new_client) {
                cl_idx = find_first_zero_bit(bitmap, FILTER_LR_MAX_CLIENTS);
        repeat:
                if (cl_idx >= FILTER_LR_MAX_CLIENTS) {
                        CERROR("no client slots - fix FILTER_LR_MAX_CLIENTS\n");
                        RETURN(-ENOMEM);
                }
                if (test_and_set_bit(cl_idx, bitmap)) {
                        CERROR("FILTER client %d: found bit is set in bitmap\n",
                               cl_idx);
                        cl_idx = find_next_zero_bit(bitmap,
                                                    FILTER_LR_MAX_CLIENTS,
                                                    cl_idx);
                        goto repeat;
                }
        } else {
                if (test_and_set_bit(cl_idx, bitmap)) {
                        CERROR("FILTER client %d: bit already set in bitmap!\n",
                               cl_idx);
                        LBUG();
                }
        }

        fed->fed_lr_idx = cl_idx;
        fed->fed_lr_off = le32_to_cpu(filter->fo_fsd->fsd_client_start) +
                cl_idx * le16_to_cpu(filter->fo_fsd->fsd_client_size);

        CDEBUG(D_INFO, "client at index %d (%llu) with UUID '%s' added\n",
               fed->fed_lr_idx, fed->fed_lr_off, fed->fed_fcd->fcd_uuid);

        if (new_client) {
                struct obd_run_ctxt saved;
                loff_t off = fed->fed_lr_off;
                int written;
                void *handle;

                CDEBUG(D_INFO, "writing client fcd at idx %u (%llu) (len %u)\n",
                       fed->fed_lr_idx,off,(unsigned int)sizeof(*fed->fed_fcd));

                push_ctxt(&saved, &filter->fo_ctxt, NULL);
                /* Transaction needed to fix bug 1403 */
                handle = fsfilt_start(obd,
                                      filter->fo_rcvd_filp->f_dentry->d_inode,
                                      FSFILT_OP_SETATTR, NULL);
                if (IS_ERR(handle)) {
                        written = PTR_ERR(handle);
                        CERROR("unable to start transaction: rc %d\n",
                               (int)written);
                } else {
                        written = fsfilt_write_record(obd, filter->fo_rcvd_filp,
                                                (char *)fed->fed_fcd,
                                                sizeof(*fed->fed_fcd), &off);
                        fsfilt_commit(obd,
                                      filter->fo_rcvd_filp->f_dentry->d_inode,
                                      handle, 0);
                }
                pop_ctxt(&saved, &filter->fo_ctxt, NULL);

                if (written != sizeof(*fed->fed_fcd)) {
                        CERROR("error writing %s client idx %u: rc %d\n",
                               LAST_RCVD, fed->fed_lr_idx, written);
                        if (written < 0)
                                RETURN(written);
                        RETURN(-ENOSPC);
                }
        }
        RETURN(0);
}

static int filter_client_free(struct obd_export *exp, int flags)
{
        struct filter_export_data *fed = &exp->exp_filter_data;
        struct filter_obd *filter = &exp->exp_obd->u.filter;
        struct obd_device *obd = exp->exp_obd;
        struct filter_client_data zero_fcd;
        struct obd_run_ctxt saved;
        int written;
        loff_t off;
        ENTRY;

        if (fed->fed_fcd == NULL)
                RETURN(0);

        if (flags & OBD_OPT_FAILOVER)
                GOTO(free, 0);

        /* XXX if fcd_uuid were a real obd_uuid, I could use obd_uuid_equals */
        if (strcmp(fed->fed_fcd->fcd_uuid, "OBD_CLASS_UUID") == 0)
                GOTO(free, 0);

        LASSERT(filter->fo_last_rcvd_slots != NULL);

        off = fed->fed_lr_off;

        CDEBUG(D_INFO, "freeing client at idx %u (%lld) with UUID '%s'\n",
               fed->fed_lr_idx, fed->fed_lr_off, fed->fed_fcd->fcd_uuid);

        if (!test_and_clear_bit(fed->fed_lr_idx, filter->fo_last_rcvd_slots)) {
                CERROR("FILTER client %u: bit already clear in bitmap!!\n",
                       fed->fed_lr_idx);
                LBUG();
        }

        memset(&zero_fcd, 0, sizeof zero_fcd);
        push_ctxt(&saved, &filter->fo_ctxt, NULL);
        written = fsfilt_write_record(obd, filter->fo_rcvd_filp,
                                      (char *)&zero_fcd, sizeof(zero_fcd),
                                      &off);

        /* XXX: this write gets lost sometimes, unless this sync is here. */
        if (written > 0)
                file_fsync(filter->fo_rcvd_filp,
                           filter->fo_rcvd_filp->f_dentry, 1);
        pop_ctxt(&saved, &filter->fo_ctxt, NULL);

        if (written != sizeof(zero_fcd)) {
                CERROR("error zeroing out client %s idx %u (%llu) in %s: %d\n",
                       fed->fed_fcd->fcd_uuid, fed->fed_lr_idx, fed->fed_lr_off,
                       LAST_RCVD, written);
        } else {
                CDEBUG(D_INFO,
                       "zeroed disconnecting client %s at idx %u (%llu)\n",
                       fed->fed_fcd->fcd_uuid, fed->fed_lr_idx,fed->fed_lr_off);
        }

free:
        OBD_FREE(fed->fed_fcd, sizeof(*fed->fed_fcd));

        RETURN(0);
}

static int filter_free_server_data(struct filter_obd *filter)
{
        OBD_FREE(filter->fo_fsd, sizeof(*filter->fo_fsd));
        filter->fo_fsd = NULL;
        OBD_FREE(filter->fo_last_rcvd_slots,
                 FILTER_LR_MAX_CLIENT_WORDS * sizeof(unsigned long));
        filter->fo_last_rcvd_slots = NULL;
        return 0;
}

/* assumes caller is already in kernel ctxt */
int filter_update_server_data(struct obd_device *obd,
                              struct file *filp, struct filter_server_data *fsd)
{
        loff_t off = 0;
        int rc;
        ENTRY;

        CDEBUG(D_INODE, "server uuid      : %s\n", fsd->fsd_uuid);
        CDEBUG(D_INODE, "server last_objid: "LPU64"\n",
               le64_to_cpu(fsd->fsd_last_objid));
        CDEBUG(D_INODE, "server last_rcvd : "LPU64"\n",
               le64_to_cpu(fsd->fsd_last_transno));
        CDEBUG(D_INODE, "server last_mount: "LPU64"\n",
               le64_to_cpu(fsd->fsd_mount_count));

        rc = fsfilt_write_record(obd, filp, (char *)fsd, sizeof(*fsd), &off);
        if (rc == sizeof(*fsd))
                RETURN(0);

        CDEBUG(D_INODE, "error writing filter_server_data: rc = %d\n", rc);
        if (rc >= 0)
                RETURN(-ENOSPC);
        RETURN(rc);
}

/* assumes caller has already in kernel ctxt */
static int filter_init_server_data(struct obd_device *obd, struct file * filp,
                                   __u64 init_lastobjid)
{
        struct filter_obd *filter = &obd->u.filter;
        struct filter_server_data *fsd;
        struct filter_client_data *fcd = NULL;
        struct inode *inode = filp->f_dentry->d_inode;
        unsigned long last_rcvd_size = inode->i_size;
        __u64 mount_count = 0;
        int cl_idx;
        loff_t off = 0;
        int rc;

        /* ensure padding in the struct is the correct size */
        LASSERT (offsetof(struct filter_server_data, fsd_padding) +
                 sizeof(fsd->fsd_padding) == FILTER_LR_SERVER_SIZE);
        LASSERT (offsetof(struct filter_client_data, fcd_padding) +
                 sizeof(fcd->fcd_padding) == FILTER_LR_CLIENT_SIZE);

        OBD_ALLOC(fsd, sizeof(*fsd));
        if (!fsd)
                RETURN(-ENOMEM);
        filter->fo_fsd = fsd;

        OBD_ALLOC(filter->fo_last_rcvd_slots,
                  FILTER_LR_MAX_CLIENT_WORDS * sizeof(unsigned long));
        if (filter->fo_last_rcvd_slots == NULL) {
                OBD_FREE(fsd, sizeof(*fsd));
                RETURN(-ENOMEM);
        }

        if (last_rcvd_size == 0) {
                CWARN("%s: initializing new %s\n", obd->obd_name, LAST_RCVD);

                memcpy(fsd->fsd_uuid, obd->obd_uuid.uuid,sizeof(fsd->fsd_uuid));
                fsd->fsd_last_objid = cpu_to_le64(init_lastobjid);
                fsd->fsd_last_transno = 0;
                mount_count = fsd->fsd_mount_count = 0;
                fsd->fsd_server_size = cpu_to_le32(FILTER_LR_SERVER_SIZE);
                fsd->fsd_client_start = cpu_to_le32(FILTER_LR_CLIENT_START);
                fsd->fsd_client_size = cpu_to_le16(FILTER_LR_CLIENT_SIZE);
                fsd->fsd_subdir_count = cpu_to_le16(FILTER_SUBDIR_COUNT);
                filter->fo_subdir_count = FILTER_SUBDIR_COUNT;
        } else {
                int retval = fsfilt_read_record(obd, filp, (char *)fsd,
                                                sizeof(*fsd), &off);
                if (retval != sizeof(*fsd)) {
                        CDEBUG(D_INODE,"OBD filter: error reading %s: rc %d\n",
                               LAST_RCVD, retval);
                        GOTO(err_fsd, rc = -EIO);
                }
                mount_count = le64_to_cpu(fsd->fsd_mount_count);
                filter->fo_subdir_count = le16_to_cpu(fsd->fsd_subdir_count);
                fsd->fsd_last_objid =
                        cpu_to_le64(le64_to_cpu(fsd->fsd_last_objid) +
                                    FILTER_SKIP_OBJID);
        }

        if (fsd->fsd_feature_incompat) {
                CERROR("unsupported feature %x\n",
                       le32_to_cpu(fsd->fsd_feature_incompat));
                GOTO(err_fsd, rc = -EINVAL);
        }
        if (fsd->fsd_feature_rocompat) {
                CERROR("read-only feature %x\n",
                       le32_to_cpu(fsd->fsd_feature_rocompat));
                /* Do something like remount filesystem read-only */
                GOTO(err_fsd, rc = -EINVAL);
        }

        CDEBUG(D_INODE, "%s: server last_objid: "LPU64"\n",
               obd->obd_name, le64_to_cpu(fsd->fsd_last_objid));
        CDEBUG(D_INODE, "%s: server last_rcvd : "LPU64"\n",
               obd->obd_name, le64_to_cpu(fsd->fsd_last_transno));
        CDEBUG(D_INODE, "%s: server last_mount: "LPU64"\n",
               obd->obd_name, mount_count);
        CDEBUG(D_INODE, "%s: server data size: %u\n",
               obd->obd_name, le32_to_cpu(fsd->fsd_server_size));
        CDEBUG(D_INODE, "%s: per-client data start: %u\n",
               obd->obd_name, le32_to_cpu(fsd->fsd_client_start));
        CDEBUG(D_INODE, "%s: per-client data size: %u\n",
               obd->obd_name, le32_to_cpu(fsd->fsd_client_size));
        CDEBUG(D_INODE, "%s: server subdir_count: %u\n",
               obd->obd_name, le16_to_cpu(fsd->fsd_subdir_count));

        if (!obd->obd_replayable) {
                CWARN("%s: recovery support OFF\n", obd->obd_name);
                GOTO(out, rc = 0);
        }

        for (cl_idx = 0; off < last_rcvd_size; cl_idx++) {
                __u64 last_rcvd;
                int mount_age;

                if (!fcd) {
                        OBD_ALLOC(fcd, sizeof(*fcd));
                        if (!fcd)
                                GOTO(err_fsd, rc = -ENOMEM);
                }

                /* Don't assume off is incremented properly, in case
                 * sizeof(fsd) isn't the same as fsd->fsd_client_size.
                 */
                off = le32_to_cpu(fsd->fsd_client_start) +
                        cl_idx * le16_to_cpu(fsd->fsd_client_size);
                rc = fsfilt_read_record(obd, filp, (char *)fcd, sizeof(*fcd),
                                        &off);
                if (rc != sizeof(*fcd)) {
                        CERROR("error reading FILTER %s offset %d: rc = %d\n",
                               LAST_RCVD, cl_idx, rc);
                        if (rc > 0) /* XXX fatal error or just abort reading? */
                                rc = -EIO;
                        break;
                }

                if (fcd->fcd_uuid[0] == '\0') {
                        CDEBUG(D_INFO, "skipping zeroed client at offset %d\n",
                               cl_idx);
                        continue;
                }

                last_rcvd = le64_to_cpu(fcd->fcd_last_rcvd);

                /* These exports are cleaned up by filter_disconnect(), so they
                 * need to be set up like real exports as filter_connect() does.
                 */
                mount_age = mount_count - le64_to_cpu(fcd->fcd_mount_count);
                if (mount_age < FILTER_MOUNT_RECOV) {
                        struct obd_export *exp = class_new_export(obd);
                        struct filter_export_data *fed;
                        CERROR("RCVRNG CLIENT uuid: %s idx: %d lr: "LPU64
                               " srv lr: "LPU64" mnt: "LPU64" last mount: "
                               LPU64"\n", fcd->fcd_uuid, cl_idx,
                               last_rcvd, le64_to_cpu(fsd->fsd_last_transno),
                               le64_to_cpu(fcd->fcd_mount_count), mount_count);
                        if (exp == NULL) {
                                /* XXX this rc is ignored  */
                                rc = -ENOMEM;
                                break;
                        }
                        memcpy(&exp->exp_client_uuid.uuid, fcd->fcd_uuid,
                               sizeof exp->exp_client_uuid.uuid);
                        fed = &exp->exp_filter_data;
                        fed->fed_fcd = fcd;
                        filter_client_add(obd, filter, fed, cl_idx);
                        /* create helper if export init gets more complex */
                        INIT_LIST_HEAD(&fed->fed_open_head);
                        spin_lock_init(&fed->fed_lock);

                        fcd = NULL;
                        obd->obd_recoverable_clients++;
                        class_export_put(exp);
                } else {
                        CDEBUG(D_INFO,
                               "discarded client %d UUID '%s' count "LPU64"\n",
                               cl_idx, fcd->fcd_uuid,
                               le64_to_cpu(fcd->fcd_mount_count));
                }

                CDEBUG(D_OTHER, "client at idx %d has last_rcvd = "LPU64"\n",
                       cl_idx, last_rcvd);

                if (last_rcvd > le64_to_cpu(filter->fo_fsd->fsd_last_transno))
                        filter->fo_fsd->fsd_last_transno=cpu_to_le64(last_rcvd);

                obd->obd_last_committed =
                        le64_to_cpu(filter->fo_fsd->fsd_last_transno);

                if (obd->obd_recoverable_clients) {
                        CERROR("RECOVERY: %d recoverable clients, last_rcvd "
                               LPU64"\n", obd->obd_recoverable_clients,
                               le64_to_cpu(filter->fo_fsd->fsd_last_transno));
                        obd->obd_next_recovery_transno =
                                obd->obd_last_committed + 1;
                        obd->obd_recovering = 1;
                }

        }

        if (fcd)
                OBD_FREE(fcd, sizeof(*fcd));

out:
        fsd->fsd_mount_count = cpu_to_le64(mount_count + 1);

        /* save it, so mount count and last_transno is current */
        rc = filter_update_server_data(obd, filp, filter->fo_fsd);

        RETURN(rc);

err_fsd:
        filter_free_server_data(filter);
        RETURN(rc);
}

/* setup the object store with correct subdirectories */
static int filter_prep(struct obd_device *obd)
{
        struct obd_run_ctxt saved;
        struct filter_obd *filter = &obd->u.filter;
        struct dentry *dentry, *O_dentry;
        struct file *file;
        struct inode *inode;
        int i;
        int rc = 0;
        int mode = 0;

        push_ctxt(&saved, &filter->fo_ctxt, NULL);
        dentry = simple_mkdir(current->fs->pwd, "O", 0700);
        CDEBUG(D_INODE, "got/created O: %p\n", dentry);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot open/create O: rc = %d\n", rc);
                GOTO(out, rc);
        }
        filter->fo_dentry_O = dentry;

        /*
         * Create directories and/or get dentries for each object type.
         * This saves us from having to do multiple lookups for each one.
         */
        O_dentry = filter->fo_dentry_O;
        for (mode = 0; mode < (S_IFMT >> S_SHIFT); mode++) {
                char *name = obd_type_by_mode[mode];

                if (!name) {
                        filter->fo_dentry_O_mode[mode] = NULL;
                        continue;
                }
                dentry = simple_mkdir(O_dentry, name, 0700);
                CDEBUG(D_INODE, "got/created O/%s: %p\n", name, dentry);
                if (IS_ERR(dentry)) {
                        rc = PTR_ERR(dentry);
                        CERROR("cannot create O/%s: rc = %d\n", name, rc);
                        GOTO(err_O_mode, rc);
                }
                filter->fo_dentry_O_mode[mode] = dentry;
        }

        file = filp_open(LAST_RCVD, O_RDWR | O_CREAT | O_LARGEFILE, 0700);
        if (!file || IS_ERR(file)) {
                rc = PTR_ERR(file);
                CERROR("OBD filter: cannot open/create %s: rc = %d\n",
                       LAST_RCVD, rc);
                GOTO(err_O_mode, rc);
        }

        if (!S_ISREG(file->f_dentry->d_inode->i_mode)) {
                CERROR("%s is not a regular file!: mode = %o\n", LAST_RCVD,
                       file->f_dentry->d_inode->i_mode);
                GOTO(err_filp, rc = -ENOENT);
        }

        rc = fsfilt_journal_data(obd, file);
        if (rc) {
                CERROR("cannot journal data on %s: rc = %d\n", LAST_RCVD, rc);
                GOTO(err_filp, rc);
        }
        /* steal operations */
        inode = file->f_dentry->d_inode;
        filter->fo_fop = file->f_op;
        filter->fo_iop = inode->i_op;
        filter->fo_aops = inode->i_mapping->a_ops;
#ifdef I_SKIP_PDFLUSH
        /*
         * we need this to protect from deadlock
         * pdflush vs. lustre_fwrite()
         */
        inode->i_flags |= I_SKIP_PDFLUSH;
#endif

        rc = filter_init_server_data(obd, file, FILTER_INIT_OBJID);
        if (rc) {
                CERROR("cannot read %s: rc = %d\n", LAST_RCVD, rc);
                GOTO(err_client, rc);
        }
        filter->fo_rcvd_filp = file;

        if (filter->fo_subdir_count) {
                O_dentry = filter->fo_dentry_O_mode[S_IFREG >> S_SHIFT];
                OBD_ALLOC(filter->fo_dentry_O_sub,
                          filter->fo_subdir_count * sizeof(dentry));
                if (!filter->fo_dentry_O_sub)
                        GOTO(err_client, rc = -ENOMEM);

                for (i = 0; i < filter->fo_subdir_count; i++) {
                        char dir[20];
                        snprintf(dir, sizeof(dir), "d%u", i);

                        dentry = simple_mkdir(O_dentry, dir, 0700);
                        CDEBUG(D_INODE, "got/created O/R/%s: %p\n", dir,dentry);
                        if (IS_ERR(dentry)) {
                                rc = PTR_ERR(dentry);
                                CERROR("can't create O/R/%s: rc = %d\n",dir,rc);
                                GOTO(err_O_sub, rc);
                        }
                        filter->fo_dentry_O_sub[i] = dentry;
                }
        }
        rc = 0;
 out:
        pop_ctxt(&saved, &filter->fo_ctxt, NULL);

        return(rc);

err_O_sub:
        while (i-- > 0) {
                struct dentry *dentry = filter->fo_dentry_O_sub[i];
                if (dentry) {
                        f_dput(dentry);
                        filter->fo_dentry_O_sub[i] = NULL;
                }
        }
        OBD_FREE(filter->fo_dentry_O_sub,
                 filter->fo_subdir_count * sizeof(dentry));
err_client:
        class_disconnect_exports(obd, 0);
err_filp:
        if (filp_close(file, 0))
                CERROR("can't close %s after error\n", LAST_RCVD);
        filter->fo_rcvd_filp = NULL;
err_O_mode:
        while (mode-- > 0) {
                struct dentry *dentry = filter->fo_dentry_O_mode[mode];
                if (dentry) {
                        f_dput(dentry);
                        filter->fo_dentry_O_mode[mode] = NULL;
                }
        }
        f_dput(filter->fo_dentry_O);
        filter->fo_dentry_O = NULL;
        goto out;
}

/* cleanup the filter: write last used object id to status file */
static void filter_post(struct obd_device *obd)
{
        struct obd_run_ctxt saved;
        struct filter_obd *filter = &obd->u.filter;
        long rc;
        int mode;

        /* XXX: filter_update_lastobjid used to call fsync_dev.  It might be
         * best to start a transaction with h_sync, because we removed this
         * from lastobjid */

        push_ctxt(&saved, &filter->fo_ctxt, NULL);
        rc = filter_update_server_data(obd, filter->fo_rcvd_filp,
                                       filter->fo_fsd);
        if (rc)
                CERROR("error writing lastobjid: rc = %ld\n", rc);


        if (filter->fo_rcvd_filp) {
                rc = file_fsync(filter->fo_rcvd_filp,
                                filter->fo_rcvd_filp->f_dentry, 1);
                filp_close(filter->fo_rcvd_filp, 0);
                filter->fo_rcvd_filp = NULL;
                if (rc)
                        CERROR("error closing %s: rc = %ld\n", LAST_RCVD, rc);
        }

        if (filter->fo_subdir_count) {
                int i;
                for (i = 0; i < filter->fo_subdir_count; i++) {
                        struct dentry *dentry = filter->fo_dentry_O_sub[i];
                        f_dput(dentry);
                        filter->fo_dentry_O_sub[i] = NULL;
                }
                OBD_FREE(filter->fo_dentry_O_sub,
                         filter->fo_subdir_count *
                         sizeof(*filter->fo_dentry_O_sub));
        }
        for (mode = 0; mode < (S_IFMT >> S_SHIFT); mode++) {
                struct dentry *dentry = filter->fo_dentry_O_mode[mode];
                if (dentry) {
                        f_dput(dentry);
                        filter->fo_dentry_O_mode[mode] = NULL;
                }
        }
        f_dput(filter->fo_dentry_O);
        filter_free_server_data(filter);
        pop_ctxt(&saved, &filter->fo_ctxt, NULL);
}

__u64 filter_next_id(struct filter_obd *filter)
{
        obd_id id;
        LASSERT(filter->fo_fsd != NULL);

        spin_lock(&filter->fo_objidlock);
        id = le64_to_cpu(filter->fo_fsd->fsd_last_objid);
        filter->fo_fsd->fsd_last_objid = cpu_to_le64(id + 1);
        spin_unlock(&filter->fo_objidlock);

        return id;
}

/* direct cut-n-paste of mds_blocking_ast() */
static int filter_blocking_ast(struct ldlm_lock *lock,
                               struct ldlm_lock_desc *desc,
                               void *data, int flag)
{
        int do_ast;
        ENTRY;

        if (flag == LDLM_CB_CANCELING) {
                /* Don't need to do anything here. */
                RETURN(0);
        }

        /* XXX layering violation!  -phil */
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        /* Get this: if filter_blocking_ast is racing with ldlm_intent_policy,
         * such that mds_blocking_ast is called just before l_i_p takes the
         * ns_lock, then by the time we get the lock, we might not be the
         * correct blocking function anymore.  So check, and return early, if
         * so. */
        if (lock->l_blocking_ast != filter_blocking_ast) {
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                RETURN(0);
        }

        lock->l_flags |= LDLM_FL_CBPENDING;
        do_ast = (!lock->l_readers && !lock->l_writers);
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);

        if (do_ast) {
                struct lustre_handle lockh;
                int rc;

                LDLM_DEBUG(lock, "already unused, calling ldlm_cli_cancel");
                ldlm_lock2handle(lock, &lockh);
                rc = ldlm_cli_cancel(&lockh);
                if (rc < 0)
                        CERROR("ldlm_cli_cancel: %d\n", rc);
        } else {
                LDLM_DEBUG(lock, "Lock still has references, will be "
                           "cancelled later");
        }
        RETURN(0);
}

static int filter_lock_dentry(struct obd_device *obd, struct dentry *de,
                              ldlm_mode_t lock_mode,struct lustre_handle *lockh)
{
        struct ldlm_res_id res_id = { .name = {0} };
        int flags = 0, rc;
        ENTRY;

        res_id.name[0] = de->d_inode->i_ino;
        res_id.name[1] = de->d_inode->i_generation;
        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, NULL,
                              res_id, LDLM_PLAIN, NULL, 0, lock_mode,
                              &flags, ldlm_completion_ast,
                              filter_blocking_ast, NULL, lockh);

        RETURN(rc == ELDLM_OK ? 0 : -ENOLCK);  /* XXX translate ldlm code */
}

/* We never dget the object parent, so DON'T dput it either */
static void filter_parent_unlock(struct dentry *dparent,
                                 struct lustre_handle *lockh,
                                 ldlm_mode_t lock_mode)
{
        ldlm_lock_decref(lockh, lock_mode);
}

/* We never dget the object parent, so DON'T dput it either */
struct dentry *filter_parent(struct obd_device *obd, obd_mode mode,
                             obd_id objid)
{
        struct filter_obd *filter = &obd->u.filter;

        LASSERT(S_ISREG(mode));   /* only regular files for now */
        if (!S_ISREG(mode) || filter->fo_subdir_count == 0)
                return filter->fo_dentry_O_mode[(mode & S_IFMT) >> S_SHIFT];

        return filter->fo_dentry_O_sub[objid & (filter->fo_subdir_count - 1)];
}

/* We never dget the object parent, so DON'T dput it either */
struct dentry *filter_parent_lock(struct obd_device *obd, obd_mode mode,
                                  obd_id objid, ldlm_mode_t lock_mode,
                                  struct lustre_handle *lockh)
{
        unsigned long now = jiffies;
        struct dentry *de = filter_parent(obd, mode, objid);
        int rc;

        if (IS_ERR(de))
                return de;

        rc = filter_lock_dentry(obd, de, lock_mode, lockh);
        if (time_after(jiffies, now + 15 * HZ))
                CERROR("slow parent lock %lus\n", (jiffies - now) / HZ);
        return rc ? ERR_PTR(rc) : de;
}

/* How to get files, dentries, inodes from object id's.
 *
 * If dir_dentry is passed, the caller has already locked the parent
 * appropriately for this operation (normally a write lock).  If
 * dir_dentry is NULL, we do a read lock while we do the lookup to
 * avoid races with create/destroy and such changing the directory
 * internal to the filesystem code. */
struct dentry *filter_fid2dentry(struct obd_device *obd,
                                 struct dentry *dir_dentry,
                                 obd_mode mode, obd_id id)
{
        struct lustre_handle lockh;
        struct dentry *dparent = dir_dentry;
        struct dentry *dchild;
        char name[32];
        int len;
        ENTRY;

        if (id == 0) {
                CERROR("fatal: invalid object id 0\n");
                LBUG();
                RETURN(ERR_PTR(-ESTALE));
        }

        len = sprintf(name, LPU64, id);
        if (dir_dentry == NULL) {
                dparent = filter_parent_lock(obd, mode, id, LCK_PR, &lockh);
                if (IS_ERR(dparent))
                        RETURN(dparent);
        }
        CDEBUG(D_INODE, "looking up object O/%*s/%s\n",
               dparent->d_name.len, dparent->d_name.name, name);
        dchild = ll_lookup_one_len(name, dparent, len);
        if (dir_dentry == NULL)
                filter_parent_unlock(dparent, &lockh, LCK_PR);
        if (IS_ERR(dchild)) {
                CERROR("child lookup error %ld\n", PTR_ERR(dchild));
                RETURN(dchild);
        }

        CDEBUG(D_INODE, "got child objid %s: %p, count = %d\n",
               name, dchild, atomic_read(&dchild->d_count));

        LASSERT(atomic_read(&dchild->d_count) > 0);

        RETURN(dchild);
}

static struct file *filter_obj_open(struct obd_export *export,
                                    struct obd_trans_info *oti,
                                    __u64 id, __u32 type, int parent_mode,
                                    struct lustre_handle *parent_lockh)
{
        struct obd_device *obd = export->exp_obd;
        struct filter_obd *filter = &obd->u.filter;
        struct dentry *dchild = NULL, *dparent = NULL;
        struct filter_export_data *fed = &export->exp_filter_data;
        struct filter_dentry_data *fdd = NULL;
        struct filter_file_data *ffd = NULL;
        struct obd_run_ctxt saved;
        char name[24];
        struct file *file;
        int len, cleanup_phase = 0;
        ENTRY;

        push_ctxt(&saved, &filter->fo_ctxt, NULL);

        if (!id) {
                CERROR("fatal: invalid obdo "LPU64"\n", id);
                GOTO(cleanup, file = ERR_PTR(-ESTALE));
        }

        if (!(type & S_IFMT)) {
                CERROR("OBD %s, object "LPU64" has bad type: %o\n",
                       __FUNCTION__, id, type);
                GOTO(cleanup, file = ERR_PTR(-EINVAL));
        }

        ffd = filter_ffd_new();
        if (ffd == NULL) {
                CERROR("obdfilter: out of memory\n");
                GOTO(cleanup, file = ERR_PTR(-ENOMEM));
        }

        cleanup_phase = 1;

        /* We preallocate this to avoid blocking while holding fo_fddlock */
        OBD_ALLOC(fdd, sizeof *fdd);
        if (fdd == NULL) {
                CERROR("obdfilter: out of memory\n");
                GOTO(cleanup, file = ERR_PTR(-ENOMEM));
        }

        cleanup_phase = 2;

        dparent = filter_parent_lock(obd, type, id, parent_mode, parent_lockh);
        if (IS_ERR(dparent))
                GOTO(cleanup, file = (void *)dparent);

        cleanup_phase = 3;

        len = snprintf(name, sizeof(name), LPU64, id);
        dchild = ll_lookup_one_len(name, dparent, len);
        if (IS_ERR(dchild))
                GOTO(cleanup, file = (void *)dchild);

        cleanup_phase = 4;

        if (dchild->d_inode == NULL) {
                CERROR("opening non-existent object %s - O_CREAT?\n", name);
                /* dput(dchild); call filter_create_internal here */
                file = ERR_PTR(-ENOENT);
                GOTO(cleanup, file);
        }

        /* dentry_open does a dput(dchild) and mntput(mnt) on error */
        mntget(filter->fo_vfsmnt);
        file = dentry_open(dchild, filter->fo_vfsmnt, O_RDWR | O_LARGEFILE);
        if (IS_ERR(file)) {
                dchild = NULL; /* prevent a double dput in step 4 */
                CERROR("error opening %s: rc %ld\n", name, PTR_ERR(file));
                GOTO(cleanup, file);
        }

        spin_lock(&filter->fo_fddlock);
        if (dchild->d_fsdata) {
                spin_unlock(&filter->fo_fddlock);
                OBD_FREE(fdd, sizeof *fdd);
                fdd = dchild->d_fsdata;
                LASSERT(fdd->fdd_magic == FILTER_DENTRY_MAGIC);
                /* should only happen during client recovery */
                if (fdd->fdd_flags & FILTER_FLAG_DESTROY)
                        CDEBUG(D_INODE,"opening destroyed object "LPU64"\n",id);
                atomic_inc(&fdd->fdd_open_count);
        } else {
                atomic_set(&fdd->fdd_open_count, 1);
                fdd->fdd_magic = FILTER_DENTRY_MAGIC;
                fdd->fdd_flags = 0;
                fdd->fdd_objid = id;
                /* If this is racy, then we can use {cmp}xchg and atomic_add */
                dchild->d_fsdata = fdd;
                spin_unlock(&filter->fo_fddlock);
        }

        ffd->ffd_file = file;
        LASSERT(file->private_data == NULL);
        file->private_data = ffd;

        if (!dchild->d_op)
                dchild->d_op = &filter_dops;
        else
                LASSERT(dchild->d_op == &filter_dops);

        spin_lock(&fed->fed_lock);
        list_add(&ffd->ffd_export_list, &fed->fed_open_head);
        spin_unlock(&fed->fed_lock);

        CDEBUG(D_INODE, "opened objid "LPU64": rc = %p\n", id, file);
cleanup:
        switch (cleanup_phase) {
        case 4:
                if (IS_ERR(file))
                        f_dput(dchild);
        case 3:
                if (IS_ERR(file))
                        filter_parent_unlock(dparent, parent_lockh,parent_mode);
        case 2:
                if (IS_ERR(file))
                        OBD_FREE(fdd, sizeof *fdd);
        case 1:
                if (IS_ERR(file))
                        filter_ffd_destroy(ffd);
                filter_ffd_put(ffd);
        case 0:
                pop_ctxt(&saved, &filter->fo_ctxt, NULL);
        }
        RETURN(file);
}

/* Caller must hold LCK_PW on parent and push us into kernel context.
 * Caller is also required to ensure that dchild->d_inode exists. */
static int filter_destroy_internal(struct obd_device *obd, obd_id objid,
                                   struct dentry *dparent,
                                   struct dentry *dchild)
{
        struct inode *inode = dchild->d_inode;
        int rc;
        ENTRY;

        if (inode->i_nlink != 1 || atomic_read(&inode->i_count) != 1) {
                CERROR("destroying objid %*s nlink = %d, count = %d\n",
                       dchild->d_name.len, dchild->d_name.name,
                       inode->i_nlink, atomic_read(&inode->i_count));
        }

        
#if 0
        /* Tell the clients that the object is gone now and that they should
         * throw away any cached pages.  We don't need to wait until they're
         * done, so just decref the lock right away and let ldlm_completion_ast
         * clean up when it's all over. */
        ldlm_cli_enqueue(..., LCK_PW, AST_INTENT_DESTROY, &lockh);
        ldlm_lock_decref(&lockh, LCK_PW);
#endif

        if (0) {
                struct lustre_handle lockh;
                int flags = 0, rc;
                struct ldlm_res_id res_id = { .name = { objid } };

                /* This part is a wee bit iffy: we really only want to bust the
                 * locks on our stripe, so that we don't end up bouncing
                 * [0->EOF] locks around on each of the OSTs as the rest of the
                 * destroys get processed.  Because we're only talking to
                 * the local LDLM, though, we should only end up locking the 
                 * whole of our stripe.  When bug 1425 (take all locks on OST
                 * for stripe 0) is fixed, this code should be revisited. */
                struct ldlm_extent extent = { 0, OBD_OBJECT_EOF };

                rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, NULL,
                                      res_id, LDLM_EXTENT, &extent,
                                      sizeof(extent), LCK_PW, &flags,
                                      ldlm_completion_ast, filter_blocking_ast,
                                      NULL, &lockh);
                /* We only care about the side-effects, just drop the lock. */
                ldlm_lock_decref(&lockh, LCK_PW);
        }

        rc = vfs_unlink(dparent->d_inode, dchild);

        if (rc)
                CERROR("error unlinking objid %*s: rc %d\n",
                       dchild->d_name.len, dchild->d_name.name, rc);

        RETURN(rc);
}

/* If closing because we are failing this device, then
   don't do the unlink on close.
*/
static int filter_close_internal(struct obd_export *exp,
                                 struct filter_file_data *ffd,
                                 struct obd_trans_info *oti, int flags)
{
        struct obd_device *obd = exp->exp_obd;
        struct filter_obd *filter = &obd->u.filter;
        struct file *filp = ffd->ffd_file;
        struct dentry *dchild = dget(filp->f_dentry);
        struct filter_dentry_data *fdd = dchild->d_fsdata;
        struct lustre_handle parent_lockh;
        int rc, rc2, cleanup_phase = 0;
        struct dentry *dparent = NULL;
        struct obd_run_ctxt saved;
        int nested_trans = (current->journal_info != NULL);
        ENTRY;

        LASSERT(filp->private_data == ffd);
        LASSERT(fdd != NULL);
        LASSERT(fdd->fdd_magic == FILTER_DENTRY_MAGIC);

        rc = filp_close(filp, 0);

        if (atomic_dec_and_test(&fdd->fdd_open_count) &&
            (fdd->fdd_flags & FILTER_FLAG_DESTROY) &&
            !(flags & OBD_OPT_FAILOVER)) {
                void *handle;

                push_ctxt(&saved, &filter->fo_ctxt, NULL);
                cleanup_phase = 1;

                LASSERT(fdd->fdd_objid > 0);
                dparent = filter_parent_lock(obd, S_IFREG, fdd->fdd_objid,
                                             LCK_PW, &parent_lockh);
                if (IS_ERR(dparent))
                        GOTO(cleanup, rc = PTR_ERR(dparent));
                cleanup_phase = 2;

                handle = fsfilt_start(obd, dparent->d_inode,
                                      FSFILT_OP_UNLINK_LOG, oti);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));

                if (oti != NULL) {
                        if (oti->oti_handle == NULL)
                                oti->oti_handle = handle;
                        else
                                LASSERT(oti->oti_handle == handle);
                }

#ifdef ENABLE_ORPHANS
                /* Remove orphan unlink record from log */
                llog_cancel_records(filter->fo_catalog, 1, &fdd->fdd_cookie);
#endif
                /* XXX unlink from PENDING directory now too */
                rc2 = filter_destroy_internal(obd, fdd->fdd_objid, dparent,
                                              dchild);
                if (rc2 && !rc)
                        rc = rc2;
                rc = filter_finish_transno(exp, oti, rc);
                rc2 = fsfilt_commit(obd, dparent->d_inode, handle, 0);
                if (rc2) {
                        CERROR("error on commit, err = %d\n", rc2);
                        if (!rc)
                                rc = rc2;
                }
                if (nested_trans == 0) {
                        LASSERT(current->journal_info == NULL);
                        if (oti != NULL)
                                oti->oti_handle = NULL;
                }
        }

cleanup:
        switch(cleanup_phase) {
        case 2:
                if (rc || oti == NULL) {
                        filter_parent_unlock(dparent, &parent_lockh, LCK_PW);
                } else {
                        memcpy(&oti->oti_ack_locks[0].lock, &parent_lockh,
                               sizeof(parent_lockh));
                        oti->oti_ack_locks[0].mode = LCK_PW;
                }
        case 1:
                pop_ctxt(&saved, &filter->fo_ctxt, NULL);
        case 0:
                f_dput(dchild);
                filter_ffd_destroy(ffd);
                break;
        default:
                CERROR("invalid cleanup_phase %d\n", cleanup_phase);
                LBUG();
        }

        RETURN(rc);
}

/* mount the file system (secretly) */
int filter_common_setup(struct obd_device *obd, obd_count len, void *buf,
                        char *option)
{
        struct obd_ioctl_data* data = buf;
        struct filter_obd *filter = &obd->u.filter;
        struct vfsmount *mnt;
        int rc = 0;
        ENTRY;

        if (!data->ioc_inlbuf1 || !data->ioc_inlbuf2)
                RETURN(-EINVAL);

        obd->obd_fsops = fsfilt_get_ops(data->ioc_inlbuf2);
        if (IS_ERR(obd->obd_fsops))
                RETURN(PTR_ERR(obd->obd_fsops));

        mnt = do_kern_mount(data->ioc_inlbuf2, MS_NOATIME | MS_NODIRATIME,
                            data->ioc_inlbuf1, option);
        rc = PTR_ERR(mnt);
        if (IS_ERR(mnt))
                GOTO(err_ops, rc);

        if (data->ioc_inllen3 > 0 && data->ioc_inlbuf3) {
                if (*data->ioc_inlbuf3 == 'f') {
                        obd->obd_replayable = 1;
                        obd_sync_filter = 1;
                        CERROR("%s: configured for recovery and sync write\n",
                               obd->obd_name);
                } else {
                        if (*data->ioc_inlbuf3 != 'n') {
                                CERROR("unrecognised flag '%c'\n",
                                       *data->ioc_inlbuf3);
                        }
                }
        }

        if (data->ioc_inllen4 > 0 && data->ioc_inlbuf4) {
                if (*data->ioc_inlbuf4 == '/') {
                        CERROR("filter namespace mount: %s\n",
                               data->ioc_inlbuf4);
                        filter->fo_nspath = strdup(data->ioc_inlbuf4);
                } else {
                        CERROR("namespace mount must be absolute path: '%s'\n",
                               data->ioc_inlbuf4);
                }
        }

        filter->fo_vfsmnt = mnt;
        filter->fo_sb = mnt->mnt_sb;
        filter->fo_fstype = mnt->mnt_sb->s_type->name;
        CDEBUG(D_SUPER, "%s: mnt = %p\n", filter->fo_fstype, mnt);

        OBD_SET_CTXT_MAGIC(&filter->fo_ctxt);
        filter->fo_ctxt.pwdmnt = mnt;
        filter->fo_ctxt.pwd = mnt->mnt_root;
        filter->fo_ctxt.fs = get_ds();

        rc = filter_prep(obd);
        if (rc)
                GOTO(err_mntput, rc);

        spin_lock_init(&filter->fo_translock);
        spin_lock_init(&filter->fo_fddlock);
        spin_lock_init(&filter->fo_objidlock);
        INIT_LIST_HEAD(&filter->fo_export_list);

        ptlrpc_init_client(MDS_REQUEST_PORTAL, MDC_REPLY_PORTAL,
                           "filter_mdc", &filter->fo_mdc_client);
        sema_init(&filter->fo_sem, 1);

        obd->obd_namespace = ldlm_namespace_new("filter-tgt",
                                                LDLM_NAMESPACE_SERVER);
        if (obd->obd_namespace == NULL)
                GOTO(err_post, rc = -ENOMEM);

        ptlrpc_init_client(LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
                           "filter_ldlm_cb_client", &obd->obd_ldlm_client);

        /* Create a non-replaying connection for recovery logging, so that
         * we don't create a client entry for this local connection, and do
         * not log or assign transaction numbers for logging operations. */
#ifdef ENABLE_ORPHANS
        filter->fo_catalog = filter_get_catalog(obd);
        if (IS_ERR(filter->fo_catalog))
                GOTO(err_post, rc = PTR_ERR(filter->fo_catalog));
#endif

        RETURN(0);

err_post:
        filter_post(obd);
err_mntput:
        unlock_kernel();
        mntput(mnt);
        filter->fo_sb = 0;
        lock_kernel();
err_ops:
        fsfilt_put_ops(obd->obd_fsops);
        return rc;
}

static int filter_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct obd_ioctl_data* data = buf;
        char *option = NULL;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        /* bug 1577: implement async-delete for 2.5 */
        if (!strcmp(data->ioc_inlbuf2, "ext3"))
                option = "asyncdel";
#endif

        return filter_common_setup(obd, len, buf, option);
}

static int filter_cleanup(struct obd_device *obd, int flags)
{
        struct filter_obd *filter = &obd->u.filter;
        ENTRY;

        if (flags & OBD_OPT_FAILOVER)
                CERROR("%s: shutting down for failover; client state will"
                       " be preserved.\n", obd->obd_name);

        if (!list_empty(&obd->obd_exports)) {
                CERROR("%s: still has clients!\n", obd->obd_name);
                class_disconnect_exports(obd, flags);
                if (!list_empty(&obd->obd_exports)) {
                        CERROR("still has exports after forced cleanup?\n");
                        RETURN(-EBUSY);
                }
        }

#ifdef ENABLE_ORPHANS
        filter_put_catalog(filter->fo_catalog);
#endif

        ldlm_namespace_free(obd->obd_namespace);

        if (filter->fo_sb == NULL)
                RETURN(0);

        filter_post(obd);

        shrink_dcache_parent(filter->fo_sb->s_root);
        filter->fo_sb = 0;

        if (atomic_read(&filter->fo_vfsmnt->mnt_count) > 1)
                CERROR("%s: mount point busy, mnt_count: %d\n", obd->obd_name,
                       atomic_read(&filter->fo_vfsmnt->mnt_count));

        unlock_kernel();
        mntput(filter->fo_vfsmnt);
        //destroy_buffers(filter->fo_sb->s_dev);
        filter->fo_sb = NULL;
        fsfilt_put_ops(obd->obd_fsops);
        lock_kernel();

        RETURN(0);
}

static int filter_attach(struct obd_device *obd, obd_count len, void *data)
{
        struct lprocfs_static_vars lvars;
        int rc;

        lprocfs_init_vars(filter, &lvars);
        rc = lprocfs_obd_attach(obd, lvars.obd_vars);
        if (rc != 0)
                return rc;

        rc = lprocfs_alloc_obd_stats(obd, LPROC_FILTER_LAST);
        if (rc != 0)
                return rc;

        /* Init obdfilter private stats here */
        lprocfs_counter_init(obd->obd_stats, LPROC_FILTER_READ_BYTES,
                             LPROCFS_CNTR_AVGMINMAX, "read_bytes", "bytes");
        lprocfs_counter_init(obd->obd_stats, LPROC_FILTER_WRITE_BYTES,
                             LPROCFS_CNTR_AVGMINMAX, "write_bytes", "bytes");
        return rc;
}

static int filter_detach(struct obd_device *dev)
{
        lprocfs_free_obd_stats(dev);
        return lprocfs_obd_detach(dev);
}

/* nearly identical to mds_connect */
static int filter_connect(struct lustre_handle *conn, struct obd_device *obd,
                          struct obd_uuid *cluuid)
{
        struct obd_export *exp;
        struct filter_export_data *fed;
        struct filter_client_data *fcd;
        struct filter_obd *filter = &obd->u.filter;
        int rc;
        ENTRY;

        if (conn == NULL || obd == NULL || cluuid == NULL)
                RETURN(-EINVAL);

        rc = class_connect(conn, obd, cluuid);
        if (rc)
                RETURN(rc);
        exp = class_conn2export(conn);
        LASSERT(exp != NULL);

        fed = &exp->exp_filter_data;
        class_export_put(exp);

        INIT_LIST_HEAD(&fed->fed_open_head);
        spin_lock_init(&fed->fed_lock);

        if (!obd->obd_replayable)
                RETURN(0);

        OBD_ALLOC(fcd, sizeof(*fcd));
        if (!fcd) {
                CERROR("filter: out of memory for client data\n");
                GOTO(out_export, rc = -ENOMEM);
        }

        memcpy(fcd->fcd_uuid, cluuid, sizeof(fcd->fcd_uuid));
        fed->fed_fcd = fcd;
        fcd->fcd_mount_count = cpu_to_le64(filter->fo_fsd->fsd_mount_count);

        rc = filter_client_add(obd, filter, fed, -1);
        if (rc)
                GOTO(out_fcd, rc);

        RETURN(rc);

out_fcd:
        OBD_FREE(fcd, sizeof(*fcd));
out_export:
        class_disconnect(conn, 0);

        RETURN(rc);
}

static void filter_destroy_export(struct obd_export *exp)
{
        struct filter_export_data *fed = &exp->exp_filter_data;

        ENTRY;
        spin_lock(&fed->fed_lock);
        while (!list_empty(&fed->fed_open_head)) {
                struct filter_file_data *ffd;

                ffd = list_entry(fed->fed_open_head.next, typeof(*ffd),
                                 ffd_export_list);
                list_del(&ffd->ffd_export_list);
                spin_unlock(&fed->fed_lock);

                CDEBUG(D_INFO, "force close file %*s (hdl %p:"LPX64") on "
                       "disconnect\n", ffd->ffd_file->f_dentry->d_name.len,
                       ffd->ffd_file->f_dentry->d_name.name,
                       ffd, ffd->ffd_handle.h_cookie);

                filter_close_internal(exp, ffd, NULL, exp->exp_flags);
                spin_lock(&fed->fed_lock);
        }
        spin_unlock(&fed->fed_lock);

        if (exp->exp_obd->obd_replayable)
                filter_client_free(exp, exp->exp_flags);
        EXIT;
}

/* also incredibly similar to mds_disconnect */
static int filter_disconnect(struct lustre_handle *conn, int flags)
{
        struct obd_export *exp = class_conn2export(conn);
        unsigned long irqflags;
        int rc;
        ENTRY;

        LASSERT(exp);
        ldlm_cancel_locks_for_export(exp);

        spin_lock_irqsave(&exp->exp_lock, irqflags);
        exp->exp_flags = flags;
        spin_unlock_irqrestore(&exp->exp_lock, irqflags);

        rc = class_disconnect(conn, flags);

        fsfilt_sync(exp->exp_obd, exp->exp_obd->u.filter.fo_sb);
        class_export_put(exp);
        /* XXX cleanup preallocated inodes */
        RETURN(rc);
}

struct dentry *__filter_oa2dentry(struct obd_device *obd,
                                  struct obdo *oa, const char *what)
{
        struct dentry *dchild = NULL;

        if (oa->o_valid & OBD_MD_FLHANDLE) {
                struct lustre_handle *ost_handle = obdo_handle(oa);
                struct filter_file_data *ffd = filter_handle2ffd(ost_handle);

                if (ffd != NULL) {
                        struct filter_dentry_data *fdd;
                        dchild = dget(ffd->ffd_file->f_dentry);
                        fdd = dchild->d_fsdata;
                        LASSERT(fdd->fdd_magic == FILTER_DENTRY_MAGIC);
                        filter_ffd_put(ffd);

                        CDEBUG(D_INODE,"%s got child objid %*s: %p, count %d\n",
                               what, dchild->d_name.len, dchild->d_name.name,
                               dchild, atomic_read(&dchild->d_count));
                }
        }

        if (!dchild)
                dchild = filter_fid2dentry(obd, NULL, oa->o_mode, oa->o_id);

        if (IS_ERR(dchild)) {
                CERROR("%s error looking up object: "LPU64"\n", what, oa->o_id);
                RETURN(dchild);
        }

        if (!dchild->d_inode) {
                CERROR("%s on non-existent object: "LPU64"\n", what, oa->o_id);
                f_dput(dchild);
                RETURN(ERR_PTR(-ENOENT));
        }

        return dchild;
}

static int filter_getattr(struct lustre_handle *conn, struct obdo *oa,
                          struct lov_stripe_md *md)
{
        struct dentry *dentry = NULL;
        struct obd_device *obd;
        int rc = 0;
        ENTRY;

        obd = class_conn2obd(conn);
        if (obd == NULL) {
                CDEBUG(D_IOCTL, "invalid client cookie "LPX64"\n",conn->cookie);
                RETURN(-EINVAL);
        }

        dentry = filter_oa2dentry(obd, oa);
        if (IS_ERR(dentry))
                RETURN(PTR_ERR(dentry));

        /* Limit the valid bits in the return data to what we actually use */
        oa->o_valid = OBD_MD_FLID;
        obdo_from_inode(oa, dentry->d_inode, FILTER_VALID_FLAGS);

        f_dput(dentry);
        RETURN(rc);
}

/* this is called from filter_truncate() until we have filter_punch() */
static int filter_setattr(struct lustre_handle *conn, struct obdo *oa,
                          struct lov_stripe_md *md, struct obd_trans_info *oti)
{
        struct obd_run_ctxt saved;
        struct obd_export *exp;
        struct filter_obd *filter;
        struct dentry *dentry;
        struct iattr iattr;
        void *handle;
        int rc, rc2;
        ENTRY;

        LASSERT(oti != NULL);
        exp = class_conn2export(conn);
        if (!exp) {
                CERROR("invalid client cookie "LPX64"\n", conn->cookie);
                RETURN(-EINVAL);
        }

        dentry = filter_oa2dentry(exp->exp_obd, oa);
        if (IS_ERR(dentry))
                GOTO(out_exp, rc = PTR_ERR(dentry));

        filter = &exp->exp_obd->u.filter;

        iattr_from_obdo(&iattr, oa, oa->o_valid);

        push_ctxt(&saved, &filter->fo_ctxt, NULL);
        lock_kernel();

        /* XXX this could be a rwsem instead, if filter_preprw played along */
        if (iattr.ia_valid & ATTR_SIZE)
                down(&dentry->d_inode->i_sem);

        handle = fsfilt_start(exp->exp_obd, dentry->d_inode, FSFILT_OP_SETATTR,
                              oti);
        if (IS_ERR(handle))
                GOTO(out_unlock, rc = PTR_ERR(handle));

        rc = fsfilt_setattr(exp->exp_obd, dentry, handle, &iattr, 1);
        rc = filter_finish_transno(exp, oti, rc);
        rc2 = fsfilt_commit(exp->exp_obd, dentry->d_inode, handle, 0);
        if (rc2) {
                CERROR("error on commit, err = %d\n", rc2);
                if (!rc)
                        rc = rc2;
        }

        if (iattr.ia_valid & ATTR_SIZE)
                up(&dentry->d_inode->i_sem);

        oa->o_valid = OBD_MD_FLID;
        obdo_from_inode(oa, dentry->d_inode, FILTER_VALID_FLAGS);

out_unlock:
        unlock_kernel();
        pop_ctxt(&saved, &filter->fo_ctxt, NULL);

        f_dput(dentry);
 out_exp:
        class_export_put(exp);
        RETURN(rc);
}

static int filter_open(struct lustre_handle *conn, struct obdo *oa,
                       struct lov_stripe_md *ea, struct obd_trans_info *oti,
                       struct obd_client_handle *och)
{
        struct obd_export *exp;
        struct lustre_handle *handle;
        struct filter_file_data *ffd;
        struct file *filp;
        struct lustre_handle parent_lockh;
        int rc = 0;
        ENTRY;

        exp = class_conn2export(conn);
        if (exp == NULL) {
                CDEBUG(D_IOCTL, "invalid client cookie "LPX64"\n",conn->cookie);
                RETURN(-EINVAL);
        }

        filp = filter_obj_open(exp, oti, oa->o_id, oa->o_mode,
                               LCK_PR, &parent_lockh);
        if (IS_ERR(filp))
                GOTO(out, rc = PTR_ERR(filp));

        oa->o_valid = OBD_MD_FLID;
        obdo_from_inode(oa, filp->f_dentry->d_inode, FILTER_VALID_FLAGS);

        ffd = filp->private_data;
        handle = obdo_handle(oa);
        handle->cookie = ffd->ffd_handle.h_cookie;
        oa->o_valid |= OBD_MD_FLHANDLE;

out:
        class_export_put(exp);
        if (!rc) {
                memcpy(&oti->oti_ack_locks[0].lock, &parent_lockh,
                       sizeof(parent_lockh));
                oti->oti_ack_locks[0].mode = LCK_PR;
        }
        RETURN(rc);
}

static int filter_close(struct lustre_handle *conn, struct obdo *oa,
                        struct lov_stripe_md *ea, struct obd_trans_info *oti)
{
        struct obd_export *exp;
        struct filter_file_data *ffd;
        struct filter_export_data *fed;
        int rc;
        ENTRY;

        exp = class_conn2export(conn);
        if (exp == NULL) {
                CDEBUG(D_IOCTL, "invalid client cookie "LPX64"\n",conn->cookie);
                RETURN(-EINVAL);
        }

        if (!(oa->o_valid & OBD_MD_FLHANDLE)) {
                CERROR("no handle for close of objid "LPU64"\n", oa->o_id);
                GOTO(out, rc = -EINVAL);
        }

        ffd = filter_handle2ffd(obdo_handle(oa));
        if (ffd == NULL) {
                CERROR("bad handle ("LPX64") for close\n",
                       obdo_handle(oa)->cookie);
                GOTO(out, rc = -ESTALE);
        }

        fed = &exp->exp_filter_data;
        spin_lock(&fed->fed_lock);
        list_del(&ffd->ffd_export_list);
        spin_unlock(&fed->fed_lock);

        oa->o_valid = OBD_MD_FLID;
        obdo_from_inode(oa,ffd->ffd_file->f_dentry->d_inode,FILTER_VALID_FLAGS);

        rc = filter_close_internal(exp, ffd, oti, 0);
        filter_ffd_put(ffd);
        GOTO(out, rc);
 out:
        class_export_put(exp);
        return rc;
}

static int filter_create(struct lustre_handle *conn, struct obdo *oa,
                         struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        struct obd_export *exp;
        struct obd_device *obd;
        struct filter_obd *filter;
        struct obd_run_ctxt saved;
        struct lustre_handle parent_lockh;
        struct dentry *dparent;
        struct ll_fid mds_fid = { .id = 0 };
        struct dentry *dchild = NULL;
        void *handle;
        int err, rc, cleanup_phase;
        ENTRY;

        exp = class_conn2export(conn);
        if (exp == NULL) {
                CDEBUG(D_IOCTL,"invalid client cookie "LPX64"\n", conn->cookie);
                RETURN(-EINVAL);
        }

        obd = exp->exp_obd;
        filter = &obd->u.filter;
        push_ctxt(&saved, &filter->fo_ctxt, NULL);
 retry:
        oa->o_id = filter_next_id(filter);

        cleanup_phase = 0;
        dparent = filter_parent_lock(obd, S_IFREG, oa->o_id, LCK_PW,
                                     &parent_lockh);
        if (IS_ERR(dparent))
                GOTO(cleanup, rc = PTR_ERR(dparent));
        cleanup_phase = 1;

        dchild = filter_fid2dentry(obd, dparent, S_IFREG, oa->o_id);
        if (IS_ERR(dchild))
                GOTO(cleanup, rc = PTR_ERR(dchild));
        if (dchild->d_inode) {
                /* This would only happen if lastobjid was bad on disk */
                CERROR("Serious error: objid %*s already exists; is this "
                       "filesystem corrupt?  I will try to work around it.\n",
                       dchild->d_name.len, dchild->d_name.name);
                f_dput(dchild);
                filter_parent_unlock(dparent, &parent_lockh, LCK_PW);
                goto retry;
        }

        cleanup_phase = 2;
        handle = fsfilt_start(obd, dparent->d_inode, FSFILT_OP_CREATE_LOG, oti);
        if (IS_ERR(handle))
                GOTO(cleanup, rc = PTR_ERR(handle));

        rc = vfs_create(dparent->d_inode, dchild, oa->o_mode);
        if (rc) {
                CERROR("create failed rc = %d\n", rc);
        } else if (oa->o_valid & (OBD_MD_FLCTIME|OBD_MD_FLMTIME|OBD_MD_FLSIZE)){
                struct iattr attr;

                iattr_from_obdo(&attr, oa, oa->o_valid);
                rc = fsfilt_setattr(obd, dchild, handle, &attr, 1);
                if (rc)
                        CERROR("create setattr failed rc = %d\n", rc);
        }
        rc = filter_finish_transno(exp, oti, rc);
        err = filter_update_server_data(obd, filter->fo_rcvd_filp,
                                        filter->fo_fsd);
        if (err)
                CERROR("unable to write lastobjid but file created\n");

        /* Set flags for fields we have set in the inode struct */
        if (!rc && mds_fid.id && (oa->o_valid & OBD_MD_FLCOOKIE)) {
                err = filter_log_op_create(obd->u.filter.fo_catalog, &mds_fid,
                                           dchild->d_inode->i_ino,
                                           dchild->d_inode->i_generation,
                                           oti->oti_logcookies);
                if (err) {
                        CERROR("error logging create record: rc %d\n", err);
                        oa->o_valid = OBD_MD_FLID;
                } else {
                        oa->o_valid = OBD_MD_FLID | OBD_MD_FLCOOKIE;
                }
        } else
                oa->o_valid = OBD_MD_FLID;

        err = fsfilt_commit(obd, dparent->d_inode, handle, 0);
        if (err) {
                CERROR("error on commit, err = %d\n", err);
                if (!rc)
                        rc = err;
        }

        if (rc)
                GOTO(cleanup, rc);

        /* Set flags for fields we have set in the inode struct */
        obdo_from_inode(oa, dchild->d_inode, FILTER_VALID_FLAGS);

        EXIT;
cleanup:
        switch(cleanup_phase) {
        case 2:
                f_dput(dchild);
        case 1: /* locked parent dentry */
                if (rc || oti == NULL) {
                        filter_parent_unlock(dparent, &parent_lockh, LCK_PW);
                } else {
                        memcpy(&oti->oti_ack_locks[0].lock, &parent_lockh,
                               sizeof(parent_lockh));
                        oti->oti_ack_locks[0].mode = LCK_PW;
                }
        case 0:
                pop_ctxt(&saved, &filter->fo_ctxt, NULL);
                class_export_put(exp);
                break;
        default:
                CERROR("invalid cleanup_phase %d\n", cleanup_phase);
                LBUG();
        }

        RETURN(rc);
}

static int filter_destroy(struct lustre_handle *conn, struct obdo *oa,
                          struct lov_stripe_md *ea, struct obd_trans_info *oti)
{
        struct obd_export *exp;
        struct obd_device *obd;
        struct filter_obd *filter;
        struct dentry *dchild = NULL, *dparent = NULL;
        struct filter_dentry_data *fdd;
        struct obd_run_ctxt saved;
        void *handle = NULL;
        struct lustre_handle parent_lockh;
        struct llog_cookie *fcc = NULL;
        int rc, rc2, cleanup_phase = 0;
        ENTRY;

        exp = class_conn2export(conn);
        if (exp == NULL) {
                CDEBUG(D_IOCTL, "invalid client cookie "LPX64"\n",conn->cookie);
                RETURN(-EINVAL);
        }

        obd = exp->exp_obd;
        filter = &obd->u.filter;

        push_ctxt(&saved, &filter->fo_ctxt, NULL);
        dparent = filter_parent_lock(obd, oa->o_mode, oa->o_id,
                                     LCK_PW, &parent_lockh);
        if (IS_ERR(dparent))
                GOTO(cleanup, rc = PTR_ERR(dparent));
        cleanup_phase = 1;

        dchild = filter_fid2dentry(obd, dparent, S_IFREG, oa->o_id);
        if (IS_ERR(dchild))
                GOTO(cleanup, rc = -ENOENT);
        cleanup_phase = 2;

        if (dchild->d_inode == NULL) {
                CERROR("destroying non-existent object "LPU64"\n", oa->o_id);
                GOTO(cleanup, rc = -ENOENT);
        }
        handle = fsfilt_start(obd, dparent->d_inode, FSFILT_OP_UNLINK_LOG, oti);
        if (IS_ERR(handle))
                GOTO(cleanup, rc = PTR_ERR(handle));
        cleanup_phase = 3;

        fdd = dchild->d_fsdata;

        /* Our MDC connection is established by the MDS to us */
        if ((oa->o_valid & OBD_MD_FLCOOKIE) && filter->fo_mdc_imp != NULL) {
                OBD_ALLOC(fcc, sizeof(*fcc));
                if (fcc != NULL)
                        memcpy(fcc, obdo_logcookie(oa), sizeof(*fcc));
        }

        if (fdd != NULL && atomic_read(&fdd->fdd_open_count)) {
                LASSERT(fdd->fdd_magic == FILTER_DENTRY_MAGIC);
                if (!(fdd->fdd_flags & FILTER_FLAG_DESTROY)) {
                        fdd->fdd_flags |= FILTER_FLAG_DESTROY;

#ifdef ENABLE_ORPHANS
                        filter_log_op_orphan(filter->fo_catalog, oa->o_id,
                                             oa->o_generation,&fdd->fdd_cookie);
#endif
                        CDEBUG(D_INODE,
                               "defer destroy of %dx open objid "LPU64"\n",
                               atomic_read(&fdd->fdd_open_count), oa->o_id);
                } else {
                        CDEBUG(D_INODE,
                               "repeat destroy of %dx open objid "LPU64"\n",
                               atomic_read(&fdd->fdd_open_count), oa->o_id);
                }
                GOTO(cleanup, rc = 0);
        }

        rc = filter_destroy_internal(obd, oa->o_id, dparent, dchild);

cleanup:
        switch(cleanup_phase) {
        case 3:
                if (fcc != NULL)
                        fsfilt_set_last_rcvd(obd, 0, oti->oti_handle,
                                             filter_cancel_cookies_cb, fcc);
                rc = filter_finish_transno(exp, oti, rc);
                rc2 = fsfilt_commit(obd, dparent->d_inode, handle, 0);
                if (rc2) {
                        CERROR("error on commit, err = %d\n", rc2);
                        if (!rc)
                                rc = rc2;
                }
        case 2:
                f_dput(dchild);
        case 1:
                if (rc || oti == NULL) {
                        filter_parent_unlock(dparent, &parent_lockh, LCK_PW);
                } else {
                        memcpy(&oti->oti_ack_locks[0].lock, &parent_lockh,
                               sizeof(parent_lockh));
                        oti->oti_ack_locks[0].mode = LCK_PW;
                }
        case 0:
                pop_ctxt(&saved, &filter->fo_ctxt, NULL);
                class_export_put(exp);
                break;
        default:
                CERROR("invalid cleanup_phase %d\n", cleanup_phase);
                LBUG();
        }

        RETURN(rc);
}

/* NB start and end are used for punch, but not truncate */
static int filter_truncate(struct lustre_handle *conn, struct obdo *oa,
                           struct lov_stripe_md *lsm,
                           obd_off start, obd_off end,
                           struct obd_trans_info *oti)
{
        int error;
        ENTRY;

        if (end != OBD_OBJECT_EOF)
                CERROR("PUNCH not supported, only truncate: end = "LPX64"\n",
                       end);

        CDEBUG(D_INODE, "calling truncate for object "LPU64", valid = %x, "
               "o_size = "LPD64"\n", oa->o_id, oa->o_valid, start);
        oa->o_size = start;
        error = filter_setattr(conn, oa, NULL, oti);
        RETURN(error);
}

static int filter_syncfs(struct obd_export *exp)
{
        ENTRY;

        RETURN(fsfilt_sync(exp->exp_obd, exp->exp_obd->u.filter.fo_sb));
}

static int filter_statfs(struct obd_device *obd, struct obd_statfs *osfs,
                         unsigned long max_age)
{
        ENTRY;
        RETURN(fsfilt_statfs(obd, obd->u.filter.fo_sb, osfs));
}

static int filter_get_info(struct lustre_handle *conn, __u32 keylen,
                           void *key, __u32 *vallen, void *val)
{
        struct obd_device *obd;
        ENTRY;

        obd = class_conn2obd(conn);
        if (obd == NULL) {
                CDEBUG(D_IOCTL, "invalid client cookie "LPX64"\n",
                       conn->cookie);
                RETURN(-EINVAL);
        }

        if (keylen == strlen("blocksize") &&
            memcmp(key, "blocksize", keylen) == 0) {
                __u32 *blocksize = val;
                *vallen = sizeof(*blocksize);
                *blocksize = obd->u.filter.fo_sb->s_blocksize;
                RETURN(0);
        }

        if (keylen == strlen("blocksize_bits") &&
            memcmp(key, "blocksize_bits", keylen) == 0) {
                __u32 *blocksize_bits = val;
                *vallen = sizeof(*blocksize_bits);
                *blocksize_bits = obd->u.filter.fo_sb->s_blocksize_bits;
                RETURN(0);
        }

        CDEBUG(D_IOCTL, "invalid key\n");
        RETURN(-EINVAL);
}

static int filter_set_info(struct lustre_handle *conn, __u32 keylen,
                           void *key, __u32 vallen, void *val)
{
        struct obd_device *obd;
        struct obd_export *exp;
        struct obd_import *imp;
        ENTRY;

        obd = class_conn2obd(conn);
        if (obd == NULL) {
                CDEBUG(D_IOCTL, "invalid client cookie "LPX64"\n",
                       conn->cookie);
                RETURN(-EINVAL);
        }

        if (keylen < strlen("mds_conn") ||
            memcmp(key, "mds_conn", keylen) != 0)
                RETURN(-EINVAL);

        CERROR("Received MDS connection ("LPX64")\n", conn->cookie);
        memcpy(&obd->u.filter.fo_mdc_conn, conn, sizeof(*conn));

        imp = obd->u.filter.fo_mdc_imp = class_new_import();

        exp = class_conn2export(conn);
        imp->imp_connection = ptlrpc_connection_addref(exp->exp_connection);
        class_export_put(exp);

        imp->imp_client = &obd->u.filter.fo_mdc_client;
        imp->imp_remote_handle = *conn;
        imp->imp_obd = obd;
        imp->imp_dlm_fake = 1; /* XXX rename imp_dlm_fake to something else */
        imp->imp_level = LUSTRE_CONN_FULL;
        class_import_put(imp);

        RETURN(0);
}

int filter_iocontrol(unsigned int cmd, struct lustre_handle *conn,
                     int len, void *karg, void *uarg)
{
        struct obd_device *obd = class_conn2obd(conn);

        switch (cmd) {
        case OBD_IOC_ABORT_RECOVERY:
                CERROR("aborting recovery for device %s\n", obd->obd_name);
                target_abort_recovery(obd);
                RETURN(0);

        default:
                RETURN(-EINVAL);
        }
        RETURN(0);
}

static struct obd_ops filter_obd_ops = {
        o_owner:          THIS_MODULE,
        o_attach:         filter_attach,
        o_detach:         filter_detach,
        o_get_info:       filter_get_info,
        o_set_info:       filter_set_info,
        o_setup:          filter_setup,
        o_cleanup:        filter_cleanup,
        o_connect:        filter_connect,
        o_disconnect:     filter_disconnect,
        o_statfs:         filter_statfs,
        o_syncfs:         filter_syncfs,
        o_getattr:        filter_getattr,
        o_create:         filter_create,
        o_setattr:        filter_setattr,
        o_destroy:        filter_destroy,
        o_open:           filter_open,
        o_close:          filter_close,
        o_brw:            filter_brw,
        o_punch:          filter_truncate,
        o_preprw:         filter_preprw,
        o_commitrw:       filter_commitrw,
        o_log_cancel:     filter_log_cancel,
        o_destroy_export: filter_destroy_export,
        o_iocontrol:      filter_iocontrol,
};

static struct obd_ops filter_sanobd_ops = {
        o_owner:          THIS_MODULE,
        o_attach:         filter_attach,
        o_detach:         filter_detach,
        o_get_info:       filter_get_info,
        o_set_info:       filter_set_info,
        o_setup:          filter_san_setup,
        o_cleanup:        filter_cleanup,
        o_connect:        filter_connect,
        o_disconnect:     filter_disconnect,
        o_statfs:         filter_statfs,
        o_getattr:        filter_getattr,
        o_create:         filter_create,
        o_setattr:        filter_setattr,
        o_destroy:        filter_destroy,
        o_open:           filter_open,
        o_close:          filter_close,
        o_brw:            filter_brw,
        o_punch:          filter_truncate,
        o_preprw:         filter_preprw,
        o_commitrw:       filter_commitrw,
        o_log_cancel:     filter_log_cancel,
        o_san_preprw:     filter_san_preprw,
        o_destroy_export: filter_destroy_export,
        o_iocontrol:      filter_iocontrol,
};

static int __init obdfilter_init(void)
{
        struct lprocfs_static_vars lvars;
        int rc;

        printk(KERN_INFO "Lustre Filtering OBD driver; info@clusterfs.com\n");

        lprocfs_init_vars(filter, &lvars);

        rc = class_register_type(&filter_obd_ops, lvars.module_vars,
                                 OBD_FILTER_DEVICENAME);
        if (rc)
                return rc;

        rc = class_register_type(&filter_sanobd_ops, lvars.module_vars,
                                 OBD_FILTER_SAN_DEVICENAME);
        if (rc)
                class_unregister_type(OBD_FILTER_DEVICENAME);
        return rc;
}

static void __exit obdfilter_exit(void)
{
        class_unregister_type(OBD_FILTER_SAN_DEVICENAME);
        class_unregister_type(OBD_FILTER_DEVICENAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Filtering OBD driver");
MODULE_LICENSE("GPL");

module_init(obdfilter_init);
module_exit(obdfilter_exit);
