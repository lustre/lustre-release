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

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/config.h>
#include <linux/module.h>
#include <linux/pagemap.h> // XXX kill me soon
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/obd_class.h>
#include <linux/lustre_dlm.h>
#include <linux/obd_filter.h>
#include <linux/init.h>
#include <linux/random.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lprocfs_status.h>
#include <linux/version.h>
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
#include <linux/mount.h>
#endif

enum {
        LPROC_FILTER_READ_BYTES = 0,
        LPROC_FILTER_WRITE_BYTES = 1,
        LPROC_FILTER_LAST,
};

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

static void filter_commit_cb(struct obd_device *obd, __u64 transno, int error)
{
        obd_transno_commit_cb(obd, transno, error);
}
/* Assumes caller has already pushed us into the kernel context. */
int filter_finish_transno(struct obd_export *export, void *handle,
                          struct obd_trans_info *oti, int rc)
{
        __u64 last_rcvd;
        struct obd_device *obd = export->exp_obd;
        struct filter_obd *filter = &obd->u.filter;
        struct filter_export_data *fed = &export->exp_filter_data;
        struct filter_client_data *fcd = fed->fed_fcd;
        loff_t off;
        ssize_t written;

        /* Propagate error code. */
        if (rc)
                RETURN(rc);

        if (!obd->obd_replayable)
                RETURN(rc);

        /* we don't allocate new transnos for replayed requests */
#if 0
        /* perhaps if transno already set? or should level be in oti? */
        if (req->rq_level == LUSTRE_CONN_RECOVD)
                GOTO(out, rc = 0);
#endif

        off = fed->fed_lr_off;

        spin_lock(&filter->fo_translock);
        last_rcvd = le64_to_cpu(filter->fo_fsd->fsd_last_rcvd);
        filter->fo_fsd->fsd_last_rcvd = cpu_to_le64(last_rcvd + 1);
        spin_unlock(&filter->fo_translock);
        if (oti)
                oti->oti_transno = last_rcvd;
        fcd->fcd_last_rcvd = cpu_to_le64(last_rcvd);
        fcd->fcd_mount_count = filter->fo_fsd->fsd_mount_count;

        /* get this from oti */
#if 0
        if (oti)
                fcd->fcd_last_xid = cpu_to_le64(oti->oti_xid);
        else
#else
        fcd->fcd_last_xid = 0;
#endif
        fsfilt_set_last_rcvd(obd, last_rcvd, handle, filter_commit_cb);
        written = lustre_fwrite(filter->fo_rcvd_filp, (char *)fcd, sizeof(*fcd),
                                &off);
        CDEBUG(D_INODE, "wrote trans #"LPD64" for client %s at #%d: written = "
               LPSZ"\n", last_rcvd, fcd->fcd_uuid, fed->fed_lr_idx, written);

        if (written == sizeof(*fcd))
                RETURN(0);
        CERROR("error writing to last_rcvd file: rc = %d\n", (int)written);
        if (written >= 0)
                RETURN(-EIO);

        RETURN(written);
}

static inline void f_dput(struct dentry *dentry)
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
        .d_release = filter_drelease,
};

#define LAST_RCVD "last_rcvd"
#define INIT_OBJID 2

/* This limit is arbitrary, but for now we fit it in 1 page (32k clients) */
#define FILTER_LR_MAX_CLIENTS (PAGE_SIZE * 8)
#define FILTER_LR_MAX_CLIENT_WORDS (FILTER_LR_MAX_CLIENTS/sizeof(unsigned long))

/* Add client data to the FILTER.  We use a bitmap to locate a free space
 * in the last_rcvd file if cl_idx is -1 (i.e. a new client).
 * Otherwise, we have just read the data from the last_rcvd file and
 * we know its offset.
 */
int filter_client_add(struct obd_device *obd, struct filter_obd *filter,
                      struct filter_export_data *fed, int cl_idx)
{
        unsigned long *bitmap = filter->fo_last_rcvd_slots;
        int new_client = (cl_idx == -1);

        LASSERT(bitmap != NULL);

        /* XXX if mcd_uuid were a real obd_uuid, I could use obd_uuid_equals */
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
                        return -ENOMEM;
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
                ssize_t written;
                void *handle;

                CDEBUG(D_INFO, "writing client fcd at idx %u (%llu) (len %u)\n",
                       fed->fed_lr_idx,off,(unsigned int)sizeof(*fed->fed_fcd));

                push_ctxt(&saved, &filter->fo_ctxt, NULL);
                /* Transaction eeded to fix for bug 1403 */
                handle = fsfilt_start(obd,
                                      filter->fo_rcvd_filp->f_dentry->d_inode,
                                      FSFILT_OP_SETATTR);
                if (IS_ERR(handle)) {
                        written = PTR_ERR(handle);
                        CERROR("unable to start transaction: rc %d\n",
                               (int)written);
                } else {
                        written = lustre_fwrite(filter->fo_rcvd_filp,
                                                (char *)fed->fed_fcd,
                                                sizeof(*fed->fed_fcd), &off);
                        fsfilt_commit(obd,
                                      filter->fo_rcvd_filp->f_dentry->d_inode,
                                      handle, 0);
                }
                pop_ctxt(&saved, &filter->fo_ctxt, NULL);

                if (written != sizeof(*fed->fed_fcd)) {
                        if (written < 0)
                                RETURN(written);
                        RETURN(-EIO);
                }
        }
        return 0;
}

int filter_client_free(struct obd_export *exp, int failover)
{
        struct filter_export_data *fed = &exp->exp_filter_data;
        struct filter_obd *filter = &exp->exp_obd->u.filter;
        struct filter_client_data zero_fcd;
        struct obd_run_ctxt saved;
        int written;
        loff_t off;

        if (!fed->fed_fcd)
                RETURN(0);

        if (failover != 0) {
                OBD_FREE(fed->fed_fcd, sizeof(*fed->fed_fcd));
                RETURN(0);
        }

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
        written = lustre_fwrite(filter->fo_rcvd_filp, (const char *)&zero_fcd,
                                sizeof(zero_fcd), &off);

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

        OBD_FREE(fed->fed_fcd, sizeof(*fed->fed_fcd));

        return 0;
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
static int filter_update_server_data(struct file *filp,
                                     struct filter_server_data *fsd)
{
        loff_t off = 0;
        int rc;

        CDEBUG(D_INODE, "server uuid      : %s\n", fsd->fsd_uuid);
        CDEBUG(D_INODE, "server last_objid: "LPU64"\n",
               le64_to_cpu(fsd->fsd_last_objid));
        CDEBUG(D_INODE, "server last_rcvd : "LPU64"\n",
               le64_to_cpu(fsd->fsd_last_rcvd));
        CDEBUG(D_INODE, "server last_mount: "LPU64"\n",
               le64_to_cpu(fsd->fsd_mount_count));

        rc = lustre_fwrite(filp, (char *)fsd, sizeof(*fsd), &off);
        if (rc != sizeof(*fsd)) {
                CDEBUG(D_INODE, "error writing filter_server_data: rc = %d\n",
                       rc);
                RETURN(-EIO);
        }
        RETURN(0);
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
                CERROR("%s: initializing new last_rcvd\n", obd->obd_name);

                memcpy(fsd->fsd_uuid, obd->obd_uuid.uuid,sizeof(fsd->fsd_uuid));
                fsd->fsd_last_objid = cpu_to_le64(init_lastobjid);
                fsd->fsd_last_rcvd = 0;
                mount_count = fsd->fsd_mount_count = 0;
                fsd->fsd_server_size = cpu_to_le32(FILTER_LR_SERVER_SIZE);
                fsd->fsd_client_start = cpu_to_le32(FILTER_LR_CLIENT_START);
                fsd->fsd_client_size = cpu_to_le16(FILTER_LR_CLIENT_SIZE);
                fsd->fsd_subdir_count = cpu_to_le16(FILTER_SUBDIR_COUNT);
                filter->fo_subdir_count = FILTER_SUBDIR_COUNT;
        } else {
                ssize_t retval = lustre_fread(filp, (char *)fsd, sizeof(*fsd),
                                              &off);
                if (retval != sizeof(*fsd)) {
                        CDEBUG(D_INODE,"OBD filter: error reading %s\n",
                               LAST_RCVD);
                        GOTO(err_fsd, rc = -EIO);
                }
                mount_count = le64_to_cpu(fsd->fsd_mount_count);
                filter->fo_subdir_count = le16_to_cpu(fsd->fsd_subdir_count);
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
               obd->obd_name, le64_to_cpu(fsd->fsd_last_rcvd));
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

        /*
         * When we do a clean FILTER shutdown, we save the last_rcvd into
         * the header.  If we find clients with higher last_rcvd values
         * then those clients may need recovery done.
         */
        if (!obd->obd_replayable) {
                CERROR("%s: recovery support OFF\n", obd->obd_name);
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
                rc = lustre_fread(filp, (char *)fcd, sizeof(*fcd), &off);
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
                               last_rcvd, le64_to_cpu(fsd->fsd_last_rcvd),
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

                if (last_rcvd > le64_to_cpu(filter->fo_fsd->fsd_last_rcvd))
                        filter->fo_fsd->fsd_last_rcvd = cpu_to_le64(last_rcvd);

                obd->obd_last_committed =
                        le64_to_cpu(filter->fo_fsd->fsd_last_rcvd);
                if (obd->obd_recoverable_clients) {
                        CERROR("RECOVERY: %d recoverable clients, last_rcvd "
                               LPU64"\n", obd->obd_recoverable_clients,
                               le64_to_cpu(filter->fo_fsd->fsd_last_rcvd));
                        obd->obd_next_recovery_transno =
                                obd->obd_last_committed + 1;
                        obd->obd_recovering = 1;
                }

        }

        if (fcd)
                OBD_FREE(fcd, sizeof(*fcd));

out:
        fsd->fsd_mount_count = cpu_to_le64(mount_count + 1);

        /* save it,so mount count and last_recvd is current */
        rc = filter_update_server_data(filp, filter->fo_fsd);

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

        file = filp_open(LAST_RCVD, O_RDWR | O_CREAT, 0700);
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

        rc = filter_init_server_data(obd, file, INIT_OBJID);
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
        rc = filter_update_server_data(filter->fo_rcvd_filp, filter->fo_fsd);
        if (rc)
                CERROR("OBD filter: error writing lastobjid: rc = %ld\n", rc);


        if (filter->fo_rcvd_filp) {
                rc = file_fsync(filter->fo_rcvd_filp,
                                filter->fo_rcvd_filp->f_dentry, 1);
                filp_close(filter->fo_rcvd_filp, 0);
                filter->fo_rcvd_filp = NULL;
                if (rc)
                        CERROR("last_rcvd file won't closed rc = %ld\n", rc);
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


static __u64 filter_next_id(struct filter_obd *filter)
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
int filter_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
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

static void filter_parent_unlock(struct dentry *dparent,
                                 struct lustre_handle *lockh,
                                 ldlm_mode_t lock_mode)
{
        ldlm_lock_decref(lockh, lock_mode);
}

/* We never dget the object parent, so DON'T dput it either */
static inline struct dentry *filter_parent(struct obd_device *obd,
                                           obd_mode mode, obd_id objid)
{
        struct filter_obd *filter = &obd->u.filter;

        LASSERT(S_ISREG(mode));   /* only regular files for now */
        if (!S_ISREG(mode) || filter->fo_subdir_count == 0)
                return filter->fo_dentry_O_mode[(mode & S_IFMT) >> S_SHIFT];

        return filter->fo_dentry_O_sub[objid & (filter->fo_subdir_count - 1)];
}

/* We never dget the object parent, so DON'T dput it either */
static inline struct dentry *filter_parent_lock(struct obd_device *obd,
                                                obd_mode mode, obd_id objid,
                                                ldlm_mode_t lock_mode,
                                                struct lustre_handle *lockh)
{
        unsigned long now = jiffies;
        struct dentry *de = filter_parent(obd, mode, objid);
        int rc;

        if (IS_ERR(de))
                return de;

        rc = filter_lock_dentry(obd, de, lock_mode, lockh);
        if (time_after(jiffies, now + 15*HZ))
                CERROR("slow parent lock %lus\n", (jiffies - now) / HZ);
        return rc ? ERR_PTR(rc) : de;
}

/* How to get files, dentries, inodes from object id's.
 *
 * If dir_dentry is passed, the caller has already locked the parent
 * appropriately for this operation (normally a write lock).  If
 * dir_dentry is NULL, we do a read lock while we do the lookup to
 * avoid races with create/destroy and such changing the directory
 * internal to the filesystem code.
 */
static struct dentry *filter_fid2dentry(struct obd_device *obd,
                                        struct dentry *dir_dentry,
                                        obd_mode mode, obd_id id)
{
        struct super_block *sb = obd->u.filter.fo_sb;
        struct lustre_handle lockh;
        struct dentry *dparent = dir_dentry;
        struct dentry *dchild;
        char name[32];
        int len;
        ENTRY;

        if (!sb || !sb->s_dev) {
                CERROR("device not initialized.\n");
                RETURN(ERR_PTR(-ENXIO));
        }

        if (id == 0) {
                CERROR("fatal: invalid object id 0\n");
                LBUG();
                RETURN(ERR_PTR(-ESTALE));
        }

        len = sprintf(name, LPU64, id);
        if (!dir_dentry) {
                dparent = filter_parent_lock(obd, mode, id, LCK_PR, &lockh);
                if (IS_ERR(dparent))
                        RETURN(dparent);
        }
        CDEBUG(D_INODE, "looking up object O/%*s/%s\n",
               dparent->d_name.len, dparent->d_name.name, name);
        dchild = ll_lookup_one_len(name, dparent, len);
        if (!dir_dentry)
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
                                    __u64 id, __u32 type,
                                    ldlm_mode_t parent_mode,
                                    struct lustre_handle *parent_lockh)
{
        struct obd_device *obd = export->exp_obd;
        struct filter_obd *filter = &obd->u.filter;
        struct super_block *sb = filter->fo_sb;
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

        if (!sb || !sb->s_dev) {
                CERROR("fatal: device not initialized.\n");
                GOTO(cleanup, file = ERR_PTR(-ENXIO));
        }

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
 * Caller is also required to ensure that dchild->d_inode exists.
 */
static int filter_destroy_internal(struct obd_device *obd,
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
                                 struct obd_trans_info *oti,
                                 int failover)
{
        struct obd_device *obd = exp->exp_obd;
        struct filter_obd *filter = &obd->u.filter;
        struct file *filp = ffd->ffd_file;
        struct dentry *dchild = dget(filp->f_dentry);
        struct filter_dentry_data *fdd = dchild->d_fsdata;
        struct lustre_handle parent_lockh;
        int rc, rc2, cleanup_phase = 0;
        struct dentry *dparent;
        struct obd_run_ctxt saved;
        ENTRY;

        LASSERT(filp->private_data == ffd);
        LASSERT(fdd);
        LASSERT(fdd->fdd_magic == FILTER_DENTRY_MAGIC);

        rc = filp_close(filp, 0);

        if (atomic_dec_and_test(&fdd->fdd_open_count) &&
            fdd->fdd_flags & FILTER_FLAG_DESTROY && !failover) {
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
                                      FSFILT_OP_UNLINK);
                if (IS_ERR(handle))
                        GOTO(cleanup, rc = PTR_ERR(handle));

                /* XXX unlink from PENDING directory now too */
                rc2 = filter_destroy_internal(obd, dparent, dchild);
                if (rc2 && !rc)
                        rc = rc2;
                rc = filter_finish_transno(exp, handle, oti, rc);
                rc2 = fsfilt_commit(obd, dparent->d_inode, handle, 0);
                if (rc2) {
                        CERROR("error on commit, err = %d\n", rc2);
                        if (!rc)
                                rc = rc2;
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

/* obd methods */
/* mount the file system (secretly) */
static int filter_common_setup(struct obd_device *obd, obd_count len, void *buf,
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

        mnt = do_kern_mount(data->ioc_inlbuf2, 0, data->ioc_inlbuf1, option);
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

        obd->obd_namespace = ldlm_namespace_new("filter-tgt",
                                                LDLM_NAMESPACE_SERVER);
        if (!obd->obd_namespace)
                GOTO(err_post, rc = -ENOMEM);

        ptlrpc_init_client(LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
                           "filter_ldlm_cb_client", &obd->obd_ldlm_client);

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

        if (!strcmp(data->ioc_inlbuf2, "ext3"))
                option = "asyncdel";

        return filter_common_setup(obd, len, buf, option);
}

/* sanobd setup methods - use a specific mount option */
static int filter_san_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct obd_ioctl_data* data = buf;
        char *option = NULL;

        if (!data->ioc_inlbuf2)
                RETURN(-EINVAL);

        /* for extN/ext3 filesystem, we must mount it with 'writeback' mode */
        if (!strcmp(data->ioc_inlbuf2, "extN"))
                option = "data=writeback";
        else if (!strcmp(data->ioc_inlbuf2, "ext3"))
                option = "data=writeback,asyncdel";
        else
                LBUG(); /* just a reminder */

        return filter_common_setup(obd, len, buf, option);
}

static int filter_cleanup(struct obd_device *obd, int force, int failover)
{
        struct super_block *sb;
        ENTRY;

        if (failover)
                CERROR("%s: shutting down for failover; client state will"
                       " be preserved.\n", obd->obd_name);

        if (!list_empty(&obd->obd_exports)) {
                CERROR("%s: still has clients!\n", obd->obd_name);
                class_disconnect_exports(obd, failover);
                if (!list_empty(&obd->obd_exports)) {
                        CERROR("still has exports after forced cleanup?\n");
                        RETURN(-EBUSY);
                }
        }

        ldlm_namespace_free(obd->obd_namespace);

        sb = obd->u.filter.fo_sb;
        if (!sb)
                RETURN(0);

        filter_post(obd);

        shrink_dcache_parent(sb->s_root);
        unlock_kernel();

        if (atomic_read(&obd->u.filter.fo_vfsmnt->mnt_count) > 1){
                CERROR("%s: mount point busy, mnt_count: %d\n", obd->obd_name,
                       atomic_read(&obd->u.filter.fo_vfsmnt->mnt_count));
        }

        mntput(obd->u.filter.fo_vfsmnt);
        obd->u.filter.fo_sb = 0;
/*        destroy_buffers(obd->u.filter.fo_sb->s_dev);*/

        fsfilt_put_ops(obd->obd_fsops);
        lock_kernel();

        RETURN(0);
}

int filter_attach(struct obd_device *obd, obd_count len, void *data)
{
        struct lprocfs_static_vars lvars;
        int rc;

        lprocfs_init_vars(&lvars);
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

int filter_detach(struct obd_device *dev)
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

        if (!conn || !obd || !cluuid)
                RETURN(-EINVAL);

        rc = class_connect(conn, obd, cluuid);
        if (rc)
                RETURN(rc);
        exp = class_conn2export(conn);
        LASSERT(exp);

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

                CERROR("force close file %*s (hdl %p:"LPX64") on disconnect\n",
                       ffd->ffd_file->f_dentry->d_name.len,
                       ffd->ffd_file->f_dentry->d_name.name,
                       ffd, ffd->ffd_handle.h_cookie);

                filter_close_internal(exp, ffd, NULL, exp->exp_failover);
                spin_lock(&fed->fed_lock);
        }
        spin_unlock(&fed->fed_lock);

        if (exp->exp_obd->obd_replayable)
                filter_client_free(exp, exp->exp_failover);
        EXIT;
}

/* also incredibly similar to mds_disconnect */
static int filter_disconnect(struct lustre_handle *conn, int failover)
{
        struct obd_export *exp = class_conn2export(conn);
        int rc;
        unsigned long flags;
        ENTRY;

        LASSERT(exp);
        ldlm_cancel_locks_for_export(exp);

        spin_lock_irqsave(&exp->exp_lock, flags);
        exp->exp_failover = failover;
        spin_unlock_irqrestore(&exp->exp_lock, flags);

        rc = class_disconnect(conn, failover);

        fsfilt_sync(exp->exp_obd, exp->exp_obd->u.filter.fo_sb);
        class_export_put(exp);
        /* XXX cleanup preallocated inodes */
        RETURN(rc);
}

static void filter_from_inode(struct obdo *oa, struct inode *inode, int valid)
{
        int type = oa->o_mode & S_IFMT;
        ENTRY;

        CDEBUG(D_INFO, "src inode %lu (%p), dst obdo "LPU64" valid 0x%08x\n",
               inode->i_ino, inode, oa->o_id, valid);
        /* Don't copy the inode number in place of the object ID */
        obdo_from_inode(oa, inode, valid);
        oa->o_mode &= ~S_IFMT;
        oa->o_mode |= type;

        if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)) {
                obd_rdev rdev = kdev_t_to_nr(inode->i_rdev);
                oa->o_rdev = rdev;
                oa->o_valid |= OBD_MD_FLRDEV;
        }

        EXIT;
}

static struct dentry *__filter_oa2dentry(struct lustre_handle *conn,
                                         struct obdo *oa, char *what)
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

                        CDEBUG(D_INODE,
                               "got child objid %*s: %p, count = %d\n",
                               dchild->d_name.len, dchild->d_name.name,
                               dchild, atomic_read(&dchild->d_count));
                }
        }

        if (!dchild) {
                struct obd_device *obd = class_conn2obd(conn);

                if (!obd) {
                        CERROR("invalid client cookie "LPX64"\n", conn->cookie);
                        RETURN(ERR_PTR(-EINVAL));
                }
                dchild = filter_fid2dentry(obd, NULL, oa->o_mode, oa->o_id);
        }

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

#define filter_oa2dentry(conn, oa) __filter_oa2dentry(conn, oa, __FUNCTION__)

static int filter_getattr(struct lustre_handle *conn, struct obdo *oa,
                          struct lov_stripe_md *md)
{
        struct dentry *dentry = NULL;
        int rc = 0;
        ENTRY;

        dentry = filter_oa2dentry(conn, oa);
        if (IS_ERR(dentry))
                RETURN(PTR_ERR(dentry));

        filter_from_inode(oa, dentry->d_inode, oa->o_valid);

        f_dput(dentry);
        RETURN(rc);
}

/* this is called from filter_truncate() until we have filter_punch() */
static int filter_setattr(struct lustre_handle *conn, struct obdo *oa,
                          struct lov_stripe_md *md, struct obd_trans_info *oti)
{
        struct obd_run_ctxt saved;
        struct obd_export *export = class_conn2export(conn);
        struct obd_device *obd = class_conn2obd(conn);
        struct filter_obd *filter = &obd->u.filter;
        struct dentry *dentry;
        struct iattr iattr;
        struct inode *inode;
        void * handle;
        int rc, rc2;
        ENTRY;

        dentry = filter_oa2dentry(conn, oa);

        if (IS_ERR(dentry))
                GOTO(out_exp, rc = PTR_ERR(dentry));

        iattr_from_obdo(&iattr, oa, oa->o_valid);
        iattr.ia_mode = (iattr.ia_mode & ~S_IFMT) | S_IFREG;
        inode = dentry->d_inode;

        push_ctxt(&saved, &filter->fo_ctxt, NULL);
        lock_kernel();
        if (iattr.ia_valid & ATTR_SIZE)
                down(&inode->i_sem);

        handle = fsfilt_start(obd, dentry->d_inode, FSFILT_OP_SETATTR);
        if (IS_ERR(handle))
                GOTO(out_unlock, rc = PTR_ERR(handle));

        rc = fsfilt_setattr(obd, dentry, handle, &iattr, 1);
        rc = filter_finish_transno(export, handle, oti, rc);
        rc2 = fsfilt_commit(obd, dentry->d_inode, handle, 0);
        if (rc2) {
                CERROR("error on commit, err = %d\n", rc2);
                if (!rc)
                        rc = rc2;
        }

        if (iattr.ia_valid & ATTR_SIZE) {
                up(&inode->i_sem);
                oa->o_valid = OBD_MD_FLBLOCKS | OBD_MD_FLCTIME | OBD_MD_FLMTIME;
                obdo_from_inode(oa, inode, oa->o_valid);
        }

out_unlock:
        unlock_kernel();
        pop_ctxt(&saved, &filter->fo_ctxt, NULL);

        f_dput(dentry);
 out_exp:
        class_export_put(export);
        RETURN(rc);
}

static int filter_open(struct lustre_handle *conn, struct obdo *oa,
                       struct lov_stripe_md *ea, struct obd_trans_info *oti,
                       struct obd_client_handle *och)
{
        struct obd_export *export = NULL;
        struct lustre_handle *handle;
        struct filter_file_data *ffd;
        struct file *filp;
        struct lustre_handle parent_lockh;
        int rc = 0;
        ENTRY;

        export = class_conn2export(conn);
        if (!export) {
                CDEBUG(D_IOCTL, "invalid client cookie "LPX64"\n",
                       conn->cookie);
                GOTO(out, rc = -EINVAL);
        }

        filp = filter_obj_open(export, oa->o_id, oa->o_mode,
                               LCK_PR, &parent_lockh);
        if (IS_ERR(filp))
                GOTO(out, rc = PTR_ERR(filp));

        filter_from_inode(oa, filp->f_dentry->d_inode, oa->o_valid);

        ffd = filp->private_data;
        handle = obdo_handle(oa);
        handle->cookie = ffd->ffd_handle.h_cookie;
        oa->o_valid |= OBD_MD_FLHANDLE;

out:
        class_export_put(export);
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
        struct obd_export *exp = class_conn2export(conn);
        struct filter_file_data *ffd;
        struct filter_export_data *fed;
        int rc;
        ENTRY;

        if (!exp) {
                CDEBUG(D_IOCTL, "invalid client cookie"LPX64"\n", conn->cookie);
                GOTO(out, rc = -EINVAL);
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
        struct obd_device *obd = class_conn2obd(conn);
        struct filter_obd *filter = &obd->u.filter;
        struct obd_run_ctxt saved;
        struct lustre_handle parent_lockh;
        struct dentry *dparent;
        struct dentry *dchild = NULL;
        struct iattr;
        void *handle;
        int err, rc, cleanup_phase;
        ENTRY;

        if (!obd) {
                CERROR("invalid client cookie "LPX64"\n", conn->cookie);
                RETURN(-EINVAL);
        }

        exp = class_conn2export(conn);

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
        handle = fsfilt_start(obd, dparent->d_inode, FSFILT_OP_CREATE);
        if (IS_ERR(handle))
                GOTO(cleanup, rc = PTR_ERR(handle));

        rc = vfs_create(dparent->d_inode, dchild, oa->o_mode);
        if (rc)
                CERROR("create failed rc = %d\n", rc);

        rc = filter_finish_transno(exp, handle, oti, rc);
        err = filter_update_server_data(filter->fo_rcvd_filp, filter->fo_fsd);
        if (err) {
                CERROR("unable to write lastobjid but file created\n");
                if (!rc)
                        rc = err;
        }
        err = fsfilt_commit(obd, dparent->d_inode, handle, 0);
        if (err) {
                CERROR("error on commit, err = %d\n", err);
                if (!rc)
                        rc = err;
        }

        if (rc)
                GOTO(cleanup, rc);

        /* Set flags for fields we have set in the inode struct */
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLBLKSZ | OBD_MD_FLBLOCKS |
                 OBD_MD_FLMTIME | OBD_MD_FLATIME | OBD_MD_FLCTIME;
        filter_from_inode(oa, dchild->d_inode, oa->o_valid);

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
        struct obd_device *obd = class_conn2obd(conn);
        struct filter_obd *filter = &obd->u.filter;
        struct dentry *dparent, *dchild = NULL;
        struct filter_dentry_data *fdd;
        struct obd_run_ctxt saved;
        void *handle = NULL;
        struct lustre_handle parent_lockh;
        int rc, rc2, cleanup_phase = 0;
        ENTRY;

        if (!obd) {
                CERROR("invalid client cookie "LPX64"\n", conn->cookie);
                RETURN(-EINVAL);
        }

        exp = class_conn2export(conn);

        CDEBUG(D_INODE, "destroying objid "LPU64"\n", oa->o_id);

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

        if (!dchild->d_inode) {
                CERROR("destroying non-existent object "LPU64"\n", oa->o_id);
                GOTO(cleanup, rc = -ENOENT);
        }

        handle = fsfilt_start(obd, dparent->d_inode, FSFILT_OP_UNLINK);
        if (IS_ERR(handle))
                GOTO(cleanup, rc = PTR_ERR(handle));
        cleanup_phase = 3;

        fdd = dchild->d_fsdata;
        if (fdd && atomic_read(&fdd->fdd_open_count)) {
                LASSERT(fdd->fdd_magic = FILTER_DENTRY_MAGIC);
                if (!(fdd->fdd_flags & FILTER_FLAG_DESTROY)) {
                        fdd->fdd_flags |= FILTER_FLAG_DESTROY;
                        /* XXX put into PENDING directory in case of crash */
                        CDEBUG(D_INODE,
                               "defer destroy of %dx open objid "LPU64"\n",
                               atomic_read(&fdd->fdd_open_count), oa->o_id);
                } else
                        CDEBUG(D_INODE,
                               "repeat destroy of %dx open objid "LPU64"\n",
                               atomic_read(&fdd->fdd_open_count), oa->o_id);
                GOTO(cleanup, rc = 0);
        }

        rc = filter_destroy_internal(obd, dparent, dchild);

cleanup:
        switch(cleanup_phase) {
        case 3:
                rc = filter_finish_transno(exp, handle, oti, rc);
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

static inline void lustre_put_page(struct page *page)
{
        page_cache_release(page);
}

static int filter_start_page_read(struct inode *inode, struct niobuf_local *lnb)
{
        struct address_space *mapping = inode->i_mapping;
        struct page *page;
        unsigned long index = lnb->offset >> PAGE_SHIFT;
        int rc;

        page = grab_cache_page(mapping, index); /* locked page */
        if (IS_ERR(page))
                return lnb->rc = PTR_ERR(page);

        lnb->page = page;

        if (inode->i_size < lnb->offset + lnb->len - 1)
                lnb->rc = inode->i_size - lnb->offset;
        else
                lnb->rc = lnb->len;

        if (PageUptodate(page)) {
                unlock_page(page);
                return 0;
        }

        rc = mapping->a_ops->readpage(NULL, page);
        if (rc < 0) {
                CERROR("page index %lu, rc = %d\n", index, rc);
                lnb->page = NULL;
                lustre_put_page(page);
                return lnb->rc = rc;
        }

        return 0;
}

static int filter_finish_page_read(struct niobuf_local *lnb)
{
        if (lnb->page == NULL)
                return 0;

        if (PageUptodate(lnb->page))
                return 0;

        wait_on_page(lnb->page);
        if (!PageUptodate(lnb->page)) {
                CERROR("page index %lu/offset "LPX64" not uptodate\n",
                       lnb->page->index, lnb->offset);
                GOTO(err_page, lnb->rc = -EIO);
        }
        if (PageError(lnb->page)) {
                CERROR("page index %lu/offset "LPX64" has error\n",
                       lnb->page->index, lnb->offset);
                GOTO(err_page, lnb->rc = -EIO);
        }

        return 0;

err_page:
        lustre_put_page(lnb->page);
        lnb->page = NULL;
        return lnb->rc;
}

static struct page *lustre_get_page_write(struct inode *inode,
                                          unsigned long index)
{
        struct address_space *mapping = inode->i_mapping;
        struct page *page;
        int rc;

        page = grab_cache_page(mapping, index); /* locked page */

        if (!IS_ERR(page)) {
                /* Note: Called with "O" and "PAGE_SIZE" this is essentially
                 * a no-op for most filesystems, because we write the whole
                 * page.  For partial-page I/O this will read in the page.
                 */
                rc = mapping->a_ops->prepare_write(NULL, page, 0, PAGE_SIZE);
                if (rc) {
                        CERROR("page index %lu, rc = %d\n", index, rc);
                        if (rc != -ENOSPC)
                                LBUG();
                        GOTO(err_unlock, rc);
                }
                /* XXX not sure if we need this if we are overwriting page */
                if (PageError(page)) {
                        CERROR("error on page index %lu, rc = %d\n", index, rc);
                        LBUG();
                        GOTO(err_unlock, rc = -EIO);
                }
        }
        return page;

err_unlock:
        unlock_page(page);
        lustre_put_page(page);
        return ERR_PTR(rc);
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
int waitfor_one_page(struct page *page)
{
        wait_on_page_locked(page);
        return 0;
}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
/* We should only change the file mtime (and not the ctime, like
 * update_inode_times() in generic_file_write()) when we only change data.
 */
static inline void inode_update_time(struct inode *inode, int ctime_too)
{
        time_t now = CURRENT_TIME;
        if (inode->i_mtime == now && (!ctime_too || inode->i_ctime == now))
                return;
        inode->i_mtime = now;
        if (ctime_too)
                inode->i_ctime = now;
        mark_inode_dirty_sync(inode);
}
#endif

static int lustre_commit_write(struct niobuf_local *lnb)
{
        struct page *page = lnb->page;
        unsigned from = lnb->offset & ~PAGE_MASK;
        unsigned to = from + lnb->len;
        struct inode *inode = page->mapping->host;
        int err;

        LASSERT(to <= PAGE_SIZE);
        err = page->mapping->a_ops->commit_write(NULL, page, from, to);
        if (!err && IS_SYNC(inode))
                err = waitfor_one_page(page);
        //SetPageUptodate(page); // the client commit_write will do this

        SetPageReferenced(page);
        unlock_page(page);
        lustre_put_page(page);
        return err;
}

int filter_get_page_write(struct inode *inode, struct niobuf_local *lnb,
                          int *pglocked)
{
        unsigned long index = lnb->offset >> PAGE_SHIFT;
        struct address_space *mapping = inode->i_mapping;
        struct page *page;
        int rc;

        //ASSERT_PAGE_INDEX(index, GOTO(err, rc = -EINVAL));
        if (*pglocked)
                page = grab_cache_page_nowait(mapping, index); /* locked page */
        else
                page = grab_cache_page(mapping, index); /* locked page */


        /* This page is currently locked, so get a temporary page instead. */
        if (!page) {
                CDEBUG(D_ERROR,"ino %lu page %ld locked\n", inode->i_ino,index);
                page = alloc_pages(GFP_KERNEL, 0); /* locked page */
                if (!page) {
                        CERROR("no memory for a temp page\n");
                        GOTO(err, rc = -ENOMEM);
                }
                page->index = index;
                lnb->page = page;
                lnb->flags |= N_LOCAL_TEMP_PAGE;
        } else if (!IS_ERR(page)) {
                (*pglocked)++;

                rc = mapping->a_ops->prepare_write(NULL, page,
                                                   lnb->offset & ~PAGE_MASK,
                                                   lnb->len);
                if (rc) {
                        if (rc != -ENOSPC)
                                CERROR("page index %lu, rc = %d\n", index, rc);
                        GOTO(err_unlock, rc);
                }
                /* XXX not sure if we need this if we are overwriting page */
                if (PageError(page)) {
                        CERROR("error on page index %lu, rc = %d\n", index, rc);
                        LBUG();
                        GOTO(err_unlock, rc = -EIO);
                }
                lnb->page = page;
        }

        return 0;

err_unlock:
        unlock_page(page);
        lustre_put_page(page);
err:
        return lnb->rc = rc;
}

/*
 * We need to balance prepare_write() calls with commit_write() calls.
 * If the page has been prepared, but we have no data for it, we don't
 * want to overwrite valid data on disk, but we still need to zero out
 * data for space which was newly allocated.  Like part of what happens
 * in __block_prepare_write() for newly allocated blocks.
 *
 * XXX currently __block_prepare_write() creates buffers for all the
 *     pages, and the filesystems mark these buffers as BH_New if they
 *     were newly allocated from disk. We use the BH_New flag similarly.
 */
static int filter_commit_write(struct niobuf_local *lnb, int err)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        if (err) {
                unsigned block_start, block_end;
                struct buffer_head *bh, *head = lnb->page->buffers;
                unsigned blocksize = head->b_size;

                /* debugging: just seeing if this ever happens */
                CDEBUG(err == -ENOSPC ? D_INODE : D_ERROR,
                       "called for ino %lu:%lu on err %d\n",
                       lnb->page->mapping->host->i_ino, lnb->page->index, err);

                /* Currently one buffer per page, but in the future... */
                for (bh = head, block_start = 0; bh != head || !block_start;
                     block_start = block_end, bh = bh->b_this_page) {
                        block_end = block_start + blocksize;
                        if (buffer_new(bh)) {
                                memset(kmap(lnb->page) + block_start, 0,
                                       blocksize);
                                kunmap(lnb->page);
                        }
                }
        }
#endif
        return lustre_commit_write(lnb);
}

static int filter_preprw(int cmd, struct obd_export *exp,
                         int objcount, struct obd_ioobj *obj,
                         int niocount, struct niobuf_remote *nb,
                         struct niobuf_local *res, void **desc_private,
                         struct obd_trans_info *oti)
{
        struct obd_run_ctxt saved;
        struct obd_device *obd;
        struct obd_ioobj *o;
        struct niobuf_remote *rnb;
        struct niobuf_local *lnb;
        struct fsfilt_objinfo *fso;
        struct dentry *dentry;
        struct inode *inode;
        int pglocked = 0, rc = 0, i, j, tot_bytes = 0;
        unsigned long now = jiffies;
        ENTRY;

        memset(res, 0, niocount * sizeof(*res));

        obd = exp->exp_obd;
        if (obd == NULL)
                RETURN(-EINVAL);

        // theoretically we support multi-obj BRW RPCs, but until then...
        LASSERT(objcount == 1);

        OBD_ALLOC(fso, objcount * sizeof(*fso));
        if (!fso)
                RETURN(-ENOMEM);

        push_ctxt(&saved, &obd->u.filter.fo_ctxt, NULL);

        for (i = 0, o = obj; i < objcount; i++, o++) {
                struct filter_dentry_data *fdd;

                LASSERT(o->ioo_bufcnt);

                dentry = filter_fid2dentry(obd, NULL, o->ioo_type, o->ioo_id);

                if (IS_ERR(dentry))
                        GOTO(out_objinfo, rc = PTR_ERR(dentry));

                fso[i].fso_dentry = dentry;
                fso[i].fso_bufcnt = o->ioo_bufcnt;

                if (!dentry->d_inode) {
                        CERROR("trying to BRW to non-existent file "LPU64"\n",
                               o->ioo_id);
                        f_dput(dentry);
                        GOTO(out_objinfo, rc = -ENOENT);
                }

                /* If we ever start to support mutli-object BRW RPCs, we will
                 * need to get locks on mulitple inodes (in order) or use the
                 * DLM to do the locking for us (and use the same locking in
                 * filter_setattr() for truncate).  That isn't all, because
                 * there still exists the possibility of a truncate starting
                 * a new transaction while holding the ext3 rwsem = write
                 * while some writes (which have started their transactions
                 * here) blocking on the ext3 rwsem = read => lock inversion.
                 *
                 * The handling gets very ugly when dealing with locked pages.
                 * It may be easier to just get rid of the locked page code
                 * (which has problems of its own) and either discover we do
                 * not need it anymore (i.e. it was a symptom of another bug)
                 * or ensure we get the page locks in an appropriate order.
                 */
                if (cmd & OBD_BRW_WRITE)
                        down(&dentry->d_inode->i_sem);
                fdd = dentry->d_fsdata;
                if (!fdd || !atomic_read(&fdd->fdd_open_count))
                        CDEBUG(D_PAGE, "I/O to unopened object "LPU64"\n",
                               o->ioo_id);
        }

        if (time_after(jiffies, now + 15*HZ))
                CERROR("slow prep setup %lus\n", (jiffies - now) / HZ);

        if (cmd & OBD_BRW_WRITE) {
                *desc_private = fsfilt_brw_start(obd, objcount, fso,
                                                 niocount, nb);
                if (IS_ERR(*desc_private)) {
                        rc = PTR_ERR(*desc_private);
                        CDEBUG(rc == -ENOSPC ? D_INODE : D_ERROR,
                               "error starting transaction: rc = %d\n", rc);
                        *desc_private = NULL;
                        GOTO(out_objinfo, rc);
                }
        }

        for (i = 0, o = obj, rnb = nb, lnb = res; i < objcount; i++, o++) {
                dentry = fso[i].fso_dentry;
                inode = dentry->d_inode;

                for (j = 0; j < o->ioo_bufcnt; j++, rnb++, lnb++) {
                        if (j == 0)
                                lnb->dentry = dentry;
                        else
                                lnb->dentry = dget(dentry);

                        lnb->offset = rnb->offset;
                        lnb->len    = rnb->len;
                        lnb->flags  = rnb->flags;
                        lnb->start  = jiffies;

                        if (cmd & OBD_BRW_WRITE) {
                                rc = filter_get_page_write(inode,lnb,&pglocked);
                                if (rc)
                                        up(&dentry->d_inode->i_sem);
                        } else if (inode->i_size <= rnb->offset) {
                                /* If there's no more data, abort early.
                                 * lnb->page == NULL and lnb->rc == 0, so it's
                                 * easy to detect later. */
                                f_dput(dentry);
                                lnb->dentry = NULL;
                                break;
                        } else {
                                rc = filter_start_page_read(inode, lnb);
                        }

                        if (rc) {
                                CDEBUG(rc == -ENOSPC ? D_INODE : D_ERROR,
                                       "page err %u@"LPU64" %u/%u %p: rc %d\n",
                                       lnb->len, lnb->offset, j, o->ioo_bufcnt,
                                       dentry, rc);
                                f_dput(dentry);
                                GOTO(out_pages, rc);
                        }

                        tot_bytes += lnb->len;

                        if ((cmd & OBD_BRW_READ) && lnb->rc < lnb->len) {
                                /* Likewise with a partial read */
                                break;
                        }
                }
        }

        if (time_after(jiffies, now + 15*HZ))
                CERROR("slow prep get page %lus\n", (jiffies - now) / HZ);

        if (cmd & OBD_BRW_READ) {
                lprocfs_counter_add(obd->obd_stats, LPROC_FILTER_READ_BYTES,
                                    tot_bytes);
                while (lnb-- > res) {
                        rc = filter_finish_page_read(lnb);
                        if (rc) {
                                CERROR("error page %u@"LPU64" %u %p: rc %d\n",
                                       lnb->len, lnb->offset, lnb - res,
                                       lnb->dentry, rc);
                                f_dput(lnb->dentry);
                                GOTO(out_pages, rc);
                        }
                }
        } else
                lprocfs_counter_add(obd->obd_stats, LPROC_FILTER_WRITE_BYTES,
                                    tot_bytes);

        if (time_after(jiffies, now + 15*HZ))
                CERROR("slow prep finish page %lus\n", (jiffies - now) / HZ);

        EXIT;
out:
        OBD_FREE(fso, objcount * sizeof(*fso));
        current->journal_info = NULL;
        pop_ctxt(&saved, &obd->u.filter.fo_ctxt, NULL);
        return rc;

out_pages:
        while (lnb-- > res) {
                if (cmd & OBD_BRW_WRITE) {
                        filter_commit_write(lnb, rc);
                        up(&lnb->dentry->d_inode->i_sem);
                } else {
                        lustre_put_page(lnb->page);
                }
                f_dput(lnb->dentry);
        }
        if (cmd & OBD_BRW_WRITE) {
                filter_finish_transno(exp, *desc_private, oti, rc);
                fsfilt_commit(obd,
                              filter_parent(obd,S_IFREG,obj->ioo_id)->d_inode,
                              *desc_private, 0);
        }
        goto out; /* dropped the dentry refs already (one per page) */

out_objinfo:
        for (i = 0; i < objcount && fso[i].fso_dentry; i++) {
                if (cmd & OBD_BRW_WRITE)
                        up(&fso[i].fso_dentry->d_inode->i_sem);
                f_dput(fso[i].fso_dentry);
        }
        goto out;
}

static int filter_write_locked_page(struct niobuf_local *lnb)
{
        struct page *lpage;
        void        *lpage_addr;
        void        *lnb_addr;
        int rc;
        ENTRY;

        lpage = lustre_get_page_write(lnb->dentry->d_inode, lnb->page->index);
        if (IS_ERR(lpage)) {
                /* It is highly unlikely that we would ever get an error here.
                 * The page we want to get was previously locked, so it had to
                 * have already allocated the space, and we were just writing
                 * over the same data, so there would be no hole in the file.
                 *
                 * XXX: possibility of a race with truncate could exist, need
                 *      to check that.  There are no guarantees w.r.t.
                 *      write order even on a local filesystem, although the
                 *      normal response would be to return the number of bytes
                 *      successfully written and leave the rest to the app.
                 */
                rc = PTR_ERR(lpage);
                CERROR("error getting locked page index %ld: rc = %d\n",
                       lnb->page->index, rc);
                LBUG();
                lustre_commit_write(lnb);
                RETURN(rc);
        }

        /* 2 kmaps == vanishingly small deadlock opportunity */
        lpage_addr = kmap(lpage);
        lnb_addr = kmap(lnb->page);

        memcpy(lpage_addr, lnb_addr, PAGE_SIZE);

        kunmap(lnb->page);
        kunmap(lpage);

        lustre_put_page(lnb->page);

        lnb->page = lpage;
        rc = lustre_commit_write(lnb);
        if (rc)
                CERROR("error committing locked page %ld: rc = %d\n",
                       lnb->page->index, rc);

        RETURN(rc);
}

static int filter_syncfs(struct obd_export *exp)
{
        struct obd_device *obd = exp->exp_obd;
        ENTRY;

        RETURN(fsfilt_sync(obd, obd->u.filter.fo_sb));
}

static int filter_commitrw(int cmd, struct obd_export *exp,
                           int objcount, struct obd_ioobj *obj,
                           int niocount, struct niobuf_local *res,
                           void *desc_private, struct obd_trans_info *oti)
{
        struct obd_run_ctxt saved;
        struct obd_ioobj *o;
        struct niobuf_local *lnb;
        struct obd_device *obd = exp->exp_obd;
        int found_locked = 0, rc = 0, i;
        unsigned long now = jiffies;  /* DEBUGGING OST TIMEOUTS */
        ENTRY;

        push_ctxt(&saved, &obd->u.filter.fo_ctxt, NULL);

        LASSERT(!current->journal_info);
        current->journal_info = desc_private;

        for (i = 0, o = obj, lnb = res; i < objcount; i++, o++) {
                int j;

                if (cmd & OBD_BRW_WRITE) {
                        inode_update_time(lnb->dentry->d_inode, 1);
                        up(&lnb->dentry->d_inode->i_sem);
                }
                for (j = 0 ; j < o->ioo_bufcnt ; j++, lnb++) {
                        if (lnb->page == NULL) {
                                continue;
                        }

                        if (lnb->flags & N_LOCAL_TEMP_PAGE) {
                                found_locked++;
                                continue;
                        }

                        if (time_after(jiffies, lnb->start + 15*HZ))
                                CERROR("slow commitrw %lus\n",
                                       (jiffies - lnb->start) / HZ);

                        if (cmd & OBD_BRW_WRITE) {
                                int err = filter_commit_write(lnb, 0);

                                if (!rc)
                                        rc = err;
                        } else {
                                lustre_put_page(lnb->page);
                        }

                        f_dput(lnb->dentry);
                        if (time_after(jiffies, lnb->start + 15*HZ))
                                CERROR("slow commit_write %lus\n",
                                       (jiffies - lnb->start) / HZ);
                }
        }

        for (i = 0, o = obj, lnb = res; found_locked > 0 && i < objcount;
             i++, o++) {
                int j;
                for (j = 0 ; j < o->ioo_bufcnt ; j++, lnb++) {
                        int err;
                        if (!(lnb->flags & N_LOCAL_TEMP_PAGE))
                                continue;

                        if (time_after(jiffies, lnb->start + 15*HZ))
                                CERROR("slow commitrw locked %lus\n",
                                       (jiffies - lnb->start) / HZ);

                        err = filter_write_locked_page(lnb);
                        if (!rc)
                                rc = err;
                        f_dput(lnb->dentry);
                        found_locked--;

                        if (time_after(jiffies, lnb->start + 15*HZ))
                                CERROR("slow commit_write locked %lus\n",
                                       (jiffies - lnb->start) / HZ);
                }
        }

        if (cmd & OBD_BRW_WRITE) {
                /* We just want any dentry for the commit, for now */
                struct dentry *dparent = filter_parent(obd, S_IFREG, 0);
                int err;

                rc = filter_finish_transno(exp, desc_private, oti, rc);
                err = fsfilt_commit(obd, dparent->d_inode, desc_private,
                                    obd_sync_filter);
                if (err)
                        rc = err;
                if (obd_sync_filter)
                        LASSERT(oti->oti_transno <= obd->obd_last_committed);

                if (time_after(jiffies, now + 15*HZ))
                        CERROR("slow commitrw commit %lus\n", (jiffies-now)/HZ);
        }

        LASSERT(!current->journal_info);

        pop_ctxt(&saved, &obd->u.filter.fo_ctxt, NULL);
        RETURN(rc);
}

static int filter_brw(int cmd, struct lustre_handle *conn,
                      struct lov_stripe_md *lsm, obd_count oa_bufs,
                      struct brw_page *pga, struct obd_trans_info *oti)
{
        struct obd_export *export = class_conn2export(conn);
        struct obd_ioobj        ioo;
        struct niobuf_local     *lnb;
        struct niobuf_remote    *rnb;
        obd_count               i;
        void                    *desc_private;
        int                     ret = 0;
        ENTRY;

        if (export == NULL)
                RETURN(-EINVAL);

        OBD_ALLOC(lnb, oa_bufs * sizeof(struct niobuf_local));
        OBD_ALLOC(rnb, oa_bufs * sizeof(struct niobuf_remote));

        if (lnb == NULL || rnb == NULL)
                GOTO(out, ret = -ENOMEM);

        for (i = 0; i < oa_bufs; i++) {
                rnb[i].offset = pga[i].off;
                rnb[i].len = pga[i].count;
        }

        ioo.ioo_id = lsm->lsm_object_id;
        ioo.ioo_gr = 0;
        ioo.ioo_type = S_IFREG;
        ioo.ioo_bufcnt = oa_bufs;

        ret = filter_preprw(cmd, export, 1, &ioo, oa_bufs, rnb, lnb,
                            &desc_private, oti);
        if (ret != 0)
                GOTO(out, ret);

        for (i = 0; i < oa_bufs; i++) {
                void *virt = kmap(pga[i].pg);
                obd_off off = pga[i].off & ~PAGE_MASK;
                void *addr = kmap(lnb[i].page);

                /* 2 kmaps == vanishingly small deadlock opportunity */

                if (cmd & OBD_BRW_WRITE)
                        memcpy(addr + off, virt + off, pga[i].count);
                else
                        memcpy(virt + off, addr + off, pga[i].count);

                kunmap(addr);
                kunmap(virt);
        }

        ret = filter_commitrw(cmd, export, 1, &ioo, oa_bufs, lnb, desc_private,
                              oti);

out:
        if (lnb)
                OBD_FREE(lnb, oa_bufs * sizeof(struct niobuf_local));
        if (rnb)
                OBD_FREE(rnb, oa_bufs * sizeof(struct niobuf_remote));
        class_export_put(export);
        RETURN(ret);
}

static int filter_san_preprw(int cmd, struct lustre_handle *conn,
                             int objcount, struct obd_ioobj *obj,
                             int niocount, struct niobuf_remote *nb)
{
        struct obd_device *obd;
        struct obd_ioobj *o = obj;
        struct niobuf_remote *rnb = nb;
        int rc = 0;
        int i;
        ENTRY;

        obd = class_conn2obd(conn);
        if (!obd) {
                CDEBUG(D_IOCTL, "invalid client cookie "LPX64"\n",
                       conn->cookie);
                RETURN(-EINVAL);
        }

        for (i = 0; i < objcount; i++, o++) {
                struct dentry *dentry;
                struct inode *inode;
                int (*fs_bmap)(struct address_space *, long);
                int j;

                dentry = filter_fid2dentry(obd, NULL, o->ioo_type, o->ioo_id);
                if (IS_ERR(dentry))
                        GOTO(out, rc = PTR_ERR(dentry));
                inode = dentry->d_inode;
                if (!inode) {
                        CERROR("trying to BRW to non-existent file "LPU64"\n",
                               o->ioo_id);
                        f_dput(dentry);
                        GOTO(out, rc = -ENOENT);
                }
                fs_bmap = inode->i_mapping->a_ops->bmap;

                for (j = 0; j < o->ioo_bufcnt; j++, rnb++) {
                        long block;

                        block = rnb->offset >> inode->i_blkbits;

                        if (cmd == OBD_BRW_READ) {
                                block = fs_bmap(inode->i_mapping, block);
                        } else {
                                loff_t newsize = rnb->offset + rnb->len;
                                /* fs_prep_san_write will also update inode
                                 * size for us:
                                 * (1) new alloced block
                                 * (2) existed block but size extented
                                 */
                                /* FIXME We could call fs_prep_san_write()
                                 * only once for all the blocks allocation.
                                 * Now call it once for each block, for
                                 * simplicity. And if error happens, we
                                 * probably need to release previous alloced
                                 * block */
                                rc = fs_prep_san_write(obd, inode, &block,
                                                       1, newsize);
                                if (rc)
                                        break;
                        }

                        rnb->offset = block;
                }
                f_dput(dentry);
        }
out:
        RETURN(rc);
}

static int filter_statfs(struct lustre_handle *conn, struct obd_statfs *osfs)
{
        struct obd_device *obd;
        ENTRY;

        obd = class_conn2obd(conn);

        RETURN(fsfilt_statfs(obd, obd->u.filter.fo_sb, osfs));
}

static int filter_get_info(struct lustre_handle *conn, __u32 keylen,
                           void *key, __u32 *vallen, void *val)
{
        struct obd_device *obd;
        ENTRY;

        obd = class_conn2obd(conn);
        if (!obd) {
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

int filter_copy_data(struct lustre_handle *dst_conn, struct obdo *dst,
                  struct lustre_handle *src_conn, struct obdo *src,
                  obd_size count, obd_off offset, struct obd_trans_info *oti)
{
        struct page *page;
        struct lov_stripe_md srcmd, dstmd;
        unsigned long index = 0;
        int err = 0;

        LBUG(); /* THIS CODE IS NOT CORRECT -phil */

        memset(&srcmd, 0, sizeof(srcmd));
        memset(&dstmd, 0, sizeof(dstmd));
        srcmd.lsm_object_id = src->o_id;
        dstmd.lsm_object_id = dst->o_id;

        ENTRY;
        CDEBUG(D_INFO, "src: ino "LPU64" blocks "LPU64", size "LPU64
               ", dst: ino "LPU64"\n",
               src->o_id, src->o_blocks, src->o_size, dst->o_id);
        page = alloc_page(GFP_USER);
        if (page == NULL)
                RETURN(-ENOMEM);

        wait_on_page(page);

        /* XXX with brw vector I/O, we could batch up reads and writes here,
         *     all we need to do is allocate multiple pages to handle the I/Os
         *     and arrays to handle the request parameters.
         */
        while (index < ((src->o_size + PAGE_SIZE - 1) >> PAGE_SHIFT)) {
                struct brw_page pg;

                pg.pg = page;
                pg.count = PAGE_SIZE;
                pg.off = (page->index) << PAGE_SHIFT;
                pg.flag = 0;

                page->index = index;
                err = obd_brw(OBD_BRW_READ, src_conn, &srcmd, 1, &pg, NULL);
                if (err) {
                        EXIT;
                        break;
                }

                pg.flag = OBD_BRW_CREATE;
                CDEBUG(D_INFO, "Read page %ld ...\n", page->index);

                err = obd_brw(OBD_BRW_WRITE, dst_conn, &dstmd, 1, &pg, oti);

                /* XXX should handle dst->o_size, dst->o_blocks here */
                if (err) {
                        EXIT;
                        break;
                }

                CDEBUG(D_INFO, "Wrote page %ld ...\n", page->index);

                index++;
        }
        dst->o_size = src->o_size;
        dst->o_blocks = src->o_blocks;
        dst->o_valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;
        unlock_page(page);
        __free_page(page);

        RETURN(err);
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
        o_destroy_export: filter_destroy_export,
        o_iocontrol:      filter_iocontrol,
#if 0
        o_san_preprw:  filter_san_preprw,
        o_preallocate: filter_preallocate_inodes,
        o_migrate:     filter_migrate,
        o_copy:        filter_copy_data,
        o_iterate:     filter_iterate
#endif
};

static struct obd_ops filter_sanobd_ops = {
        o_owner:          THIS_MODULE,
        o_attach:         filter_attach,
        o_detach:         filter_detach,
        o_get_info:       filter_get_info,
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
        o_san_preprw:     filter_san_preprw,
        o_destroy_export: filter_destroy_export,
        o_iocontrol:      filter_iocontrol,
#if 0
        o_preallocate:  filter_preallocate_inodes,
        o_migrate:      filter_migrate,
        o_copy:         filter_copy_data,
        o_iterate:      filter_iterate
#endif
};


static int __init obdfilter_init(void)
{
        struct lprocfs_static_vars lvars;
        int rc;

        printk(KERN_INFO "Lustre Filtering OBD driver; info@clusterfs.com\n");

        lprocfs_init_vars(&lvars);

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
