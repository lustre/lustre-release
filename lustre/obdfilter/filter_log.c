/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/fs/obdfilter/filter_log.c
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
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

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/config.h>
#include <linux/module.h>
#include <linux/version.h>

#include <portals/list.h>
#include <linux/obd_class.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_commit_confd.h>

#include "filter_internal.h"

static struct llog_handle *filter_log_create(struct obd_device *obd);

/* This is a callback from the llog_* functions.
 * Assumes caller has already pushed us into the kernel context. */
static int filter_log_close(struct llog_handle *cathandle,
                            struct llog_handle *loghandle)
{
        struct llog_object_hdr *llh = loghandle->lgh_hdr;
        struct file *file = loghandle->lgh_file;
        struct dentry *dparent = NULL, *dchild = NULL;
        struct lustre_handle parent_lockh;
        struct llog_logid *lgl = &loghandle->lgh_cookie.lgc_lgl;
        int rc;
        ENTRY;

        /* If we are going to delete this log, grab a ref before we close
         * it so we don't have to immediately do another lookup. */
        if (llh->llh_hdr.lth_type != LLOG_CATALOG_MAGIC && llh->llh_count == 0){
                CDEBUG(D_INODE, "deleting log file "LPX64":%x\n",
                       lgl->lgl_oid, lgl->lgl_ogen);
                dparent = filter_parent_lock(loghandle->lgh_obd, S_IFREG,
                                             lgl->lgl_oid,LCK_PW,&parent_lockh);
                if (IS_ERR(dparent)) {
                        rc = PTR_ERR(dparent);
                        CERROR("error locking parent, orphan log %*s: rc %d\n",
                               file->f_dentry->d_name.len,
                               file->f_dentry->d_name.name, rc);
                        RETURN(rc);
                } else {
                        dchild = dget(file->f_dentry);
                        llog_delete_log(cathandle, loghandle);
                }
        } else {
                CDEBUG(D_INODE, "closing log file "LPX64":%x\n",
                       lgl->lgl_oid, lgl->lgl_ogen);
        }

        rc = filp_close(file, 0);

        llog_free_handle(loghandle); /* also removes loghandle from list */

        if (dchild != NULL) {
                int err = vfs_unlink(dparent->d_inode, dchild);
                if (err) {
                        CERROR("error unlinking empty log %*s: rc %d\n",
                               dchild->d_name.len, dchild->d_name.name, err);
                        if (!rc)
                                rc = err;
                }
                f_dput(dchild);
                ldlm_lock_decref(&parent_lockh, LCK_PW);
        }
        RETURN(rc);
}

/* This is a callback from the llog_* functions.
 * Assumes caller has already pushed us into the kernel context. */
static struct llog_handle *filter_log_open(struct obd_device *obd,
                                           struct llog_cookie *logcookie)
{
        struct llog_logid *lgl = &logcookie->lgc_lgl;
        struct llog_handle *loghandle;
        struct dentry *dchild;
        int rc;
        ENTRY;

        loghandle = llog_alloc_handle();
        if (!loghandle)
                RETURN(ERR_PTR(-ENOMEM));

        dchild = filter_fid2dentry(obd, NULL, S_IFREG, lgl->lgl_oid);
        if (IS_ERR(dchild))
                GOTO(out_handle, rc = PTR_ERR(dchild));

        if (dchild->d_inode == NULL) {
                CERROR("logcookie references non-existent object %*s\n",
                       dchild->d_name.len, dchild->d_name.name);
                GOTO(out_dentry, rc = -ENOENT);
        }

        if (dchild->d_inode->i_generation != lgl->lgl_ogen) {
                CERROR("logcookie for %*s had different generation %x != %x\n",
                       dchild->d_name.len, dchild->d_name.name,
                       dchild->d_inode->i_generation, lgl->lgl_ogen);
                GOTO(out_dentry, rc = -ESTALE);
        }

        /* dentry_open does a dput(dchild) and mntput(mnt) on error */
        mntget(obd->u.filter.fo_vfsmnt);
        loghandle->lgh_file = dentry_open(dchild, obd->u.filter.fo_vfsmnt,
                                          O_RDWR);
        if (IS_ERR(loghandle->lgh_file)) {
                rc = PTR_ERR(loghandle->lgh_file);
                CERROR("error opening logfile %*s: rc %d\n",
                       dchild->d_name.len, dchild->d_name.name, rc);
                GOTO(out_dentry, rc);
        }
        memcpy(&loghandle->lgh_cookie, logcookie, sizeof(*logcookie));
        loghandle->lgh_log_create = filter_log_create;
        loghandle->lgh_log_open = filter_log_open;
        loghandle->lgh_log_close = filter_log_close;
        loghandle->lgh_obd = obd;
        RETURN(loghandle);

out_dentry:
        f_dput(dchild);
out_handle:
        llog_free_handle(loghandle);
        RETURN(ERR_PTR(rc));
}

/* This is a callback from the llog_* functions.
 * Assumes caller has already pushed us into the kernel context. */
static struct llog_handle *filter_log_create(struct obd_device *obd)
{
        struct filter_obd *filter = &obd->u.filter;
        struct lustre_handle parent_lockh;
        struct dentry *dparent, *dchild;
        struct llog_handle *loghandle;
        struct file *file;
        int err, rc;
        obd_id id;
        ENTRY;

        loghandle = llog_alloc_handle();
        if (!loghandle)
                RETURN(ERR_PTR(-ENOMEM));

 retry:
        id = filter_next_id(filter);

        dparent = filter_parent_lock(obd, S_IFREG, id, LCK_PW, &parent_lockh);
        if (IS_ERR(dparent))
                GOTO(out_ctxt, rc = PTR_ERR(dparent));

        dchild = filter_fid2dentry(obd, dparent, S_IFREG, id);
        if (IS_ERR(dchild))
                GOTO(out_lock, rc = PTR_ERR(dchild));

        if (dchild->d_inode != NULL) {
                /* This would only happen if lastobjid was bad on disk */
                CERROR("Serious error: objid %*s already exists; is this "
                       "filesystem corrupt?  I will try to work around it.\n",
                       dchild->d_name.len, dchild->d_name.name);
                f_dput(dchild);
                ldlm_lock_decref(&parent_lockh, LCK_PW);
                goto retry;
        }

        rc = ll_vfs_create(dparent->d_inode, dchild, S_IFREG, NULL);
        if (rc) {
                CERROR("log create failed rc = %d\n", rc);
                GOTO(out_child, rc);
        }

        rc = filter_update_server_data(obd, filter->fo_rcvd_filp,
                                       filter->fo_fsd);
        if (rc) {
                CERROR("can't write lastobjid but log created: rc %d\n",rc);
                GOTO(out_destroy, rc);
        }

        /* dentry_open does a dput(dchild) and mntput(mnt) on error */
        mntget(filter->fo_vfsmnt);
        file = dentry_open(dchild, filter->fo_vfsmnt, O_RDWR | O_LARGEFILE);
        if (IS_ERR(file)) {
                rc = PTR_ERR(file);
                CERROR("error opening log file "LPX64": rc %d\n", id, rc);
                GOTO(out_destroy, rc);
        }
        ldlm_lock_decref(&parent_lockh, LCK_PW);

        loghandle->lgh_file = file;
        loghandle->lgh_cookie.lgc_lgl.lgl_oid = id;
        loghandle->lgh_cookie.lgc_lgl.lgl_ogen = dchild->d_inode->i_generation;
        loghandle->lgh_log_create = filter_log_create;
        loghandle->lgh_log_open = filter_log_open;
        loghandle->lgh_log_close = filter_log_close;
        loghandle->lgh_obd = obd;

        RETURN(loghandle);

out_destroy:
        err = vfs_unlink(dparent->d_inode, dchild);
        if (err)
                CERROR("error unlinking %*s on error: rc %d\n",
                       dchild->d_name.len, dchild->d_name.name, err);
out_child:
        f_dput(dchild);
out_lock:
        ldlm_lock_decref(&parent_lockh, LCK_PW);
out_ctxt:
        llog_free_handle(loghandle);
        RETURN(ERR_PTR(rc));
}

/* This is called from filter_setup() and should be single threaded */
struct llog_handle *filter_get_catalog(struct obd_device *obd)
{
        struct filter_obd *filter = &obd->u.filter;
        struct filter_server_data *fsd = filter->fo_fsd;
        struct obd_run_ctxt saved;
        struct llog_handle *cathandle = NULL;
        int rc;
        ENTRY;

        push_ctxt(&saved, &filter->fo_ctxt, NULL);
        if (fsd->fsd_catalog_oid) {
                struct llog_cookie catcookie;

                catcookie.lgc_lgl.lgl_oid = le64_to_cpu(fsd->fsd_catalog_oid);
                catcookie.lgc_lgl.lgl_ogen = le32_to_cpu(fsd->fsd_catalog_ogen);
                cathandle = filter_log_open(obd, &catcookie);
                if (IS_ERR(cathandle)) {
                        CERROR("error opening catalog "LPX64":%x: rc %d\n",
                               catcookie.lgc_lgl.lgl_oid,
                               catcookie.lgc_lgl.lgl_ogen,
                               (int)PTR_ERR(cathandle));
                        fsd->fsd_catalog_oid = 0;
                        fsd->fsd_catalog_ogen = 0;
                }
        }

        if (!fsd->fsd_catalog_oid) {
                struct llog_logid *lgl;

                cathandle = filter_log_create(obd);
                if (IS_ERR(cathandle)) {
                        CERROR("error creating new catalog: rc %d\n",
                               (int)PTR_ERR(cathandle));
                        GOTO(out, cathandle);
                }
                lgl = &cathandle->lgh_cookie.lgc_lgl;
                fsd->fsd_catalog_oid = cpu_to_le64(lgl->lgl_oid);
                fsd->fsd_catalog_ogen = cpu_to_le32(lgl->lgl_ogen);
                rc = filter_update_server_data(obd, filter->fo_rcvd_filp, fsd);
                if (rc) {
                        CERROR("error writing new catalog to disk: rc %d\n",rc);
                        GOTO(out_handle, rc);
                }
        }

        rc = llog_init_catalog(cathandle, &obd->u.filter.fo_mdc_uuid);
        if (rc)
                GOTO(out_handle, rc);
out:
        pop_ctxt(&saved, &filter->fo_ctxt, NULL);
        RETURN(cathandle);

out_handle:
        filter_log_close(cathandle, cathandle);
        cathandle = ERR_PTR(rc);
        goto out;
}

void filter_put_catalog(struct llog_handle *cathandle)
{
        struct llog_handle *loghandle, *n;
        int rc;
        ENTRY;

        list_for_each_entry_safe(loghandle, n, &cathandle->lgh_list, lgh_list)
                filter_log_close(cathandle, loghandle);

        rc = filp_close(cathandle->lgh_file, 0);
        if (rc)
                CERROR("error closing catalog: rc %d\n", rc);

        llog_free_handle(cathandle);
        EXIT;
}

int filter_log_cancel(struct lustre_handle *conn, struct lov_stripe_md *lsm,
                      int num_cookies, struct llog_cookie *logcookies,
                      int flags)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct obd_run_ctxt saved;
        int rc;
        ENTRY;

        push_ctxt(&saved, &obd->u.filter.fo_ctxt, NULL);
        rc = llog_cancel_records(obd->u.filter.fo_catalog, num_cookies,
                                 logcookies);
        pop_ctxt(&saved, &obd->u.filter.fo_ctxt, NULL);

        RETURN(rc);
}

int filter_log_op_create(struct llog_handle *cathandle, struct ll_fid *mds_fid,
                         obd_id oid, obd_count ogen,
                         struct llog_cookie *logcookie)
{
        struct llog_create_rec *lcr;
        int rc;
        ENTRY;

        OBD_ALLOC(lcr, sizeof(*lcr));
        if (lcr == NULL)
                RETURN(-ENOMEM);
        lcr->lcr_hdr.lth_len = lcr->lcr_end_len = sizeof(*lcr);
        lcr->lcr_hdr.lth_type = OST_CREATE_REC;
        lcr->lcr_fid.id = mds_fid->id;
        lcr->lcr_fid.generation = mds_fid->generation;
        lcr->lcr_fid.f_type = mds_fid->f_type;
        lcr->lcr_oid = oid;
        lcr->lcr_ogen = ogen;

        rc = llog_add_record(cathandle, &lcr->lcr_hdr, logcookie);
        OBD_FREE(lcr, sizeof(*lcr));

        if (rc > 0) {
                LASSERT(rc == sizeof(*logcookie));
                rc = 0;
        }
        RETURN(rc);
}

int filter_log_op_orphan(struct llog_handle *cathandle, obd_id oid,
                         obd_count ogen, struct llog_cookie *logcookie)
{
        struct llog_orphan_rec *lor;
        int rc;
        ENTRY;

        OBD_ALLOC(lor, sizeof(*lor));
        if (lor == NULL)
                RETURN(-ENOMEM);
        lor->lor_hdr.lth_len = lor->lor_end_len = sizeof(*lor);
        lor->lor_hdr.lth_type = OST_ORPHAN_REC;
        lor->lor_oid = oid;
        lor->lor_ogen = ogen;

        rc = llog_add_record(cathandle, &lor->lor_hdr, logcookie);

        if (rc > 0) {
                LASSERT(rc == sizeof(*logcookie));
                rc = 0;
        }
        RETURN(rc);
}
