/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2003 Cluster File Systems, Inc.
 *   Author: Phil Schwan <phil@clusterfs.com>
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
 *
 * A kernel module which tests the llog API from the OBD setup function.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/module.h>
#include <linux/init.h>

#include <linux/obd_class.h>
#include <linux/lustre_log.h>

static int llog_test_rand;
static struct obd_uuid uuid = { .uuid = "test_uuid" };
static struct llog_logid cat_logid;

/* Test named-log create/open, close */
static int llog_test_1(struct obd_device *obd)
{
        struct llog_handle *llh;
        char name[10];
        int rc;
        ENTRY;

        CERROR("1a: create a log with a name\n");
        sprintf(name, "%x", llog_test_rand);
        rc = llog_create(obd, &llh, NULL, name);
        if (rc) {
                CERROR("1a: llog_create with name %s failed: %d\n", name, rc);
                RETURN(rc);
        }
        llog_init_handle(llh, LLOG_F_IS_PLAIN, &uuid);

        if (llh->lgh_last_idx != 0) {
                CERROR("1a: handle->last_idx is %d, expected 0 after create\n",
                       llh->lgh_last_idx);
                GOTO(out, rc = -ERANGE);
        }
        if (!ext2_test_bit(0, llh->lgh_hdr->llh_bitmap)) {
                CERROR("3: first bit in bitmap should be set after write\n");
                RETURN(-ERANGE);
        }
        if (llh->lgh_hdr->llh_count != 1) {
                CERROR("1a: header->count is %d, expected 1 after create\n",
                       llh->lgh_hdr->llh_count);
                GOTO(out, rc = -ERANGE);
        }

 out:
        CERROR("1b: close newly-created log\n");
        rc = llog_close(llh);
        if (rc)
                CERROR("1b: close log %s failed: %d\n", name, rc);
        RETURN(rc);
}

/* Test named-log reopen; returns opened log on success */
static int llog_test_2(struct obd_device *obd, struct llog_handle **llh)
{
        char name[10];
        int rc;
        ENTRY;

        CERROR("2: re-open a log with a name\n");
        sprintf(name, "%x", llog_test_rand);
        rc = llog_create(obd, llh, NULL, name);
        if (rc) {
                CERROR("2: re-open log with name %s failed: %d\n", name, rc);
                RETURN(rc);
        }
        llog_init_handle(*llh, LLOG_F_IS_PLAIN, &uuid);

        if ((*llh)->lgh_last_idx != 0) {
                CERROR("2: handle->last_idx is %d, expected 1 after reopen\n",
                       (*llh)->lgh_last_idx);
                RETURN(-ERANGE);
        }
        if (!ext2_test_bit(0, (*llh)->lgh_hdr->llh_bitmap)) {
                CERROR("3: first bit in bitmap should be set after write\n");
                RETURN(-ERANGE);
        }
        if ((*llh)->lgh_hdr->llh_count != 1) {
                CERROR("2: header->count is %d, expected 1 after reopen\n",
                       (*llh)->lgh_hdr->llh_count);
                RETURN(-ERANGE);
        }

        RETURN(rc);
}

/* Test record writing, single and in bulk */
static int llog_test_3(struct obd_device *obd, struct llog_handle *llh)
{
        struct llog_rec_hdr rec;
        int rc, i;
        ENTRY;

        rec.lrh_len = LLOG_MIN_REC_SIZE;
        rec.lrh_type = 0xf00f00;

        CERROR("3a: write one log record\n");
        rc = llog_write_rec(llh, &rec, NULL, 0, NULL, -1);
        if (rc) {
                CERROR("3a: write one log record failed: %d\n", rc);
                RETURN(rc);
        }

        if (llh->lgh_last_idx != 1) {
                CERROR("3: handle->last_idx is %d, expected 1 after write\n",
                       llh->lgh_last_idx);
                RETURN(-ERANGE);
        }
        if (llh->lgh_hdr->llh_count != 2) {
                CERROR("3: header->count is %d, expected 2 after write\n",
                       llh->lgh_hdr->llh_count);
                RETURN(-ERANGE);
        }
        if (!ext2_test_bit(1, llh->lgh_hdr->llh_bitmap)) {
                CERROR("3: bit 1 in bitmap should be set after write\n");
                RETURN(-ERANGE);
        }

        CERROR("3b: write 1000 more log records\n");
        for (i = 0; i < 1000; i++) {
                rc = llog_write_rec(llh, &rec, NULL, 0, NULL, -1);
                if (rc) {
                        CERROR("3b: write 1000 records failed at #%d: %d\n",
                               i + 1, rc);
                        RETURN(rc);
                }
        }

        if (llh->lgh_last_idx != 1001) {
                CERROR("3: handle->last_idx is %d, expected 1001 after write\n",
                       llh->lgh_last_idx);
                RETURN(-ERANGE);
        }
        if (llh->lgh_hdr->llh_count != 1002) {
                CERROR("3: header->count is %d, expected 1001 after write\n",
                       llh->lgh_hdr->llh_count);
                RETURN(-ERANGE);
        }
        for (i = 0; i < 1002; i++) {
                if (!ext2_test_bit(i, llh->lgh_hdr->llh_bitmap)) {
                        CERROR("3: bit %d not set after 1001 writes\n", i);
                        RETURN(-ERANGE);
                }
        }
        for (i = 1002; i < LLOG_BITMAP_BYTES * 8; i++) {
                if (ext2_test_bit(i, llh->lgh_hdr->llh_bitmap)) {
                        CERROR("3: bit %d is set, but should not be\n", i);
                        RETURN(-ERANGE);
                }
        }

        RETURN(rc);
}

/* Test catalogue additions */
static int llog_test_4(struct obd_device *obd)
{
        struct llog_handle *llh;
        char name[10];
        int rc, i;
        struct llog_rec_hdr rec;
        struct llog_cookie cookie;

        ENTRY;

        rec.lrh_len = LLOG_MIN_REC_SIZE;
        rec.lrh_type = 0xf00f00;

        CERROR("4a: create a catalog log with a name\n");
        sprintf(name, "%x", llog_test_rand+1);
        rc = llog_create(obd, &llh, NULL, name);
        if (rc) {
                CERROR("1a: llog_create with name %s failed: %d\n", name, rc);
                GOTO(out, rc);
        }
        llog_init_handle(llh, LLOG_F_IS_CAT, &uuid);
        cat_logid = llh->lgh_id;

        CERROR("4b: write 1 log records\n");
        rc = llog_cat_add_rec(llh, &rec, &cookie, NULL);
        if (rc != 1) {
                CERROR("4b: write 1 catalog record failed at: %d\n", rc);
                GOTO(out, rc);
        }

        if (llh->u.chd.chd_current_log->lgh_hdr->llh_count != 2) {
                CERROR("llh->u.chd.chd_current_log->lgh_hdr->llh_count != 2\n");
                GOTO(out, rc = -EINVAL);
        }

        CERROR("4c: cancel 1 log record\n");
        rc = llog_cat_cancel_records(llh, 1, &cookie);
        if (rc) {
                CERROR("4c: cancel 1 catalog based record failed: %d\n", rc);
                GOTO(out, rc);
        }

        if (llh->u.chd.chd_current_log && 
            llh->u.chd.chd_current_log->lgh_hdr->llh_count != 1) {
                CERROR("llh->u.chd.chd_current_log->lgh_hdr->llh_count != 2\n");
                GOTO(out, rc = -EINVAL);
        }

        CERROR("4d: write 40,000 more log records\n");
        for (i = 0; i < 40000; i++) {
                rc = llog_cat_add_rec(llh, &rec, NULL, NULL);
                if (rc) {
                        CERROR("4d: write 1000 records failed at #%d: %d\n",
                               i + 1, rc);
                        GOTO(out, rc);
                }
        }

 out:
        CERROR("4e: put newly-created catalog\n");
        rc = llog_cat_put(llh);
        if (rc)
                CERROR("1b: close log %s failed: %d\n", name, rc);
        RETURN(rc);
}

static int cat_print_cb(struct llog_handle *llh, struct llog_rec_hdr *rec, void *data)
{
        struct llog_logid_rec *lir = (struct llog_logid_rec *)rec;

        if (rec->lrh_type != LLOG_LOGID_MAGIC) {
                CERROR("invalid record in catalog\n");
                RETURN(-EINVAL);
        }

        CERROR("seeing record at index %d in log "LPX64"\n", rec->lrh_index, 
               lir->lid_id.lgl_oid);
        RETURN(0);
}

/* Test log and catalogue processing */
static int llog_test_5(struct obd_device *obd)
{
        struct llog_handle *llh = NULL;
        char name[10];
        int rc;
        struct llog_rec_hdr rec;

        ENTRY;

        rec.lrh_len = LLOG_MIN_REC_SIZE;
        rec.lrh_type = 0xf00f00;

        CERROR("5a: re-open catalog by id\n");
        rc = llog_create(obd, &llh, &cat_logid, NULL);
        if (rc) {
                CERROR("5a: llog_create with logid failed: %d\n", rc);
                GOTO(out, rc);
        }
        llog_init_handle(llh, LLOG_F_IS_CAT, &uuid);

        CERROR("5b: print the catalog entries.. we expect 2\n");
        rc = llog_process_log(llh, (llog_cb_t)cat_print_cb, "test 5");
        if (rc) {
                CERROR("5b: process with cat_print_cb failed: %d\n", rc);
                GOTO(out, rc);
        }

 out:
        CERROR("5: close re-opened catalog\n");
        if (llh)
                rc = llog_cat_put(llh);
        if (rc)
                CERROR("1b: close log %s failed: %d\n", name, rc);
        RETURN(rc);
}



/* -------------------------------------------------------------------------
 * Tests above, boring obd functions below
 * ------------------------------------------------------------------------- */
static int llog_run_tests(struct obd_device *obd)
{
        struct llog_handle *llh;
        struct obd_run_ctxt saved;
        int rc, err, cleanup_phase = 0;
        ENTRY;

        push_ctxt(&saved, &obd->obd_log_exp->exp_obd->obd_ctxt, NULL);

        rc = llog_test_1(obd);
        if (rc)
                GOTO(cleanup, rc);

        rc = llog_test_2(obd, &llh);
        if (rc)
                GOTO(cleanup, rc);
        cleanup_phase = 1; /* close llh */

        rc = llog_test_3(obd, llh);
        if (rc)
                GOTO(cleanup, rc);

        rc = llog_test_4(obd);
        if (rc)
                GOTO(cleanup, rc);

        rc = llog_test_5(obd);
        if (rc)
                GOTO(cleanup, rc);

        GOTO(cleanup, rc);
 cleanup:
        switch (cleanup_phase) {
        case 1:
                err = llog_close(llh);
                if (err)
                        CERROR("cleanup: llog_close failed: %d\n", err);
                if (!rc)
                        rc = err;
        case 0:
                pop_ctxt(&saved, &obd->obd_log_exp->exp_obd->obd_ctxt, NULL);
        }

        return rc;
}

static int llog_test_cleanup(struct obd_device *obd, int flags)
{
        int rc = obd_disconnect(obd->obd_log_exp, 0);
        if (rc)
                CERROR("failed to disconnect from log device: %d\n", rc);
        return rc;
}

static int llog_test_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct obd_ioctl_data *data = buf;
        struct lustre_handle exph = {0, };
        struct obd_device *tgt;
        struct obd_uuid fake_uuid = { "LLOG_TEST_UUID" };
        int rc;
        ENTRY;

        if (data->ioc_inllen1 < 1) {
                CERROR("requires a TARGET OBD name\n");
                RETURN(-EINVAL);
        }

        tgt = class_name2obd(data->ioc_inlbuf1);
        if (!tgt || !tgt->obd_attached || !tgt->obd_set_up) {
                CERROR("target device not attached or not set up (%d/%s)\n",
                       data->ioc_dev, data->ioc_inlbuf1);
                RETURN(-EINVAL);
        }

        rc = obd_connect(&exph, tgt, &fake_uuid);
        if (rc) {
                CERROR("fail to connect to target device %d\n", data->ioc_dev);
                RETURN(rc);
        }
        obd->obd_log_exp = class_conn2export(&exph);

        llog_test_rand = ll_insecure_random_int();

        rc = llog_run_tests(obd);
        if (rc)
                llog_test_cleanup(obd, 0);
        RETURN(rc);
}

static int llog_test_attach(struct obd_device *dev, obd_count len, void *data)
{
        struct lprocfs_static_vars lvars;

        lprocfs_init_vars(ost, &lvars);
        return lprocfs_obd_attach(dev, lvars.obd_vars);
}

static int llog_test_detach(struct obd_device *dev)
{
        return lprocfs_obd_detach(dev);
}

static struct obd_ops llog_obd_ops = {
        o_owner:       THIS_MODULE,
        o_attach:      llog_test_attach,
        o_detach:      llog_test_detach,
        o_setup:       llog_test_setup,
        o_cleanup:     llog_test_cleanup,
};

static int __init llog_test_init(void)
{
        struct lprocfs_static_vars lvars;

        lprocfs_init_multi_vars(0, &lvars);
        return class_register_type(&llog_obd_ops,lvars.module_vars,"llog_test");
}

static void __exit llog_test_exit(void)
{
        class_unregister_type("llog_test");
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("llog test module");
MODULE_LICENSE("GPL");

module_init(llog_test_init);
module_exit(llog_test_exit);
