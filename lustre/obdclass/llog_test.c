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

static int verify_handle(char * test, struct llog_handle *llh, int num_recs)
{
        int i;
        int last_idx = 0;
        int active_recs = 0;

        for (i = 0; i < LLOG_BITMAP_BYTES * 8; i++) {
                if (ext2_test_bit(i, llh->lgh_hdr->llh_bitmap)) {
                        last_idx = i;
                        active_recs++;
                }
        }

        if (active_recs != num_recs) {
                CERROR("%s: expected %d active recs after write, found %d\n",
                       test, num_recs, active_recs);
                RETURN(-ERANGE);
        }

        if (le32_to_cpu(llh->lgh_hdr->llh_count) != num_recs) {
                CERROR("%s: handle->count is %d, expected %d after write\n",
                       test, le32_to_cpu(llh->lgh_hdr->llh_count), num_recs);
                RETURN(-ERANGE);
        }

        if (llh->lgh_last_idx < last_idx) {
                CERROR("%s: handle->last_idx is %d, expected %d after write\n",
                       test, llh->lgh_last_idx, last_idx);
                RETURN(-ERANGE);
        }

        RETURN(0);
}

/* Test named-log create/open, close */
static int llog_test_1(struct obd_device *obd, char * name)
{
        struct llog_handle *llh;
        int rc;
        int rc2;
        ENTRY;

        CERROR("1a: create a log with name: %s\n", name);

        rc = llog_create(obd, &llh, NULL, name);
        if (rc) {
                CERROR("1a: llog_create with name %s failed: %d\n", name, rc);
                RETURN(rc);
        }
        llog_init_handle(llh, LLOG_F_IS_PLAIN, &uuid);

        if ((rc = verify_handle("1", llh, 1)))
                GOTO(out, rc);

 out:
        CERROR("1b: close newly-created log\n");
        rc2 = llog_close(llh);
        if (rc2) {
                CERROR("1b: close log %s failed: %d\n", name, rc2);
                if (rc == 0)
                        rc = rc2;
        }
        RETURN(rc);
}

/* Test named-log reopen; returns opened log on success */
static int llog_test_2(struct obd_device *obd, char * name, struct llog_handle **llh)
{
        struct llog_handle *loghandle;
        struct llog_logid logid;
        int rc;
        ENTRY;

        CERROR("2a: re-open a log with name: %s\n", name);
        rc = llog_create(obd, llh, NULL, name);
        if (rc) {
                CERROR("2a: re-open log with name %s failed: %d\n", name, rc);
                RETURN(rc);
        }
        llog_init_handle(*llh, LLOG_F_IS_PLAIN, &uuid);

        if ((rc = verify_handle("2", *llh, 1)))
                RETURN(rc);

        CERROR("2b: create a log without specified NAME & LOGID\n");
        rc = llog_create(obd, &loghandle, NULL, NULL);
        if (rc) {
                CERROR("2b: create log failed\n");
                RETURN(rc);
        }
        llog_init_handle(loghandle, LLOG_F_IS_PLAIN, &uuid);
        logid = loghandle->lgh_id;
        llog_close(loghandle);

        CERROR("2b: re-open the log by LOGID\n");
        rc = llog_create(obd, &loghandle, &logid, NULL);
        if (rc) {
                CERROR("2b: re-open log by LOGID failed\n");
                RETURN(rc);
        }
        llog_init_handle(loghandle, LLOG_F_IS_PLAIN, &uuid);

        CERROR("2b: destroy this log\n");
        rc = llog_destroy(loghandle);
        if (rc) {
                CERROR("2b: destroy log failed\n");
                RETURN(rc);
        }
        llog_free_handle(loghandle);
        
        RETURN(rc);
}

/* Test record writing, single and in bulk */
static int llog_test_3(struct obd_device *obd, struct llog_handle *llh)
{
        struct llog_create_rec lcr;
        int rc, i;
        int num_recs = 1;       /* 1 for the header */
        ENTRY;

        lcr.lcr_hdr.lrh_len = lcr.lcr_tail.lrt_len = cpu_to_le32(sizeof(lcr));
        lcr.lcr_hdr.lrh_type = cpu_to_le32(OST_SZ_REC);

        CERROR("3a: write one create_rec\n");
        rc = llog_write_rec(llh,  &lcr.lcr_hdr, NULL, 0, NULL, -1);
        num_recs++;
        if (rc) {
                CERROR("3a: write one log record failed: %d\n", rc);
                RETURN(rc);
        }

        if ((rc = verify_handle("3a", llh, num_recs)))
                RETURN(rc);

        CERROR("3b: write 10 cfg log records with 12 byte bufs\n");
        for (i = 0; i < 10; i++) {
                struct llog_rec_hdr hdr;
                char buf[12];
                hdr.lrh_len = cpu_to_le32(12);
                hdr.lrh_type = cpu_to_le32(OBD_CFG_REC);
                memset(buf, 0, sizeof buf);
                rc = llog_write_rec(llh, &hdr, NULL, 0, buf, -1);
                if (rc) {
                        CERROR("3b: write 10 records failed at #%d: %d\n",
                               i + 1, rc);
                        RETURN(rc);
                }
                num_recs++;
                if ((rc = verify_handle("3c", llh, num_recs)))
                        RETURN(rc);
        }
        
        if ((rc = verify_handle("3b", llh, num_recs)))
                RETURN(rc);
        
        CERROR("3c: write 1000 more log records\n");
        for (i = 0; i < 1000; i++) {
                rc = llog_write_rec(llh, &lcr.lcr_hdr, NULL, 0, NULL, -1);
                if (rc) {
                        CERROR("3c: write 1000 records failed at #%d: %d\n",
                               i + 1, rc);
                        RETURN(rc);
                }
                num_recs++;
                if ((rc = verify_handle("3b", llh, num_recs)))
                        RETURN(rc);
        }

        if ((rc = verify_handle("3c", llh, num_recs)))
                RETURN(rc);
                
        RETURN(rc);
}

/* Test catalogue additions */
static int llog_test_4(struct obd_device *obd)
{
        struct llog_handle *cath;
        char name[10];
        int rc, i, buflen;
        struct llog_mini_rec lmr;
        struct llog_cookie cookie;
        int num_recs = 0;
        char *buf;
        struct llog_rec_hdr rec;

        ENTRY;

        lmr.lmr_hdr.lrh_len = lmr.lmr_tail.lrt_len = cpu_to_le32(LLOG_MIN_REC_SIZE);
        lmr.lmr_hdr.lrh_type = cpu_to_le32(0xf00f00);

        sprintf(name, "%x", llog_test_rand+1);
        CERROR("4a: create a catalog log with name: %s\n", name);
        rc = llog_create(obd, &cath, NULL, name);
        if (rc) {
                CERROR("1a: llog_create with name %s failed: %d\n", name, rc);
                GOTO(out, rc);
        }
        llog_init_handle(cath, LLOG_F_IS_CAT, &uuid);
        num_recs++;
        cat_logid = cath->lgh_id;

        CERROR("4b: write 1 record into the catalog\n");
        rc = llog_cat_add_rec(cath, &lmr.lmr_hdr, &cookie, NULL);
        if (rc != 1) {
                CERROR("4b: write 1 catalog record failed at: %d\n", rc);
                GOTO(out, rc);
        }
        num_recs++; 
        if ((rc = verify_handle("4b", cath, 2)))
                RETURN(rc);

        if ((rc = verify_handle("4b", cath->u.chd.chd_current_log, num_recs)))
                RETURN(rc);

        CERROR("4c: cancel 1 log record\n");
        rc = llog_cat_cancel_records(cath, 1, &cookie);
        if (rc) {
                CERROR("4c: cancel 1 catalog based record failed: %d\n", rc);
                GOTO(out, rc);
        }
        num_recs--;

        if ((rc = verify_handle("4c", cath->u.chd.chd_current_log, num_recs)))
                RETURN(rc);

        CERROR("4d: write 40,000 more log records\n");
        for (i = 0; i < 40000; i++) {
                rc = llog_cat_add_rec(cath, &lmr.lmr_hdr, NULL, NULL);
                if (rc) {
                        CERROR("4d: write 40000 records failed at #%d: %d\n",
                               i + 1, rc);
                        GOTO(out, rc);
                }
                num_recs++;
        }

        CERROR("4e: add 5 large records, one record per block\n");
        buflen = LLOG_CHUNK_SIZE - sizeof(struct llog_rec_hdr)
                        - sizeof(struct llog_rec_tail);
        OBD_ALLOC(buf, buflen);
        if (buf == NULL)
                GOTO(out, rc = -ENOMEM);
        for (i = 0; i < 5; i++) {
                rec.lrh_len = cpu_to_le32(buflen);
                rec.lrh_type = cpu_to_le32(OBD_CFG_REC);
                rc = llog_cat_add_rec(cath, &rec, NULL, buf);
                if (rc) {
                        CERROR("4e: write 5 records failed at #%d: %d\n",
                               i + 1, rc);
                        OBD_FREE(buf, buflen);
                        GOTO(out, rc);
                }
                num_recs++;
        }
        OBD_FREE(buf, buflen);

 out:
        CERROR("4f: put newly-created catalog\n");
        rc = llog_cat_put(cath);
        if (rc)
                CERROR("1b: close log %s failed: %d\n", name, rc);
        RETURN(rc);
}

static int cat_print_cb(struct llog_handle *llh, struct llog_rec_hdr *rec, void *data)
{
        struct llog_logid_rec *lir = (struct llog_logid_rec *)rec;

        if (le32_to_cpu(rec->lrh_type) != LLOG_LOGID_MAGIC) {
                CERROR("invalid record in catalog\n");
                RETURN(-EINVAL);
        }

        CERROR("seeing record at index %d in log "LPX64"\n", le32_to_cpu(rec->lrh_index), 
               lir->lid_id.lgl_oid);
        RETURN(0);
}

static int plain_print_cb(struct llog_handle *llh, struct llog_rec_hdr *rec, void *data)
{
        if (!le32_to_cpu(llh->lgh_hdr->llh_flags) & LLOG_F_IS_PLAIN) {
                CERROR("log is not plain\n");
                RETURN(-EINVAL);
        }

        CERROR("seeing record at index %d in log "LPX64"\n", 
               le32_to_cpu(rec->lrh_index), llh->lgh_id.lgl_oid);
        RETURN(0);
}

static int llog_cancel_rec_cb(struct llog_handle *llh, struct llog_rec_hdr *rec, void *data)
{
        struct llog_cookie cookie;
        static int i = 0;

        if (!le32_to_cpu(llh->lgh_hdr->llh_flags) & LLOG_F_IS_PLAIN) {
                CERROR("log is not plain\n");
                RETURN(-EINVAL);
        }

        cookie.lgc_lgl = llh->lgh_id;
        cookie.lgc_index = le32_to_cpu(rec->lrh_index);
        
        llog_cat_cancel_records(llh->u.phd.phd_cat_handle, 1, &cookie);
        i++;
        if (i == 40000)
                RETURN(-4711);
        RETURN(0);
}



/* Test log and catalogue processing */
static int llog_test_5(struct obd_device *obd)
{
        struct llog_handle *llh = NULL;
        char name[10];
        int rc;
        struct llog_mini_rec lmr;

        ENTRY;

        lmr.lmr_hdr.lrh_len = lmr.lmr_tail.lrt_len = cpu_to_le32(LLOG_MIN_REC_SIZE);
        lmr.lmr_hdr.lrh_type = cpu_to_le32(0xf00f00);

        CERROR("5a: re-open catalog by id\n");
        rc = llog_create(obd, &llh, &cat_logid, NULL);
        if (rc) {
                CERROR("5a: llog_create with logid failed: %d\n", rc);
                GOTO(out, rc);
        }
        llog_init_handle(llh, LLOG_F_IS_CAT, &uuid);

        CERROR("5b: print the catalog entries.. we expect 2\n");
        rc = llog_process(llh, (llog_cb_t)cat_print_cb, "test 5");
        if (rc) {
                CERROR("5b: process with cat_print_cb failed: %d\n", rc);
                GOTO(out, rc);
        }

        CERROR("5c: Cancel 40000 records, see one log zapped\n");
        rc = llog_cat_process(llh, llog_cancel_rec_cb, "foobar");
        if (rc != -4711) {
                CERROR("5c: process with cat_cancel_cb failed: %d\n", rc);
                GOTO(out, rc);
        }

        CERROR("5d: add 1 record to the log with many canceled empty pages\n");
        rc = llog_cat_add_rec(llh, &lmr.lmr_hdr, NULL, NULL);
        if (rc) {
                CERROR("5d: add record to the log with many canceled empty\
                       pages failed\n");
                GOTO(out, rc);
        }

        CERROR("5b: print the catalog entries.. we expect 1\n");
        rc = llog_process(llh, (llog_cb_t)cat_print_cb, "test 5");
        if (rc) {
                CERROR("5b: process with cat_print_cb failed: %d\n", rc);
                GOTO(out, rc);
        }

        CERROR("5e: print plain log entries.. expect 6\n");
        rc = llog_cat_process(llh, plain_print_cb, "foobar");
        if (rc) {
                CERROR("5e: process with plain_print_cb failed: %d\n", rc);
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

static int llog_test6_process_rec(struct llog_handle *handle,
                                  struct llog_rec_hdr * rec, void * private) 
{
        return 0;
}

/* Test client api; open log by name and process */
static int llog_test_6(struct obd_device *obd, char * name)
{
        struct obd_device *mdc_obd;
        struct obd_uuid *mds_uuid = &obd->obd_log_exp->exp_obd->obd_uuid;
        struct lustre_handle exph = {0, };
        struct obd_export * exp;
        struct obd_uuid uuid = {"LLOG_TEST6_UUID"};
        struct llog_handle *llh = NULL;
        int rc;

        CERROR("6a: re-open log %s using client API\n", name);
        mdc_obd = class_find_client_obd(mds_uuid, LUSTRE_MDC_NAME, NULL);
        if (mdc_obd == NULL) {
                CERROR("6: no MDC devices connected to %s found.\n", 
                       mds_uuid->uuid);
                RETURN(-ENOENT);
        }

        rc = obd_connect(&exph, mdc_obd, &uuid);
        if (rc) {
                CERROR("6: failed to connect to MDC: %s\n", mdc_obd->obd_name);
                RETURN(rc);
        }

        exp = class_conn2export(&exph);
        rc = llog_create(obd, &llh, NULL, name);
        if (rc) {
                CERROR("6: llog_create failed %d\n", rc);
                RETURN(rc);
        }

        rc = llog_init_handle(llh, LLOG_F_IS_PLAIN, NULL);
        if (rc) {
                CERROR("6: llog_init_handle failed %d\n", rc);
                GOTO(parse_out, rc);
        }

        rc = llog_process(llh, llog_test6_process_rec, NULL);
parse_out:
        if (rc) 
                CERROR("6: llog_process failed %d\n", rc);

        rc = llog_close(llh);
        if (rc) {
                CERROR("6: llog_close failed: rc = %d\n", rc);
        }

        rc = obd_disconnect(exp, 0);
        
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
        char name[10];
        ENTRY;

        sprintf(name, "%x", llog_test_rand);
        push_ctxt(&saved, &obd->obd_log_exp->exp_obd->obd_ctxt, NULL);

        rc = llog_test_1(obd, name);
        if (rc)
                GOTO(cleanup, rc);

        rc = llog_test_2(obd, name, &llh);
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

        rc = llog_test_6(obd, name);
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
        struct lustre_cfg *lcfg = buf;
        struct lustre_handle exph = {0, };
        struct obd_device *tgt;
        struct obd_uuid fake_uuid = { "LLOG_TEST_UUID" };
        int rc;
        ENTRY;

        if (lcfg->lcfg_inllen1 < 1) {
                CERROR("requires a TARGET OBD name\n");
                RETURN(-EINVAL);
        }

        tgt = class_name2obd(lcfg->lcfg_inlbuf1);
        if (!tgt || !tgt->obd_attached || !tgt->obd_set_up) {
                CERROR("target device not attached or not set up (%d/%s)\n",
                       lcfg->lcfg_dev, lcfg->lcfg_inlbuf1);
                RETURN(-EINVAL);
        }

        rc = obd_connect(&exph, tgt, &fake_uuid);
        if (rc) {
                CERROR("fail to connect to target device %d\n", lcfg->lcfg_dev);
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
