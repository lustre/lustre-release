/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/obdclass/llog_test.c
 *
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/module.h>
#include <linux/init.h>

#include <obd_class.h>
#include <lustre_log.h>

static int llog_test_rand;
static struct obd_uuid uuid = { .uuid = "test_uuid" };
static struct llog_logid cat_logid;

struct llog_mini_rec {
        struct llog_rec_hdr     lmr_hdr;
        struct llog_rec_tail    lmr_tail;
} __attribute__((packed));

static int verify_handle(char *test, struct llog_handle *llh, int num_recs)
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

        if (llh->lgh_hdr->llh_count != num_recs) {
                CERROR("%s: handle->count is %d, expected %d after write\n",
                       test, llh->lgh_hdr->llh_count, num_recs);
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
static int llog_test_1(struct obd_device *obd, char *name)
{
        struct llog_handle *llh;
        struct llog_ctxt *ctxt = llog_get_context(obd, LLOG_TEST_ORIG_CTXT);
        int rc;
        int rc2;
        ENTRY;

        CWARN("1a: create a log with name: %s\n", name);
        LASSERT(ctxt);

	rc = llog_open_create(NULL, ctxt, &llh, NULL, name);
        if (rc) {
                CERROR("1a: llog_create with name %s failed: %d\n", name, rc);
                llog_ctxt_put(ctxt);
                RETURN(rc);
        }
	llog_init_handle(NULL, llh, LLOG_F_IS_PLAIN, &uuid);

        if ((rc = verify_handle("1", llh, 1)))
                GOTO(out, rc);

 out:
        CWARN("1b: close newly-created log\n");
	rc2 = llog_close(NULL, llh);
        llog_ctxt_put(ctxt);
        if (rc2) {
                CERROR("1b: close log %s failed: %d\n", name, rc2);
                if (rc == 0)
                        rc = rc2;
        }
        RETURN(rc);
}

/* Test named-log reopen; returns opened log on success */
static int llog_test_2(struct obd_device *obd, char *name,
                       struct llog_handle **llh)
{
        struct llog_ctxt *ctxt = llog_get_context(obd, LLOG_TEST_ORIG_CTXT);
        int rc;
        ENTRY;

        CWARN("2a: re-open a log with name: %s\n", name);
	rc = llog_open(NULL, ctxt, llh, NULL, name, LLOG_OPEN_EXISTS);
        if (rc) {
                CERROR("2a: re-open log with name %s failed: %d\n", name, rc);
                GOTO(out, rc);
        }
	llog_init_handle(NULL, *llh, LLOG_F_IS_PLAIN, &uuid);

        if ((rc = verify_handle("2", *llh, 1)))
                GOTO(out, rc);
#if 0
        CWARN("2b: create a log without specified NAME & LOGID\n");
        rc = llog_create(ctxt, &loghandle, NULL, NULL);
        if (rc) {
                CERROR("2b: create log failed\n");
                GOTO(out, rc);
        }
        llog_init_handle(loghandle, LLOG_F_IS_PLAIN, &uuid);
        logid = loghandle->lgh_id;
        llog_close(loghandle);

        CWARN("2b: re-open the log by LOGID\n");
        rc = llog_create(ctxt, &loghandle, &logid, NULL);
        if (rc) {
                CERROR("2b: re-open log by LOGID failed\n");
                GOTO(out, rc);
        }
        llog_init_handle(loghandle, LLOG_F_IS_PLAIN, &uuid);

        CWARN("2b: destroy this log\n");
        rc = llog_destroy(loghandle);
        if (rc) {
                CERROR("2b: destroy log failed\n");
                GOTO(out, rc);
        }
        llog_free_handle(loghandle);
#endif
out:
        llog_ctxt_put(ctxt);

        RETURN(rc);
}

/* Test record writing, single and in bulk */
static int llog_test_3(struct obd_device *obd, struct llog_handle *llh)
{
        struct llog_create_rec lcr;
        int rc, i;
        int num_recs = 1;       /* 1 for the header */
        ENTRY;

        lcr.lcr_hdr.lrh_len = lcr.lcr_tail.lrt_len = sizeof(lcr);
        lcr.lcr_hdr.lrh_type = OST_SZ_REC;

        CWARN("3a: write one create_rec\n");
	rc = llog_write_rec(NULL, llh,  &lcr.lcr_hdr, NULL, 0, NULL, -1);
        num_recs++;
        if (rc) {
                CERROR("3a: write one log record failed: %d\n", rc);
                RETURN(rc);
        }

        if ((rc = verify_handle("3a", llh, num_recs)))
                RETURN(rc);

        CWARN("3b: write 10 cfg log records with 8 bytes bufs\n");
        for (i = 0; i < 10; i++) {
                struct llog_rec_hdr hdr;
                char buf[8];
                hdr.lrh_len = 8;
                hdr.lrh_type = OBD_CFG_REC;
                memset(buf, 0, sizeof buf);
		rc = llog_write_rec(NULL, llh, &hdr, NULL, 0, buf, -1);
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

        CWARN("3c: write 1000 more log records\n");
        for (i = 0; i < 1000; i++) {
		rc = llog_write_rec(NULL, llh, &lcr.lcr_hdr, NULL, 0, NULL,
				    -1);
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

        CWARN("3d: write log more than BITMAP_SIZE, return -ENOSPC\n");
        for (i = 0; i < LLOG_BITMAP_SIZE(llh->lgh_hdr) + 1; i++) {
                struct llog_rec_hdr hdr;
                char buf_even[24];
                char buf_odd[32];

                memset(buf_odd, 0, sizeof buf_odd);
                memset(buf_even, 0, sizeof buf_even);
                if ((i % 2) == 0) {
                        hdr.lrh_len = 24;
                        hdr.lrh_type = OBD_CFG_REC;
			rc = llog_write_rec(NULL, llh, &hdr, NULL, 0, buf_even,
					    -1);
                } else {
                        hdr.lrh_len = 32;
                        hdr.lrh_type = OBD_CFG_REC;
			rc = llog_write_rec(NULL, llh, &hdr, NULL, 0, buf_odd,
					    -1);
                }
                if (rc) {
                        if (rc == -ENOSPC) {
                                break;
                        } else {
                                CERROR("3c: write recs failed at #%d: %d\n",
                                        i + 1, rc);
                                RETURN(rc);
                        }
                }
                num_recs++;
        }
        if (rc != -ENOSPC) {
                CWARN("3d: write record more than BITMAP size!\n");
                RETURN(-EINVAL);
        }
        if ((rc = verify_handle("3d", llh, num_recs)))
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
        struct llog_ctxt *ctxt = llog_get_context(obd, LLOG_TEST_ORIG_CTXT);
        int num_recs = 0;
        char *buf;
        struct llog_rec_hdr rec;

        ENTRY;

        lmr.lmr_hdr.lrh_len = lmr.lmr_tail.lrt_len = LLOG_MIN_REC_SIZE;
        lmr.lmr_hdr.lrh_type = 0xf00f00;

        sprintf(name, "%x", llog_test_rand+1);
        CWARN("4a: create a catalog log with name: %s\n", name);
	rc = llog_open_create(NULL, ctxt, &cath, NULL, name);
        if (rc) {
                CERROR("1a: llog_create with name %s failed: %d\n", name, rc);
                GOTO(out, rc);
        }
	llog_init_handle(NULL, cath, LLOG_F_IS_CAT, &uuid);
        num_recs++;
        cat_logid = cath->lgh_id;

        CWARN("4b: write 1 record into the catalog\n");
	rc = llog_cat_add_rec(NULL, cath, &lmr.lmr_hdr, &cookie, NULL);
        if (rc != 1) {
                CERROR("4b: write 1 catalog record failed at: %d\n", rc);
                GOTO(out, rc);
        }
        num_recs++;
        if ((rc = verify_handle("4b", cath, 2)))
                GOTO(ctxt_release, rc);

        if ((rc = verify_handle("4b", cath->u.chd.chd_current_log, num_recs)))
                GOTO(ctxt_release, rc);

        CWARN("4c: cancel 1 log record\n");
	rc = llog_cat_cancel_records(NULL, cath, 1, &cookie);
        if (rc) {
                CERROR("4c: cancel 1 catalog based record failed: %d\n", rc);
                GOTO(out, rc);
        }
        num_recs--;

        if ((rc = verify_handle("4c", cath->u.chd.chd_current_log, num_recs)))
                GOTO(ctxt_release, rc);

        CWARN("4d: write 40,000 more log records\n");
        for (i = 0; i < 40000; i++) {
		rc = llog_cat_add_rec(NULL, cath, &lmr.lmr_hdr, NULL, NULL);
                if (rc) {
                        CERROR("4d: write 40000 records failed at #%d: %d\n",
                               i + 1, rc);
                        GOTO(out, rc);
                }
                num_recs++;
        }

        CWARN("4e: add 5 large records, one record per block\n");
        buflen = LLOG_CHUNK_SIZE - sizeof(struct llog_rec_hdr)
                        - sizeof(struct llog_rec_tail);
        OBD_ALLOC(buf, buflen);
        if (buf == NULL)
                GOTO(out, rc = -ENOMEM);
        for (i = 0; i < 5; i++) {
                rec.lrh_len = buflen;
                rec.lrh_type = OBD_CFG_REC;
		rc = llog_cat_add_rec(NULL, cath, &rec, NULL, buf);
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
        CWARN("4f: put newly-created catalog\n");
	rc = llog_cat_close(NULL, cath);
ctxt_release:
        llog_ctxt_put(ctxt);
        if (rc)
                CERROR("1b: close log %s failed: %d\n", name, rc);
        RETURN(rc);
}

static int cat_print_cb(const struct lu_env *env, struct llog_handle *llh,
			struct llog_rec_hdr *rec, void *data)
{
        struct llog_logid_rec *lir = (struct llog_logid_rec *)rec;

        if (rec->lrh_type != LLOG_LOGID_MAGIC) {
                CERROR("invalid record in catalog\n");
                RETURN(-EINVAL);
        }

        CWARN("seeing record at index %d - "LPX64":%x in log "LPX64"\n",
               rec->lrh_index, lir->lid_id.lgl_oid,
               lir->lid_id.lgl_ogen, llh->lgh_id.lgl_oid);
        RETURN(0);
}

static int plain_print_cb(const struct lu_env *env, struct llog_handle *llh,
			  struct llog_rec_hdr *rec, void *data)
{
        if (!(llh->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN)) {
                CERROR("log is not plain\n");
                RETURN(-EINVAL);
        }

        CWARN("seeing record at index %d in log "LPX64"\n",
               rec->lrh_index, llh->lgh_id.lgl_oid);
        RETURN(0);
}

static int llog_cancel_rec_cb(const struct lu_env *env,
			      struct llog_handle *llh,
			      struct llog_rec_hdr *rec, void *data)
{
        struct llog_cookie cookie;
        static int i = 0;

        if (!(llh->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN)) {
                CERROR("log is not plain\n");
                RETURN(-EINVAL);
        }

        cookie.lgc_lgl = llh->lgh_id;
        cookie.lgc_index = rec->lrh_index;

	llog_cat_cancel_records(NULL, llh->u.phd.phd_cat_handle, 1, &cookie);
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
        struct llog_ctxt *ctxt = llog_get_context(obd, LLOG_TEST_ORIG_CTXT);

        ENTRY;

        lmr.lmr_hdr.lrh_len = lmr.lmr_tail.lrt_len = LLOG_MIN_REC_SIZE;
        lmr.lmr_hdr.lrh_type = 0xf00f00;

        CWARN("5a: re-open catalog by id\n");
	rc = llog_open(NULL, ctxt, &llh, &cat_logid, NULL, LLOG_OPEN_EXISTS);
        if (rc) {
                CERROR("5a: llog_create with logid failed: %d\n", rc);
                GOTO(out, rc);
        }
	llog_init_handle(NULL, llh, LLOG_F_IS_CAT, &uuid);

        CWARN("5b: print the catalog entries.. we expect 2\n");
	rc = llog_process(NULL, llh, cat_print_cb, "test 5", NULL);
        if (rc) {
                CERROR("5b: process with cat_print_cb failed: %d\n", rc);
                GOTO(out, rc);
        }

        CWARN("5c: Cancel 40000 records, see one log zapped\n");
	rc = llog_cat_process(NULL, llh, llog_cancel_rec_cb, "foobar", 0, 0);
        if (rc != -4711) {
                CERROR("5c: process with cat_cancel_cb failed: %d\n", rc);
                GOTO(out, rc);
        }

        CWARN("5d: add 1 record to the log with many canceled empty pages\n");
	rc = llog_cat_add_rec(NULL, llh, &lmr.lmr_hdr, NULL, NULL);
        if (rc) {
                CERROR("5d: add record to the log with many canceled empty\
                       pages failed\n");
                GOTO(out, rc);
        }

        CWARN("5b: print the catalog entries.. we expect 1\n");
	rc = llog_process(NULL, llh, cat_print_cb, "test 5", NULL);
        if (rc) {
                CERROR("5b: process with cat_print_cb failed: %d\n", rc);
                GOTO(out, rc);
        }

        CWARN("5e: print plain log entries.. expect 6\n");
	rc = llog_cat_process(NULL, llh, plain_print_cb, "foobar", 0, 0);
        if (rc) {
                CERROR("5e: process with plain_print_cb failed: %d\n", rc);
                GOTO(out, rc);
        }

        CWARN("5f: print plain log entries reversely.. expect 6\n");
	rc = llog_cat_reverse_process(NULL, llh, plain_print_cb, "foobar");
        if (rc) {
                CERROR("5f: reversely process with plain_print_cb failed: %d\n", rc);
                GOTO(out, rc);
        }

 out:
        CWARN("5: close re-opened catalog\n");
        if (llh)
		rc = llog_cat_close(NULL, llh);
        if (rc)
                CERROR("1b: close log %s failed: %d\n", name, rc);
        llog_ctxt_put(ctxt);

        RETURN(rc);
}

/* Test client api; open log by name and process */
static int llog_test_6(struct obd_device *obd, char *name)
{
        struct obd_device *mgc_obd;
        struct llog_ctxt *ctxt = llog_get_context(obd, LLOG_TEST_ORIG_CTXT);
        struct obd_uuid *mgs_uuid = &ctxt->loc_exp->exp_obd->obd_uuid;
        struct obd_export *exp;
        struct obd_uuid uuid = {"LLOG_TEST6_UUID"};
        struct llog_handle *llh = NULL;
        struct llog_ctxt *nctxt;
        int rc;

        CWARN("6a: re-open log %s using client API\n", name);
        mgc_obd = class_find_client_obd(mgs_uuid, LUSTRE_MGC_NAME, NULL);
        if (mgc_obd == NULL) {
                CERROR("6: no MGC devices connected to %s found.\n",
                       mgs_uuid->uuid);
                GOTO(ctxt_release, rc = -ENOENT);
        }

        rc = obd_connect(NULL, &exp, mgc_obd, &uuid,
                         NULL /* obd_connect_data */, NULL);
        if (rc != -EALREADY) {
                CERROR("6: connect on connected MDC (%s) failed to return"
                       " -EALREADY", mgc_obd->obd_name);
                if (rc == 0)
                        obd_disconnect(exp);
                GOTO(ctxt_release, rc = -EINVAL);
        }

        nctxt = llog_get_context(mgc_obd, LLOG_CONFIG_REPL_CTXT);
	rc = llog_open(NULL, nctxt, &llh, NULL, name, LLOG_OPEN_EXISTS);
        if (rc) {
                CERROR("6: llog_create failed %d\n", rc);
                llog_ctxt_put(nctxt);
                GOTO(ctxt_release, rc);
        }

	rc = llog_init_handle(NULL, llh, LLOG_F_IS_PLAIN, NULL);
        if (rc) {
                CERROR("6: llog_init_handle failed %d\n", rc);
                GOTO(parse_out, rc);
        }

	rc = llog_process(NULL, llh, plain_print_cb, NULL, NULL);
        if (rc)
                CERROR("6: llog_process failed %d\n", rc);

	rc = llog_reverse_process(NULL, llh, plain_print_cb, NULL, NULL);
        if (rc)
                CERROR("6: llog_reverse_process failed %d\n", rc);

parse_out:
	rc = llog_close(NULL, llh);
        llog_ctxt_put(nctxt);
        if (rc) {
                CERROR("6: llog_close failed: rc = %d\n", rc);
        }
ctxt_release:
        llog_ctxt_put(ctxt);
        RETURN(rc);
}

static int llog_test_7(struct obd_device *obd)
{
        struct llog_ctxt *ctxt = llog_get_context(obd, LLOG_TEST_ORIG_CTXT);
        struct llog_handle *llh;
        struct llog_create_rec lcr;
        char name[10];
        int rc;
        ENTRY;

        sprintf(name, "%x", llog_test_rand+2);
        CWARN("7: create a log with name: %s\n", name);
        LASSERT(ctxt);

	rc = llog_open_create(NULL, ctxt, &llh, NULL, name);
        if (rc) {
                CERROR("7: llog_create with name %s failed: %d\n", name, rc);
                GOTO(ctxt_release, rc);
        }
	llog_init_handle(NULL, llh, LLOG_F_IS_PLAIN, &uuid);

        lcr.lcr_hdr.lrh_len = lcr.lcr_tail.lrt_len = sizeof(lcr);
        lcr.lcr_hdr.lrh_type = OST_SZ_REC;
	rc = llog_write_rec(NULL, llh,  &lcr.lcr_hdr, NULL, 0, NULL, -1);
        if (rc) {
                CERROR("7: write one log record failed: %d\n", rc);
                GOTO(ctxt_release, rc);
        }

	rc = llog_destroy(NULL, llh);
        if (rc)
                CERROR("7: llog_destroy failed: %d\n", rc);
	llog_close(NULL, llh);
ctxt_release:
        llog_ctxt_put(ctxt);
        RETURN(rc);
}

/* -------------------------------------------------------------------------
 * Tests above, boring obd functions below
 * ------------------------------------------------------------------------- */
static int llog_run_tests(struct obd_device *obd)
{
        struct llog_handle *llh;
        struct lvfs_run_ctxt saved;
        struct llog_ctxt *ctxt = llog_get_context(obd, LLOG_TEST_ORIG_CTXT);
        int rc, err, cleanup_phase = 0;
        char name[10];
        ENTRY;

        sprintf(name, "%x", llog_test_rand);
        push_ctxt(&saved, &ctxt->loc_exp->exp_obd->obd_lvfs_ctxt, NULL);

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

        rc = llog_test_7(obd);
        if (rc)
                GOTO(cleanup, rc);

 cleanup:
        switch (cleanup_phase) {
        case 1:
		err = llog_close(NULL, llh);
                if (err)
                        CERROR("cleanup: llog_close failed: %d\n", err);
                if (!rc)
                        rc = err;
        case 0:
                pop_ctxt(&saved, &ctxt->loc_exp->exp_obd->obd_lvfs_ctxt, NULL);
        }
        llog_ctxt_put(ctxt);
        return rc;
}

static int llog_test_llog_init(struct obd_device *obd,
                               struct obd_llog_group *olg,
                               struct obd_device *tgt, int *index)
{
        int rc;
        ENTRY;

        rc = llog_setup(obd, &obd->obd_olg, LLOG_TEST_ORIG_CTXT, tgt, 0, NULL,
                        &llog_lvfs_ops);
        RETURN(rc);
}

static int llog_test_llog_finish(struct obd_device *obd, int count)
{
        int rc;
        ENTRY;

        rc = llog_cleanup(llog_get_context(obd, LLOG_TEST_ORIG_CTXT));
        RETURN(rc);
}
#ifdef LPROCFS
static struct lprocfs_vars lprocfs_llog_test_obd_vars[] = { {0} };
static struct lprocfs_vars lprocfs_llog_test_module_vars[] = { {0} };
static void lprocfs_llog_test_init_vars(struct lprocfs_static_vars *lvars)
{
    lvars->module_vars  = lprocfs_llog_test_module_vars;
    lvars->obd_vars     = lprocfs_llog_test_obd_vars;
}
#endif

static int llog_test_cleanup(struct obd_device *obd)
{
        int rc = obd_llog_finish(obd, 0);
        if (rc)
                CERROR("failed to llog_test_llog_finish: %d\n", rc);

        lprocfs_obd_cleanup(obd);

        return rc;
}

static int llog_test_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
        struct lprocfs_static_vars lvars;
        struct obd_device *tgt;
        int rc;
        ENTRY;

        if (lcfg->lcfg_bufcount < 2) {
                CERROR("requires a TARGET OBD name\n");
                RETURN(-EINVAL);
        }

        if (lcfg->lcfg_buflens[1] < 1) {
                CERROR("requires a TARGET OBD name\n");
                RETURN(-EINVAL);
        }

        /* disk obd */
        tgt = class_name2obd(lustre_cfg_string(lcfg, 1));
        if (!tgt || !tgt->obd_attached || !tgt->obd_set_up) {
                CERROR("target device not attached or not set up (%s)\n",
                       lustre_cfg_string(lcfg, 1));
                RETURN(-EINVAL);
        }

        rc = obd_llog_init(obd, NULL, tgt, NULL);
        if (rc)
                RETURN(rc);

        llog_test_rand = cfs_rand();

        rc = llog_run_tests(obd);
        if (rc)
                llog_test_cleanup(obd);

        lprocfs_llog_test_init_vars(&lvars);
        lprocfs_obd_setup(obd, lvars.obd_vars);

        RETURN(rc);
}

static struct obd_ops llog_obd_ops = {
        .o_owner       = THIS_MODULE,
        .o_setup       = llog_test_setup,
        .o_cleanup     = llog_test_cleanup,
        .o_llog_init   = llog_test_llog_init,
        .o_llog_finish = llog_test_llog_finish,
};

static int __init llog_test_init(void)
{
        struct lprocfs_static_vars lvars;

        lprocfs_llog_test_init_vars(&lvars);
        return class_register_type(&llog_obd_ops, NULL,
                                   lvars.module_vars,"llog_test", NULL);
}

static void __exit llog_test_exit(void)
{
        class_unregister_type("llog_test");
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("llog test module");
MODULE_LICENSE("GPL");

module_init(llog_test_init);
module_exit(llog_test_exit);
