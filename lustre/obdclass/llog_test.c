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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/obdclass/llog_test.c
 *
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>

#include <obd_class.h>
#include <lustre_fid.h>
#include <lustre_log.h>

/* This is slightly more than the number of records that can fit into a
 * single llog file, because the llog_log_header takes up some of the
 * space in the first block that cannot be used for the bitmap. */
static int llog_test_recnum = (LLOG_MIN_CHUNK_SIZE * 8);
static int llog_test_rand;
static struct obd_uuid uuid = { .uuid = "test_uuid" };
static struct llog_logid cat_logid;

struct llog_mini_rec {
	struct llog_rec_hdr lmr_hdr;
	struct llog_rec_tail lmr_tail;
} __attribute__((packed));

static int verify_handle(char *test, struct llog_handle *llh, int num_recs)
{
	int i;
	int last_idx = 0;
	int active_recs = 0;

	for (i = 0; i < LLOG_HDR_BITMAP_SIZE(llh->lgh_hdr); i++) {
		if (ext2_test_bit(i, LLOG_HDR_BITMAP(llh->lgh_hdr))) {
			last_idx = i;
			active_recs++;
		}
	}

	/* check the llog is sane at first, llh_count and lgh_last_idx*/
	if (llh->lgh_hdr->llh_count != active_recs) {
		CERROR("%s: handle->count is %d, but there are %d recs found\n",
		       test, llh->lgh_hdr->llh_count, active_recs);
		RETURN(-ERANGE);
	}

	if (llh->lgh_last_idx != LLOG_HDR_TAIL(llh->lgh_hdr)->lrt_index ||
	    (!(llh->lgh_hdr->llh_flags & LLOG_F_IS_CAT) &&
	     llh->lgh_last_idx < last_idx)) {
		CERROR("%s: lgh_last_idx is %d (%d in the header), last found %d\n",
		       test, llh->lgh_last_idx,
		       LLOG_HDR_TAIL(llh->lgh_hdr)->lrt_index, last_idx);
		RETURN(-ERANGE);
	}

	/* finally checks against expected value from the caller */
	if (active_recs != num_recs) {
		CERROR("%s: expected %d active recs after write, found %d\n",
		       test, num_recs, active_recs);
		RETURN(-ERANGE);
	}

	RETURN(0);
}

/* Test named-log create/open, close */
static int llog_test_1(const struct lu_env *env,
		       struct obd_device *obd, char *name)
{
	struct llog_handle *llh;
	struct llog_ctxt *ctxt;
	int rc;
	int rc2;

	ENTRY;

	CWARN("1a: create a log with name: %s\n", name);
	ctxt = llog_get_context(obd, LLOG_TEST_ORIG_CTXT);
	LASSERT(ctxt);

	rc = llog_open_create(env, ctxt, &llh, NULL, name);
	if (rc) {
		CERROR("1a: llog_create with name %s failed: %d\n", name, rc);
		GOTO(out, rc);
	}
	rc = llog_init_handle(env, llh, LLOG_F_IS_PLAIN, &uuid);
	if (rc) {
		CERROR("1a: can't init llog handle: %d\n", rc);
		GOTO(out_close, rc);
	}

	rc = verify_handle("1", llh, 1);

	CWARN("1b: close newly-created log\n");
out_close:
	rc2 = llog_close(env, llh);
	if (rc2) {
		CERROR("1b: close log %s failed: %d\n", name, rc2);
		if (rc == 0)
			rc = rc2;
	}
out:
	llog_ctxt_put(ctxt);
	RETURN(rc);
}

static int test_2_cancel_cb(const struct lu_env *env, struct llog_handle *llh,
			    struct llog_rec_hdr *rec, void *data)
{
	return LLOG_DEL_RECORD;
}

/* Test named-log reopen; returns opened log on success */
static int llog_test_2(const struct lu_env *env, struct obd_device *obd,
		       char *name, struct llog_handle **llh)
{
	struct llog_ctxt *ctxt;
	struct llog_handle *lgh;
	struct llog_logid  logid;
	int rc;
	struct llog_mini_rec lmr;

	ENTRY;

	CWARN("2a: re-open a log with name: %s\n", name);
	ctxt = llog_get_context(obd, LLOG_TEST_ORIG_CTXT);
	LASSERT(ctxt);

	rc = llog_open(env, ctxt, llh, NULL, name, LLOG_OPEN_EXISTS);
	if (rc) {
		CERROR("2a: re-open log with name %s failed: %d\n", name, rc);
		GOTO(out_put, rc);
	}

	rc = llog_init_handle(env, *llh, LLOG_F_IS_PLAIN, &uuid);
	if (rc) {
		CERROR("2a: can't init llog handle: %d\n", rc);
		GOTO(out_close_llh, rc);
	}

	rc = verify_handle("2", *llh, 1);
	if (rc)
		GOTO(out_close_llh, rc);

	CWARN("2b: create a log without specified NAME & LOGID\n");
	rc = llog_open_create(env, ctxt, &lgh, NULL, NULL);
	if (rc) {
		CERROR("2b: create log failed\n");
		GOTO(out_close_llh, rc);
	}
	rc = llog_init_handle(env, lgh, LLOG_F_IS_PLAIN, &uuid);
	if (rc) {
		CERROR("2b: can't init llog handle: %d\n", rc);
		GOTO(out_close, rc);
	}

	logid = lgh->lgh_id;

	lmr.lmr_hdr.lrh_len = lmr.lmr_tail.lrt_len = LLOG_MIN_REC_SIZE;
	lmr.lmr_hdr.lrh_type = LLOG_OP_MAGIC;

	/* Check llog header values are correct after record add/cancel */
	CWARN("2b: write 1 llog records, check llh_count\n");
	rc = llog_write(env, lgh, &lmr.lmr_hdr, LLOG_NEXT_IDX);
	if (rc < 0)
		GOTO(out_close, rc);

	/* in-memory values after record addition */
	rc = verify_handle("2b", lgh, 2);
	if (rc < 0)
		GOTO(out_close, rc);

	/* re-open llog to read on-disk values */
	llog_close(env, lgh);

	CWARN("2c: re-open the log by LOGID and verify llh_count\n");
	rc = llog_open(env, ctxt, &lgh, &logid, NULL, LLOG_OPEN_EXISTS);
	if (rc < 0) {
		CERROR("2c: re-open log by LOGID failed\n");
		GOTO(out_close_llh, rc);
	}

	rc = llog_init_handle(env, lgh, LLOG_F_IS_PLAIN, &uuid);
	if (rc < 0) {
		CERROR("2c: can't init llog handle: %d\n", rc);
		GOTO(out_close, rc);
	}

	/* check values just read from disk */
	rc = verify_handle("2c", lgh, 2);
	if (rc < 0)
		GOTO(out_close, rc);

	rc = llog_process(env, lgh, test_2_cancel_cb, NULL, NULL);
	if (rc < 0)
		GOTO(out_close, rc);

	/* in-memory values */
	rc = verify_handle("2c", lgh, 1);
	if (rc < 0)
		GOTO(out_close, rc);

	/* re-open llog to get on-disk values */
	llog_close(env, lgh);

	rc = llog_open(env, ctxt, &lgh, &logid, NULL, LLOG_OPEN_EXISTS);
	if (rc) {
		CERROR("2c: re-open log by LOGID failed\n");
		GOTO(out_close_llh, rc);
	}

	rc = llog_init_handle(env, lgh, LLOG_F_IS_PLAIN, &uuid);
	if (rc) {
		CERROR("2c: can't init llog handle: %d\n", rc);
		GOTO(out_close, rc);
	}

	/* on-disk values after llog re-open */
	rc = verify_handle("2c", lgh, 1);
	if (rc < 0)
		GOTO(out_close, rc);

	CWARN("2d: destroy this log\n");
	rc = llog_destroy(env, lgh);
	if (rc)
		CERROR("2d: destroy log failed\n");
out_close:
	llog_close(env, lgh);
out_close_llh:
	if (rc)
		llog_close(env, *llh);
out_put:
	llog_ctxt_put(ctxt);

	RETURN(rc);
}

static int test_3_rec_num;
static off_t test_3_rec_off;
static int test_3_paddings;
static int test_3_start_idx;

/*
 * Test 3 callback.
 * - check lgh_cur_offset correctness
 * - check record index consistency
 * - modify each record in-place
 * - add new record during *last_idx processing
 */
static int test3_check_n_add_cb(const struct lu_env *env,
				struct llog_handle *lgh,
				struct llog_rec_hdr *rec, void *data)
{
	struct llog_gen_rec *lgr = (struct llog_gen_rec *)rec;
	int *last_rec = data;
	unsigned cur_idx = test_3_start_idx + test_3_rec_num;
	int rc;

	if (lgh->lgh_hdr->llh_flags & LLOG_F_IS_FIXSIZE) {
		LASSERT(lgh->lgh_hdr->llh_size > 0);
		if (lgh->lgh_cur_offset != lgh->lgh_hdr->llh_hdr.lrh_len +
					(cur_idx - 1) * lgh->lgh_hdr->llh_size)
			CERROR("Wrong record offset in cur_off: %llu, should be %u\n",
			       lgh->lgh_cur_offset,
			       lgh->lgh_hdr->llh_hdr.lrh_len +
			       (cur_idx - 1) * lgh->lgh_hdr->llh_size);
	} else {
		size_t chunk_size = lgh->lgh_hdr->llh_hdr.lrh_len;

		/*
		 * For variable size records the start offset is unknown, trust
		 * the first value and check others are consistent with it.
		 */
		if (test_3_rec_off == 0)
			test_3_rec_off = lgh->lgh_cur_offset;

		if (lgh->lgh_cur_offset != test_3_rec_off) {
			__u64 tmp = lgh->lgh_cur_offset;

			/* there can be padding record */
			if ((do_div(tmp, chunk_size) == 0) &&
			    (lgh->lgh_cur_offset - test_3_rec_off <
			     rec->lrh_len + LLOG_MIN_REC_SIZE)) {
				test_3_rec_off = lgh->lgh_cur_offset;
				test_3_paddings++;
			} else {
				CERROR("Wrong record offset in cur_off: %llu"
				       ", should be %lld (rec len %u)\n",
				       lgh->lgh_cur_offset,
				       (long long)test_3_rec_off,
				       rec->lrh_len);
			}
		}
		test_3_rec_off += rec->lrh_len;
	}

	cur_idx += test_3_paddings;
	if (cur_idx != rec->lrh_index)
		CERROR("Record with wrong index was read: %u, expected %u\n",
		       rec->lrh_index, cur_idx);

	/* modify all records in place */
	lgr->lgr_gen.conn_cnt = rec->lrh_index;
	rc = llog_write(env, lgh, rec, rec->lrh_index);
	if (rc < 0)
		CERROR("cb_test_3: cannot modify record while processing\n");

	/*
	 * Add new record to the llog at *last_rec position one by one to
	 * check that last block is re-read during processing
	 */
	if (cur_idx == *last_rec || cur_idx == (*last_rec + 1)) {
		rc = llog_write(env, lgh, rec, LLOG_NEXT_IDX);
		if (rc < 0)
			CERROR("cb_test_3: cannot add new record while "
			       "processing\n");
	}
	test_3_rec_num++;

	return rc;
}

/* Check in-place modifications were done for all records*/
static int test3_check_cb(const struct lu_env *env, struct llog_handle *lgh,
			  struct llog_rec_hdr *rec, void *data)
{
	struct llog_gen_rec *lgr = (struct llog_gen_rec *)rec;

	if (lgr->lgr_gen.conn_cnt != rec->lrh_index) {
		CERROR("cb_test_3: record %u is not modified\n",
		       rec->lrh_index);
		return -EINVAL;
	}
	test_3_rec_num++;
	return 0;
}

static int llog_test3_process(const struct lu_env *env,
			      struct llog_handle *lgh,
			      llog_cb_t cb, int start)
{
	struct llog_process_cat_data cd;
	int last_idx; /* new record will be injected here */
	int rc = 0;

	CWARN("test3: processing records from index %d to the end\n",
	      start);
	cd.lpcd_first_idx = start - 1;
	cd.lpcd_last_idx = 0;
	test_3_rec_num = test_3_paddings = 0;
	last_idx = lgh->lgh_last_idx;
	rc = llog_process(env, lgh, cb, &last_idx, &cd);
	if (rc < 0)
		return rc;
	CWARN("test3: total %u records processed with %u paddings\n",
	      test_3_rec_num, test_3_paddings);
	return test_3_rec_num;
}

/* Test plain llog functionality */
static int llog_test_3(const struct lu_env *env, struct obd_device *obd,
		       struct llog_handle *llh)
{
	char buf[128];
	struct llog_rec_hdr *hdr = (void *)buf;
	int rc, i;
	int num_recs = 1; /* 1 for the header */
	int expected;

	ENTRY;

	hdr->lrh_len = sizeof(struct llog_gen_rec);
	hdr->lrh_type = LLOG_GEN_REC;
	llh->lgh_hdr->llh_size = sizeof(struct llog_gen_rec);
	llh->lgh_hdr->llh_flags |= LLOG_F_IS_FIXSIZE;

	/*
	 * Fill the llog with 64-bytes records, use 1023 records,
	 * so last chunk will be partially full. Don't change this
	 * value until record size is changed.
	 */
	CWARN("3a: write 1023 fixed-size llog records\n");
	for (i = 0; i < 1023; i++) {
		rc = llog_write(env, llh, hdr, LLOG_NEXT_IDX);
		if (rc < 0) {
			CERROR("3a: write 1023 records failed at #%d: %d\n",
			       i + 1, rc);
			RETURN(rc);
		}
		num_recs++;
	}

	rc = verify_handle("3a", llh, num_recs);
	if (rc)
		RETURN(rc);

	/*
	 * Test fixed-size records processing:
	 * - search the needed index
	 * - go through all records from that index
	 * - check all indices are growing monotonically and exist
	 * - modify each record
	 *
	 * NB: test3_check_n_add adds two new records while processing
	 * after last record. There were 1023 records created so the last chunk
	 * misses exactly one record. Therefore one of new records will be
	 * the last in the current chunk and second causes the new chunk to be
	 * created.
	 */
	test_3_rec_off = 0;
	test_3_start_idx = 501;
	expected = 525;
	rc = llog_test3_process(env, llh, test3_check_n_add_cb,
				test_3_start_idx);
	if (rc < 0)
		RETURN(rc);

	/* extra record is created during llog_process() */
	if (rc != expected) {
		CERROR("3a: process total %d records but expect %d\n",
		       rc, expected);
		RETURN(-ERANGE);
	}

	num_recs += 2;

	/* test modification in place */
	rc = llog_test3_process(env, llh, test3_check_cb, test_3_start_idx);
	if (rc < 0)
		RETURN(rc);

	if (rc != expected) {
		CERROR("3a: process total %d records but expect %d\n",
		       rc, expected);
		RETURN(-ERANGE);
	}

	CWARN("3b: write 566 variable size llog records\n");

	/*
	 * Drop llh_size to 0 to mark llog as variable-size and write
	 * header to make this change permanent.
	 */
	llh->lgh_hdr->llh_flags &= ~LLOG_F_IS_FIXSIZE;
	llog_write(env, llh, &llh->lgh_hdr->llh_hdr, LLOG_HEADER_IDX);

	hdr->lrh_type = OBD_CFG_REC;

	/*
	 * there are 1025 64-bytes records in llog already,
	 * the last chunk contains single record, i.e. 64 bytes.
	 * Each pair of variable size records is 200 bytes, so
	 * we will have the following distribution per chunks:
	 * block 1: 64 + 80(80/120) + 80 + 48(pad) = 81 iterations
	 * block 2: 80(120/80) + 120 + 72(pad) = 81 itereations
	 * block 3: 80(80/120) + 80 + 112(pad) = 81 iterations
	 * -- the same as block 2 again and so on.
	 * block 7: 80(80/120) = 80 iterations and 192 bytes remain
	 * Total 6 * 81 + 80 = 566 itereations.
	 * Callback will add another 120 bytes in the end of the last chunk
	 * and another 120 bytes will cause padding (72 bytes) plus 120
	 * bytes in the new block.
	 */
	for (i = 0; i < 566; i++) {
		if ((i % 2) == 0)
			hdr->lrh_len = 80;
		else
			hdr->lrh_len = 120;

		rc = llog_write(env, llh, hdr, LLOG_NEXT_IDX);
		if (rc < 0) {
			CERROR("3b: write 566 records failed at #%d: %d\n",
			       i + 1, rc);
			RETURN(rc);
		}
		num_recs++;
	}

	rc = verify_handle("3b", llh, num_recs);
	if (rc)
		RETURN(rc);

	test_3_start_idx = 1026;
	expected = 568;
	rc = llog_test3_process(env, llh, test3_check_n_add_cb,
				test_3_start_idx);
	if (rc < 0)
		RETURN(rc);

	if (rc != expected) {
		CERROR("3b: process total %d records but expect %d\n",
		       rc, expected);
		RETURN(-ERANGE);
	}

	num_recs += 2;

	/* test modification in place */
	rc = llog_test3_process(env, llh, test3_check_cb, test_3_start_idx);
	if (rc < 0)
		RETURN(rc);

	if (rc != expected) {
		CERROR("3b: process total %d records but expect %d\n",
		       rc, expected);
		RETURN(-ERANGE);
	}

	CWARN("3c: write records with variable size until BITMAP_SIZE, "
	      "return -ENOSPC\n");
	while (num_recs < LLOG_HDR_BITMAP_SIZE(llh->lgh_hdr)) {
		if ((num_recs % 2) == 0)
			hdr->lrh_len = 80;
		else
			hdr->lrh_len = 128;

		rc = llog_write(env, llh, hdr, LLOG_NEXT_IDX);
		if (rc == -ENOSPC) {
			break;
		} else if (rc < 0) {
			CERROR("3c: write recs failed at #%d: %d\n",
			       num_recs, rc);
			RETURN(rc);
		}
		num_recs++;
	}

	if (rc != -ENOSPC) {
		CWARN("3c: write record more than BITMAP size!\n");
		RETURN(-EINVAL);
	}
	CWARN("3c: wrote %d more records before end of llog is reached\n",
	      num_recs);

	rc = verify_handle("3c", llh, num_recs);

	RETURN(rc);
}

/* Test catalogue additions */
static int llog_test_4(const struct lu_env *env, struct obd_device *obd)
{
	struct llog_handle *cath, *llh;
	char name[10];
	int rc, rc2, i, buflen;
	struct llog_mini_rec lmr;
	struct llog_cookie cookie;
	struct llog_ctxt *ctxt;
	int num_recs = 0;
	char *buf;
	struct llog_rec_hdr *rec;

	ENTRY;

	ctxt = llog_get_context(obd, LLOG_TEST_ORIG_CTXT);
	LASSERT(ctxt);

	lmr.lmr_hdr.lrh_len = lmr.lmr_tail.lrt_len = LLOG_MIN_REC_SIZE;
	lmr.lmr_hdr.lrh_type = LLOG_OP_MAGIC;

	sprintf(name, "%x", llog_test_rand + 1);
	CWARN("4a: create a catalog log with name: %s\n", name);
	rc = llog_open_create(env, ctxt, &cath, NULL, name);
	if (rc) {
		CERROR("4a: llog_create with name %s failed: %d\n", name, rc);
		GOTO(ctxt_release, rc);
        }
	rc = llog_init_handle(env, cath, LLOG_F_IS_CAT, &uuid);
	if (rc) {
		CERROR("4a: can't init llog handle: %d\n", rc);
		GOTO(out, rc);
	}

	num_recs++;
	cat_logid = cath->lgh_id;

	CWARN("4b: write 1 record into the catalog\n");
	rc = llog_cat_add(env, cath, &lmr.lmr_hdr, &cookie);
	if (rc != 1) {
		CERROR("4b: write 1 catalog record failed at: %d\n", rc);
		GOTO(out, rc);
	}
	num_recs++;
	rc = verify_handle("4b", cath, 2);
	if (rc)
		GOTO(out, rc);

	rc = verify_handle("4b", cath->u.chd.chd_current_log, num_recs);
	if (rc)
		GOTO(out, rc);

	/* estimate the max number of record for the plain llog
	 * cause it depends on disk size
	 */
	llh = cath->u.chd.chd_current_log;
	if (llh->lgh_max_size != 0) {
		llog_test_recnum = (llh->lgh_max_size -
			sizeof(struct llog_log_hdr)) / LLOG_MIN_REC_SIZE;
	}

	if (llog_test_recnum >= LLOG_HDR_BITMAP_SIZE(llh->lgh_hdr))
		llog_test_recnum = LLOG_HDR_BITMAP_SIZE(llh->lgh_hdr) - 1;

	CWARN("4c: cancel 1 log record\n");
	rc = llog_cat_cancel_records(env, cath, 1, &cookie);
	if (rc) {
		CERROR("4c: cancel 1 catalog based record failed: %d\n", rc);
		GOTO(out, rc);
	}
	num_recs--;

	rc = verify_handle("4c", cath->u.chd.chd_current_log, num_recs);
	if (rc)
		GOTO(out, rc);

	CWARN("4d: write %d more log records\n", llog_test_recnum);
	for (i = 0; i < llog_test_recnum; i++) {
		rc = llog_cat_add(env, cath, &lmr.lmr_hdr, NULL);
		if (rc) {
			CERROR("4d: write %d records failed at #%d: %d\n",
			       llog_test_recnum, i + 1, rc);
			GOTO(out, rc);
		}
		num_recs++;
	}

	/* make sure new plain llog appears */
	rc = verify_handle("4d", cath, 3);
	if (rc)
		GOTO(out, rc);

	CWARN("4e: add 5 large records, one record per block\n");
	buflen = LLOG_MIN_CHUNK_SIZE;
	OBD_ALLOC(buf, buflen);
	if (buf == NULL)
		GOTO(out, rc = -ENOMEM);
	for (i = 0; i < 5; i++) {
		rec = (void *)buf;
		rec->lrh_len = buflen;
		rec->lrh_type = OBD_CFG_REC;
		rc = llog_cat_add(env, cath, rec, NULL);
		if (rc) {
			CERROR("4e: write 5 records failed at #%d: %d\n",
			       i + 1, rc);
			GOTO(out_free, rc);
		}
		num_recs++;
	}
out_free:
	OBD_FREE(buf, buflen);
out:
	CWARN("4f: put newly-created catalog\n");
	rc2 = llog_cat_close(env, cath);
	if (rc2) {
		CERROR("4: close log %s failed: %d\n", name, rc2);
		if (rc == 0)
			rc = rc2;
	}
ctxt_release:
	llog_ctxt_put(ctxt);
	RETURN(rc);
}

static int cat_counter;

static int cat_print_cb(const struct lu_env *env, struct llog_handle *llh,
			struct llog_rec_hdr *rec, void *data)
{
	struct llog_logid_rec *lir = (struct llog_logid_rec *)rec;
	struct lu_fid fid = {0};

	if (rec->lrh_type != LLOG_LOGID_MAGIC) {
		CERROR("invalid record in catalog\n");
		RETURN(-EINVAL);
	}

	logid_to_fid(&lir->lid_id, &fid);

	CWARN("seeing record at index %d - "DFID" in log "DFID"\n",
	      rec->lrh_index, PFID(&fid),
	      PFID(lu_object_fid(&llh->lgh_obj->do_lu)));

	cat_counter++;

	RETURN(0);
}

static int plain_counter;

static int plain_print_cb(const struct lu_env *env, struct llog_handle *llh,
			  struct llog_rec_hdr *rec, void *data)
{
	struct lu_fid fid = {0};

	if (!(llh->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN)) {
		CERROR("log is not plain\n");
		RETURN(-EINVAL);
	}

	logid_to_fid(&llh->lgh_id, &fid);

	CDEBUG(D_INFO, "seeing record at index %d in log "DFID"\n",
	       rec->lrh_index, PFID(&fid));

	plain_counter++;

	RETURN(0);
}

static int cancel_count;

static int llog_cancel_rec_cb(const struct lu_env *env,
			      struct llog_handle *llh,
			      struct llog_rec_hdr *rec, void *data)
{
	struct llog_cookie cookie;

	if (!(llh->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN)) {
		CERROR("log is not plain\n");
		RETURN(-EINVAL);
	}

	cookie.lgc_lgl = llh->lgh_id;
	cookie.lgc_index = rec->lrh_index;

	llog_cat_cancel_records(env, llh->u.phd.phd_cat_handle, 1, &cookie);
	cancel_count++;
	if (cancel_count == llog_test_recnum)
		RETURN(-LLOG_EEMPTY);
	RETURN(0);
}

/* Test log and catalogue processing */
static int llog_test_5(const struct lu_env *env, struct obd_device *obd)
{
	struct llog_handle *llh = NULL;
	char name[10];
	int rc, rc2;
	struct llog_mini_rec lmr;
	struct llog_ctxt *ctxt;

	ENTRY;

	ctxt = llog_get_context(obd, LLOG_TEST_ORIG_CTXT);
	LASSERT(ctxt);

	lmr.lmr_hdr.lrh_len = lmr.lmr_tail.lrt_len = LLOG_MIN_REC_SIZE;
	lmr.lmr_hdr.lrh_type = LLOG_OP_MAGIC;

	CWARN("5a: re-open catalog by id\n");
	rc = llog_open(env, ctxt, &llh, &cat_logid, NULL, LLOG_OPEN_EXISTS);
	if (rc) {
		CERROR("5a: llog_create with logid failed: %d\n", rc);
		GOTO(out_put, rc);
	}

	rc = llog_init_handle(env, llh, LLOG_F_IS_CAT, &uuid);
	if (rc) {
		CERROR("5a: can't init llog handle: %d\n", rc);
		GOTO(out, rc);
	}

	CWARN("5b: print the catalog entries.. we expect 2\n");
	cat_counter = 0;
	rc = llog_process(env, llh, cat_print_cb, "test 5", NULL);
	if (rc) {
		CERROR("5b: process with cat_print_cb failed: %d\n", rc);
		GOTO(out, rc);
	}
	if (cat_counter != 2) {
		CERROR("5b: %d entries in catalog\n", cat_counter);
		GOTO(out, rc = -EINVAL);
	}

	CWARN("5c: Cancel %d records, see one log zapped\n", llog_test_recnum);
	cancel_count = 0;
	rc = llog_cat_process(env, llh, llog_cancel_rec_cb, "foobar", 0, 0);
	if (rc != -LLOG_EEMPTY) {
		CERROR("5c: process with llog_cancel_rec_cb failed: %d\n", rc);
		GOTO(out, rc);
	}

	CWARN("5c: print the catalog entries.. we expect 1\n");
	cat_counter = 0;
	rc = llog_process(env, llh, cat_print_cb, "test 5", NULL);
	if (rc) {
		CERROR("5c: process with cat_print_cb failed: %d\n", rc);
		GOTO(out, rc);
	}
	if (cat_counter != 1) {
		CERROR("5c: %d entries in catalog\n", cat_counter);
		GOTO(out, rc = -EINVAL);
	}

	CWARN("5d: add 1 record to the log with many canceled empty pages\n");
	rc = llog_cat_add(env, llh, &lmr.lmr_hdr, NULL);
	if (rc) {
		CERROR("5d: add record to the log with many canceled empty "
		       "pages failed\n");
		GOTO(out, rc);
	}

	CWARN("5e: print plain log entries.. expect 6\n");
	plain_counter = 0;
	rc = llog_cat_process(env, llh, plain_print_cb, "foobar", 0, 0);
	if (rc) {
		CERROR("5e: process with plain_print_cb failed: %d\n", rc);
		GOTO(out, rc);
	}
	if (plain_counter != 6) {
		CERROR("5e: found %d records\n", plain_counter);
		GOTO(out, rc = -EINVAL);
	}

	CWARN("5f: print plain log entries reversely.. expect 6\n");
	plain_counter = 0;
	rc = llog_cat_reverse_process(env, llh, plain_print_cb, "foobar");
	if (rc) {
		CERROR("5f: reversely process with plain_print_cb failed: "
		       "%d\n", rc);
		GOTO(out, rc);
	}
	if (plain_counter != 6) {
		CERROR("5f: found %d records\n", plain_counter);
		GOTO(out, rc = -EINVAL);
	}

out:
	CWARN("5g: close re-opened catalog\n");
	rc2 = llog_cat_close(env, llh);
	if (rc2) {
		CERROR("5g: close log %s failed: %d\n", name, rc2);
		if (rc == 0)
			rc = rc2;
	}
out_put:
	llog_ctxt_put(ctxt);

	RETURN(rc);
}

/* Test client api; open log by name and process */
static int llog_test_6(const struct lu_env *env, struct obd_device *obd,
		       char *name)
{
	struct obd_device *mgc_obd;
	struct llog_ctxt *ctxt;
	struct obd_uuid *mgs_uuid;
	struct obd_export *exp;
	struct obd_uuid uuid = { "LLOG_TEST6_UUID" };
	struct llog_handle *llh = NULL;
	struct llog_ctxt *nctxt;
	int rc, rc2;

	ctxt = llog_get_context(obd, LLOG_TEST_ORIG_CTXT);
	LASSERT(ctxt);
	mgs_uuid = &ctxt->loc_exp->exp_obd->obd_uuid;

	CWARN("6a: re-open log %s using client API\n", name);
	mgc_obd = class_find_client_obd(mgs_uuid, LUSTRE_MGC_NAME, NULL);
	if (mgc_obd == NULL) {
		CERROR("6a: no MGC devices connected to %s found.\n",
		       mgs_uuid->uuid);
		GOTO(ctxt_release, rc = -ENOENT);
	}

	rc = obd_connect(NULL, &exp, mgc_obd, &uuid,
			 NULL /* obd_connect_data */, NULL);
	if (rc != -EALREADY) {
		CERROR("6a: connect on connected MGC (%s) failed to return"
		       " -EALREADY\n", mgc_obd->obd_name);
		if (rc == 0)
			obd_disconnect(exp);
		GOTO(ctxt_release, rc = -EINVAL);
	}

	nctxt = llog_get_context(mgc_obd, LLOG_CONFIG_REPL_CTXT);
	rc = llog_open(env, nctxt, &llh, NULL, name, LLOG_OPEN_EXISTS);
	if (rc) {
		CERROR("6a: llog_open failed %d\n", rc);
		GOTO(nctxt_put, rc);
	}

	rc = llog_init_handle(env, llh, LLOG_F_IS_PLAIN, NULL);
	if (rc) {
		CERROR("6a: llog_init_handle failed %d\n", rc);
		GOTO(parse_out, rc);
	}

	plain_counter = 1; /* llog header is first record */
	CWARN("6b: process log %s using client API\n", name);
	rc = llog_process(env, llh, plain_print_cb, NULL, NULL);
	if (rc)
		CERROR("6b: llog_process failed %d\n", rc);
	CWARN("6b: processed %d records\n", plain_counter);

	rc = verify_handle("6b", llh, plain_counter);
	if (rc)
		GOTO(parse_out, rc);

	plain_counter = 1; /* llog header is first record */
	CWARN("6c: process log %s reversely using client API\n", name);
	rc = llog_reverse_process(env, llh, plain_print_cb, NULL, NULL);
	if (rc)
		CERROR("6c: llog_reverse_process failed %d\n", rc);
	CWARN("6c: processed %d records\n", plain_counter);

	rc = verify_handle("6c", llh, plain_counter);
	if (rc)
		GOTO(parse_out, rc);

parse_out:
	rc2 = llog_close(env, llh);
	if (rc2) {
		CERROR("6: llog_close failed: rc = %d\n", rc2);
		if (rc == 0)
			rc = rc2;
	}
nctxt_put:
	llog_ctxt_put(nctxt);
ctxt_release:
	llog_ctxt_put(ctxt);
	RETURN(rc);
}

static union {
	struct llog_rec_hdr		lrh;   /* common header */
	struct llog_logid_rec		llr;   /* LLOG_LOGID_MAGIC */
	struct llog_unlink64_rec	lur;   /* MDS_UNLINK64_REC */
	struct llog_setattr64_rec	lsr64; /* MDS_SETATTR64_REC */
	struct llog_setattr64_rec_v2	lsr64_v2; /* MDS_SETATTR64_REC */
	struct llog_size_change_rec	lscr;  /* OST_SZ_REC */
	struct llog_changelog_rec	lcr;   /* CHANGELOG_REC */
	struct llog_changelog_user_rec	lcur;  /* CHANGELOG_USER_REC */
	struct llog_gen_rec		lgr;   /* LLOG_GEN_REC */
} llog_records;

static int test_7_print_cb(const struct lu_env *env, struct llog_handle *llh,
			   struct llog_rec_hdr *rec, void *data)
{
	struct lu_fid fid = {0};

	logid_to_fid(&llh->lgh_id, &fid);

	CDEBUG(D_OTHER, "record type %#x at index %d in log "DFID"\n",
	       rec->lrh_type, rec->lrh_index, PFID(&fid));

	plain_counter++;
	return 0;
}

static int test_7_cancel_cb(const struct lu_env *env, struct llog_handle *llh,
			    struct llog_rec_hdr *rec, void *data)
{
	plain_counter++;
	/* test LLOG_DEL_RECORD is working */
	return LLOG_DEL_RECORD;
}

static int llog_test_7_sub(const struct lu_env *env, struct llog_ctxt *ctxt)
{
	struct llog_handle *llh;
	int rc = 0, i, process_count;
	int num_recs = 0;

	ENTRY;

	rc = llog_open_create(env, ctxt, &llh, NULL, NULL);
	if (rc) {
		CERROR("7_sub: create log failed\n");
		RETURN(rc);
	}

	rc = llog_init_handle(env, llh,
			      LLOG_F_IS_PLAIN | LLOG_F_ZAP_WHEN_EMPTY,
			      &uuid);
	if (rc) {
		CERROR("7_sub: can't init llog handle: %d\n", rc);
		GOTO(out_close, rc);
	}
	for (i = 0; i < LLOG_HDR_BITMAP_SIZE(llh->lgh_hdr); i++) {
		rc = llog_write(env, llh, &llog_records.lrh, LLOG_NEXT_IDX);
		if (rc == -ENOSPC) {
			break;
		} else if (rc < 0) {
			CERROR("7_sub: write recs failed at #%d: %d\n",
			       i + 1, rc);
			GOTO(out_close, rc);
		}
		num_recs++;
	}
	if (rc != -ENOSPC) {
		CWARN("7_sub: write record more than BITMAP size!\n");
		GOTO(out_close, rc = -EINVAL);
	}

	rc = verify_handle("7_sub", llh, num_recs + 1);
	if (rc) {
		CERROR("7_sub: verify handle failed: %d\n", rc);
		GOTO(out_close, rc);
	}
	if (num_recs < LLOG_HDR_BITMAP_SIZE(llh->lgh_hdr) - 1)
		CWARN("7_sub: records are not aligned, written %d from %u\n",
		      num_recs, LLOG_HDR_BITMAP_SIZE(llh->lgh_hdr) - 1);

	plain_counter = 0;
	rc = llog_process(env, llh, test_7_print_cb, "test 7", NULL);
	if (rc) {
		CERROR("7_sub: llog process failed: %d\n", rc);
		GOTO(out_close, rc);
	}
	process_count = plain_counter;
	if (process_count != num_recs) {
		CERROR("7_sub: processed %d records from %d total\n",
		       process_count, num_recs);
		GOTO(out_close, rc = -EINVAL);
	}

	plain_counter = 0;
	rc = llog_reverse_process(env, llh, test_7_cancel_cb, "test 7", NULL);
	if (rc && rc != LLOG_DEL_PLAIN) {
		CERROR("7_sub: reverse llog process failed: %d\n", rc);
		GOTO(out_close, rc);
	}
	if (process_count != plain_counter) {
		CERROR("7_sub: Reverse/direct processing found different"
		       "number of records: %d/%d\n",
		       plain_counter, process_count);
		GOTO(out_close, rc = -EINVAL);
	}
	if (llog_exist(llh)) {
		CERROR("7_sub: llog exists but should be zapped\n");
		GOTO(out_close, rc = -EEXIST);
	}

	rc = verify_handle("7_sub", llh, 1);
out_close:
	if (rc)
		llog_destroy(env, llh);
	llog_close(env, llh);
	RETURN(rc);
}

/* Test all llog records writing and processing */
static int llog_test_7(const struct lu_env *env, struct obd_device *obd)
{
	struct llog_ctxt *ctxt;
	int rc;

	ENTRY;

	ctxt = llog_get_context(obd, LLOG_TEST_ORIG_CTXT);

	CWARN("7a: test llog_logid_rec\n");
	llog_records.llr.lid_hdr.lrh_len = sizeof(llog_records.llr);
	llog_records.llr.lid_tail.lrt_len = sizeof(llog_records.llr);
	llog_records.llr.lid_hdr.lrh_type = LLOG_LOGID_MAGIC;

	rc = llog_test_7_sub(env, ctxt);
	if (rc) {
		CERROR("7a: llog_logid_rec test failed\n");
		GOTO(out, rc);
	}

	CWARN("7b: test llog_unlink64_rec\n");
	llog_records.lur.lur_hdr.lrh_len = sizeof(llog_records.lur);
	llog_records.lur.lur_tail.lrt_len = sizeof(llog_records.lur);
	llog_records.lur.lur_hdr.lrh_type = MDS_UNLINK64_REC;

	rc = llog_test_7_sub(env, ctxt);
	if (rc) {
		CERROR("7b: llog_unlink_rec test failed\n");
		GOTO(out, rc);
	}

	CWARN("7c: test llog_setattr64_rec\n");
	llog_records.lsr64.lsr_hdr.lrh_len = sizeof(llog_records.lsr64);
	llog_records.lsr64.lsr_tail.lrt_len = sizeof(llog_records.lsr64);
	llog_records.lsr64.lsr_hdr.lrh_type = MDS_SETATTR64_REC;

	rc = llog_test_7_sub(env, ctxt);
	if (rc) {
		CERROR("7c: llog_setattr64_rec test failed\n");
		GOTO(out, rc);
	}

	CWARN("7d: test llog_size_change_rec\n");
	llog_records.lscr.lsc_hdr.lrh_len = sizeof(llog_records.lscr);
	llog_records.lscr.lsc_tail.lrt_len = sizeof(llog_records.lscr);
	llog_records.lscr.lsc_hdr.lrh_type = OST_SZ_REC;

	rc = llog_test_7_sub(env, ctxt);
	if (rc) {
		CERROR("7d: llog_size_change_rec test failed\n");
		GOTO(out, rc);
	}

	CWARN("7e: test llog_changelog_rec\n");
	/* Direct access to cr_do_not_use: peculiar case for this test */
	llog_records.lcr.cr_hdr.lrh_len = sizeof(llog_records.lcr);
	llog_records.lcr.cr_do_not_use.lrt_len = sizeof(llog_records.lcr);
	llog_records.lcr.cr_hdr.lrh_type = CHANGELOG_REC;

	rc = llog_test_7_sub(env, ctxt);
	if (rc) {
		CERROR("7e: llog_changelog_rec test failed\n");
		GOTO(out, rc);
	}

	CWARN("7f: test llog_changelog_user_rec\n");
	llog_records.lcur.cur_hdr.lrh_len = sizeof(llog_records.lcur);
	llog_records.lcur.cur_tail.lrt_len = sizeof(llog_records.lcur);
	llog_records.lcur.cur_hdr.lrh_type = CHANGELOG_USER_REC;

	rc = llog_test_7_sub(env, ctxt);
	if (rc) {
		CERROR("7f: llog_changelog_user_rec test failed\n");
		GOTO(out, rc);
	}

	CWARN("7g: test llog_gen_rec\n");
	llog_records.lgr.lgr_hdr.lrh_len = sizeof(llog_records.lgr);
	llog_records.lgr.lgr_tail.lrt_len = sizeof(llog_records.lgr);
	llog_records.lgr.lgr_hdr.lrh_type = LLOG_GEN_REC;

	rc = llog_test_7_sub(env, ctxt);
	if (rc) {
		CERROR("7g: llog_size_change_rec test failed\n");
		GOTO(out, rc);
	}

	CWARN("7h: test llog_setattr64_rec_v2\n");
	llog_records.lsr64.lsr_hdr.lrh_len = sizeof(llog_records.lsr64_v2);
	llog_records.lsr64.lsr_tail.lrt_len = sizeof(llog_records.lsr64_v2);
	llog_records.lsr64.lsr_hdr.lrh_type = MDS_SETATTR64_REC;

	rc = llog_test_7_sub(env, ctxt);
	if (rc) {
		CERROR("7h: llog_setattr64_rec_v2 test failed\n");
		GOTO(out, rc);
	}
out:
	llog_ctxt_put(ctxt);
	RETURN(rc);
}

static int test_8_cb(const struct lu_env *env, struct llog_handle *llh,
			  struct llog_rec_hdr *rec, void *data)
{
	plain_counter++;
	return 0;
}

static int llog_test_8(const struct lu_env *env, struct obd_device *obd)
{
	struct llog_handle *llh = NULL;
	char name[10];
	int rc, rc2, i;
	int orig_counter;
	struct llog_mini_rec lmr;
	struct llog_ctxt *ctxt;
	struct dt_object *obj = NULL;

	ENTRY;

	ctxt = llog_get_context(obd, LLOG_TEST_ORIG_CTXT);
	LASSERT(ctxt);

	lmr.lmr_hdr.lrh_len = lmr.lmr_tail.lrt_len = LLOG_MIN_REC_SIZE;
	lmr.lmr_hdr.lrh_type = LLOG_OP_MAGIC;

	CWARN("8a: fill the first plain llog\n");
	rc = llog_open(env, ctxt, &llh, &cat_logid, NULL, LLOG_OPEN_EXISTS);
	if (rc) {
		CERROR("8a: llog_create with logid failed: %d\n", rc);
		GOTO(out_put, rc);
	}

	rc = llog_init_handle(env, llh, LLOG_F_IS_CAT, &uuid);
	if (rc) {
		CERROR("8a: can't init llog handle: %d\n", rc);
		GOTO(out, rc);
	}

	plain_counter = 0;
	rc = llog_cat_process(env, llh, test_8_cb, "foobar", 0, 0);
	if (rc != 0) {
		CERROR("5a: process with test_8_cb failed: %d\n", rc);
		GOTO(out, rc);
	}
	orig_counter = plain_counter;

	for (i = 0; i < 100; i++) {
		rc = llog_cat_add(env, llh, &lmr.lmr_hdr, NULL);
		if (rc) {
			CERROR("5a: add record failed\n");
			GOTO(out, rc);
		}
	}

	/* grab the current plain llog, we'll corrupt it later */
	obj = llh->u.chd.chd_current_log->lgh_obj;
	LASSERT(obj);
	lu_object_get(&obj->do_lu);
	CWARN("8a: pin llog "DFID"\n", PFID(lu_object_fid(&obj->do_lu)));

	rc2 = llog_cat_close(env, llh);
	if (rc2) {
		CERROR("8a: close log %s failed: %d\n", name, rc2);
		if (rc == 0)
			rc = rc2;
		GOTO(out_put, rc);
	}

	CWARN("8b: fill the second plain llog\n");
	rc = llog_open(env, ctxt, &llh, &cat_logid, NULL, LLOG_OPEN_EXISTS);
	if (rc) {
		CERROR("8b: llog_create with logid failed: %d\n", rc);
		GOTO(out_put, rc);
	}

	rc = llog_init_handle(env, llh, LLOG_F_IS_CAT, &uuid);
	if (rc) {
		CERROR("8b: can't init llog handle: %d\n", rc);
		GOTO(out, rc);
	}

	for (i = 0; i < 100; i++) {
		rc = llog_cat_add(env, llh, &lmr.lmr_hdr, NULL);
		if (rc) {
			CERROR("8b: add record failed\n");
			GOTO(out, rc);
		}
	}
	CWARN("8b: second llog "DFID"\n",
	      PFID(lu_object_fid(&llh->u.chd.chd_current_log->lgh_obj->do_lu)));

	rc2 = llog_cat_close(env, llh);
	if (rc2) {
		CERROR("8b: close log %s failed: %d\n", name, rc2);
		if (rc == 0)
			rc = rc2;
		GOTO(out_put, rc);
	}

	/* Here was 8c: drop two records from the first plain llog
	 * llog_truncate was bad idea cause it creates a wrong state,
	 * lgh_last_idx is wrong and two records belongs to zeroed buffer
	 */

	CWARN("8d: count survived records\n");
	rc = llog_open(env, ctxt, &llh, &cat_logid, NULL, LLOG_OPEN_EXISTS);
	if (rc) {
		CERROR("8d: llog_create with logid failed: %d\n", rc);
		GOTO(out_put, rc);
	}

	rc = llog_init_handle(env, llh, LLOG_F_IS_CAT, &uuid);
	if (rc) {
		CERROR("8d: can't init llog handle: %d\n", rc);
		GOTO(out, rc);
	}

	plain_counter = 0;
	rc = llog_cat_process(env, llh, test_8_cb, "foobar", 0, 0);
	if (rc != 0) {
		CERROR("8d: process with test_8_cb failed: %d\n", rc);
		GOTO(out, rc);
	}

	if (orig_counter + 200 != plain_counter) {
		CERROR("found %d records (expected %d)\n", plain_counter,
		       orig_counter + 200);
		rc = -EIO;
	}

out:
	CWARN("8d: close re-opened catalog\n");
	rc2 = llog_cat_close(env, llh);
	if (rc2) {
		CERROR("8d: close log %s failed: %d\n", name, rc2);
		if (rc == 0)
			rc = rc2;
	}
out_put:
	llog_ctxt_put(ctxt);

	if (obj != NULL)
		dt_object_put(env, obj);

	RETURN(rc);
}

static int llog_test_9_sub(const struct lu_env *env, struct llog_ctxt *ctxt)
{
	struct llog_handle *llh;
	struct lu_fid fid;
	int rc = 0;

	ENTRY;

	rc = llog_open_create(env, ctxt, &llh, NULL, NULL);
	if (rc != 0) {
		CERROR("9_sub: create log failed\n");
		RETURN(rc);
	}

	rc = llog_init_handle(env, llh,
			      LLOG_F_IS_PLAIN | LLOG_F_ZAP_WHEN_EMPTY,
			      &uuid);
	if (rc != 0) {
		CERROR("9_sub: can't init llog handle: %d\n", rc);
		GOTO(out_close, rc);
	}

	logid_to_fid(&llh->lgh_id, &fid);
	fid_to_logid(&fid, &llog_records.llr.lid_id);
	rc = llog_write(env, llh, &llog_records.lrh, LLOG_NEXT_IDX);
	if (rc < 0) {
		CERROR("9_sub: write recs failed at #1: %d\n", rc);
		GOTO(out_close, rc);
	}
	CWARN("9_sub: record type %x in log "DFID_NOBRACE"\n",
	      llog_records.lrh.lrh_type, PFID(&fid));
out_close:
	llog_close(env, llh);
	RETURN(rc);
}

/* Prepare different types of llog records for llog_reader test*/
static int llog_test_9(const struct lu_env *env, struct obd_device *obd)
{
	struct llog_ctxt *ctxt;
	int rc;

	ENTRY;

	ctxt = llog_get_context(obd, LLOG_TEST_ORIG_CTXT);

	CWARN("9a: test llog_logid_rec\n");
	llog_records.llr.lid_hdr.lrh_len = sizeof(llog_records.llr);
	llog_records.llr.lid_tail.lrt_len = sizeof(llog_records.llr);
	llog_records.llr.lid_hdr.lrh_type = LLOG_LOGID_MAGIC;

	rc = llog_test_9_sub(env, ctxt);
	if (rc != 0) {
		CERROR("9a: llog_logid_rec test failed\n");
		GOTO(out, rc);
	}

	CWARN("9b: test llog_obd_cfg_rec\n");
	llog_records.lscr.lsc_hdr.lrh_len = sizeof(llog_records.lscr);
	llog_records.lscr.lsc_tail.lrt_len = sizeof(llog_records.lscr);
	llog_records.lscr.lsc_hdr.lrh_type = OBD_CFG_REC;

	rc = llog_test_9_sub(env, ctxt);
	if (rc != 0) {
		CERROR("9b: llog_obd_cfg_rec test failed\n");
		GOTO(out, rc);
	}

	CWARN("9c: test llog_changelog_rec\n");
	/* Direct access to cr_do_not_use: peculiar case for this test */
	llog_records.lcr.cr_hdr.lrh_len = sizeof(llog_records.lcr);
	llog_records.lcr.cr_do_not_use.lrt_len = sizeof(llog_records.lcr);
	llog_records.lcr.cr_hdr.lrh_type = CHANGELOG_REC;

	rc = llog_test_9_sub(env, ctxt);
	if (rc != 0) {
		CERROR("9c: llog_changelog_rec test failed\n");
		GOTO(out, rc);
	}

	CWARN("9d: test llog_changelog_user_rec\n");
	llog_records.lcur.cur_hdr.lrh_len = sizeof(llog_records.lcur);
	llog_records.lcur.cur_tail.lrt_len = sizeof(llog_records.lcur);
	llog_records.lcur.cur_hdr.lrh_type = CHANGELOG_USER_REC;

	rc = llog_test_9_sub(env, ctxt);
	if (rc != 0) {
		CERROR("9d: llog_changelog_user_rec test failed\n");
		GOTO(out, rc);
	}

out:
	llog_ctxt_put(ctxt);
	RETURN(rc);
}

struct llog_process_info {
	struct llog_handle *lpi_loghandle;
	llog_cb_t lpi_cb;
	void *lpi_cbdata;
	void *lpi_catdata;
	int lpi_rc;
	struct completion lpi_completion;
	const struct lu_env *lpi_env;
	struct task_struct *lpi_reftask;
};


static int llog_test_process_thread(void *arg)
{
	struct llog_process_info *lpi = arg;
	int rc;

	rc = llog_cat_process_or_fork(NULL, lpi->lpi_loghandle, lpi->lpi_cb,
				      NULL, lpi->lpi_cbdata, 1, 0, true);

	complete(&lpi->lpi_completion);

	lpi->lpi_rc = rc;
	if (rc)
		CWARN("10h: Error during catalog processing %d\n", rc);
	return rc;
}

static int cat_check_old_cb(const struct lu_env *env, struct llog_handle *llh,
			struct llog_rec_hdr *rec, void *data)
{
	struct llog_logid_rec *lir = (struct llog_logid_rec *)rec;
	struct lu_fid fid = {0};
	struct lu_fid *prev_fid = data;

	if (rec->lrh_type != LLOG_LOGID_MAGIC) {
		CERROR("invalid record in catalog\n");
		RETURN(-EINVAL);
	}

	logid_to_fid(&lir->lid_id, &fid);

	CWARN("seeing record at index %d - "DFID" in log "DFID"\n",
	      rec->lrh_index, PFID(&fid),
	      PFID(lu_object_fid(&llh->lgh_obj->do_lu)));

	if (prev_fid->f_oid > fid.f_oid) {
		CWARN("processing old record, fail\n");
		prev_fid->f_oid = 0xbad;
		RETURN(-LLOG_EEMPTY);
	}

	if (prev_fid->f_oid == 0) {
		cfs_fail_loc = OBD_FAIL_ONCE | OBD_FAIL_LLOG_PROCESS_TIMEOUT;
		cfs_fail_val = (unsigned int) (llh->lgh_id.lgl_oi.oi.oi_id &
					       0xFFFFFFFF);
		msleep(1 * MSEC_PER_SEC);
	}
	*prev_fid = fid;

	RETURN(0);
}

/* test catalog wrap around */
static int llog_test_10(const struct lu_env *env, struct obd_device *obd)
{
	struct llog_handle *cath;
	char name[10];
	int rc, rc2, i, enospc, eok;
	struct llog_mini_rec lmr;
	struct llog_ctxt *ctxt;
	struct lu_attr la;
	__u64 cat_max_size;
	struct dt_device *dt;

	ENTRY;

	ctxt = llog_get_context(obd, LLOG_TEST_ORIG_CTXT);
	LASSERT(ctxt);

	lmr.lmr_hdr.lrh_len = lmr.lmr_tail.lrt_len = LLOG_MIN_REC_SIZE;
	lmr.lmr_hdr.lrh_type = LLOG_OP_MAGIC;

	snprintf(name, sizeof(name), "%x", llog_test_rand + 2);
	CWARN("10a: create a catalog log with name: %s\n", name);
	rc = llog_open_create(env, ctxt, &cath, NULL, name);
	if (rc) {
		CERROR("10a: llog_create with name %s failed: %d\n", name, rc);
		GOTO(ctxt_release, rc);
	}
	rc = llog_init_handle(env, cath, LLOG_F_IS_CAT, &uuid);
	if (rc) {
		CERROR("10a: can't init llog handle: %d\n", rc);
		GOTO(out, rc);
	}

	cat_logid = cath->lgh_id;
	dt = lu2dt_dev(cath->lgh_obj->do_lu.lo_dev);

	/*
	 * sync device to commit all recent LLOG changes to disk and avoid
	 * to consume a huge space with delayed journal commit callbacks
	 * particularly on low memory nodes or VMs
	 */
	rc = dt_sync(env, dt);
	if (rc) {
		CERROR("10c: sync failed: %d\n", rc);
		GOTO(out, rc);
	}

	/* force catalog wrap for 5th plain LLOG */
	cfs_fail_loc = CFS_FAIL_SKIP|OBD_FAIL_CAT_RECORDS;
	cfs_fail_val = 4;

	CWARN("10b: write %d log records\n", llog_test_recnum);
	for (i = 0; i < llog_test_recnum; i++) {
		rc = llog_cat_add(env, cath, &lmr.lmr_hdr, NULL);
		if (rc) {
			CERROR("10b: write %d records failed at #%d: %d\n",
			       llog_test_recnum, i + 1, rc);
			GOTO(out, rc);
		}
	}

	/* make sure 2 new plain llog appears in catalog (+1 with hdr) */
	rc = verify_handle("10b", cath, 3);
	if (rc)
		GOTO(out, rc);

	/*
	 * sync device to commit all recent LLOG changes to disk and avoid
	 * to consume a huge space with delayed journal commit callbacks
	 * particularly on low memory nodes or VMs
	 */
	rc = dt_sync(env, dt);
	if (rc) {
		CERROR("10b: sync failed: %d\n", rc);
		GOTO(out, rc);
	}

	CWARN("10c: write %d more log records\n", 2 * llog_test_recnum);
	for (i = 0; i < 2 * llog_test_recnum; i++) {
		rc = llog_cat_add(env, cath, &lmr.lmr_hdr, NULL);
		if (rc) {
			CERROR("10c: write %d records failed at #%d: %d\n",
			       2*llog_test_recnum, i + 1, rc);
			GOTO(out, rc);
		}
	}

	/* make sure 2 new plain llog appears in catalog (+1 with hdr) */
	rc = verify_handle("10c", cath, 5);
	if (rc)
		GOTO(out, rc);

	/*
	 * sync device to commit all recent LLOG changes to disk and avoid
	 * to consume a huge space with delayed journal commit callbacks
	 * particularly on low memory nodes or VMs
	 */
	rc = dt_sync(env, dt);
	if (rc) {
		CERROR("10c: sync failed: %d\n", rc);
		GOTO(out, rc);
	}

	/*
	 * fill last allocated plain LLOG and reach -ENOSPC condition
	 * because no slot available in Catalog
	 */
	enospc = 0;
	eok = 0;
	CWARN("10c: write %d more log records\n", llog_test_recnum);
	for (i = 0; i < llog_test_recnum; i++) {
		rc = llog_cat_add(env, cath, &lmr.lmr_hdr, NULL);
		if (rc && rc != -ENOSPC) {
			CERROR("10c: write %d records failed at #%d: %d\n",
			       llog_test_recnum, i + 1, rc);
			GOTO(out, rc);
		}
		/*
		 * after last added plain LLOG has filled up, all new
		 * records add should fail with -ENOSPC
		 */
		if (rc == -ENOSPC) {
			enospc++;
		} else {
			enospc = 0;
			eok++;
		}
	}

	if ((enospc == 0) && (enospc+eok != llog_test_recnum)) {
		CERROR("10c: all last records adds should have failed with"
		       " -ENOSPC\n");
		GOTO(out, rc = -EINVAL);
	}

	CWARN("10c: wrote %d records then %d failed with ENOSPC\n", eok,
	      enospc);

	/* make sure no new record in Catalog */
	rc = verify_handle("10c", cath, 5);
	if (rc)
		GOTO(out, rc);

	/* Catalog should have reached its max size for test */
	rc = dt_attr_get(env, cath->lgh_obj, &la);
	if (rc) {
		CERROR("10c: failed to get catalog attrs: %d\n", rc);
		GOTO(out, rc);
	}
	cat_max_size = la.la_size;

	/*
	 * cancel all 1st plain llog records to empty it, this will also cause
	 * its catalog entry to be freed for next forced wrap in 10e
	 */
	CWARN("10d: Cancel %d records, see one log zapped\n", llog_test_recnum);
	cancel_count = 0;
	rc = llog_cat_process(env, cath, llog_cancel_rec_cb, "foobar", 0, 0);
	if (rc != -LLOG_EEMPTY) {
		CERROR("10d: process with llog_cancel_rec_cb failed: %d\n", rc);
		/*
		 * need to indicate error if for any reason llog_test_recnum is
		 * not reached
		 */
		if (rc == 0)
			rc = -ERANGE;
		GOTO(out, rc);
	}

	CWARN("10d: print the catalog entries.. we expect 3\n");
	cat_counter = 0;
	rc = llog_process(env, cath, cat_print_cb, "test 10", NULL);
	if (rc) {
		CERROR("10d: process with cat_print_cb failed: %d\n", rc);
		GOTO(out, rc);
	}
	if (cat_counter != 3) {
		CERROR("10d: %d entries in catalog\n", cat_counter);
		GOTO(out, rc = -EINVAL);
	}

	/* verify one down in catalog (+1 with hdr) */
	rc = verify_handle("10d", cath, 4);
	if (rc)
		GOTO(out, rc);

	/*
	 * sync device to commit all recent LLOG changes to disk and avoid
	 * to consume a huge space with delayed journal commit callbacks
	 * particularly on low memory nodes or VMs
	 */
	rc = dt_sync(env, dt);
	if (rc) {
		CERROR("10d: sync failed: %d\n", rc);
		GOTO(out, rc);
	}

	enospc = 0;
	eok = 0;
	CWARN("10e: write %d more log records\n", llog_test_recnum);
	for (i = 0; i < llog_test_recnum; i++) {
		rc = llog_cat_add(env, cath, &lmr.lmr_hdr, NULL);
		if (rc && rc != -ENOSPC) {
			CERROR("10e: write %d records failed at #%d: %d\n",
			       llog_test_recnum, i + 1, rc);
			GOTO(out, rc);
		}
		/*
		 * after last added plain LLOG has filled up, all new
		 * records add should fail with -ENOSPC
		 */
		if (rc == -ENOSPC) {
			enospc++;
		} else {
			enospc = 0;
			eok++;
		}
	}

	if ((enospc == 0) && (enospc+eok != llog_test_recnum)) {
		CERROR("10e: all last records adds should have failed with"
		       " -ENOSPC\n");
		GOTO(out, rc = -EINVAL);
	}

	CWARN("10e: wrote %d records then %d failed with ENOSPC\n", eok,
	      enospc);

	CWARN("10e: print the catalog entries.. we expect 4\n");
	cat_counter = 0;
	rc = llog_cat_process_or_fork(env, cath, cat_print_cb, NULL, "test 10",
				      0, 0, false);
	if (rc) {
		CERROR("10e: process with cat_print_cb failed: %d\n", rc);
		GOTO(out, rc);
	}
	if (cat_counter != 4) {
		CERROR("10e: %d entries in catalog\n", cat_counter);
		GOTO(out, rc = -EINVAL);
	}

	/* make sure 1 new plain llog appears in catalog (+1 with hdr) */
	rc = verify_handle("10e", cath, 5);
	if (rc)
		GOTO(out, rc);

	/* verify catalog has wrap around */
	if (cath->lgh_last_idx > cath->lgh_hdr->llh_cat_idx) {
		CERROR("10e: catalog failed to wrap around\n");
		GOTO(out, rc = -EINVAL);
	}

	rc = dt_attr_get(env, cath->lgh_obj, &la);
	if (rc) {
		CERROR("10e: failed to get catalog attrs: %d\n", rc);
		GOTO(out, rc);
	}

	if (la.la_size != cat_max_size) {
		CERROR("10e: catalog size has changed after it has wrap around,"
		       " current size = %llu, expected size = %llu\n",
		       la.la_size, cat_max_size);
		GOTO(out, rc = -EINVAL);
	}
	CWARN("10e: catalog successfully wrap around, last_idx %d, first %d\n",
	      cath->lgh_last_idx, cath->lgh_hdr->llh_cat_idx);

	/*
	 * sync device to commit all recent LLOG changes to disk and avoid
	 * to consume a huge space with delayed journal commit callbacks
	 * particularly on low memory nodes or VMs
	 */
	rc = dt_sync(env, dt);
	if (rc) {
		CERROR("10e: sync failed: %d\n", rc);
		GOTO(out, rc);
	}

	/*
	 * cancel more records to free one more slot in Catalog
	 * see if it is re-allocated when adding more records
	 */
	CWARN("10f: Cancel %d records, see one log zapped\n", llog_test_recnum);
	cancel_count = 0;
	rc = llog_cat_process(env, cath, llog_cancel_rec_cb, "foobar", 0, 0);
	if (rc != -LLOG_EEMPTY) {
		CERROR("10f: process with llog_cancel_rec_cb failed: %d\n", rc);
		/*
		 * need to indicate error if for any reason llog_test_recnum is
		 * not reached
		 */
		if (rc == 0)
			rc = -ERANGE;
		GOTO(out, rc);
	}

	CWARN("10f: print the catalog entries.. we expect 3\n");
	cat_counter = 0;
	rc = llog_cat_process_or_fork(env, cath, cat_print_cb, NULL, "test 10",
				      0, 0, false);
	if (rc) {
		CERROR("10f: process with cat_print_cb failed: %d\n", rc);
		GOTO(out, rc);
	}
	if (cat_counter != 3) {
		CERROR("10f: %d entries in catalog\n", cat_counter);
		GOTO(out, rc = -EINVAL);
	}

	/* verify one down in catalog (+1 with hdr) */
	rc = verify_handle("10f", cath, 4);
	if (rc)
		GOTO(out, rc);

	/*
	 * sync device to commit all recent LLOG changes to disk and avoid
	 * to consume a huge space with delayed journal commit callbacks
	 * particularly on low memory nodes or VMs
	 */
	rc = dt_sync(env, dt);
	if (rc) {
		CERROR("10f: sync failed: %d\n", rc);
		GOTO(out, rc);
	}

	enospc = 0;
	eok = 0;
	CWARN("10f: write %d more log records\n", llog_test_recnum);
	for (i = 0; i < llog_test_recnum; i++) {
		rc = llog_cat_add(env, cath, &lmr.lmr_hdr, NULL);
		if (rc && rc != -ENOSPC) {
			CERROR("10f: write %d records failed at #%d: %d\n",
			       llog_test_recnum, i + 1, rc);
			GOTO(out, rc);
		}
		/*
		 * after last added plain LLOG has filled up, all new
		 * records add should fail with -ENOSPC
		 */
		if (rc == -ENOSPC) {
			enospc++;
		} else {
			enospc = 0;
			eok++;
		}
	}

	if ((enospc == 0) && (enospc+eok != llog_test_recnum)) {
		CERROR("10f: all last records adds should have failed with"
		       " -ENOSPC\n");
		GOTO(out, rc = -EINVAL);
	}

	CWARN("10f: wrote %d records then %d failed with ENOSPC\n", eok,
	      enospc);

	/* make sure 1 new plain llog appears in catalog (+1 with hdr) */
	rc = verify_handle("10f", cath, 5);
	if (rc)
		GOTO(out, rc);

	/* verify lgh_last_idx = llh_cat_idx = 2 now */
	if (cath->lgh_last_idx != cath->lgh_hdr->llh_cat_idx ||
	    cath->lgh_last_idx != 2) {
		CERROR("10f: lgh_last_idx = %d vs 2, llh_cat_idx = %d vs 2\n",
		       cath->lgh_last_idx, cath->lgh_hdr->llh_cat_idx);
		GOTO(out, rc = -EINVAL);
	}

	rc = dt_attr_get(env, cath->lgh_obj, &la);
	if (rc) {
		CERROR("10f: failed to get catalog attrs: %d\n", rc);
		GOTO(out, rc);
	}

	if (la.la_size != cat_max_size) {
		CERROR("10f: catalog size has changed after it has wrap around,"
		       " current size = %llu, expected size = %llu\n",
		       la.la_size, cat_max_size);
		GOTO(out, rc = -EINVAL);
	}

	/*
	 * sync device to commit all recent LLOG changes to disk and avoid
	 * to consume a huge space with delayed journal commit callbacks
	 * particularly on low memory nodes or VMs
	 */
	rc = dt_sync(env, dt);
	if (rc) {
		CERROR("10f: sync failed: %d\n", rc);
		GOTO(out, rc);
	}

	/* will llh_cat_idx also successfully wrap ? */

	/*
	 * cancel all records in the plain LLOGs referenced by 2 last indexes in
	 * Catalog
	 */

	/* cancel more records to free one more slot in Catalog */
	CWARN("10g: Cancel %d records, see one log zapped\n", llog_test_recnum);
	cancel_count = 0;
	rc = llog_cat_process(env, cath, llog_cancel_rec_cb, "foobar", 0, 0);
	if (rc != -LLOG_EEMPTY) {
		CERROR("10g: process with llog_cancel_rec_cb failed: %d\n", rc);
		/* need to indicate error if for any reason llog_test_recnum is
		 * not reached */
		if (rc == 0)
			rc = -ERANGE;
		GOTO(out, rc);
	}

	CWARN("10g: print the catalog entries.. we expect 3\n");
	cat_counter = 0;
	rc = llog_cat_process_or_fork(env, cath, cat_print_cb, NULL, "test 10",
				      0, 0, false);
	if (rc) {
		CERROR("10g: process with cat_print_cb failed: %d\n", rc);
		GOTO(out, rc);
	}
	if (cat_counter != 3) {
		CERROR("10g: %d entries in catalog\n", cat_counter);
		GOTO(out, rc = -EINVAL);
	}

	/* verify one down in catalog (+1 with hdr) */
	rc = verify_handle("10g", cath, 4);
	if (rc)
		GOTO(out, rc);

	/*
	 * sync device to commit all recent LLOG changes to disk and avoid
	 * to consume a huge space with delayed journal commit callbacks
	 * particularly on low memory nodes or VMs
	 */
	rc = dt_sync(env, dt);
	if (rc) {
		CERROR("10g: sync failed: %d\n", rc);
		GOTO(out, rc);
	}

	/* cancel more records to free one more slot in Catalog */
	CWARN("10g: Cancel %d records, see one log zapped\n", llog_test_recnum);
	cancel_count = 0;
	rc = llog_cat_process(env, cath, llog_cancel_rec_cb, "foobar", 0, 0);
	if (rc != -LLOG_EEMPTY) {
		CERROR("10g: process with llog_cancel_rec_cb failed: %d\n", rc);
		/*
		 * need to indicate error if for any reason llog_test_recnum is
		 * not reached
		 */
		if (rc == 0)
			rc = -ERANGE;
		GOTO(out, rc);
	}

	CWARN("10g: print the catalog entries.. we expect 2\n");
	cat_counter = 0;
	rc = llog_cat_process_or_fork(env, cath, cat_print_cb, NULL, "test 10",
				      0, 0, false);
	if (rc) {
		CERROR("10g: process with cat_print_cb failed: %d\n", rc);
		GOTO(out, rc);
	}
	if (cat_counter != 2) {
		CERROR("10g: %d entries in catalog\n", cat_counter);
		GOTO(out, rc = -EINVAL);
	}

	/* verify one down in catalog (+1 with hdr) */
	rc = verify_handle("10g", cath, 3);
	if (rc)
		GOTO(out, rc);

	/* verify lgh_last_idx = 2 and llh_cat_idx = 0 now */
	if (cath->lgh_hdr->llh_cat_idx != 0 ||
	    cath->lgh_last_idx != 2) {
		CERROR("10g: lgh_last_idx = %d vs 2, llh_cat_idx = %d vs 0\n",
		       cath->lgh_last_idx, cath->lgh_hdr->llh_cat_idx);
		GOTO(out, rc = -EINVAL);
	}

	/*
	 * sync device to commit all recent LLOG changes to disk and avoid
	 * to consume a huge space with delayed journal commit callbacks
	 * particularly on low memory nodes or VMs
	 */
	rc = dt_sync(env, dt);
	if (rc) {
		CERROR("10g: sync failed: %d\n", rc);
		GOTO(out, rc);
	}

	/* cancel more records to free one more slot in Catalog */
	CWARN("10g: Cancel %d records, see one log zapped\n", llog_test_recnum);
	cancel_count = 0;
	rc = llog_cat_process(env, cath, llog_cancel_rec_cb, "foobar", 0, 0);
	if (rc != -LLOG_EEMPTY) {
		CERROR("10g: process with llog_cancel_rec_cb failed: %d\n", rc);
		/*
		 * need to indicate error if for any reason llog_test_recnum is
		 * not reached
		 */
		if (rc == 0)
			rc = -ERANGE;
		GOTO(out, rc);
	}

	CWARN("10g: print the catalog entries.. we expect 1\n");
	cat_counter = 0;
	rc = llog_cat_process_or_fork(env, cath, cat_print_cb, NULL, "test 10",
				      0, 0, false);
	if (rc) {
		CERROR("10g: process with cat_print_cb failed: %d\n", rc);
		GOTO(out, rc);
	}
	if (cat_counter != 1) {
		CERROR("10g: %d entries in catalog\n", cat_counter);
		GOTO(out, rc = -EINVAL);
	}

	/* verify one down in catalog (+1 with hdr) */
	rc = verify_handle("10g", cath, 2);
	if (rc)
		GOTO(out, rc);

	/* verify lgh_last_idx = 2 and llh_cat_idx = 1 now */
	if (cath->lgh_hdr->llh_cat_idx != 1 ||
	    cath->lgh_last_idx != 2) {
		CERROR("10g: lgh_last_idx = %d vs 2, llh_cat_idx = %d vs 1\n",
		       cath->lgh_last_idx, cath->lgh_hdr->llh_cat_idx);
		GOTO(out, rc = -EINVAL);
	}

	CWARN("10g: llh_cat_idx has also successfully wrapped!\n");

	/*
	 * catalog has only one valid entry other slots has outdated
	 * records. Trying to race the llog_thread_process with llog_add
	 * llog_thread_process read buffer and loop record on it.
	 * llog_add adds a record and mark a record in bitmap.
	 * llog_thread_process process record with old data.
	 */
	{
	struct llog_process_info lpi;
	struct lu_fid test_fid = {0};

	lpi.lpi_loghandle = cath;
	lpi.lpi_cb = cat_check_old_cb;
	lpi.lpi_catdata = NULL;
	lpi.lpi_cbdata = &test_fid;
	init_completion(&lpi.lpi_completion);

	kthread_run(llog_test_process_thread, &lpi, "llog_test_process_thread");

	msleep(1 * MSEC_PER_SEC / 2);
	enospc = 0;
	eok = 0;
	CWARN("10h: write %d more log records\n", llog_test_recnum);
	for (i = 0; i < llog_test_recnum; i++) {
		rc = llog_cat_add(env, cath, &lmr.lmr_hdr, NULL);
		if (rc && rc != -ENOSPC) {
			CERROR("10h: write %d records failed at #%d: %d\n",
			       llog_test_recnum, i + 1, rc);
			GOTO(out, rc);
		}
		/*
		 * after last added plain LLOG has filled up, all new
		 * records add should fail with -ENOSPC
		 */
		if (rc == -ENOSPC) {
			enospc++;
		} else {
			enospc = 0;
			eok++;
		}
	}

	if ((enospc == 0) && (enospc+eok != llog_test_recnum)) {
		CERROR("10h: all last records adds should have failed with"
		       " -ENOSPC\n");
		GOTO(out, rc = -EINVAL);
	}

	CWARN("10h: wrote %d records then %d failed with ENOSPC\n", eok,
	      enospc);

	wait_for_completion(&lpi.lpi_completion);

	if (lpi.lpi_rc != 0) {
		CERROR("10h: race happened, old record was processed\n");
		GOTO(out, rc = -EINVAL);
	}
	}
out:
	cfs_fail_loc = 0;
	cfs_fail_val = 0;

	CWARN("10: put newly-created catalog\n");
	rc2 = llog_cat_close(env, cath);
	if (rc2) {
		CERROR("10: close log %s failed: %d\n", name, rc2);
		if (rc == 0)
			rc = rc2;
	}
ctxt_release:
	llog_ctxt_put(ctxt);
	RETURN(rc);
}

/*
 * -------------------------------------------------------------------------
 * Tests above, boring obd functions below
 * -------------------------------------------------------------------------
 */
static int llog_run_tests(const struct lu_env *env, struct obd_device *obd)
{
	struct llog_handle *llh = NULL;
	struct llog_ctxt *ctxt;
	int rc, err;
	char name[10];

	ENTRY;
	ctxt = llog_get_context(obd, LLOG_TEST_ORIG_CTXT);
	LASSERT(ctxt);

	sprintf(name, "%x", llog_test_rand);

	rc = llog_test_1(env, obd, name);
	if (rc)
		GOTO(cleanup_ctxt, rc);

	rc = llog_test_2(env, obd, name, &llh);
	if (rc)
		GOTO(cleanup_ctxt, rc);

	rc = llog_test_3(env, obd, llh);
	if (rc)
		GOTO(cleanup, rc);

	rc = llog_test_4(env, obd);
	if (rc)
		GOTO(cleanup, rc);

	rc = llog_test_5(env, obd);
	if (rc)
		GOTO(cleanup, rc);

	rc = llog_test_6(env, obd, name);
	if (rc)
		GOTO(cleanup, rc);

	rc = llog_test_7(env, obd);
	if (rc)
		GOTO(cleanup, rc);

	rc = llog_test_8(env, obd);
	if (rc)
		GOTO(cleanup, rc);

	rc = llog_test_9(env, obd);
	if (rc != 0)
		GOTO(cleanup, rc);

	rc = llog_test_10(env, obd);
	if (rc)
		GOTO(cleanup, rc);

cleanup:
	err = llog_destroy(env, llh);
	if (err)
		CERROR("cleanup: llog_destroy failed: %d\n", err);
	llog_close(env, llh);
	if (rc == 0)
		rc = err;
cleanup_ctxt:
	llog_ctxt_put(ctxt);
	return rc;
}

static int llog_test_cleanup(struct obd_device *obd)
{
	struct obd_device *tgt;
	struct lu_env env;
	int rc;

	ENTRY;

	rc = lu_env_init(&env, LCT_LOCAL | LCT_MG_THREAD);
	if (rc)
		RETURN(rc);

	tgt = obd->obd_lvfs_ctxt.dt->dd_lu_dev.ld_obd;
	rc = llog_cleanup(&env, llog_get_context(tgt, LLOG_TEST_ORIG_CTXT));
	if (rc)
		CERROR("failed to llog_test_llog_finish: %d\n", rc);
	lu_env_fini(&env);
	RETURN(rc);
}

static int llog_test_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
	struct obd_device *tgt;
	struct llog_ctxt *ctxt;
	struct dt_object *o;
	struct lu_env env;
	struct lu_context test_session;
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

	rc = lu_env_init(&env, LCT_LOCAL | LCT_MG_THREAD);
	if (rc)
		RETURN(rc);

	rc = lu_context_init(&test_session, LCT_SERVER_SESSION);
	if (rc)
		GOTO(cleanup_env, rc);
	test_session.lc_thread = (struct ptlrpc_thread *)current;
	lu_context_enter(&test_session);
	env.le_ses = &test_session;

	CWARN("Setup llog-test device over %s device\n",
	      lustre_cfg_string(lcfg, 1));

	OBD_SET_CTXT_MAGIC(&obd->obd_lvfs_ctxt);
	obd->obd_lvfs_ctxt.dt = lu2dt_dev(tgt->obd_lu_dev);

	rc = llog_setup(&env, tgt, &tgt->obd_olg, LLOG_TEST_ORIG_CTXT, tgt,
			&llog_osd_ops);
	if (rc)
		GOTO(cleanup_session, rc);

	/* use MGS llog dir for tests */
	ctxt = llog_get_context(tgt, LLOG_CONFIG_ORIG_CTXT);
	LASSERT(ctxt);
	o = ctxt->loc_dir;
	llog_ctxt_put(ctxt);

	ctxt = llog_get_context(tgt, LLOG_TEST_ORIG_CTXT);
	LASSERT(ctxt);
	ctxt->loc_dir = o;
	llog_ctxt_put(ctxt);

	llog_test_rand = cfs_rand();

	rc = llog_run_tests(&env, tgt);
	if (rc)
		llog_test_cleanup(obd);
cleanup_session:
	lu_context_exit(&test_session);
	lu_context_fini(&test_session);
cleanup_env:
	lu_env_fini(&env);
	RETURN(rc);
}

static struct obd_ops llog_obd_ops = {
	.o_owner       = THIS_MODULE,
	.o_setup       = llog_test_setup,
	.o_cleanup     = llog_test_cleanup,
};

static int __init llog_test_init(void)
{
	return class_register_type(&llog_obd_ops, NULL, false, NULL,
				   "llog_test", NULL);
}

static void __exit llog_test_exit(void)
{
	class_unregister_type("llog_test");
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Log test module");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(llog_test_init);
module_exit(llog_test_exit);
