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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/selftest/brw_test.c
 *
 * Author: Isaac Huang <isaac@clusterfs.com>
 */

#include "selftest.h"


extern int brw_inject_errors;

static void
brw_client_fini (sfw_test_instance_t *tsi)
{
        srpc_bulk_t     *bulk;
        sfw_test_unit_t *tsu;

        LASSERT (tsi->tsi_is_client);

        cfs_list_for_each_entry_typed (tsu, &tsi->tsi_units,
                                       sfw_test_unit_t, tsu_list) {
                bulk = tsu->tsu_private;
                if (bulk == NULL) continue;

                srpc_free_bulk(bulk);
                tsu->tsu_private = NULL;
        }
}

int
brw_client_init (sfw_test_instance_t *tsi)
{
        test_bulk_req_t  *breq = &tsi->tsi_u.bulk;
        int               flags = breq->blk_flags;
        int               npg = breq->blk_npg;
        srpc_bulk_t      *bulk;
        sfw_test_unit_t  *tsu;

        LASSERT (tsi->tsi_is_client);

        if (npg > LNET_MAX_IOV || npg <= 0)
                return -EINVAL;

        if (breq->blk_opc != LST_BRW_READ && breq->blk_opc != LST_BRW_WRITE)
                return -EINVAL;

        if (flags != LST_BRW_CHECK_NONE &&
            flags != LST_BRW_CHECK_FULL && flags != LST_BRW_CHECK_SIMPLE)
                return -EINVAL;

        cfs_list_for_each_entry_typed (tsu, &tsi->tsi_units,
                                       sfw_test_unit_t, tsu_list) {
                bulk = srpc_alloc_bulk(npg, breq->blk_opc == LST_BRW_READ);
                if (bulk == NULL) {
                        brw_client_fini(tsi);
                        return -ENOMEM;
                }

                tsu->tsu_private = bulk;
        }

        return 0;
}

#define BRW_POISON      0xbeefbeefbeefbeefULL
#define BRW_MAGIC       0xeeb0eeb1eeb2eeb3ULL
#define BRW_MSIZE       sizeof(__u64)

int
brw_inject_one_error (void)
{
        struct timeval tv;

        if (brw_inject_errors <= 0) return 0;

#ifndef __KERNEL__
        gettimeofday(&tv, NULL);
#else
        cfs_gettimeofday(&tv);
#endif

        if ((tv.tv_usec & 1) == 0) return 0;

        return brw_inject_errors--;
}

void
brw_fill_page (cfs_page_t *pg, int pattern, __u64 magic)
{
        char *addr = cfs_page_address(pg);
        int   i;

        LASSERT (addr != NULL);

        if (pattern == LST_BRW_CHECK_NONE) return;

        if (magic == BRW_MAGIC)
                magic += brw_inject_one_error();

        if (pattern == LST_BRW_CHECK_SIMPLE) {
                memcpy(addr, &magic, BRW_MSIZE);
                addr += CFS_PAGE_SIZE - BRW_MSIZE;
                memcpy(addr, &magic, BRW_MSIZE);
                return;
        }

        if (pattern == LST_BRW_CHECK_FULL) {
                for (i = 0; i < CFS_PAGE_SIZE / BRW_MSIZE; i++)
                        memcpy(addr + i * BRW_MSIZE, &magic, BRW_MSIZE);
                return;
        }

        LBUG ();
        return;
}

int
brw_check_page (cfs_page_t *pg, int pattern, __u64 magic)
{
        char  *addr = cfs_page_address(pg);
        __u64  data = 0; /* make compiler happy */
        int    i;

        LASSERT (addr != NULL);

        if (pattern == LST_BRW_CHECK_NONE)
                return 0;

        if (pattern == LST_BRW_CHECK_SIMPLE) {
                data = *((__u64 *) addr);
                if (data != magic) goto bad_data;

                addr += CFS_PAGE_SIZE - BRW_MSIZE;
                data = *((__u64 *) addr);
                if (data != magic) goto bad_data;

                return 0;
        }

        if (pattern == LST_BRW_CHECK_FULL) {
                for (i = 0; i < CFS_PAGE_SIZE / BRW_MSIZE; i++) {
                        data = *(((__u64 *) addr) + i);
                        if (data != magic) goto bad_data;
                }

                return 0;
        }

        LBUG ();

bad_data:
        CERROR ("Bad data in page %p: "LPX64", "LPX64" expected\n",
                pg, data, magic);
        return 1;
}

void
brw_fill_bulk (srpc_bulk_t *bk, int pattern, __u64 magic)
{
        int         i;
        cfs_page_t *pg;

        for (i = 0; i < bk->bk_niov; i++) {
#ifdef __KERNEL__
                pg = bk->bk_iovs[i].kiov_page;
#else
                LASSERT (bk->bk_pages != NULL);
                pg = bk->bk_pages[i];
#endif
                brw_fill_page(pg, pattern, magic);
        }
}

int
brw_check_bulk (srpc_bulk_t *bk, int pattern, __u64 magic)
{
        int         i;
        cfs_page_t *pg;

        for (i = 0; i < bk->bk_niov; i++) {
#ifdef __KERNEL__
                pg = bk->bk_iovs[i].kiov_page;
#else
                LASSERT (bk->bk_pages != NULL);
                pg = bk->bk_pages[i];
#endif
                if (brw_check_page(pg, pattern, magic) != 0) {
                        CERROR ("Bulk page %p (%d/%d) is corrupted!\n",
                                pg, i, bk->bk_niov);
                        return 1;
                }
        }

        return 0;
}

static int
brw_client_prep_rpc (sfw_test_unit_t *tsu,
                     lnet_process_id_t dest, srpc_client_rpc_t **rpcpp)
{
        srpc_bulk_t         *bulk = tsu->tsu_private;
        sfw_test_instance_t *tsi = tsu->tsu_instance;
        test_bulk_req_t     *breq = &tsi->tsi_u.bulk;
        int                  npg = breq->blk_npg;
        int                  flags = breq->blk_flags;
        srpc_client_rpc_t   *rpc;
        srpc_brw_reqst_t    *req;
        int                  rc;

        LASSERT (bulk != NULL);
        LASSERT (bulk->bk_niov == npg);

        rc = sfw_create_test_rpc(tsu, dest, npg, npg * CFS_PAGE_SIZE, &rpc);
        if (rc != 0) return rc;

        memcpy(&rpc->crpc_bulk, bulk, offsetof(srpc_bulk_t, bk_iovs[npg]));
        if (breq->blk_opc == LST_BRW_WRITE)
                brw_fill_bulk(&rpc->crpc_bulk, flags, BRW_MAGIC);
        else
                brw_fill_bulk(&rpc->crpc_bulk, flags, BRW_POISON);

        req = &rpc->crpc_reqstmsg.msg_body.brw_reqst;
        req->brw_flags = flags;
        req->brw_rw    = breq->blk_opc;
        req->brw_len   = npg * CFS_PAGE_SIZE;

        *rpcpp = rpc;
        return 0;
}

static void
brw_client_done_rpc (sfw_test_unit_t *tsu, srpc_client_rpc_t *rpc)
{
        __u64                magic = BRW_MAGIC;
        sfw_test_instance_t *tsi = tsu->tsu_instance;
        sfw_session_t       *sn = tsi->tsi_batch->bat_session;
        srpc_msg_t          *msg = &rpc->crpc_replymsg;
        srpc_brw_reply_t    *reply = &msg->msg_body.brw_reply;
        srpc_brw_reqst_t    *reqst = &rpc->crpc_reqstmsg.msg_body.brw_reqst;

        LASSERT (sn != NULL);

        if (rpc->crpc_status != 0) {
                CERROR ("BRW RPC to %s failed with %d\n",
                        libcfs_id2str(rpc->crpc_dest), rpc->crpc_status);
                if (!tsi->tsi_stopping) /* rpc could have been aborted */
                        cfs_atomic_inc(&sn->sn_brw_errors);
                goto out;
        }

        if (msg->msg_magic != SRPC_MSG_MAGIC) {
                __swab64s(&magic);
                __swab32s(&reply->brw_status);
        }

        CDEBUG (reply->brw_status ? D_WARNING : D_NET,
                "BRW RPC to %s finished with brw_status: %d\n",
                libcfs_id2str(rpc->crpc_dest), reply->brw_status);

        if (reply->brw_status != 0) {
                cfs_atomic_inc(&sn->sn_brw_errors);
                rpc->crpc_status = -(int)reply->brw_status;
                goto out;
        }

        if (reqst->brw_rw == LST_BRW_WRITE) goto out;

        if (brw_check_bulk(&rpc->crpc_bulk, reqst->brw_flags, magic) != 0) {
                CERROR ("Bulk data from %s is corrupted!\n",
                        libcfs_id2str(rpc->crpc_dest));
                cfs_atomic_inc(&sn->sn_brw_errors);
                rpc->crpc_status = -EBADMSG;
        }

out:
#ifndef __KERNEL__
        rpc->crpc_bulk.bk_pages = NULL;
#endif
        return;
}

void
brw_server_rpc_done (srpc_server_rpc_t *rpc)
{
        srpc_bulk_t *blk = rpc->srpc_bulk;

        if (blk == NULL) return;

        if (rpc->srpc_status != 0)
                CERROR ("Bulk transfer %s %s has failed: %d\n",
                        blk->bk_sink ? "from" : "to",
                        libcfs_id2str(rpc->srpc_peer), rpc->srpc_status);
        else
                CDEBUG (D_NET, "Transfered %d pages bulk data %s %s\n",
                        blk->bk_niov, blk->bk_sink ? "from" : "to",
                        libcfs_id2str(rpc->srpc_peer));

        sfw_free_pages(rpc);
}

int
brw_bulk_ready (srpc_server_rpc_t *rpc, int status)
{
        __u64             magic = BRW_MAGIC;
        srpc_brw_reply_t *reply = &rpc->srpc_replymsg.msg_body.brw_reply;
        srpc_brw_reqst_t *reqst;
        srpc_msg_t       *reqstmsg;

        LASSERT (rpc->srpc_bulk != NULL);
        LASSERT (rpc->srpc_reqstbuf != NULL);

        reqstmsg = &rpc->srpc_reqstbuf->buf_msg;
        reqst = &reqstmsg->msg_body.brw_reqst;

        if (status != 0) {
                CERROR ("BRW bulk %s failed for RPC from %s: %d\n",
                        reqst->brw_rw == LST_BRW_READ ? "READ" : "WRITE",
                        libcfs_id2str(rpc->srpc_peer), status);
                return -EIO;
        }

        if (reqst->brw_rw == LST_BRW_READ)
                return 0;

        if (reqstmsg->msg_magic != SRPC_MSG_MAGIC)
                __swab64s(&magic);

        if (brw_check_bulk(rpc->srpc_bulk, reqst->brw_flags, magic) != 0) {
                CERROR ("Bulk data from %s is corrupted!\n",
                        libcfs_id2str(rpc->srpc_peer));
                reply->brw_status = EBADMSG;
        }

        return 0;
}

int
brw_server_handle (srpc_server_rpc_t *rpc)
{
        srpc_service_t   *sv = rpc->srpc_service;
        srpc_msg_t       *replymsg = &rpc->srpc_replymsg;
        srpc_msg_t       *reqstmsg = &rpc->srpc_reqstbuf->buf_msg;
        srpc_brw_reply_t *reply = &replymsg->msg_body.brw_reply;
        srpc_brw_reqst_t *reqst = &reqstmsg->msg_body.brw_reqst;
        int               rc;

        LASSERT (sv->sv_id == SRPC_SERVICE_BRW);

        if (reqstmsg->msg_magic != SRPC_MSG_MAGIC) {
                LASSERT (reqstmsg->msg_magic == __swab32(SRPC_MSG_MAGIC));

                __swab32s(&reqstmsg->msg_type);
                __swab32s(&reqst->brw_rw);
                __swab32s(&reqst->brw_len);
                __swab32s(&reqst->brw_flags);
                __swab64s(&reqst->brw_rpyid);
                __swab64s(&reqst->brw_bulkid);
        }
        LASSERT (reqstmsg->msg_type == (__u32)srpc_service2request(sv->sv_id));

        rpc->srpc_done = brw_server_rpc_done;

        if ((reqst->brw_rw != LST_BRW_READ && reqst->brw_rw != LST_BRW_WRITE) ||
            reqst->brw_len == 0 || (reqst->brw_len & ~CFS_PAGE_MASK) != 0 ||
            reqst->brw_len / CFS_PAGE_SIZE > LNET_MAX_IOV ||
            (reqst->brw_flags != LST_BRW_CHECK_NONE &&
             reqst->brw_flags != LST_BRW_CHECK_FULL &&
             reqst->brw_flags != LST_BRW_CHECK_SIMPLE)) {
                reply->brw_status = EINVAL;
                return 0;
        }

        reply->brw_status = 0;
        rc = sfw_alloc_pages(rpc, reqst->brw_len / CFS_PAGE_SIZE,
                             reqst->brw_rw == LST_BRW_WRITE);
        if (rc != 0) return rc;

        if (reqst->brw_rw == LST_BRW_READ)
                brw_fill_bulk(rpc->srpc_bulk, reqst->brw_flags, BRW_MAGIC);
        else
                brw_fill_bulk(rpc->srpc_bulk, reqst->brw_flags, BRW_POISON);

        return 0;
}

sfw_test_client_ops_t brw_test_client;
void brw_init_test_client(void)
{
        brw_test_client.tso_init       = brw_client_init;
        brw_test_client.tso_fini       = brw_client_fini;
        brw_test_client.tso_prep_rpc   = brw_client_prep_rpc;
        brw_test_client.tso_done_rpc   = brw_client_done_rpc;
};

srpc_service_t brw_test_service;
void brw_init_test_service(void)
{
        brw_test_service.sv_id         = SRPC_SERVICE_BRW;
        brw_test_service.sv_name       = "brw_test";
        brw_test_service.sv_handler    = brw_server_handle;
        brw_test_service.sv_bulk_ready = brw_bulk_ready;
}
