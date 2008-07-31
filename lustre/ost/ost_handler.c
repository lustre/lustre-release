/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ost/ost_handler.c
 *
 * Author: Peter J. Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_OST

#include <linux/module.h>
#include <obd_ost.h>
#include <lustre_net.h>
#include <lustre_dlm.h>
#include <lustre_export.h>
#include <lustre_debug.h>
#include <linux/init.h>
#include <lprocfs_status.h>
#include <lustre_commit_confd.h>
#include <libcfs/list.h>
#include <lustre_quota.h>
#include "ost_internal.h"

static int oss_num_threads;
CFS_MODULE_PARM(oss_num_threads, "i", int, 0444,
                "number of OSS service threads to start");

static int ost_num_threads;
CFS_MODULE_PARM(ost_num_threads, "i", int, 0444,
                "number of OST service threads to start (deprecated)");

static int oss_num_create_threads;
CFS_MODULE_PARM(oss_num_create_threads, "i", int, 0444,
                "number of OSS create threads to start");

void oti_to_request(struct obd_trans_info *oti, struct ptlrpc_request *req)
{
        struct oti_req_ack_lock *ack_lock;
        int i;

        if (oti == NULL)
                return;

        if (req->rq_repmsg) {
                __u64 versions[PTLRPC_NUM_VERSIONS] = { 0 };
                lustre_msg_set_transno(req->rq_repmsg, oti->oti_transno);
                versions[0] = oti->oti_pre_version;
                lustre_msg_set_versions(req->rq_repmsg, versions);
        }
        req->rq_transno = oti->oti_transno;

        /* XXX 4 == entries in oti_ack_locks??? */
        for (ack_lock = oti->oti_ack_locks, i = 0; i < 4; i++, ack_lock++) {
                if (!ack_lock->mode)
                        break;
                /* XXX not even calling target_send_reply in some cases... */
                ptlrpc_save_lock (req, &ack_lock->lock, ack_lock->mode);
        }
}

static int ost_destroy(struct obd_export *exp, struct ptlrpc_request *req,
                       struct obd_trans_info *oti)
{
        struct ost_body *body, *repbody;
        __u32 size[2] = { sizeof(struct ptlrpc_body), sizeof(*body) };
        int rc;
        ENTRY;

        body = lustre_swab_reqbuf(req, REQ_REC_OFF, sizeof(*body),
                                  lustre_swab_ost_body);
        if (body == NULL)
                RETURN(-EFAULT);

        if (body->oa.o_id == 0)
                RETURN(-EPROTO);

        if (lustre_msg_buflen(req->rq_reqmsg, REQ_REC_OFF + 1)) {
                struct ldlm_request *dlm;
                dlm = lustre_swab_reqbuf(req, REQ_REC_OFF + 1, sizeof(*dlm),
                                         lustre_swab_ldlm_request);
                if (dlm == NULL)
                        RETURN (-EFAULT);
                ldlm_request_cancel(req, dlm, 0);
        }

        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc)
                RETURN(rc);

        if (body->oa.o_valid & OBD_MD_FLCOOKIE)
                oti->oti_logcookies = &body->oa.o_lcookie;
        repbody = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                                 sizeof(*repbody));
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        req->rq_status = obd_destroy(exp, &body->oa, NULL, oti, NULL);
        RETURN(0);
}

static int ost_getattr(struct obd_export *exp, struct ptlrpc_request *req)
{
        struct ost_body *body, *repbody;
        struct obd_info oinfo = { { { 0 } } };
        __u32 size[2] = { sizeof(struct ptlrpc_body), sizeof(*body) };
        int rc;
        ENTRY;

        body = lustre_swab_reqbuf(req, REQ_REC_OFF, sizeof(*body),
                                  lustre_swab_ost_body);
        if (body == NULL)
                RETURN(-EFAULT);

        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                                 sizeof(*repbody));
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));

        oinfo.oi_oa = &repbody->oa;
        req->rq_status = obd_getattr(exp, &oinfo);
        RETURN(0);
}

static int ost_statfs(struct ptlrpc_request *req)
{
        struct obd_statfs *osfs;
        __u32 size[2] = { sizeof(struct ptlrpc_body), sizeof(*osfs) };
        int rc;
        ENTRY;

        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc)
                RETURN(rc);

        osfs = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF, sizeof(*osfs));

        req->rq_status = obd_statfs(req->rq_export->exp_obd, osfs, 
                                    cfs_time_current_64() - HZ, 0);
        if (OBD_FAIL_CHECK_ONCE(OBD_FAIL_OST_ENOSPC))
                osfs->os_bfree = osfs->os_bavail = 64;
        if (req->rq_status != 0)
                CERROR("ost: statfs failed: rc %d\n", req->rq_status);

        RETURN(0);
}

static int ost_create(struct obd_export *exp, struct ptlrpc_request *req,
                      struct obd_trans_info *oti)
{
        struct ost_body *body, *repbody;
        __u32 size[2] = { sizeof(struct ptlrpc_body), sizeof(*repbody) };
        int rc;
        ENTRY;

        body = lustre_swab_reqbuf(req, REQ_REC_OFF, sizeof(*body),
                                  lustre_swab_ost_body);
        if (body == NULL)
                RETURN(-EFAULT);

        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                                 sizeof(*repbody));
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        oti->oti_logcookies = &repbody->oa.o_lcookie;
        req->rq_status = obd_create(exp, &repbody->oa, NULL, oti);
        //obd_log_cancel(conn, NULL, 1, oti->oti_logcookies, 0);
        RETURN(0);
}

/*
 * Helper function for ost_punch(): if asked by client, acquire [size, EOF]
 * lock on the file being truncated.
 */
static int ost_punch_lock_get(struct obd_export *exp, struct obdo *oa,
                              struct lustre_handle *lh)
{
        int flags;
        struct ldlm_res_id res_id = { .name = { oa->o_id } };
        ldlm_policy_data_t policy;
        __u64 start;
        __u64 finis;

        ENTRY;

        LASSERT(!lustre_handle_is_used(lh));

        if (!(oa->o_valid & OBD_MD_FLFLAGS) ||
            !(oa->o_flags & OBD_FL_TRUNCLOCK))
                RETURN(0);

        CDEBUG(D_INODE, "OST-side truncate lock.\n");

        start = oa->o_size;
        finis = start + oa->o_blocks;

        /*
         * standard truncate optimization: if file body is completely
         * destroyed, don't send data back to the server.
         */
        flags = (start == 0) ? LDLM_AST_DISCARD_DATA : 0;

        policy.l_extent.start = start & CFS_PAGE_MASK;

        /*
         * If ->o_blocks is EOF it means "lock till the end of the
         * file". Otherwise, it's size of a hole being punched (in bytes)
         */
        if (oa->o_blocks == OBD_OBJECT_EOF || finis < start)
                policy.l_extent.end = OBD_OBJECT_EOF;
        else
                policy.l_extent.end = finis | ~CFS_PAGE_MASK;

        RETURN(ldlm_cli_enqueue_local(exp->exp_obd->obd_namespace, &res_id, 
                                      LDLM_EXTENT, &policy, LCK_PW, &flags,
                                      ldlm_blocking_ast, ldlm_completion_ast,
                                      ldlm_glimpse_ast, NULL, 0, NULL, lh));
}

/*
 * Helper function for ost_punch(): release lock acquired by
 * ost_punch_lock_get(), if any.
 */
static void ost_punch_lock_put(struct obd_export *exp, struct obdo *oa,
                               struct lustre_handle *lh)
{
        ENTRY;
        if (lustre_handle_is_used(lh))
                ldlm_lock_decref(lh, LCK_PW);
        EXIT;
}

static int ost_punch(struct obd_export *exp, struct ptlrpc_request *req,
                     struct obd_trans_info *oti)
{
        struct obd_info oinfo = { { { 0 } } };
        struct ost_body *body, *repbody;
        __u32 size[2] = { sizeof(struct ptlrpc_body), sizeof(*repbody) };
        int rc;
        struct lustre_handle lh = {0,};
        ENTRY;

        /* check that we do support OBD_CONNECT_TRUNCLOCK. */
        CLASSERT(OST_CONNECT_SUPPORTED & OBD_CONNECT_TRUNCLOCK);

        body = lustre_swab_reqbuf(req, REQ_REC_OFF, sizeof(*body),
                                  lustre_swab_ost_body);
        if (body == NULL)
                RETURN(-EFAULT);

        oinfo.oi_oa = &body->oa;
        oinfo.oi_policy.l_extent.start = oinfo.oi_oa->o_size;
        oinfo.oi_policy.l_extent.end = oinfo.oi_oa->o_blocks;

        if ((oinfo.oi_oa->o_valid & (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS)) !=
            (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS))
                RETURN(-EINVAL);

        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                                 sizeof(*repbody));
        rc = ost_punch_lock_get(exp, oinfo.oi_oa, &lh);
        if (rc == 0) {
                if (oinfo.oi_oa->o_valid & OBD_MD_FLFLAGS &&
                    oinfo.oi_oa->o_flags == OBD_FL_TRUNCLOCK)
                        /*
                         * If OBD_FL_TRUNCLOCK is the only bit set in
                         * ->o_flags, clear OBD_MD_FLFLAGS to avoid falling
                         * through filter_setattr() to filter_iocontrol().
                         */
                        oinfo.oi_oa->o_valid &= ~OBD_MD_FLFLAGS;

                req->rq_status = obd_punch(exp, &oinfo, oti, NULL);
                ost_punch_lock_put(exp, oinfo.oi_oa, &lh);
        }
        repbody->oa = *oinfo.oi_oa;
        RETURN(rc);
}

static int ost_sync(struct obd_export *exp, struct ptlrpc_request *req)
{
        struct ost_body *body, *repbody;
        __u32 size[2] = { sizeof(struct ptlrpc_body), sizeof(*repbody) };
        int rc;
        ENTRY;

        body = lustre_swab_reqbuf(req, REQ_REC_OFF, sizeof(*body),
                                  lustre_swab_ost_body);
        if (body == NULL)
                RETURN(-EFAULT);

        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                                 sizeof(*repbody));
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        req->rq_status = obd_sync(exp, &repbody->oa, NULL, repbody->oa.o_size,
                                  repbody->oa.o_blocks);
        RETURN(0);
}

static int ost_setattr(struct obd_export *exp, struct ptlrpc_request *req,
                       struct obd_trans_info *oti)
{
        struct ost_body *body, *repbody;
        __u32 size[2] = { sizeof(struct ptlrpc_body), sizeof(*repbody) };
        int rc;
        struct obd_info oinfo = { { { 0 } } };
        ENTRY;

        body = lustre_swab_reqbuf(req, REQ_REC_OFF, sizeof(*body),
                                  lustre_swab_ost_body);
        if (body == NULL)
                RETURN(-EFAULT);

        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                                 sizeof(*repbody));
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));

        oinfo.oi_oa = &repbody->oa;
        req->rq_status = obd_setattr(exp, &oinfo, oti);
        RETURN(0);
}

static int ost_bulk_timeout(void *data)
{
        ENTRY;
        /* We don't fail the connection here, because having the export
         * killed makes the (vital) call to commitrw very sad.
         */
        RETURN(1);
}

static int get_per_page_niobufs(struct obd_ioobj *ioo, int nioo,
                                struct niobuf_remote *rnb, int nrnb,
                                struct niobuf_remote **pp_rnbp)
{
        /* Copy a remote niobuf, splitting it into page-sized chunks
         * and setting ioo[i].ioo_bufcnt accordingly */
        struct niobuf_remote *pp_rnb;
        int   i;
        int   j;
        int   page;
        int   rnbidx = 0;
        int   npages = 0;

        /*
         * array of sufficient size already preallocated by caller
         */
        LASSERT(pp_rnbp != NULL);
        LASSERT(*pp_rnbp != NULL);

        /* first count and check the number of pages required */
        for (i = 0; i < nioo; i++)
                for (j = 0; j < ioo->ioo_bufcnt; j++, rnbidx++) {
                        obd_off offset = rnb[rnbidx].offset;
                        obd_off p0 = offset >> CFS_PAGE_SHIFT;
                        obd_off pn = (offset + rnb[rnbidx].len - 1)>>CFS_PAGE_SHIFT;

                        LASSERT(rnbidx < nrnb);

                        npages += (pn + 1 - p0);

                        if (rnb[rnbidx].len == 0) {
                                CERROR("zero len BRW: obj %d objid "LPX64
                                       " buf %u\n", i, ioo[i].ioo_id, j);
                                return -EINVAL;
                        }
                        if (j > 0 &&
                            rnb[rnbidx].offset <= rnb[rnbidx-1].offset) {
                                CERROR("unordered BRW: obj %d objid "LPX64
                                       " buf %u offset "LPX64" <= "LPX64"\n",
                                       i, ioo[i].ioo_id, j, rnb[rnbidx].offset,
                                       rnb[rnbidx].offset);
                                return -EINVAL;
                        }
                }

        LASSERT(rnbidx == nrnb);

        if (npages == nrnb) {       /* all niobufs are for single pages */
                *pp_rnbp = rnb;
                return npages;
        }

        pp_rnb = *pp_rnbp;

        /* now do the actual split */
        page = rnbidx = 0;
        for (i = 0; i < nioo; i++) {
                int  obj_pages = 0;

                for (j = 0; j < ioo[i].ioo_bufcnt; j++, rnbidx++) {
                        obd_off off = rnb[rnbidx].offset;
                        int     nob = rnb[rnbidx].len;

                        LASSERT(rnbidx < nrnb);
                        do {
                                obd_off  poff = off & ~CFS_PAGE_MASK;
                                int      pnob = (poff + nob > CFS_PAGE_SIZE) ?
                                                CFS_PAGE_SIZE - poff : nob;

                                LASSERT(page < npages);
                                pp_rnb[page].len = pnob;
                                pp_rnb[page].offset = off;
                                pp_rnb[page].flags = rnb[rnbidx].flags;

                                CDEBUG(0, "   obj %d id "LPX64
                                       "page %d(%d) "LPX64" for %d, flg %x\n",
                                       i, ioo[i].ioo_id, obj_pages, page,
                                       pp_rnb[page].offset, pp_rnb[page].len,
                                       pp_rnb[page].flags);
                                page++;
                                obj_pages++;

                                off += pnob;
                                nob -= pnob;
                        } while (nob > 0);
                        LASSERT(nob == 0);
                }
                ioo[i].ioo_bufcnt = obj_pages;
        }
        LASSERT(page == npages);

        return npages;
}

static __u32 ost_checksum_bulk(struct ptlrpc_bulk_desc *desc, int opc,
                               cksum_type_t cksum_type)
{
        __u32 cksum;
        int i;

        cksum = init_checksum(cksum_type);
        for (i = 0; i < desc->bd_iov_count; i++) {
                struct page *page = desc->bd_iov[i].kiov_page;
                int off = desc->bd_iov[i].kiov_offset & ~CFS_PAGE_MASK;
                char *ptr = kmap(page) + off;
                int len = desc->bd_iov[i].kiov_len;

                /* corrupt the data before we compute the checksum, to
                 * simulate a client->OST data error */
                if (i == 0 && opc == OST_WRITE &&
                    OBD_FAIL_CHECK_ONCE(OBD_FAIL_OST_CHECKSUM_RECEIVE))
                        memcpy(ptr, "bad3", min(4, len));
                cksum = compute_checksum(cksum, ptr, len, cksum_type);
                /* corrupt the data after we compute the checksum, to
                 * simulate an OST->client data error */
                if (i == 0 && opc == OST_READ &&
                    OBD_FAIL_CHECK_ONCE(OBD_FAIL_OST_CHECKSUM_SEND))
                        memcpy(ptr, "bad4", min(4, len));
                kunmap(page);
        }

        return cksum;
}

/*
 * populate @nio by @nrpages pages from per-thread page pool
 */
static void ost_nio_pages_get(struct ptlrpc_request *req,
                              struct niobuf_local *nio, int nrpages)
{
        int i;
        struct ost_thread_local_cache *tls;

        ENTRY;

        LASSERT(nrpages <= OST_THREAD_POOL_SIZE);
        LASSERT(req != NULL);
        LASSERT(req->rq_svc_thread != NULL);

        tls = ost_tls(req);
        LASSERT(tls != NULL);

        memset(nio, 0, nrpages * sizeof *nio);
        for (i = 0; i < nrpages; ++ i) {
                struct page *page;

                page = tls->page[i];
                LASSERT(page != NULL);
                POISON_PAGE(page, 0xf1);
                nio[i].page = page;
                LL_CDEBUG_PAGE(D_INFO, page, "%d\n", i);
        }
        EXIT;
}

/*
 * Dual for ost_nio_pages_get(). Poison pages in pool for debugging
 */
static void ost_nio_pages_put(struct ptlrpc_request *req,
                              struct niobuf_local *nio, int nrpages)
{
        int i;

        ENTRY;

        LASSERT(nrpages <= OST_THREAD_POOL_SIZE);

        for (i = 0; i < nrpages; ++ i)
                POISON_PAGE(nio[i].page, 0xf2);
        EXIT;
}

static int ost_brw_lock_get(int mode, struct obd_export *exp,
                            struct obd_ioobj *obj, struct niobuf_remote *nb,
                            struct lustre_handle *lh)
{
        int flags                 = 0;
        int nrbufs                = obj->ioo_bufcnt;
        struct ldlm_res_id res_id = { .name = { obj->ioo_id } };
        ldlm_policy_data_t policy;
        int i;

        ENTRY;

        LASSERT(mode == LCK_PR || mode == LCK_PW);
        LASSERT(!lustre_handle_is_used(lh));

        if (nrbufs == 0 || !(nb[0].flags & OBD_BRW_SRVLOCK))
                RETURN(0);

        /* EXPENSIVE ASSERTION */
        for (i = 1; i < nrbufs; i ++)
                LASSERT((nb[0].flags & OBD_BRW_SRVLOCK) ==
                        (nb[i].flags & OBD_BRW_SRVLOCK));

        policy.l_extent.start = nb[0].offset & CFS_PAGE_MASK;
        policy.l_extent.end   = (nb[nrbufs - 1].offset +
                                 nb[nrbufs - 1].len - 1) | ~CFS_PAGE_MASK;

        RETURN(ldlm_cli_enqueue_local(exp->exp_obd->obd_namespace, &res_id, 
                                      LDLM_EXTENT, &policy, mode, &flags,
                                      ldlm_blocking_ast, ldlm_completion_ast,
                                      ldlm_glimpse_ast, NULL, 0, NULL, lh));
}

static void ost_brw_lock_put(int mode,
                             struct obd_ioobj *obj, struct niobuf_remote *niob,
                             struct lustre_handle *lh)
{
        ENTRY;
        LASSERT(mode == LCK_PR || mode == LCK_PW);
        LASSERT((obj->ioo_bufcnt > 0 && (niob[0].flags & OBD_BRW_SRVLOCK)) ==
                lustre_handle_is_used(lh));
        if (lustre_handle_is_used(lh))
                ldlm_lock_decref(lh, mode);
        EXIT;
}

struct ost_prolong_data {
        struct obd_export *opd_exp;
        ldlm_policy_data_t opd_policy;
        ldlm_mode_t opd_mode;
};

static int ost_prolong_locks_iter(struct ldlm_lock *lock, void *data)
{
        struct ost_prolong_data *opd = data;

        LASSERT(lock->l_resource->lr_type == LDLM_EXTENT);

        if (lock->l_req_mode != lock->l_granted_mode) {
                /* scan granted locks only */
                return LDLM_ITER_STOP;
        }

        if (lock->l_export != opd->opd_exp) {
                /* prolong locks only for given client */
                return LDLM_ITER_CONTINUE;
        }

        if (!(lock->l_granted_mode & opd->opd_mode)) {
                /* we aren't interesting in all type of locks */
                return LDLM_ITER_CONTINUE;
        }

        if (lock->l_policy_data.l_extent.end < opd->opd_policy.l_extent.start ||
            lock->l_policy_data.l_extent.start > opd->opd_policy.l_extent.end) {
                /* the request doesn't cross the lock, skip it */
                return LDLM_ITER_CONTINUE;
        }

        if (!(lock->l_flags & LDLM_FL_AST_SENT)) {
                /* ignore locks not being cancelled */
                return LDLM_ITER_CONTINUE;
        }

        /* OK. this is a possible lock the user holds doing I/O
         * let's refresh eviction timer for it */
        ldlm_refresh_waiting_lock(lock);

        return LDLM_ITER_CONTINUE;
}

static void ost_prolong_locks(struct obd_export *exp, struct obd_ioobj *obj,
                              struct niobuf_remote *nb, struct obdo *oa,
                              ldlm_mode_t mode)


{
        struct ldlm_res_id res_id = { .name = { obj->ioo_id } };
        int nrbufs = obj->ioo_bufcnt;
        struct ost_prolong_data opd;

        ENTRY;

        opd.opd_mode = mode;
        opd.opd_exp = exp;
        opd.opd_policy.l_extent.start = nb[0].offset & CFS_PAGE_MASK;
        opd.opd_policy.l_extent.end = (nb[nrbufs - 1].offset +
                                       nb[nrbufs - 1].len - 1) | ~CFS_PAGE_MASK;

        CDEBUG(D_DLMTRACE,"refresh locks: "LPU64"/"LPU64" ("LPU64"->"LPU64")\n",
               res_id.name[0], res_id.name[1], opd.opd_policy.l_extent.start,
               opd.opd_policy.l_extent.end);

        if (oa->o_valid & OBD_MD_FLHANDLE) {
                struct ldlm_lock *lock;

                lock = ldlm_handle2lock(&oa->o_handle);
                if (lock != NULL) {
                        ost_prolong_locks_iter(lock, &opd);
                        LDLM_LOCK_PUT(lock);
                        EXIT;
                        return;
                }
        }

        ldlm_resource_iterate(exp->exp_obd->obd_namespace, &res_id,
                              ost_prolong_locks_iter, &opd);

        EXIT;
}

static int ost_brw_read(struct ptlrpc_request *req, struct obd_trans_info *oti)
{
        struct ptlrpc_bulk_desc *desc;
        struct obd_export       *exp = req->rq_export;
        struct niobuf_remote *remote_nb;
        struct niobuf_remote *pp_rnb = NULL;
        struct niobuf_local *local_nb;
        struct obd_ioobj *ioo;
        struct ost_body *body, *repbody;
        struct l_wait_info lwi;
        struct lustre_handle lockh = { 0 };
        __u32  size[2] = { sizeof(struct ptlrpc_body), sizeof(*body) };
        int niocount, npages, nob = 0, rc, i;
        int no_reply = 0;
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_OST_BRW_READ_BULK))
                GOTO(out, rc = -EIO);

        OBD_FAIL_TIMEOUT(OBD_FAIL_OST_BRW_PAUSE_BULK, (obd_timeout + 1) / 4);

        /* Check if there is eviction in progress, and if so, wait for it to
         * finish */
        if (unlikely(atomic_read(&exp->exp_obd->obd_evict_inprogress))) {
                lwi = LWI_INTR(NULL, NULL); // We do not care how long it takes
                rc = l_wait_event(exp->exp_obd->obd_evict_inprogress_waitq,
                        !atomic_read(&exp->exp_obd->obd_evict_inprogress),
                        &lwi);
        }
        if (exp->exp_failed)
                GOTO(out, rc = -ENOTCONN);

        body = lustre_swab_reqbuf(req, REQ_REC_OFF, sizeof(*body),
                                  lustre_swab_ost_body);
        if (body == NULL) {
                CERROR("Missing/short ost_body\n");
                GOTO(out, rc = -EFAULT);
        }

        ioo = lustre_swab_reqbuf(req, REQ_REC_OFF + 1, sizeof(*ioo),
                                 lustre_swab_obd_ioobj);
        if (ioo == NULL) {
                CERROR("Missing/short ioobj\n");
                GOTO(out, rc = -EFAULT);
        }

        niocount = ioo->ioo_bufcnt;
        if (niocount > PTLRPC_MAX_BRW_PAGES) {
                DEBUG_REQ(D_ERROR, req, "bulk has too many pages (%d)",
                          niocount);
                GOTO(out, rc = -EFAULT);
        }

        remote_nb = lustre_swab_reqbuf(req, REQ_REC_OFF + 2,
                                       niocount * sizeof(*remote_nb),
                                       lustre_swab_niobuf_remote);
        if (remote_nb == NULL) {
                CERROR("Missing/short niobuf\n");
                GOTO(out, rc = -EFAULT);
        }
        if (lustre_req_need_swab(req)) {
                /* swab remaining niobufs */
                for (i = 1; i < niocount; i++)
                        lustre_swab_niobuf_remote (&remote_nb[i]);
        }

        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc)
                GOTO(out, rc);

        /*
         * Per-thread array of struct niobuf_{local,remote}'s was allocated by
         * ost_thread_init().
         */
        local_nb = ost_tls(req)->local;
        pp_rnb   = ost_tls(req)->remote;

        /* FIXME all niobuf splitting should be done in obdfilter if needed */
        /* CAVEAT EMPTOR this sets ioo->ioo_bufcnt to # pages */
        npages = get_per_page_niobufs(ioo, 1, remote_nb, niocount, &pp_rnb);
        if (npages < 0)
                GOTO(out, rc = npages);

        LASSERT(npages <= OST_THREAD_POOL_SIZE);

        ost_nio_pages_get(req, local_nb, npages);

        desc = ptlrpc_prep_bulk_exp(req, npages,
                                     BULK_PUT_SOURCE, OST_BULK_PORTAL);
        if (desc == NULL)
                GOTO(out, rc = -ENOMEM);

        rc = ost_brw_lock_get(LCK_PR, exp, ioo, pp_rnb, &lockh);
        if (rc != 0)
                GOTO(out_bulk, rc);

        /* 
         * If getting the lock took more time than
         * client was willing to wait, drop it. b=11330
         */
        if (cfs_time_current_sec() > req->rq_deadline || 
            OBD_FAIL_CHECK(OBD_FAIL_OST_DROP_REQ)) {
                no_reply = 1;
                CERROR("Dropping timed-out read from %s because locking"
                       "object "LPX64" took %ld seconds (limit was %ld).\n",
                       libcfs_id2str(req->rq_peer), ioo->ioo_id,
                       cfs_time_current_sec() - req->rq_arrival_time.tv_sec,
                       req->rq_deadline - req->rq_arrival_time.tv_sec);
                GOTO(out_lock, rc = -ETIMEDOUT);
        }

        rc = obd_preprw(OBD_BRW_READ, exp, &body->oa, 1,
                        ioo, npages, pp_rnb, local_nb, oti);
        if (rc != 0)
                GOTO(out_lock, rc);

        ost_prolong_locks(exp, ioo, pp_rnb, &body->oa, LCK_PW | LCK_PR);

        nob = 0;
        for (i = 0; i < npages; i++) {
                int page_rc = local_nb[i].rc;

                if (page_rc < 0) {              /* error */
                        rc = page_rc;
                        break;
                }

                LASSERTF(page_rc <= pp_rnb[i].len, "page_rc (%d) > "
                         "pp_rnb[%d].len (%d)\n", page_rc, i, pp_rnb[i].len);
                nob += page_rc;
                if (page_rc != 0) {             /* some data! */
                        LASSERT (local_nb[i].page != NULL);
                        ptlrpc_prep_bulk_page(desc, local_nb[i].page,
                                              pp_rnb[i].offset & ~CFS_PAGE_MASK,
                                              page_rc);
                }

                if (page_rc != pp_rnb[i].len) { /* short read */
                        /* All subsequent pages should be 0 */
                        while(++i < npages)
                                LASSERT(local_nb[i].rc == 0);
                        break;
                }
        }

        if (body->oa.o_valid & OBD_MD_FLCKSUM) {
                cksum_type_t cksum_type = OBD_CKSUM_CRC32;

                if (body->oa.o_valid & OBD_MD_FLFLAGS)
                        cksum_type = cksum_type_unpack(body->oa.o_flags);
                body->oa.o_flags = cksum_type_pack(cksum_type);
                body->oa.o_valid = OBD_MD_FLCKSUM | OBD_MD_FLFLAGS;
                body->oa.o_cksum = ost_checksum_bulk(desc, OST_READ, cksum_type);
                CDEBUG(D_PAGE,"checksum at read origin: %x\n",body->oa.o_cksum);
        } else {
                body->oa.o_valid = 0;
        }
        /* We're finishing using body->oa as an input variable */

        /* Check if client was evicted while we were doing i/o before touching
           network */
        if (rc == 0) {
                /* Check if there is eviction in progress, and if so, wait for
                 * it to finish */
                if (unlikely(atomic_read(&exp->exp_obd->
                                                obd_evict_inprogress))) {
                        lwi = LWI_INTR(NULL, NULL);
                        rc = l_wait_event(exp->exp_obd->
                                                obd_evict_inprogress_waitq,
                                          !atomic_read(&exp->exp_obd->
                                                        obd_evict_inprogress),
                                          &lwi);
                }
                if (exp->exp_failed)
                        rc = -ENOTCONN;
                else
                        rc = ptlrpc_start_bulk_transfer(desc);
                if (rc == 0) {
                        time_t start = cfs_time_current_sec();
                        do {
                                long timeoutl = req->rq_deadline - 
                                        cfs_time_current_sec();
                                cfs_duration_t timeout = (timeoutl <= 0 || rc) ? 
                                        CFS_TICK : cfs_time_seconds(timeoutl);
                                lwi = LWI_TIMEOUT_INTERVAL(timeout, 
                                                           cfs_time_seconds(1),
                                                           ost_bulk_timeout, 
                                                           desc);
                                rc = l_wait_event(desc->bd_waitq, 
                                                  !ptlrpc_bulk_active(desc) ||
                                                  exp->exp_failed, &lwi);
                                LASSERT(rc == 0 || rc == -ETIMEDOUT);
                                /* Wait again if we changed deadline */
                        } while ((rc == -ETIMEDOUT) && 
                                 (req->rq_deadline > cfs_time_current_sec()));

                        if (rc == -ETIMEDOUT) {
                                DEBUG_REQ(D_ERROR, req,
                                          "timeout on bulk PUT after %ld%+lds",
                                          req->rq_deadline - start,
                                          cfs_time_current_sec() -
                                          req->rq_deadline);
                                ptlrpc_abort_bulk(desc);
                        } else if (exp->exp_failed) {
                                DEBUG_REQ(D_ERROR, req, "Eviction on bulk PUT");
                                rc = -ENOTCONN;
                                ptlrpc_abort_bulk(desc);
                        } else if (!desc->bd_success ||
                                   desc->bd_nob_transferred != desc->bd_nob) {
                                DEBUG_REQ(D_ERROR, req, "%s bulk PUT %d(%d)",
                                          desc->bd_success ?
                                          "truncated" : "network error on",
                                          desc->bd_nob_transferred,
                                          desc->bd_nob);
                                /* XXX should this be a different errno? */
                                rc = -ETIMEDOUT;
                        }
                } else {
                        DEBUG_REQ(D_ERROR, req, "bulk PUT failed: rc %d", rc);
                }
                no_reply = rc != 0;
        }

        /* Must commit after prep above in all cases */
        rc = obd_commitrw(OBD_BRW_READ, exp, &body->oa, 1,
                          ioo, npages, local_nb, oti, rc);

        ost_nio_pages_put(req, local_nb, npages);

        if (rc == 0) {
                repbody = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                                         sizeof(*repbody));
                memcpy(&repbody->oa, &body->oa, sizeof(repbody->oa));
        }

 out_lock:
        ost_brw_lock_put(LCK_PR, ioo, pp_rnb, &lockh);
 out_bulk:
        ptlrpc_free_bulk(desc);
 out:
        LASSERT(rc <= 0);
        if (rc == 0) {
                req->rq_status = nob;
                target_committed_to_req(req);
                ptlrpc_reply(req);
        } else if (!no_reply) {
                /* Only reply if there was no comms problem with bulk */
                target_committed_to_req(req);
                req->rq_status = rc;
                ptlrpc_error(req);
        } else {
                /* reply out callback would free */
                ptlrpc_req_drop_rs(req);
                CWARN("%s: ignoring bulk IO comm error with %s@%s id %s - "
                      "client will retry\n",
                      exp->exp_obd->obd_name,
                      exp->exp_client_uuid.uuid,
                      exp->exp_connection->c_remote_uuid.uuid,
                      libcfs_id2str(req->rq_peer));
        }

        RETURN(rc);
}

static int ost_brw_write(struct ptlrpc_request *req, struct obd_trans_info *oti)
{
        struct ptlrpc_bulk_desc *desc;
        struct obd_export       *exp = req->rq_export;
        struct niobuf_remote    *remote_nb;
        struct niobuf_remote    *pp_rnb;
        struct niobuf_local     *local_nb;
        struct obd_ioobj        *ioo;
        struct ost_body         *body, *repbody;
        struct l_wait_info       lwi;
        struct lustre_handle     lockh = {0};
        __u32                   *rcs;
        __u32 size[3] = { sizeof(struct ptlrpc_body), sizeof(*body) };
        int objcount, niocount, npages;
        int rc, swab, i, j;
        obd_count                client_cksum = 0, server_cksum = 0;
        cksum_type_t             cksum_type = OBD_CKSUM_CRC32;
        int                      no_reply = 0; 
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_OST_BRW_WRITE_BULK))
                GOTO(out, rc = -EIO);
        if (OBD_FAIL_CHECK(OBD_FAIL_OST_BRW_WRITE_BULK2))
                GOTO(out, rc = -EFAULT);

        /* pause before transaction has been started */
        OBD_FAIL_TIMEOUT(OBD_FAIL_OST_BRW_PAUSE_BULK, (obd_timeout + 1) / 4);

        /* Check if there is eviction in progress, and if so, wait for it to
         * finish */
        if (unlikely(atomic_read(&exp->exp_obd->obd_evict_inprogress))) {
                lwi = LWI_INTR(NULL, NULL); // We do not care how long it takes
                rc = l_wait_event(exp->exp_obd->obd_evict_inprogress_waitq,
                        !atomic_read(&exp->exp_obd->obd_evict_inprogress),
                        &lwi);
        }
        if (exp->exp_failed)
                GOTO(out, rc = -ENOTCONN);

        swab = lustre_req_need_swab(req);
        body = lustre_swab_reqbuf(req, REQ_REC_OFF, sizeof(*body),
                                  lustre_swab_ost_body);
        if (body == NULL) {
                CERROR("Missing/short ost_body\n");
                GOTO(out, rc = -EFAULT);
        }

        objcount = lustre_msg_buflen(req->rq_reqmsg, REQ_REC_OFF + 1) /
                   sizeof(*ioo);
        if (objcount == 0) {
                CERROR("Missing/short ioobj\n");
                GOTO(out, rc = -EFAULT);
        }
        if (objcount > 1) {
                CERROR("too many ioobjs (%d)\n", objcount);
                GOTO(out, rc = -EFAULT);
        }

        lustre_set_req_swabbed(req, REQ_REC_OFF + 1);
        ioo = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF + 1,
                             objcount * sizeof(*ioo));
        LASSERT (ioo != NULL);
        for (niocount = i = 0; i < objcount; i++) {
                if (swab)
                        lustre_swab_obd_ioobj(&ioo[i]);
                if (ioo[i].ioo_bufcnt == 0) {
                        CERROR("ioo[%d] has zero bufcnt\n", i);
                        GOTO(out, rc = -EFAULT);
                }
                niocount += ioo[i].ioo_bufcnt;
        }

        if (niocount > PTLRPC_MAX_BRW_PAGES) {
                DEBUG_REQ(D_ERROR, req, "bulk has too many pages (%d)",
                          niocount);
                GOTO(out, rc = -EFAULT);
        }

        remote_nb = lustre_swab_reqbuf(req, REQ_REC_OFF + 2,
                                       niocount * sizeof(*remote_nb),
                                       lustre_swab_niobuf_remote);
        if (remote_nb == NULL) {
                CERROR("Missing/short niobuf\n");
                GOTO(out, rc = -EFAULT);
        }
        if (swab) {                             /* swab the remaining niobufs */
                for (i = 1; i < niocount; i++)
                        lustre_swab_niobuf_remote (&remote_nb[i]);
        }

        size[REPLY_REC_OFF + 1] = niocount * sizeof(*rcs);
        rc = lustre_pack_reply(req, 3, size, NULL);
        if (rc != 0)
                GOTO(out, rc);

        OBD_FAIL_TIMEOUT(OBD_FAIL_OST_BRW_PAUSE_PACK, obd_fail_val);
        rcs = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF + 1,
                             niocount * sizeof(*rcs));

        /*
         * Per-thread array of struct niobuf_{local,remote}'s was allocated by
         * ost_thread_init().
         */
        local_nb = ost_tls(req)->local;
        pp_rnb   = ost_tls(req)->remote;

        /* FIXME all niobuf splitting should be done in obdfilter if needed */
        /* CAVEAT EMPTOR this sets ioo->ioo_bufcnt to # pages */
        npages = get_per_page_niobufs(ioo, objcount,remote_nb,niocount,&pp_rnb);
        if (npages < 0)
                GOTO(out, rc = npages);

        LASSERT(npages <= OST_THREAD_POOL_SIZE);

        ost_nio_pages_get(req, local_nb, npages);

        desc = ptlrpc_prep_bulk_exp(req, npages,
                                     BULK_GET_SINK, OST_BULK_PORTAL);
        if (desc == NULL)
                GOTO(out, rc = -ENOMEM);

        rc = ost_brw_lock_get(LCK_PW, exp, ioo, pp_rnb, &lockh);
        if (rc != 0)
                GOTO(out_bulk, rc);

        /* 
         * If getting the lock took more time than
         * client was willing to wait, drop it. b=11330
         */
        if (cfs_time_current_sec() > req->rq_deadline || 
            OBD_FAIL_CHECK(OBD_FAIL_OST_DROP_REQ)) {
                no_reply = 1;
                CERROR("Dropping timed-out write from %s because locking "
                       "object "LPX64" took %ld seconds (limit was %ld).\n",
                       libcfs_id2str(req->rq_peer), ioo->ioo_id,
                       cfs_time_current_sec() - req->rq_arrival_time.tv_sec,
                       req->rq_deadline - req->rq_arrival_time.tv_sec);
                GOTO(out_lock, rc = -ETIMEDOUT);
        }

        ost_prolong_locks(exp, ioo, pp_rnb, &body->oa, LCK_PW);

        /* obd_preprw clobbers oa->valid, so save what we need */
        if (body->oa.o_valid & OBD_MD_FLCKSUM) {
                client_cksum = body->oa.o_cksum;
                if (body->oa.o_valid & OBD_MD_FLFLAGS)
                        cksum_type = cksum_type_unpack(body->oa.o_flags);
        }

        /* Because we already sync grant info with client when reconnect,
         * grant info will be cleared for resent req, then fed_grant and 
         * total_grant will not be modified in following preprw_write*/ 
        if (lustre_msg_get_flags(req->rq_reqmsg) & (MSG_RESENT | MSG_REPLAY)) {
                DEBUG_REQ(D_CACHE, req, "clear resent/replay req grant info");
                body->oa.o_valid &= ~OBD_MD_FLGRANT;
        }

        rc = obd_preprw(OBD_BRW_WRITE, exp, &body->oa, objcount,
                        ioo, npages, pp_rnb, local_nb, oti);
        if (rc != 0)
                GOTO(out_lock, rc);

        /* NB Having prepped, we must commit... */

        for (i = 0; i < npages; i++)
                ptlrpc_prep_bulk_page(desc, local_nb[i].page,
                                      pp_rnb[i].offset & ~CFS_PAGE_MASK,
                                      pp_rnb[i].len);

        /* Check if client was evicted while we were doing i/o before touching
           network */
        if (desc->bd_export->exp_failed)
                rc = -ENOTCONN;
        else
                rc = ptlrpc_start_bulk_transfer (desc);
        if (rc == 0) {
                time_t start = cfs_time_current_sec();
                do {
                        long timeoutl = req->rq_deadline - 
                                cfs_time_current_sec();
                        cfs_duration_t timeout = (timeoutl <= 0 || rc) ? 
                                CFS_TICK : cfs_time_seconds(timeoutl);
                        lwi = LWI_TIMEOUT_INTERVAL(timeout, cfs_time_seconds(1),
                                                   ost_bulk_timeout, desc);
                        rc = l_wait_event(desc->bd_waitq, 
                                          !ptlrpc_bulk_active(desc) ||
                                          desc->bd_export->exp_failed, &lwi);
                        LASSERT(rc == 0 || rc == -ETIMEDOUT);
                        /* Wait again if we changed deadline */
                } while ((rc == -ETIMEDOUT) && 
                         (req->rq_deadline > cfs_time_current_sec()));

                if (rc == -ETIMEDOUT) {
                        DEBUG_REQ(D_ERROR, req,
                                  "timeout on bulk GET after %ld%+lds",
                                  req->rq_deadline - start,
                                  cfs_time_current_sec() -
                                  req->rq_deadline);
                        ptlrpc_abort_bulk(desc);
                } else if (desc->bd_export->exp_failed) {
                        DEBUG_REQ(D_ERROR, req, "Eviction on bulk GET");
                        rc = -ENOTCONN;
                        ptlrpc_abort_bulk(desc);
                } else if (!desc->bd_success ||
                           desc->bd_nob_transferred != desc->bd_nob) {
                        DEBUG_REQ(D_ERROR, req, "%s bulk GET %d(%d)",
                                  desc->bd_success ?
                                  "truncated" : "network error on",
                                  desc->bd_nob_transferred, desc->bd_nob);
                        /* XXX should this be a different errno? */
                        rc = -ETIMEDOUT;
                }
        } else {
                DEBUG_REQ(D_ERROR, req, "ptlrpc_bulk_get failed: rc %d", rc);
        }
        no_reply = rc != 0;

        repbody = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                                 sizeof(*repbody));
        memcpy(&repbody->oa, &body->oa, sizeof(repbody->oa));

        if (client_cksum != 0 && rc == 0) {
                static int cksum_counter;

                repbody->oa.o_valid |= OBD_MD_FLCKSUM | OBD_MD_FLFLAGS;
                repbody->oa.o_flags &= ~OBD_FL_CKSUM_ALL;
                repbody->oa.o_flags |= cksum_type_pack(cksum_type);
                server_cksum = ost_checksum_bulk(desc, OST_WRITE, cksum_type);
                repbody->oa.o_cksum = server_cksum;
                cksum_counter++;
                if (unlikely(client_cksum != server_cksum)) {
                        CERROR("client csum %x, server csum %x\n",
                               client_cksum, server_cksum);
                        cksum_counter = 0;
                } else if ((cksum_counter & (-cksum_counter)) == cksum_counter){
                        CDEBUG(D_INFO, "Checksum %u from %s OK: %x\n",
                               cksum_counter, libcfs_id2str(req->rq_peer),
                               server_cksum);
                }
        }

        /* Check if there is eviction in progress, and if so, wait for
         * it to finish */
        if (unlikely(atomic_read(&exp->exp_obd->obd_evict_inprogress))) {
                lwi = LWI_INTR(NULL, NULL);
                rc = l_wait_event(exp->exp_obd->obd_evict_inprogress_waitq,
                        !atomic_read(&exp->exp_obd->obd_evict_inprogress),
                        &lwi);
        }
        if (rc == 0 && exp->exp_failed)
                rc = -ENOTCONN;

        /* Must commit after prep above in all cases */
        rc = obd_commitrw(OBD_BRW_WRITE, exp, &repbody->oa,
                           objcount, ioo, npages, local_nb, oti, rc);

        if (unlikely(client_cksum != server_cksum && rc == 0)) {
                int  new_cksum = ost_checksum_bulk(desc, OST_WRITE, cksum_type);
                char *msg;
                char *via;
                char *router;

                if (new_cksum == server_cksum)
                        msg = "changed in transit before arrival at OST";
                else if (new_cksum == client_cksum)
                        msg = "initial checksum before message complete";
                else
                        msg = "changed in transit AND after initial checksum";

                if (req->rq_peer.nid == desc->bd_sender) {
                        via = router = "";
                } else {
                        via = " via ";
                        router = libcfs_nid2str(desc->bd_sender);
                }

                LCONSOLE_ERROR_MSG(0x168, "%s: BAD WRITE CHECKSUM: %s from %s"
                                   "%s%s inum "LPU64"/"LPU64" object "LPU64"/"
                                   LPU64" extent ["LPU64"-"LPU64"]\n",
                                   exp->exp_obd->obd_name, msg,
                                   libcfs_id2str(req->rq_peer),
                                   via, router,
                                   body->oa.o_valid & OBD_MD_FLFID ?
                                                body->oa.o_fid : (__u64)0,
                                   body->oa.o_valid & OBD_MD_FLFID ?
                                                body->oa.o_generation :(__u64)0,
                                   body->oa.o_id,
                                   body->oa.o_valid & OBD_MD_FLGROUP ?
                                                body->oa.o_gr : (__u64)0,
                                   pp_rnb[0].offset,
                                   pp_rnb[npages-1].offset+pp_rnb[npages-1].len
                                   - 1 );
                CERROR("client csum %x, original server csum %x, "
                       "server csum now %x\n",
                       client_cksum, server_cksum, new_cksum);
        }

        ost_nio_pages_put(req, local_nb, npages);

        if (rc == 0) {
                /* set per-requested niobuf return codes */
                for (i = j = 0; i < niocount; i++) {
                        int nob = remote_nb[i].len;

                        rcs[i] = 0;
                        do {
                                LASSERT(j < npages);
                                if (local_nb[j].rc < 0)
                                        rcs[i] = local_nb[j].rc;
                                nob -= pp_rnb[j].len;
                                j++;
                        } while (nob > 0);
                        LASSERT(nob == 0);
                }
                LASSERT(j == npages);
        }

 out_lock:
        ost_brw_lock_put(LCK_PW, ioo, pp_rnb, &lockh);
 out_bulk:
        ptlrpc_free_bulk(desc);
 out:
        if (rc == 0) {
                oti_to_request(oti, req);
                target_committed_to_req(req);
                rc = ptlrpc_reply(req);
        } else if (!no_reply) {
                /* Only reply if there was no comms problem with bulk */
                target_committed_to_req(req);
                req->rq_status = rc;
                ptlrpc_error(req);
        } else {
                /* reply out callback would free */
                ptlrpc_req_drop_rs(req);
                CWARN("%s: ignoring bulk IO comm error with %s@%s id %s - "
                      "client will retry\n",
                      exp->exp_obd->obd_name,
                      exp->exp_client_uuid.uuid,
                      exp->exp_connection->c_remote_uuid.uuid,
                      libcfs_id2str(req->rq_peer));
        }
        RETURN(rc);
}

static int ost_set_info(struct obd_export *exp, struct ptlrpc_request *req)
{
        char *key, *val = NULL;
        int keylen, vallen, rc = 0;
        ENTRY;

        key = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF, 1);
        if (key == NULL) {
                DEBUG_REQ(D_HA, req, "no set_info key");
                RETURN(-EFAULT);
        }
        keylen = lustre_msg_buflen(req->rq_reqmsg, REQ_REC_OFF);

        rc = lustre_pack_reply(req, 1, NULL, NULL);
        if (rc)
                RETURN(rc);

        vallen = lustre_msg_buflen(req->rq_reqmsg, REQ_REC_OFF + 1);
        if (vallen)
                val = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF + 1, 0);

        if (KEY_IS(KEY_EVICT_BY_NID)) {
                if (val && vallen)
                        obd_export_evict_by_nid(exp->exp_obd, val);

                GOTO(out, rc = 0);
        }

        rc = obd_set_info_async(exp, keylen, key, vallen, val, NULL);
out:
        lustre_msg_set_status(req->rq_repmsg, 0);
        RETURN(rc);
}

static int ost_get_info(struct obd_export *exp, struct ptlrpc_request *req)
{
        void *key, *reply;
        int keylen, rc = 0;
        int size[2] = { sizeof(struct ptlrpc_body), 0 };
        ENTRY;

        key = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF, 1);
        if (key == NULL) {
                DEBUG_REQ(D_HA, req, "no get_info key");
                RETURN(-EFAULT);
        }
        keylen = lustre_msg_buflen(req->rq_reqmsg, REQ_REC_OFF);

        /* call once to get the size to allocate the reply buffer */
        rc = obd_get_info(exp, keylen, key, &size[1], NULL, NULL);
        if (rc)
                RETURN(rc);

        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc)
                RETURN(rc);

        reply = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF, sizeof(*reply));
        /* call again to fill in the reply buffer */
        rc = obd_get_info(exp, keylen, key, size, reply, NULL);
        lustre_msg_set_status(req->rq_repmsg, 0);

        RETURN(rc);
}

static int ost_handle_quotactl(struct ptlrpc_request *req)
{
        struct obd_quotactl *oqctl, *repoqc;
        __u32 size[2] = { sizeof(struct ptlrpc_body), sizeof(*repoqc) };
        int rc;
        ENTRY;

        oqctl = lustre_swab_reqbuf(req, REQ_REC_OFF, sizeof(*oqctl),
                                   lustre_swab_obd_quotactl);
        if (oqctl == NULL)
                GOTO(out, rc = -EPROTO);

        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc)
                GOTO(out, rc);

        repoqc = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF, sizeof(*repoqc));

        req->rq_status = obd_quotactl(req->rq_export, oqctl);
        *repoqc = *oqctl;
out:
        RETURN(rc);
}

static int ost_handle_quotacheck(struct ptlrpc_request *req)
{
        struct obd_quotactl *oqctl;
        int rc;
        ENTRY;

        oqctl = lustre_swab_reqbuf(req, REQ_REC_OFF, sizeof(*oqctl),
                                   lustre_swab_obd_quotactl);
        if (oqctl == NULL) 
                RETURN(-EPROTO);

        rc = lustre_pack_reply(req, 1, NULL, NULL);
        if (rc)
                RETURN(rc);

        req->rq_status = obd_quotacheck(req->rq_export, oqctl);
        RETURN(0);
}

static int ost_handle_quota_adjust_qunit(struct ptlrpc_request *req)
{
        struct quota_adjust_qunit *oqaq, *repoqa;
        struct lustre_quota_ctxt *qctxt;
        int size[2] = { sizeof(struct ptlrpc_body), sizeof(*repoqa) };
        int rc;
        ENTRY;

        qctxt = &req->rq_export->exp_obd->u.obt.obt_qctxt;
        oqaq = lustre_swab_reqbuf(req, REQ_REC_OFF, sizeof(*oqaq),
                                  lustre_swab_quota_adjust_qunit);

        if (oqaq == NULL)
                GOTO(out, rc = -EPROTO);
        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc)
                GOTO(out, rc);
        repoqa = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF, sizeof(*repoqa));
        req->rq_status = obd_quota_adjust_qunit(req->rq_export, oqaq, qctxt);
        *repoqa = *oqaq;
 out:
        RETURN(rc);
}

static int ost_filter_recovery_request(struct ptlrpc_request *req,
                                       struct obd_device *obd, int *process)
{
        switch (lustre_msg_get_opc(req->rq_reqmsg)) {
        case OST_CONNECT: /* This will never get here, but for completeness. */
        case OST_DISCONNECT:
               *process = 1;
               RETURN(0);

        case OBD_PING:
        case OST_CREATE:
        case OST_DESTROY:
        case OST_PUNCH:
        case OST_SETATTR:
        case OST_SYNC:
        case OST_WRITE:
        case OBD_LOG_CANCEL:
        case LDLM_ENQUEUE:
                *process = target_queue_recovery_request(req, obd);
                RETURN(0);

        default:
                DEBUG_REQ(D_ERROR, req, "not permitted during recovery");
                *process = 0;
                /* XXX what should we set rq_status to here? */
                req->rq_status = -EAGAIN;
                RETURN(ptlrpc_error(req));
        }
}

int ost_msg_check_version(struct lustre_msg *msg)
{
        int rc;

        switch(lustre_msg_get_opc(msg)) {
        case OST_CONNECT:
        case OST_DISCONNECT:
        case OBD_PING:
                rc = lustre_msg_check_version(msg, LUSTRE_OBD_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               lustre_msg_get_opc(msg),
                               lustre_msg_get_version(msg),
                               LUSTRE_OBD_VERSION);
                break;
        case OST_CREATE:
        case OST_DESTROY:
        case OST_GETATTR:
        case OST_SETATTR:
        case OST_WRITE:
        case OST_READ:
        case OST_PUNCH:
        case OST_STATFS:
        case OST_SYNC:
        case OST_SET_INFO:
        case OST_GET_INFO:
        case OST_QUOTACHECK:
        case OST_QUOTACTL:
        case OST_QUOTA_ADJUST_QUNIT:
                rc = lustre_msg_check_version(msg, LUSTRE_OST_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               lustre_msg_get_opc(msg),
                               lustre_msg_get_version(msg),
                               LUSTRE_OST_VERSION);
                break;
        case LDLM_ENQUEUE:
        case LDLM_CONVERT:
        case LDLM_CANCEL:
        case LDLM_BL_CALLBACK:
        case LDLM_CP_CALLBACK:
                rc = lustre_msg_check_version(msg, LUSTRE_DLM_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               lustre_msg_get_opc(msg),
                               lustre_msg_get_version(msg),
                               LUSTRE_DLM_VERSION);
                break;
        case LLOG_ORIGIN_CONNECT:
        case OBD_LOG_CANCEL:
                rc = lustre_msg_check_version(msg, LUSTRE_LOG_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               lustre_msg_get_opc(msg),
                               lustre_msg_get_version(msg),
                               LUSTRE_LOG_VERSION);
                break;
        default:
                CERROR("Unexpected opcode %d\n", lustre_msg_get_opc(msg));
                rc = -ENOTSUPP;
        }
        return rc;
}

static int ost_handle(struct ptlrpc_request *req)
{
        struct obd_trans_info trans_info = { 0, };
        struct obd_trans_info *oti = &trans_info;
        int should_process, fail = OBD_FAIL_OST_ALL_REPLY_NET, rc = 0;
        struct obd_device *obd = NULL;
        ENTRY;

        LASSERT(current->journal_info == NULL);
        /* XXX identical to MDS */
        if (lustre_msg_get_opc(req->rq_reqmsg) != OST_CONNECT) {
                int abort_recovery, recovering;

                if (req->rq_export == NULL) {
                        CDEBUG(D_HA,"operation %d on unconnected OST from %s\n",
                               lustre_msg_get_opc(req->rq_reqmsg),
                               libcfs_id2str(req->rq_peer));
                        req->rq_status = -ENOTCONN;
                        GOTO(out, rc = -ENOTCONN);
                }

                obd = req->rq_export->exp_obd;

                /* Check for aborted recovery. */
                spin_lock_bh(&obd->obd_processing_task_lock);
                abort_recovery = obd->obd_abort_recovery;
                recovering = obd->obd_recovering;
                spin_unlock_bh(&obd->obd_processing_task_lock);
                if (abort_recovery) {
                        target_abort_recovery(obd);
                } else if (recovering) {
                        rc = ost_filter_recovery_request(req, obd,
                                                         &should_process);
                        if (rc || !should_process)
                                RETURN(rc);
                }
        }

        oti_init(oti, req);
        rc = ost_msg_check_version(req->rq_reqmsg);
        if (rc)
                RETURN(rc);

        switch (lustre_msg_get_opc(req->rq_reqmsg)) {
        case OST_CONNECT: {
                CDEBUG(D_INODE, "connect\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_CONNECT_NET, 0);
                rc = target_handle_connect(req, ost_handle);
                OBD_FAIL_RETURN(OBD_FAIL_OST_CONNECT_NET2, 0);
                if (!rc)
                        obd = req->rq_export->exp_obd;
                break;
        }
        case OST_DISCONNECT:
                CDEBUG(D_INODE, "disconnect\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_DISCONNECT_NET, 0);
                rc = target_handle_disconnect(req);
                break;
        case OST_CREATE:
                CDEBUG(D_INODE, "create\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_CREATE_NET, 0);
                OBD_FAIL_TIMEOUT_MS(OBD_FAIL_OST_PAUSE_CREATE, obd_fail_val);
                if (OBD_FAIL_CHECK_ONCE(OBD_FAIL_OST_ENOSPC))
                        GOTO(out, rc = -ENOSPC);
                if (OBD_FAIL_CHECK_ONCE(OBD_FAIL_OST_EROFS))
                        GOTO(out, rc = -EROFS);
                rc = ost_create(req->rq_export, req, oti);
                break;
        case OST_DESTROY:
                CDEBUG(D_INODE, "destroy\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_DESTROY_NET, 0);
                if (OBD_FAIL_CHECK_ONCE(OBD_FAIL_OST_EROFS))
                        GOTO(out, rc = -EROFS);
                rc = ost_destroy(req->rq_export, req, oti);
                break;
        case OST_GETATTR:
                CDEBUG(D_INODE, "getattr\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_GETATTR_NET, 0);
                rc = ost_getattr(req->rq_export, req);
                break;
        case OST_SETATTR:
                CDEBUG(D_INODE, "setattr\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_SETATTR_NET, 0);
                rc = ost_setattr(req->rq_export, req, oti);
                break;
        case OST_WRITE:
                CDEBUG(D_INODE, "write\n");
                /* req->rq_request_portal would be nice, if it was set */
                if (req->rq_rqbd->rqbd_service->srv_req_portal !=OST_IO_PORTAL){
                        CERROR("%s: deny write request from %s to portal %u\n",
                               req->rq_export->exp_obd->obd_name,
                               obd_export_nid2str(req->rq_export),
                               req->rq_rqbd->rqbd_service->srv_req_portal);
                        GOTO(out, rc = -EPROTO);
                }
                OBD_FAIL_RETURN(OBD_FAIL_OST_BRW_NET, 0);
                if (OBD_FAIL_CHECK_ONCE(OBD_FAIL_OST_ENOSPC))
                        GOTO(out, rc = -ENOSPC);
                if (OBD_FAIL_CHECK_ONCE(OBD_FAIL_OST_EROFS))
                        GOTO(out, rc = -EROFS);
                rc = ost_brw_write(req, oti);
                LASSERT(current->journal_info == NULL);
                /* ost_brw_write sends its own replies */
                RETURN(rc);
        case OST_READ:
                CDEBUG(D_INODE, "read\n");
                /* req->rq_request_portal would be nice, if it was set */
                if (req->rq_rqbd->rqbd_service->srv_req_portal !=OST_IO_PORTAL){
                        CERROR("%s: deny read request from %s to portal %u\n",
                               req->rq_export->exp_obd->obd_name,
                               obd_export_nid2str(req->rq_export),
                               req->rq_rqbd->rqbd_service->srv_req_portal);
                        GOTO(out, rc = -EPROTO);
                }
                OBD_FAIL_RETURN(OBD_FAIL_OST_BRW_NET, 0);
                rc = ost_brw_read(req, oti);
                LASSERT(current->journal_info == NULL);
                /* ost_brw_read sends its own replies */
                RETURN(rc);
        case OST_PUNCH:
                CDEBUG(D_INODE, "punch\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_PUNCH_NET, 0);
                if (OBD_FAIL_CHECK_ONCE(OBD_FAIL_OST_EROFS))
                        GOTO(out, rc = -EROFS);
                rc = ost_punch(req->rq_export, req, oti);
                break;
        case OST_STATFS:
                CDEBUG(D_INODE, "statfs\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_STATFS_NET, 0);
                rc = ost_statfs(req);
                break;
        case OST_SYNC:
                CDEBUG(D_INODE, "sync\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_SYNC_NET, 0);
                rc = ost_sync(req->rq_export, req);
                break;
        case OST_SET_INFO:
                DEBUG_REQ(D_INODE, req, "set_info");
                rc = ost_set_info(req->rq_export, req);
                break;
        case OST_GET_INFO:
                DEBUG_REQ(D_INODE, req, "get_info");
                rc = ost_get_info(req->rq_export, req);
                break;
        case OST_QUOTACHECK:
                CDEBUG(D_INODE, "quotacheck\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_QUOTACHECK_NET, 0);
                rc = ost_handle_quotacheck(req);
                break;
        case OST_QUOTACTL:
                CDEBUG(D_INODE, "quotactl\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_QUOTACTL_NET, 0);
                rc = ost_handle_quotactl(req);
                break;
        case OST_QUOTA_ADJUST_QUNIT:
                CDEBUG(D_INODE, "quota_adjust_qunit\n");
                rc = ost_handle_quota_adjust_qunit(req);
                break;
        case OBD_PING:
                DEBUG_REQ(D_INODE, req, "ping");
                rc = target_handle_ping(req);
                break;
        /* FIXME - just reply status */
        case LLOG_ORIGIN_CONNECT:
                DEBUG_REQ(D_INODE, req, "log connect");
                rc = llog_handle_connect(req);
                req->rq_status = rc;
                rc = lustre_pack_reply(req, 1, NULL, NULL);
                if (rc)
                        RETURN(rc);
                RETURN(ptlrpc_reply(req));
        case OBD_LOG_CANCEL:
                CDEBUG(D_INODE, "log cancel\n");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOG_CANCEL_NET, 0);
                rc = llog_origin_handle_cancel(req);
                req->rq_status = rc;
                rc = lustre_pack_reply(req, 1, NULL, NULL);
                if (rc)
                        RETURN(rc);
                RETURN(ptlrpc_reply(req));
        case LDLM_ENQUEUE:
                CDEBUG(D_INODE, "enqueue\n");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_ENQUEUE, 0);
                rc = ldlm_handle_enqueue(req, ldlm_server_completion_ast,
                                         ldlm_server_blocking_ast,
                                         ldlm_server_glimpse_ast);
                fail = OBD_FAIL_OST_LDLM_REPLY_NET;
                break;
        case LDLM_CONVERT:
                CDEBUG(D_INODE, "convert\n");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_CONVERT, 0);
                rc = ldlm_handle_convert(req);
                break;
        case LDLM_CANCEL:
                CDEBUG(D_INODE, "cancel\n");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_CANCEL, 0);
                rc = ldlm_handle_cancel(req);
                break;
        case LDLM_BL_CALLBACK:
        case LDLM_CP_CALLBACK:
                CDEBUG(D_INODE, "callback\n");
                CERROR("callbacks should not happen on OST\n");
                /* fall through */
        default:
                CERROR("Unexpected opcode %d\n",
                       lustre_msg_get_opc(req->rq_reqmsg));
                req->rq_status = -ENOTSUPP;
                rc = ptlrpc_error(req);
                RETURN(rc);
        }

        LASSERT(current->journal_info == NULL);

        EXIT;
        /* If we're DISCONNECTing, the export_data is already freed */
        if (!rc && lustre_msg_get_opc(req->rq_reqmsg) != OST_DISCONNECT)
                target_committed_to_req(req);

out:
        if (!rc)
                oti_to_request(oti, req);
        return target_handle_reply(req, rc, fail);
}

/*
 * free per-thread pool created by ost_thread_init().
 */
static void ost_thread_done(struct ptlrpc_thread *thread)
{
        int i;
        struct ost_thread_local_cache *tls; /* TLS stands for Thread-Local
                                             * Storage */

        ENTRY;

        LASSERT(thread != NULL);

        /*
         * be prepared to handle partially-initialized pools (because this is
         * called from ost_thread_init() for cleanup.
         */
        tls = thread->t_data;
        if (tls != NULL) {
                for (i = 0; i < OST_THREAD_POOL_SIZE; ++ i) {
                        if (tls->page[i] != NULL)
                                OBD_PAGE_FREE(tls->page[i]);
                }
                OBD_FREE_PTR(tls);
                thread->t_data = NULL;
        }
        EXIT;
}

/*
 * initialize per-thread page pool (bug 5137).
 */
static int ost_thread_init(struct ptlrpc_thread *thread)
{
        int result;
        int i;
        struct ost_thread_local_cache *tls;

        ENTRY;

        LASSERT(thread != NULL);
        LASSERT(thread->t_data == NULL);
        LASSERTF(thread->t_id <= OSS_THREADS_MAX, "%u\n", thread->t_id);

        OBD_ALLOC_PTR(tls);
        if (tls != NULL) {
                result = 0;
                thread->t_data = tls;
                /*
                 * populate pool
                 */
                for (i = 0; i < OST_THREAD_POOL_SIZE; ++ i) {
                        OBD_PAGE_ALLOC(tls->page[i], OST_THREAD_POOL_GFP);
                        if (tls->page[i] == NULL) {
                                ost_thread_done(thread);
                                result = -ENOMEM;
                                break;
                        }
                }
        } else
                result = -ENOMEM;
        RETURN(result);
}

/* Sigh - really, this is an OSS, the _server_, not the _target_ */
static int ost_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct ost_obd *ost = &obd->u.ost;
        struct lprocfs_static_vars lvars;
        int oss_min_threads;
        int oss_max_threads;
        int oss_min_create_threads;
        int oss_max_create_threads;
        int rc;
        ENTRY;

        rc = cleanup_group_info();
        if (rc)
                RETURN(rc);
        lprocfs_ost_init_vars(&lvars);
        lprocfs_obd_setup(obd, lvars.obd_vars);

        sema_init(&ost->ost_health_sem, 1);

        if (oss_num_threads) {
                /* If oss_num_threads is set, it is the min and the max. */
                if (oss_num_threads > OSS_THREADS_MAX) 
                        oss_num_threads = OSS_THREADS_MAX;
                if (oss_num_threads < OSS_THREADS_MIN)
                        oss_num_threads = OSS_THREADS_MIN;
                oss_max_threads = oss_min_threads = oss_num_threads;
        } else {
                /* Base min threads on memory and cpus */
                oss_min_threads = num_possible_cpus() * num_physpages >> 
                        (27 - CFS_PAGE_SHIFT);
                if (oss_min_threads < OSS_THREADS_MIN)
                        oss_min_threads = OSS_THREADS_MIN;
                /* Insure a 4x range for dynamic threads */
                if (oss_min_threads > OSS_THREADS_MAX / 4) 
                        oss_min_threads = OSS_THREADS_MAX / 4;
                oss_max_threads = min(OSS_THREADS_MAX, oss_min_threads * 4);
        }

        ost->ost_service =
                ptlrpc_init_svc(OST_NBUFS, OST_BUFSIZE, OST_MAXREQSIZE,
                                OST_MAXREPSIZE, OST_REQUEST_PORTAL,
                                OSC_REPLY_PORTAL, OSS_SERVICE_WATCHDOG_FACTOR, 
                                ost_handle, LUSTRE_OSS_NAME,
                                obd->obd_proc_entry, target_print_req,
                                oss_min_threads, oss_max_threads, "ll_ost");
        if (ost->ost_service == NULL) {
                CERROR("failed to start OST service\n");
                GOTO(out_lprocfs, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(obd, ost->ost_service);
        if (rc)
                GOTO(out_service, rc = -EINVAL);

        if (oss_num_create_threads) {
                if (oss_num_create_threads > OSS_MAX_CREATE_THREADS)
                        oss_num_create_threads = OSS_MAX_CREATE_THREADS;
                if (oss_num_create_threads < OSS_DEF_CREATE_THREADS)
                        oss_num_create_threads = OSS_DEF_CREATE_THREADS;
                oss_min_create_threads = oss_max_create_threads = 
                        oss_num_create_threads;
        } else {
                oss_min_create_threads = OSS_DEF_CREATE_THREADS;
                oss_max_create_threads = OSS_MAX_CREATE_THREADS;
        }

        ost->ost_create_service =
                ptlrpc_init_svc(OST_NBUFS, OST_BUFSIZE, OST_MAXREQSIZE,
                                OST_MAXREPSIZE, OST_CREATE_PORTAL,
                                OSC_REPLY_PORTAL, OSS_SERVICE_WATCHDOG_FACTOR,
                                ost_handle, "ost_create",
                                obd->obd_proc_entry, target_print_req,
                                oss_min_create_threads,
                                oss_max_create_threads,
                                "ll_ost_creat");
        if (ost->ost_create_service == NULL) {
                CERROR("failed to start OST create service\n");
                GOTO(out_service, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(obd, ost->ost_create_service);
        if (rc)
                GOTO(out_create, rc = -EINVAL);

        ost->ost_io_service =
                ptlrpc_init_svc(OST_NBUFS, OST_BUFSIZE, OST_MAXREQSIZE,
                                OST_MAXREPSIZE, OST_IO_PORTAL,
                                OSC_REPLY_PORTAL, OSS_SERVICE_WATCHDOG_FACTOR, 
                                ost_handle, "ost_io",
                                obd->obd_proc_entry, target_print_req,
                                oss_min_threads, oss_max_threads, "ll_ost_io");
        if (ost->ost_io_service == NULL) {
                CERROR("failed to start OST I/O service\n");
                GOTO(out_create, rc = -ENOMEM);
        }

        ost->ost_io_service->srv_init = ost_thread_init;
        ost->ost_io_service->srv_done = ost_thread_done;
        ost->ost_io_service->srv_cpu_affinity = 1;
        rc = ptlrpc_start_threads(obd, ost->ost_io_service);
        if (rc)
                GOTO(out_io, rc = -EINVAL);

        ping_evictor_start();

        RETURN(0);

out_io:
        ptlrpc_unregister_service(ost->ost_io_service);
        ost->ost_io_service = NULL;
out_create:
        ptlrpc_unregister_service(ost->ost_create_service);
        ost->ost_create_service = NULL;
out_service:
        ptlrpc_unregister_service(ost->ost_service);
        ost->ost_service = NULL;
out_lprocfs:
        lprocfs_obd_cleanup(obd);
        RETURN(rc);
}

static int ost_cleanup(struct obd_device *obd)
{
        struct ost_obd *ost = &obd->u.ost;
        int err = 0;
        ENTRY;

        ping_evictor_stop();

        spin_lock_bh(&obd->obd_processing_task_lock);
        if (obd->obd_recovering) {
                target_cancel_recovery_timer(obd);
                obd->obd_recovering = 0;
        }
        spin_unlock_bh(&obd->obd_processing_task_lock);

        down(&ost->ost_health_sem);
        ptlrpc_unregister_service(ost->ost_service);
        ptlrpc_unregister_service(ost->ost_create_service);
        ptlrpc_unregister_service(ost->ost_io_service);
        ost->ost_service = NULL;
        ost->ost_create_service = NULL;
        up(&ost->ost_health_sem);

        lprocfs_obd_cleanup(obd);

        RETURN(err);
}

static int ost_health_check(struct obd_device *obd)
{
        struct ost_obd *ost = &obd->u.ost;
        int rc = 0;

        down(&ost->ost_health_sem);
        rc |= ptlrpc_service_health_check(ost->ost_service);
        rc |= ptlrpc_service_health_check(ost->ost_create_service);
        rc |= ptlrpc_service_health_check(ost->ost_io_service);
        up(&ost->ost_health_sem);

        /*
         * health_check to return 0 on healthy
         * and 1 on unhealthy.
         */
        if( rc != 0)
                rc = 1;

        return rc;
}

struct ost_thread_local_cache *ost_tls(struct ptlrpc_request *r)
{
        return (struct ost_thread_local_cache *)(r->rq_svc_thread->t_data);
}

/* use obd ops to offer management infrastructure */
static struct obd_ops ost_obd_ops = {
        .o_owner        = THIS_MODULE,
        .o_setup        = ost_setup,
        .o_cleanup      = ost_cleanup,
        .o_health_check = ost_health_check,
};


static int __init ost_init(void)
{
        struct lprocfs_static_vars lvars;
        int rc;
        ENTRY;

        lprocfs_ost_init_vars(&lvars);
        rc = class_register_type(&ost_obd_ops, lvars.module_vars,
                                 LUSTRE_OSS_NAME);

        if (ost_num_threads != 0 && oss_num_threads == 0) {
                LCONSOLE_INFO("ost_num_threads module parameter is deprecated, "
                              "use oss_num_threads instead or unset both for "
                              "dynamic thread startup\n");
                oss_num_threads = ost_num_threads;
        }

        RETURN(rc);
}

static void /*__exit*/ ost_exit(void)
{
        class_unregister_type(LUSTRE_OSS_NAME);
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Object Storage Target (OST) v0.01");
MODULE_LICENSE("GPL");

module_init(ost_init);
module_exit(ost_exit);
