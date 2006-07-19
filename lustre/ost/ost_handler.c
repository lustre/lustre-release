/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 *
 *  Storage Target Handling functions
 *  Lustre Object Server Module (OST)
 *
 *  This server is single threaded at present (but can easily be multi
 *  threaded). For testing and management it is treated as an
 *  obd_device, although it does not export a full OBD method table
 *  (the requests are coming in over the wire, so object target
 *  modules do not have a full method table.)
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

static int ost_num_threads;
CFS_MODULE_PARM(ost_num_threads, "i", int, 0444,
                "number of OST service threads to start");

void oti_to_request(struct obd_trans_info *oti, struct ptlrpc_request *req)
{
        struct oti_req_ack_lock *ack_lock;
        int i;

        if (oti == NULL)
                return;

        if (req->rq_repmsg)
                req->rq_repmsg->transno = oti->oti_transno;
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
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_swab_reqbuf(req, 0, sizeof(*body), lustre_swab_ost_body);
        if (body == NULL)
                RETURN(-EFAULT);

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc)
                RETURN(rc);

        if (body->oa.o_valid & OBD_MD_FLCOOKIE)
                oti->oti_logcookies = obdo_logcookie(&body->oa);
        repbody = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*repbody));
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        req->rq_status = obd_destroy(exp, &body->oa, NULL, oti, NULL);
        RETURN(0);
}

static int ost_getattr(struct obd_export *exp, struct ptlrpc_request *req)
{
        struct ost_body *body, *repbody;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_swab_reqbuf(req, 0, sizeof(*body), lustre_swab_ost_body);
        if (body == NULL)
                RETURN(-EFAULT);

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf (req->rq_repmsg, 0, sizeof(*repbody));
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        req->rq_status = obd_getattr(exp, &repbody->oa, NULL);
        RETURN(0);
}

static int ost_statfs(struct ptlrpc_request *req)
{
        struct obd_statfs *osfs;
        int rc, size = sizeof(*osfs);
        ENTRY;

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc)
                RETURN(rc);

        osfs = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*osfs));

        req->rq_status = obd_statfs(req->rq_export->exp_obd, osfs, jiffies-HZ);
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
        int rc, size = sizeof(*repbody);
        ENTRY;

        body = lustre_swab_reqbuf(req, 0, sizeof(*body), lustre_swab_ost_body);
        if (body == NULL)
                RETURN(-EFAULT);

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf (req->rq_repmsg, 0, sizeof(*repbody));
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        oti->oti_logcookies = obdo_logcookie(&repbody->oa);
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

        RETURN(ldlm_cli_enqueue(NULL, NULL, exp->exp_obd->obd_namespace,
                                res_id, LDLM_EXTENT, &policy, LCK_PW, &flags,
                                ldlm_blocking_ast, ldlm_completion_ast,
                                ldlm_glimpse_ast,
                                NULL, NULL, 0, NULL, lh));
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
        struct obdo     *oa;
        struct ost_body *body, *repbody;
        struct lustre_handle lh = {0,};

        int rc, size = sizeof(*repbody);

        ENTRY;

        /*
         * check that we do support OBD_CONNECT_TRUNCLOCK.
         */
        CLASSERT(OST_CONNECT_SUPPORTED & OBD_CONNECT_TRUNCLOCK);

        body = lustre_swab_reqbuf(req, 0, sizeof *body, lustre_swab_ost_body);
        if (body == NULL)
                RETURN(-EFAULT);

        oa = &body->oa;
        if ((oa->o_valid & (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS)) !=
            (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS))
                RETURN(-EINVAL);

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*repbody));
        repbody->oa = *oa;
        rc = ost_punch_lock_get(exp, oa, &lh);
        if (rc == 0) {
                if (oa->o_valid & OBD_MD_FLFLAGS &&
                    oa->o_flags == OBD_FL_TRUNCLOCK)
                        /*
                         * If OBD_FL_TRUNCLOCK is the only bit set in
                         * ->o_flags, clear OBD_MD_FLFLAGS to avoid falling
                         * through filter_setattr() to filter_iocontrol().
                         */
                        oa->o_valid &= ~OBD_MD_FLFLAGS;

                req->rq_status = obd_punch(exp, oa, NULL,
                                           oa->o_size, oa->o_blocks, oti);
                ost_punch_lock_put(exp, oa, &lh);
        }
        RETURN(rc);
}

static int ost_sync(struct obd_export *exp, struct ptlrpc_request *req)
{
        struct ost_body *body, *repbody;
        int rc, size = sizeof(*repbody);
        ENTRY;

        body = lustre_swab_reqbuf(req, 0, sizeof(*body), lustre_swab_ost_body);
        if (body == NULL)
                RETURN(-EFAULT);

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*repbody));
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        req->rq_status = obd_sync(exp, &repbody->oa, NULL, repbody->oa.o_size,
                                  repbody->oa.o_blocks);
        RETURN(0);
}

static int ost_setattr(struct obd_export *exp, struct ptlrpc_request *req,
                       struct obd_trans_info *oti)
{
        struct ost_body *body, *repbody;
        int rc, size = sizeof(*repbody);
        ENTRY;

        body = lustre_swab_reqbuf(req, 0, sizeof(*body), lustre_swab_ost_body);
        if (body == NULL)
                RETURN(-EFAULT);

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*repbody));
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));

        req->rq_status = obd_setattr(exp, &repbody->oa, NULL, oti);
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
                        obd_off p0 = offset >> PAGE_SHIFT;
                        obd_off pn = (offset + rnb[rnbidx].len - 1)>>PAGE_SHIFT;

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
                                obd_off  poff = off & (PAGE_SIZE - 1);
                                int      pnob = (poff + nob > PAGE_SIZE) ?
                                                PAGE_SIZE - poff : nob;

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

static __u32 ost_checksum_bulk(struct ptlrpc_bulk_desc *desc)
{
        __u32 cksum = ~0;
        int i;

        for (i = 0; i < desc->bd_iov_count; i++) {
                struct page *page = desc->bd_iov[i].kiov_page;
                int off = desc->bd_iov[i].kiov_offset & ~PAGE_MASK;
                char *ptr = kmap(page) + off;
                int len = desc->bd_iov[i].kiov_len;

                cksum = crc32_le(cksum, ptr, len);
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

#if 0
/* see ldlm_blocking_ast */
/* cut-n-paste of mds_blocking_ast() */
static int ost_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
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
        /* Get this: if mds_blocking_ast is racing with mds_intent_policy,
         * such that mds_blocking_ast is called just before l_i_p takes the
         * ns_lock, then by the time we get the lock, we might not be the
         * correct blocking function anymore.  So check, and return early, if
         * so. */
        if (lock->l_blocking_ast != ost_blocking_ast) {
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
#endif

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

        RETURN(ldlm_cli_enqueue(NULL, NULL, exp->exp_obd->obd_namespace,
                                res_id, LDLM_EXTENT, &policy, mode, &flags,
                                ldlm_blocking_ast, ldlm_completion_ast,
                                ldlm_glimpse_ast,
                                NULL, NULL, 0, NULL, lh));
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

static int ost_brw_read(struct ptlrpc_request *req, struct obd_trans_info *oti)
{
        struct ptlrpc_bulk_desc *desc;
        struct niobuf_remote    *remote_nb;
        struct niobuf_remote    *pp_rnb = NULL;
        struct niobuf_local     *local_nb;
        struct obd_ioobj        *ioo;
        struct ost_body         *body, *repbody;
        struct l_wait_info       lwi;
        struct lustre_handle     lockh = {0};
        int                      size[1] = { sizeof(*body) };
        int                      comms_error = 0;
        int                      niocount;
        int                      npages;
        int                      nob = 0;
        int                      rc;
        int                      i, do_checksum;
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_OST_BRW_READ_BULK))
                GOTO(out, rc = -EIO);

        OBD_FAIL_TIMEOUT(OBD_FAIL_OST_BRW_PAUSE_BULK | OBD_FAIL_ONCE,
                         (obd_timeout + 1) / 4);

        body = lustre_swab_reqbuf(req, 0, sizeof(*body), lustre_swab_ost_body);
        if (body == NULL) {
                CERROR("Missing/short ost_body\n");
                GOTO(out, rc = -EFAULT);
        }

        ioo = lustre_swab_reqbuf(req, 1, sizeof(*ioo), lustre_swab_obd_ioobj);
        if (ioo == NULL) {
                CERROR("Missing/short ioobj\n");
                GOTO(out, rc = -EFAULT);
        }

        niocount = ioo->ioo_bufcnt;
        if (niocount > PTLRPC_MAX_BRW_PAGES) {
                DEBUG_REQ(D_ERROR, req, "bulk has too many pages (%d)\n",
                          niocount);
                GOTO(out, rc = -EFAULT);
        }

        remote_nb = lustre_swab_reqbuf(req, 2, niocount * sizeof(*remote_nb),
                                       lustre_swab_niobuf_remote);
        if (remote_nb == NULL) {
                CERROR("Missing/short niobuf\n");
                GOTO(out, rc = -EFAULT);
        }
        if (lustre_msg_swabbed(req->rq_reqmsg)) { /* swab remaining niobufs */
                for (i = 1; i < niocount; i++)
                        lustre_swab_niobuf_remote (&remote_nb[i]);
        }

        rc = lustre_pack_reply(req, 1, size, NULL);
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

        rc = ost_brw_lock_get(LCK_PR, req->rq_export, ioo, pp_rnb, &lockh);
        if (rc != 0)
                GOTO(out_bulk, rc);

        rc = obd_preprw(OBD_BRW_READ, req->rq_export, &body->oa, 1,
                        ioo, npages, pp_rnb, local_nb, oti);
        if (rc != 0)
                GOTO(out_lock, rc);

        /* We're finishing using body->oa as an input variable */
        do_checksum = (body->oa.o_valid & OBD_MD_FLCKSUM);
        body->oa.o_valid = 0;

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
                                              pp_rnb[i].offset & (PAGE_SIZE-1),
                                              page_rc);
                }

                if (page_rc != pp_rnb[i].len) { /* short read */
                        /* All subsequent pages should be 0 */
                        while(++i < npages)
                                LASSERT(local_nb[i].rc == 0);
                        break;
                }
        }

        /* Check if client was evicted while we were doing i/o before touching
           network */
        if (rc == 0) {
                if (desc->bd_export->exp_failed)
                        rc = -ENOTCONN;
                else
                        rc = ptlrpc_start_bulk_transfer(desc);
                if (rc == 0) {
                        lwi = LWI_TIMEOUT_INTERVAL(obd_timeout * HZ / 4, HZ,
                                                   ost_bulk_timeout, desc);
                        rc = l_wait_event(desc->bd_waitq,
                                          !ptlrpc_bulk_active(desc) ||
                                          desc->bd_export->exp_failed, &lwi);
                        LASSERT(rc == 0 || rc == -ETIMEDOUT);
                        if (rc == -ETIMEDOUT) {
                                DEBUG_REQ(D_ERROR, req, "timeout on bulk PUT");
                                ptlrpc_abort_bulk(desc);
                        } else if (desc->bd_export->exp_failed) {
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
                        DEBUG_REQ(D_ERROR, req, "bulk PUT failed: rc %d\n", rc);
                }
                comms_error = rc != 0;
        }

        /* Must commit after prep above in all cases */
        rc = obd_commitrw(OBD_BRW_READ, req->rq_export, &body->oa, 1,
                          ioo, npages, local_nb, oti, rc);

        ost_nio_pages_put(req, local_nb, npages);

        if (rc == 0) {
                repbody = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*repbody));
                memcpy(&repbody->oa, &body->oa, sizeof(repbody->oa));

                if (unlikely(do_checksum)) {
                        repbody->oa.o_cksum = ost_checksum_bulk(desc);
                        repbody->oa.o_valid |= OBD_MD_FLCKSUM;
                        CDEBUG(D_PAGE, "checksum at read origin: %x\n",
                               repbody->oa.o_cksum);
                }
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
        } else if (!comms_error) {
                /* Only reply if there was no comms problem with bulk */
                target_committed_to_req(req);
                req->rq_status = rc;
                ptlrpc_error(req);
        } else {
                if (req->rq_reply_state != NULL) {
                        /* reply out callback would free */
                        ptlrpc_rs_decref(req->rq_reply_state);
                        req->rq_reply_state = NULL;
                }
                if (req->rq_reqmsg->conn_cnt == req->rq_export->exp_conn_cnt) {
                        CERROR("%s: bulk IO comm error evicting %s@%s id %s\n",
                               req->rq_export->exp_obd->obd_name,
                               req->rq_export->exp_client_uuid.uuid,
                               req->rq_export->exp_connection->c_remote_uuid.uuid,
                               libcfs_id2str(req->rq_peer));
                        class_fail_export(req->rq_export);
                } else {
                        CERROR("ignoring bulk IO comms error: "
                               "client reconnected %s@%s id %s\n",
                               req->rq_export->exp_client_uuid.uuid,
                               req->rq_export->exp_connection->c_remote_uuid.uuid,
                               libcfs_id2str(req->rq_peer));
                }
        }

        RETURN(rc);
}

static int ost_brw_write(struct ptlrpc_request *req, struct obd_trans_info *oti)
{
        struct ptlrpc_bulk_desc *desc;
        struct niobuf_remote    *remote_nb;
        struct niobuf_remote    *pp_rnb;
        struct niobuf_local     *local_nb;
        struct obd_ioobj        *ioo;
        struct ost_body         *body, *repbody;
        struct l_wait_info       lwi;
        struct lustre_handle     lockh = {0};
        __u32                   *rcs;
        int                      size[2] = { sizeof(*body) };
        int                      objcount, niocount, npages;
        int                      comms_error = 0;
        int                      rc, swab, i, j, do_checksum;
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_OST_BRW_WRITE_BULK))
                GOTO(out, rc = -EIO);

        /* pause before transaction has been started */
        OBD_FAIL_TIMEOUT(OBD_FAIL_OST_BRW_PAUSE_BULK | OBD_FAIL_ONCE,
                         (obd_timeout + 1) / 4);

        swab = lustre_msg_swabbed(req->rq_reqmsg);
        body = lustre_swab_reqbuf(req, 0, sizeof(*body), lustre_swab_ost_body);
        if (body == NULL) {
                CERROR("Missing/short ost_body\n");
                GOTO(out, rc = -EFAULT);
        }

        LASSERT_REQSWAB(req, 1);
        objcount = req->rq_reqmsg->buflens[1] / sizeof(*ioo);
        if (objcount == 0) {
                CERROR("Missing/short ioobj\n");
                GOTO(out, rc = -EFAULT);
        }
        if (objcount > 1) {
                CERROR("too many ioobjs (%d)\n", objcount);
                GOTO(out, rc = -EFAULT);
        }

        ioo = lustre_msg_buf (req->rq_reqmsg, 1, objcount * sizeof(*ioo));
        LASSERT (ioo != NULL);
        for (niocount = i = 0; i < objcount; i++) {
                if (swab)
                        lustre_swab_obd_ioobj (&ioo[i]);
                if (ioo[i].ioo_bufcnt == 0) {
                        CERROR("ioo[%d] has zero bufcnt\n", i);
                        GOTO(out, rc = -EFAULT);
                }
                niocount += ioo[i].ioo_bufcnt;
        }

        if (niocount > PTLRPC_MAX_BRW_PAGES) {
                DEBUG_REQ(D_ERROR, req, "bulk has too many pages (%d)\n",
                          niocount);
                GOTO(out, rc = -EFAULT);
        }

        remote_nb = lustre_swab_reqbuf(req, 2, niocount * sizeof(*remote_nb),
                                       lustre_swab_niobuf_remote);
        if (remote_nb == NULL) {
                CERROR("Missing/short niobuf\n");
                GOTO(out, rc = -EFAULT);
        }
        if (swab) {                             /* swab the remaining niobufs */
                for (i = 1; i < niocount; i++)
                        lustre_swab_niobuf_remote (&remote_nb[i]);
        }

        size[1] = niocount * sizeof(*rcs);
        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc != 0)
                GOTO(out, rc);
        rcs = lustre_msg_buf(req->rq_repmsg, 1, niocount * sizeof(*rcs));

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

        rc = ost_brw_lock_get(LCK_PW, req->rq_export, ioo, pp_rnb, &lockh);
        if (rc != 0)
                GOTO(out_bulk, rc);

        /* obd_preprw clobbers oa->valid, so save what we need */
        do_checksum = (body->oa.o_valid & OBD_MD_FLCKSUM);

        rc = obd_preprw(OBD_BRW_WRITE, req->rq_export, &body->oa, objcount,
                        ioo, npages, pp_rnb, local_nb, oti);
        if (rc != 0)
                GOTO(out_lock, rc);

        /* NB Having prepped, we must commit... */

        for (i = 0; i < npages; i++)
                ptlrpc_prep_bulk_page(desc, local_nb[i].page,
                                      pp_rnb[i].offset & (PAGE_SIZE - 1),
                                      pp_rnb[i].len);

        /* Check if client was evicted while we were doing i/o before touching
           network */
        if (desc->bd_export->exp_failed)
                rc = -ENOTCONN;
        else
                rc = ptlrpc_start_bulk_transfer (desc);
        if (rc == 0) {
                lwi = LWI_TIMEOUT_INTERVAL(obd_timeout * HZ / 4, HZ,
                                           ost_bulk_timeout, desc);
                rc = l_wait_event(desc->bd_waitq, !ptlrpc_bulk_active(desc) ||
                                  desc->bd_export->exp_failed, &lwi);
                LASSERT(rc == 0 || rc == -ETIMEDOUT);
                if (rc == -ETIMEDOUT) {
                        DEBUG_REQ(D_ERROR, req, "timeout on bulk GET");
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
                DEBUG_REQ(D_ERROR, req, "ptlrpc_bulk_get failed: rc %d\n", rc);
        }
        comms_error = rc != 0;

        repbody = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*repbody));
        memcpy(&repbody->oa, &body->oa, sizeof(repbody->oa));

        if (unlikely(do_checksum && rc == 0)) {
                static int cksum_counter;
                obd_count client_cksum = body->oa.o_cksum;
                obd_count cksum = ost_checksum_bulk(desc);

                cksum_counter++;
                if (client_cksum != cksum) {
                        CERROR("Bad checksum: client %x, server %x id %s\n",
                               client_cksum, cksum,
                               libcfs_id2str(req->rq_peer));
                        cksum_counter = 0;
                        repbody->oa.o_cksum = cksum;
                        repbody->oa.o_valid |= OBD_MD_FLCKSUM;
                } else if ((cksum_counter & (-cksum_counter)) ==
                           cksum_counter) {
                        CWARN("Checksum %u from %s: %x OK\n", cksum_counter,
                              libcfs_id2str(req->rq_peer), cksum);
                } else {
                        cksum_counter++;
                        if ((cksum_counter & (-cksum_counter)) == cksum_counter)
                                CWARN("Checksum %u from %s: %x OK\n",
                                      cksum_counter,
                                      libcfs_id2str(req->rq_peer), cksum);
                }
        }

        /* Must commit after prep above in all cases */
        rc = obd_commitrw(OBD_BRW_WRITE, req->rq_export, &repbody->oa,
                           objcount, ioo, npages, local_nb, oti, rc);

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
        } else if (!comms_error) {
                /* Only reply if there was no comms problem with bulk */
                target_committed_to_req(req);
                req->rq_status = rc;
                ptlrpc_error(req);
        } else {
                if (req->rq_reply_state != NULL) {
                        /* reply out callback would free */
                        ptlrpc_rs_decref(req->rq_reply_state);
                        req->rq_reply_state = NULL;
                }
                if (req->rq_reqmsg->conn_cnt == req->rq_export->exp_conn_cnt) {
                        CERROR("%s: bulk IO comm error evicting %s@%s id %s\n",
                               req->rq_export->exp_obd->obd_name,
                               req->rq_export->exp_client_uuid.uuid,
                               req->rq_export->exp_connection->c_remote_uuid.uuid,
                               libcfs_id2str(req->rq_peer));
                        class_fail_export(req->rq_export);
                } else {
                        CERROR("ignoring bulk IO comms error: "
                               "client reconnected %s@%s id %s\n",
                               req->rq_export->exp_client_uuid.uuid,
                               req->rq_export->exp_connection->c_remote_uuid.uuid,
                               libcfs_id2str(req->rq_peer));
                }
        }
        RETURN(rc);
}

static int ost_san_brw(struct ptlrpc_request *req, int cmd)
{
        struct niobuf_remote *remote_nb, *res_nb, *pp_rnb = NULL;
        struct obd_ioobj *ioo;
        struct ost_body *body, *repbody;
        int rc, i, objcount, niocount, size[2] = {sizeof(*body)}, npages;
        int swab;
        ENTRY;

        /* XXX not set to use latest protocol */

        swab = lustre_msg_swabbed(req->rq_reqmsg);
        body = lustre_swab_reqbuf(req, 0, sizeof(*body), lustre_swab_ost_body);
        if (body == NULL) {
                CERROR("Missing/short ost_body\n");
                GOTO(out, rc = -EFAULT);
        }

        ioo = lustre_swab_reqbuf(req, 1, sizeof(*ioo), lustre_swab_obd_ioobj);
        if (ioo == NULL) {
                CERROR("Missing/short ioobj\n");
                GOTO(out, rc = -EFAULT);
        }
        objcount = req->rq_reqmsg->buflens[1] / sizeof(*ioo);
        niocount = ioo[0].ioo_bufcnt;
        for (i = 1; i < objcount; i++) {
                if (swab)
                        lustre_swab_obd_ioobj (&ioo[i]);
                niocount += ioo[i].ioo_bufcnt;
        }

        remote_nb = lustre_swab_reqbuf(req, 2, niocount * sizeof(*remote_nb),
                                       lustre_swab_niobuf_remote);
        if (remote_nb == NULL) {
                CERROR("Missing/short niobuf\n");
                GOTO(out, rc = -EFAULT);
        }
        if (swab) {                             /* swab the remaining niobufs */
                for (i = 1; i < niocount; i++)
                        lustre_swab_niobuf_remote (&remote_nb[i]);
        }

        /*
         * Per-thread array of struct niobuf_remote's was allocated by
         * ost_thread_init().
         */
        pp_rnb = ost_tls(req)->remote;

        /* CAVEAT EMPTOR this sets ioo->ioo_bufcnt to # pages */
        npages = get_per_page_niobufs(ioo, objcount,remote_nb,niocount,&pp_rnb);
        if (npages < 0)
                GOTO (out, rc = npages);

        size[1] = npages * sizeof(*pp_rnb);
        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc)
                GOTO(out, rc);

        req->rq_status = obd_san_preprw(cmd, req->rq_export, &body->oa,
                                        objcount, ioo, npages, pp_rnb);

        if (req->rq_status)
                GOTO(out, rc = 0);

        repbody = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*repbody));
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));

        res_nb = lustre_msg_buf(req->rq_repmsg, 1, size[1]);
        memcpy(res_nb, remote_nb, size[1]);
        rc = 0;
out:
        target_committed_to_req(req);
        if (rc) {
                req->rq_status = rc;
                ptlrpc_error(req);
        } else {
                ptlrpc_reply(req);
        }

        return rc;
}


static int ost_set_info(struct obd_export *exp, struct ptlrpc_request *req)
{
        char *key, *val = NULL;
        int keylen, vallen, rc = 0;
        ENTRY;

        key = lustre_msg_buf(req->rq_reqmsg, 0, 1);
        if (key == NULL) {
                DEBUG_REQ(D_HA, req, "no set_info key");
                RETURN(-EFAULT);
        }
        keylen = lustre_msg_buflen(req->rq_reqmsg,0);

        rc = lustre_pack_reply(req, 0, NULL, NULL);
        if (rc)
                RETURN(rc);

        vallen = lustre_msg_buflen(req->rq_reqmsg, 1);
        if (vallen)
                val = lustre_msg_buf(req->rq_reqmsg, 1, 0);

        if (KEY_IS("evict_by_nid")) {
                if (val && vallen)
                        obd_export_evict_by_nid(exp->exp_obd, val);

                GOTO(out, rc = 0);
        }

        rc = obd_set_info_async(exp, keylen, key, vallen, val, NULL);
out:
        req->rq_repmsg->status = 0;
        RETURN(rc);
}

static int ost_get_info(struct obd_export *exp, struct ptlrpc_request *req)
{
        char *key;
        int keylen, rc = 0, size = sizeof(obd_id);
        obd_id *reply;
        ENTRY;

        key = lustre_msg_buf(req->rq_reqmsg, 0, 1);
        if (key == NULL) {
                DEBUG_REQ(D_HA, req, "no get_info key");
                RETURN(-EFAULT);
        }
        keylen = req->rq_reqmsg->buflens[0];

        if (keylen < strlen("last_id") || memcmp(key, "last_id", 7) != 0)
                RETURN(-EPROTO);

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc)
                RETURN(rc);

        reply = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*reply));
        rc = obd_get_info(exp, keylen, key, &size, reply);
        req->rq_repmsg->status = 0;
        RETURN(rc);
}

static int ost_handle_quotactl(struct ptlrpc_request *req)
{
        struct obd_quotactl *oqctl, *repoqc;
        int rc, size = sizeof(*repoqc);
        ENTRY;

        oqctl = lustre_swab_reqbuf(req, 0, sizeof(*oqctl),
                                   lustre_swab_obd_quotactl);
        if (oqctl == NULL)
                GOTO(out, rc = -EPROTO);

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc)
                GOTO(out, rc);

        repoqc = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*repoqc));

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

        oqctl = lustre_swab_reqbuf(req, 0, sizeof(*oqctl),
                                   lustre_swab_obd_quotactl);
        if (oqctl == NULL)
                RETURN(-EPROTO);

        rc = lustre_pack_reply(req, 0, NULL, NULL);
        if (rc) {
                CERROR("ost: out of memory while packing quotacheck reply\n");
                RETURN(-ENOMEM);
        }

        req->rq_status = obd_quotacheck(req->rq_export, oqctl);
        RETURN(0);
}

static int ost_filter_recovery_request(struct ptlrpc_request *req,
                                       struct obd_device *obd, int *process)
{
        switch (req->rq_reqmsg->opc) {
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

        /* TODO: enable the below check while really introducing msg version.
         * it's disabled because it will break compatibility with b1_4.
         */
        return (0);
        switch(msg->opc) {
        case OST_CONNECT:
        case OST_DISCONNECT:
        case OBD_PING:
                rc = lustre_msg_check_version(msg, LUSTRE_OBD_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               msg->opc, msg->version, LUSTRE_OBD_VERSION);
                break;
        case OST_CREATE:
        case OST_DESTROY:
        case OST_GETATTR:
        case OST_SETATTR:
        case OST_WRITE:
        case OST_READ:
        case OST_SAN_READ:
        case OST_SAN_WRITE:
        case OST_PUNCH:
        case OST_STATFS:
        case OST_SYNC:
        case OST_SET_INFO:
        case OST_GET_INFO:
        case OST_QUOTACHECK:
        case OST_QUOTACTL:
                rc = lustre_msg_check_version(msg, LUSTRE_OST_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               msg->opc, msg->version, LUSTRE_OST_VERSION);
                break;
        case LDLM_ENQUEUE:
        case LDLM_CONVERT:
        case LDLM_CANCEL:
        case LDLM_BL_CALLBACK:
        case LDLM_CP_CALLBACK:
                rc = lustre_msg_check_version(msg, LUSTRE_DLM_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               msg->opc, msg->version, LUSTRE_DLM_VERSION);
                break;
        case LLOG_ORIGIN_CONNECT:
        case OBD_LOG_CANCEL:
                rc = lustre_msg_check_version(msg, LUSTRE_LOG_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               msg->opc, msg->version, LUSTRE_LOG_VERSION);
        default:
                CERROR("Unexpected opcode %d\n", msg->opc);
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
        if (req->rq_reqmsg->opc != OST_CONNECT) {
                int abort_recovery, recovering;

                if (req->rq_export == NULL) {
                        CDEBUG(D_HA,"operation %d on unconnected OST from %s\n",
                               req->rq_reqmsg->opc, libcfs_id2str(req->rq_peer));
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

        switch (req->rq_reqmsg->opc) {
        case OST_CONNECT: {
                CDEBUG(D_INODE, "connect\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_CONNECT_NET, 0);
                rc = target_handle_connect(req, ost_handle);
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
                OBD_FAIL_RETURN(OBD_FAIL_OST_BRW_NET, 0);
                rc = ost_brw_read(req, oti);
                LASSERT(current->journal_info == NULL);
                /* ost_brw_read sends its own replies */
                RETURN(rc);
        case OST_SAN_READ:
                CDEBUG(D_INODE, "san read\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_BRW_NET, 0);
                rc = ost_san_brw(req, OBD_BRW_READ);
                /* ost_san_brw sends its own replies */
                RETURN(rc);
        case OST_SAN_WRITE:
                CDEBUG(D_INODE, "san write\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_BRW_NET, 0);
                rc = ost_san_brw(req, OBD_BRW_WRITE);
                /* ost_san_brw sends its own replies */
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
        case OBD_PING:
                DEBUG_REQ(D_INODE, req, "ping");
                rc = target_handle_ping(req);
                break;
        /* FIXME - just reply status */
        case LLOG_ORIGIN_CONNECT:
                DEBUG_REQ(D_INODE, req, "log connect\n");
                rc = llog_handle_connect(req);
                req->rq_status = rc;
                rc = lustre_pack_reply(req, 0, NULL, NULL);
                if (rc)
                        RETURN(rc);
                RETURN(ptlrpc_reply(req));
        case OBD_LOG_CANCEL:
                CDEBUG(D_INODE, "log cancel\n");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOG_CANCEL_NET, 0);
                rc = llog_origin_handle_cancel(req);
                req->rq_status = rc;
                rc = lustre_pack_reply(req, 0, NULL, NULL);
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
                CERROR("Unexpected opcode %d\n", req->rq_reqmsg->opc);
                req->rq_status = -ENOTSUPP;
                rc = ptlrpc_error(req);
                RETURN(rc);
        }

        LASSERT(current->journal_info == NULL);

        EXIT;
        /* If we're DISCONNECTing, the export_data is already freed */
        if (!rc && req->rq_reqmsg->opc != OST_DISCONNECT)
                target_committed_to_req(req);

out:
        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_LAST_REPLAY) {
                if (obd && obd->obd_recovering) {
                        DEBUG_REQ(D_HA, req, "LAST_REPLAY, queuing reply");
                        return target_queue_final_reply(req, rc);
                }
                /* Lost a race with recovery; let the error path DTRT. */
                rc = req->rq_status = -ENOTCONN;
        }

        if (!rc)
                oti_to_request(oti, req);

        target_send_reply(req, rc, fail);
        return 0;
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
                                __free_page(tls->page[i]);
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
        LASSERT(thread->t_id < OST_MAX_THREADS);

        OBD_ALLOC_PTR(tls);
        if (tls != NULL) {
                result = 0;
                thread->t_data = tls;
                /*
                 * populate pool
                 */
                for (i = 0; i < OST_THREAD_POOL_SIZE; ++ i) {
                        tls->page[i] = alloc_page(OST_THREAD_POOL_GFP);
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

static int ost_setup(struct obd_device *obd, struct lustre_cfg* lcfg)
{
        struct ost_obd *ost = &obd->u.ost;
        struct lprocfs_static_vars lvars;
        int rc;
        ENTRY;

        rc = cleanup_group_info();
        if (rc)
                RETURN(rc);

        rc = llog_start_commit_thread();
        if (rc < 0)
                RETURN(rc);

        lprocfs_init_vars(ost, &lvars);
        lprocfs_obd_setup(obd, lvars.obd_vars);

        sema_init(&ost->ost_health_sem, 1);

        if (ost_num_threads < 2)
                ost_num_threads = OST_DEF_THREADS;
        if (ost_num_threads > OST_MAX_THREADS)
                ost_num_threads = OST_MAX_THREADS;

        ost->ost_service =
                ptlrpc_init_svc(OST_NBUFS, OST_BUFSIZE, OST_MAXREQSIZE,
                                OST_MAXREPSIZE, OST_REQUEST_PORTAL,
                                OSC_REPLY_PORTAL,
                                obd_timeout * 1000, ost_handle, LUSTRE_OSS_NAME,
                                obd->obd_proc_entry, ost_print_req,
                                ost_num_threads, LCT_DT_THREAD);
        if (ost->ost_service == NULL) {
                CERROR("failed to start service\n");
                GOTO(out_lprocfs, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(obd, ost->ost_service, "ll_ost");
        if (rc)
                GOTO(out_service, rc = -EINVAL);

        ost->ost_create_service =
                ptlrpc_init_svc(OST_NBUFS, OST_BUFSIZE, OST_MAXREQSIZE,
                                OST_MAXREPSIZE, OST_CREATE_PORTAL,
                                OSC_REPLY_PORTAL,
                                obd_timeout * 1000, ost_handle, "ost_create",
                                obd->obd_proc_entry, ost_print_req, 1,
                                LCT_DT_THREAD);
        if (ost->ost_create_service == NULL) {
                CERROR("failed to start OST create service\n");
                GOTO(out_service, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(obd, ost->ost_create_service,
                                  "ll_ost_creat");
        if (rc)
                GOTO(out_create, rc = -EINVAL);

        ost->ost_io_service =
                ptlrpc_init_svc(OST_NBUFS, OST_BUFSIZE, OST_MAXREQSIZE,
                                OST_MAXREPSIZE, OST_IO_PORTAL,
                                OSC_REPLY_PORTAL,
                                obd_timeout * 1000, ost_handle, "ost_io",
                                obd->obd_proc_entry, ost_print_req,
                                ost_num_threads, LCT_DT_THREAD);
        if (ost->ost_io_service == NULL) {
                CERROR("failed to start OST I/O service\n");
                GOTO(out_create, rc = -ENOMEM);
        }

        ost->ost_io_service->srv_init = ost_thread_init;
        ost->ost_io_service->srv_done = ost_thread_done;
        ost->ost_io_service->srv_cpu_affinity = 1;
        rc = ptlrpc_start_threads(obd, ost->ost_io_service,
                                  "ll_ost_io");
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

        lprocfs_init_vars(ost, &lvars);
        rc = class_register_type(&ost_obd_ops, NULL, lvars.module_vars,
                                 LUSTRE_OSS_NAME, NULL);
        RETURN(rc);
}

static void /*__exit*/ ost_exit(void)
{
        class_unregister_type(LUSTRE_OSS_NAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Object Storage Target (OST) v0.01");
MODULE_LICENSE("GPL");

module_init(ost_init);
module_exit(ost_exit);
