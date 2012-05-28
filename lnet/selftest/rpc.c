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
 * lnet/selftest/rpc.c
 *
 * Author: Isaac Huang <isaac@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LNET

#include "selftest.h"


typedef enum {
        SRPC_STATE_NONE,
        SRPC_STATE_NI_INIT,
        SRPC_STATE_EQ_INIT,
        SRPC_STATE_RUNNING,
        SRPC_STATE_STOPPING,
} srpc_state_t;

struct smoketest_rpc {
        cfs_spinlock_t    rpc_glock;     /* global lock */
        srpc_service_t   *rpc_services[SRPC_SERVICE_MAX_ID + 1];
        lnet_handle_eq_t  rpc_lnet_eq;   /* _the_ LNet event queue */
        srpc_state_t      rpc_state;
        srpc_counters_t   rpc_counters;
        __u64             rpc_matchbits; /* matchbits counter */
} srpc_data;

/* forward ref's */
int srpc_handle_rpc (swi_workitem_t *wi);

void srpc_get_counters (srpc_counters_t *cnt)
{
        cfs_spin_lock(&srpc_data.rpc_glock);
        *cnt = srpc_data.rpc_counters;
        cfs_spin_unlock(&srpc_data.rpc_glock);
}

void srpc_set_counters (const srpc_counters_t *cnt)
{
        cfs_spin_lock(&srpc_data.rpc_glock);
        srpc_data.rpc_counters = *cnt;
        cfs_spin_unlock(&srpc_data.rpc_glock);
}

void
srpc_add_bulk_page (srpc_bulk_t *bk, cfs_page_t *pg, int i)
{
        LASSERT (i >= 0 && i < bk->bk_niov);

#ifdef __KERNEL__
        bk->bk_iovs[i].kiov_offset = 0;
        bk->bk_iovs[i].kiov_page   = pg;
        bk->bk_iovs[i].kiov_len    = CFS_PAGE_SIZE;
#else
        LASSERT (bk->bk_pages != NULL);

        bk->bk_pages[i] = pg;
        bk->bk_iovs[i].iov_len  = CFS_PAGE_SIZE;
        bk->bk_iovs[i].iov_base = cfs_page_address(pg);
#endif
        return;
}

void
srpc_free_bulk (srpc_bulk_t *bk)
{
        int         i;
        cfs_page_t *pg;

        LASSERT (bk != NULL);
#ifndef __KERNEL__
        LASSERT (bk->bk_pages != NULL);
#endif

        for (i = 0; i < bk->bk_niov; i++) {
#ifdef __KERNEL__
                pg = bk->bk_iovs[i].kiov_page;
#else
                pg = bk->bk_pages[i];
#endif
                if (pg == NULL) break;

                cfs_free_page(pg);
        }

#ifndef __KERNEL__
        LIBCFS_FREE(bk->bk_pages, sizeof(cfs_page_t *) * bk->bk_niov);
#endif
        LIBCFS_FREE(bk, offsetof(srpc_bulk_t, bk_iovs[bk->bk_niov]));
        return;
}

srpc_bulk_t *
srpc_alloc_bulk (int npages, int sink)
{
        srpc_bulk_t  *bk;
        cfs_page_t  **pages;
        int           i;

        LASSERT (npages > 0 && npages <= LNET_MAX_IOV);

        LIBCFS_ALLOC(bk, offsetof(srpc_bulk_t, bk_iovs[npages]));
        if (bk == NULL) {
                CERROR ("Can't allocate descriptor for %d pages\n", npages);
                return NULL;
        }

        memset(bk, 0, offsetof(srpc_bulk_t, bk_iovs[npages]));
        bk->bk_sink = sink;
        bk->bk_niov = npages;
        bk->bk_len  = npages * CFS_PAGE_SIZE;
#ifndef __KERNEL__
        LIBCFS_ALLOC(pages, sizeof(cfs_page_t *) * npages);
        if (pages == NULL) {
                LIBCFS_FREE(bk, offsetof(srpc_bulk_t, bk_iovs[npages]));
                CERROR ("Can't allocate page array for %d pages\n", npages);
                return NULL;
        }

        memset(pages, 0, sizeof(cfs_page_t *) * npages);
        bk->bk_pages = pages;
#else
        UNUSED (pages);
#endif

        for (i = 0; i < npages; i++) {
                cfs_page_t *pg = cfs_alloc_page(CFS_ALLOC_STD);

                if (pg == NULL) {
                        CERROR ("Can't allocate page %d of %d\n", i, npages);
                        srpc_free_bulk(bk);
                        return NULL;
                }

                srpc_add_bulk_page(bk, pg, i);
        }

        return bk;
}

static inline __u64
srpc_next_id (void)
{
        __u64 id;

        cfs_spin_lock(&srpc_data.rpc_glock);
        id = srpc_data.rpc_matchbits++;
        cfs_spin_unlock(&srpc_data.rpc_glock);
        return id;
}

void
srpc_init_server_rpc (srpc_server_rpc_t *rpc,
                      srpc_service_t *sv, srpc_buffer_t *buffer)
{
        memset(rpc, 0, sizeof(*rpc));
        swi_init_workitem(&rpc->srpc_wi, rpc, srpc_handle_rpc,
                          sv->sv_id <= SRPC_FRAMEWORK_SERVICE_MAX_ID ?
                          CFS_WI_SCHED_SERIAL : CFS_WI_SCHED_ANY);

        rpc->srpc_ev.ev_fired = 1; /* no event expected now */

        rpc->srpc_service  = sv;
        rpc->srpc_reqstbuf = buffer;
        rpc->srpc_peer     = buffer->buf_peer;
        rpc->srpc_self     = buffer->buf_self;
        LNetInvalidateHandle(&rpc->srpc_replymdh);
}

int
srpc_add_service (srpc_service_t *sv)
{
        int                id = sv->sv_id;
        int                i;
        srpc_server_rpc_t *rpc;

        LASSERT (sv->sv_concur > 0);
        LASSERT (0 <= id && id <= SRPC_SERVICE_MAX_ID);

        cfs_spin_lock(&srpc_data.rpc_glock);

        LASSERT (srpc_data.rpc_state == SRPC_STATE_RUNNING);

        if (srpc_data.rpc_services[id] != NULL) {
                cfs_spin_unlock(&srpc_data.rpc_glock);
                return -EBUSY;
        }

        srpc_data.rpc_services[id] = sv;
        cfs_spin_unlock(&srpc_data.rpc_glock);

        sv->sv_nprune       = 0;
        sv->sv_nposted_msg  = 0;
        sv->sv_shuttingdown = 0;
        cfs_spin_lock_init(&sv->sv_lock);
        CFS_INIT_LIST_HEAD(&sv->sv_free_rpcq);
        CFS_INIT_LIST_HEAD(&sv->sv_active_rpcq);
        CFS_INIT_LIST_HEAD(&sv->sv_posted_msgq);
        CFS_INIT_LIST_HEAD(&sv->sv_blocked_msgq);

        sv->sv_ev.ev_data = sv;
        sv->sv_ev.ev_type = SRPC_REQUEST_RCVD;

        for (i = 0; i < sv->sv_concur; i++) {
                LIBCFS_ALLOC(rpc, sizeof(*rpc));
                if (rpc == NULL) goto enomem;

                cfs_list_add(&rpc->srpc_list, &sv->sv_free_rpcq);
        }

        CDEBUG (D_NET, "Adding service: id %d, name %s, concurrency %d\n",
                id, sv->sv_name, sv->sv_concur);
        return 0;

enomem:
        while (!cfs_list_empty(&sv->sv_free_rpcq)) {
                rpc = cfs_list_entry(sv->sv_free_rpcq.next,
                                     srpc_server_rpc_t, srpc_list);
                cfs_list_del(&rpc->srpc_list);
                LIBCFS_FREE(rpc, sizeof(*rpc));
        }

        cfs_spin_lock(&srpc_data.rpc_glock);
        srpc_data.rpc_services[id] = NULL;
        cfs_spin_unlock(&srpc_data.rpc_glock);
        return -ENOMEM;
}

int
srpc_remove_service (srpc_service_t *sv)
{
        int id = sv->sv_id;

        cfs_spin_lock(&srpc_data.rpc_glock);

        if (srpc_data.rpc_services[id] != sv) {
                cfs_spin_unlock(&srpc_data.rpc_glock);
                return -ENOENT;
        }

        srpc_data.rpc_services[id] = NULL;
        cfs_spin_unlock(&srpc_data.rpc_glock);
        return 0;
}

int
srpc_post_passive_rdma(int portal, __u64 matchbits, void *buf,
                       int len, int options, lnet_process_id_t peer,
                       lnet_handle_md_t *mdh, srpc_event_t *ev)
{
        int              rc;
        lnet_md_t        md;
        lnet_handle_me_t meh;

        rc = LNetMEAttach(portal, peer, matchbits, 0,
                          LNET_UNLINK, LNET_INS_AFTER, &meh);
        if (rc != 0) {
                CERROR ("LNetMEAttach failed: %d\n", rc);
                LASSERT (rc == -ENOMEM);
                return -ENOMEM;
        }

        md.threshold = 1;
        md.user_ptr  = ev;
        md.start     = buf;
        md.length    = len;
        md.options   = options;
        md.eq_handle = srpc_data.rpc_lnet_eq;

        rc = LNetMDAttach(meh, md, LNET_UNLINK, mdh);
        if (rc != 0) {
                CERROR ("LNetMDAttach failed: %d\n", rc);
                LASSERT (rc == -ENOMEM);

                rc = LNetMEUnlink(meh);
                LASSERT (rc == 0);
                return -ENOMEM;
        }

        CDEBUG (D_NET,
                "Posted passive RDMA: peer %s, portal %d, matchbits "LPX64"\n",
                libcfs_id2str(peer), portal, matchbits);
        return 0;
}

int
srpc_post_active_rdma(int portal, __u64 matchbits, void *buf, int len,
                      int options, lnet_process_id_t peer, lnet_nid_t self,
                      lnet_handle_md_t *mdh, srpc_event_t *ev)
{
        int       rc;
        lnet_md_t md;

        md.user_ptr  = ev;
        md.start     = buf;
        md.length    = len;
        md.eq_handle = srpc_data.rpc_lnet_eq;
        md.threshold = ((options & LNET_MD_OP_GET) != 0) ? 2 : 1;
        md.options   = options & ~(LNET_MD_OP_PUT | LNET_MD_OP_GET);

        rc = LNetMDBind(md, LNET_UNLINK, mdh);
        if (rc != 0) {
                CERROR ("LNetMDBind failed: %d\n", rc);
                LASSERT (rc == -ENOMEM);
                return -ENOMEM;
        }

        /* this is kind of an abuse of the LNET_MD_OP_{PUT,GET} options.
         * they're only meaningful for MDs attached to an ME (i.e. passive
         * buffers... */
        if ((options & LNET_MD_OP_PUT) != 0) {
                rc = LNetPut(self, *mdh, LNET_NOACK_REQ, peer,
                             portal, matchbits, 0, 0);
        } else {
                LASSERT ((options & LNET_MD_OP_GET) != 0);

                rc = LNetGet(self, *mdh, peer, portal, matchbits, 0);
        }

        if (rc != 0) {
                CERROR ("LNet%s(%s, %d, "LPD64") failed: %d\n",
                        ((options & LNET_MD_OP_PUT) != 0) ? "Put" : "Get",
                        libcfs_id2str(peer), portal, matchbits, rc);

                /* The forthcoming unlink event will complete this operation
                 * with failure, so fall through and return success here.
                 */
                rc = LNetMDUnlink(*mdh);
                LASSERT (rc == 0);
        } else {
                CDEBUG (D_NET,
                        "Posted active RDMA: peer %s, portal %u, matchbits "LPX64"\n",
                        libcfs_id2str(peer), portal, matchbits);
        }
        return 0;
}

int
srpc_post_active_rqtbuf(lnet_process_id_t peer, int service, void *buf,
                        int len, lnet_handle_md_t *mdh, srpc_event_t *ev)
{
        int rc;
        int portal;

        if (service > SRPC_FRAMEWORK_SERVICE_MAX_ID)
                portal = SRPC_REQUEST_PORTAL;
        else
                portal = SRPC_FRAMEWORK_REQUEST_PORTAL;

        rc = srpc_post_active_rdma(portal, service, buf, len,
                                   LNET_MD_OP_PUT, peer,
                                   LNET_NID_ANY, mdh, ev);
        return rc;
}

int
srpc_post_passive_rqtbuf(int service, void *buf, int len,
                         lnet_handle_md_t *mdh, srpc_event_t *ev)
{
        int               rc;
        int               portal;
        lnet_process_id_t any = {0};

        any.nid = LNET_NID_ANY;
        any.pid = LNET_PID_ANY;

        if (service > SRPC_FRAMEWORK_SERVICE_MAX_ID)
                portal = SRPC_REQUEST_PORTAL;
        else
                portal = SRPC_FRAMEWORK_REQUEST_PORTAL;

        rc = srpc_post_passive_rdma(portal, service, buf, len,
                                    LNET_MD_OP_PUT, any, mdh, ev);
        return rc;
}

int
srpc_service_post_buffer (srpc_service_t *sv, srpc_buffer_t *buf)
{
        srpc_msg_t *msg = &buf->buf_msg;
        int         rc;

        LASSERT (!sv->sv_shuttingdown);

        LNetInvalidateHandle(&buf->buf_mdh);
        cfs_list_add(&buf->buf_list, &sv->sv_posted_msgq);
        sv->sv_nposted_msg++;
        cfs_spin_unlock(&sv->sv_lock);

        rc = srpc_post_passive_rqtbuf(sv->sv_id, msg, sizeof(*msg),
                                      &buf->buf_mdh, &sv->sv_ev);

        /* At this point, a RPC (new or delayed) may have arrived in
         * msg and its event handler has been called. So we must add
         * buf to sv_posted_msgq _before_ dropping sv_lock */

        cfs_spin_lock(&sv->sv_lock);

        if (rc == 0) {
                if (sv->sv_shuttingdown) {
                        cfs_spin_unlock(&sv->sv_lock);

                        /* srpc_shutdown_service might have tried to unlink me
                         * when my buf_mdh was still invalid */
                        LNetMDUnlink(buf->buf_mdh);

                        cfs_spin_lock(&sv->sv_lock);
                }
                return 0;
        }

        sv->sv_nposted_msg--;
        if (sv->sv_shuttingdown) return rc;

        cfs_list_del(&buf->buf_list);

        cfs_spin_unlock(&sv->sv_lock);
        LIBCFS_FREE(buf, sizeof(*buf));
        cfs_spin_lock(&sv->sv_lock);
        return rc;
}

int
srpc_service_add_buffers (srpc_service_t *sv, int nbuffer)
{
        int                rc;
        int                posted;
        srpc_buffer_t     *buf;

        LASSERTF (nbuffer > 0,
                  "nbuffer must be positive: %d\n", nbuffer);

        for (posted = 0; posted < nbuffer; posted++) {
                LIBCFS_ALLOC(buf, sizeof(*buf));
                if (buf == NULL) break;

                cfs_spin_lock(&sv->sv_lock);
                rc = srpc_service_post_buffer(sv, buf);
                cfs_spin_unlock(&sv->sv_lock);

                if (rc != 0) break;
        }

        return posted;
}

void
srpc_service_remove_buffers (srpc_service_t *sv, int nbuffer)
{
        LASSERTF (nbuffer > 0,
                  "nbuffer must be positive: %d\n", nbuffer);

        cfs_spin_lock(&sv->sv_lock);

        LASSERT (sv->sv_nprune >= 0);
        LASSERT (!sv->sv_shuttingdown);

        sv->sv_nprune += nbuffer;

        cfs_spin_unlock(&sv->sv_lock);
        return;
}

/* returns 1 if sv has finished, otherwise 0 */
int
srpc_finish_service (srpc_service_t *sv)
{
        srpc_server_rpc_t *rpc;
        srpc_buffer_t     *buf;

        cfs_spin_lock(&sv->sv_lock);

        LASSERT (sv->sv_shuttingdown); /* srpc_shutdown_service called */

        if (sv->sv_nposted_msg != 0 || !cfs_list_empty(&sv->sv_active_rpcq)) {
                CDEBUG (D_NET,
                        "waiting for %d posted buffers to unlink and "
                        "in-flight RPCs to die.\n",
                        sv->sv_nposted_msg);

                if (!cfs_list_empty(&sv->sv_active_rpcq)) {
                        rpc = cfs_list_entry(sv->sv_active_rpcq.next,
                                             srpc_server_rpc_t, srpc_list);
                        CNETERR("Active RPC %p on shutdown: sv %s, peer %s, "
                                "wi %s scheduled %d running %d, "
                                "ev fired %d type %d status %d lnet %d\n",
                                rpc, sv->sv_name, libcfs_id2str(rpc->srpc_peer),
                                swi_state2str(rpc->srpc_wi.swi_state),
                                rpc->srpc_wi.swi_workitem.wi_scheduled,
                                rpc->srpc_wi.swi_workitem.wi_running,
                                rpc->srpc_ev.ev_fired,
                                rpc->srpc_ev.ev_type,
                                rpc->srpc_ev.ev_status,
                                rpc->srpc_ev.ev_lnet);
                }

                cfs_spin_unlock(&sv->sv_lock);
                return 0;
        }

        cfs_spin_unlock(&sv->sv_lock); /* no lock needed from now on */

        for (;;) {
                cfs_list_t *q;

                if (!cfs_list_empty(&sv->sv_posted_msgq))
                        q = &sv->sv_posted_msgq;
                else if (!cfs_list_empty(&sv->sv_blocked_msgq))
                        q = &sv->sv_blocked_msgq;
                else
                        break;

                buf = cfs_list_entry(q->next, srpc_buffer_t, buf_list);
                cfs_list_del(&buf->buf_list);

                LIBCFS_FREE(buf, sizeof(*buf));
        }

        while (!cfs_list_empty(&sv->sv_free_rpcq)) {
                rpc = cfs_list_entry(sv->sv_free_rpcq.next,
                                     srpc_server_rpc_t, srpc_list);
                cfs_list_del(&rpc->srpc_list);
                LIBCFS_FREE(rpc, sizeof(*rpc));
        }

        return 1;
}

/* called with sv->sv_lock held */
void
srpc_service_recycle_buffer (srpc_service_t *sv, srpc_buffer_t *buf)
{
        if (sv->sv_shuttingdown) goto free;

        if (sv->sv_nprune == 0) {
                if (srpc_service_post_buffer(sv, buf) != 0)
                        CWARN ("Failed to post %s buffer\n", sv->sv_name);
                return;
        }

        sv->sv_nprune--;
free:
        cfs_spin_unlock(&sv->sv_lock);
        LIBCFS_FREE(buf, sizeof(*buf));
        cfs_spin_lock(&sv->sv_lock);
}

/* called with srpc_service_t::sv_lock held */
inline void
srpc_schedule_server_rpc (srpc_server_rpc_t *rpc)
{
        swi_schedule_workitem(&rpc->srpc_wi);
}

void
srpc_abort_service (srpc_service_t *sv)
{
        srpc_server_rpc_t *rpc;

        cfs_spin_lock(&sv->sv_lock);

        CDEBUG(D_NET, "Aborting service: id %d, name %s\n",
               sv->sv_id, sv->sv_name);

        /* schedule in-flight RPCs to notice the abort, NB:
         * racing with incoming RPCs; complete fix should make test
         * RPCs carry session ID in its headers */
        cfs_list_for_each_entry (rpc, &sv->sv_active_rpcq, srpc_list) {
                rpc->srpc_aborted = 1;
                srpc_schedule_server_rpc(rpc);
        }

        cfs_spin_unlock(&sv->sv_lock);
        return;
}

void
srpc_shutdown_service (srpc_service_t *sv)
{
        srpc_server_rpc_t *rpc;
        srpc_buffer_t     *buf;

        cfs_spin_lock(&sv->sv_lock);

        CDEBUG(D_NET, "Shutting down service: id %d, name %s\n",
               sv->sv_id, sv->sv_name);

        sv->sv_shuttingdown = 1; /* i.e. no new active RPC */

        /* schedule in-flight RPCs to notice the shutdown */
        cfs_list_for_each_entry_typed (rpc, &sv->sv_active_rpcq,
                                       srpc_server_rpc_t, srpc_list) {
                srpc_schedule_server_rpc(rpc);
        }

        cfs_spin_unlock(&sv->sv_lock);

        /* OK to traverse sv_posted_msgq without lock, since no one
         * touches sv_posted_msgq now */
        cfs_list_for_each_entry_typed (buf, &sv->sv_posted_msgq,
                                       srpc_buffer_t, buf_list)
                LNetMDUnlink(buf->buf_mdh);

        return;
}

int
srpc_send_request (srpc_client_rpc_t *rpc)
{
        srpc_event_t *ev = &rpc->crpc_reqstev;
        int           rc;

        ev->ev_fired = 0;
        ev->ev_data  = rpc;
        ev->ev_type  = SRPC_REQUEST_SENT;

        rc = srpc_post_active_rqtbuf(rpc->crpc_dest, rpc->crpc_service,
                                     &rpc->crpc_reqstmsg, sizeof(srpc_msg_t),
                                     &rpc->crpc_reqstmdh, ev);
        if (rc != 0) {
                LASSERT (rc == -ENOMEM);
                ev->ev_fired = 1;  /* no more event expected */
        }
        return rc;
}

int
srpc_prepare_reply (srpc_client_rpc_t *rpc)
{
        srpc_event_t *ev = &rpc->crpc_replyev;
        __u64        *id = &rpc->crpc_reqstmsg.msg_body.reqst.rpyid;
        int           rc;

        ev->ev_fired = 0;
        ev->ev_data  = rpc;
        ev->ev_type  = SRPC_REPLY_RCVD;

        *id = srpc_next_id();

        rc = srpc_post_passive_rdma(SRPC_RDMA_PORTAL, *id,
                                    &rpc->crpc_replymsg, sizeof(srpc_msg_t),
                                    LNET_MD_OP_PUT, rpc->crpc_dest,
                                    &rpc->crpc_replymdh, ev);
        if (rc != 0) {
                LASSERT (rc == -ENOMEM);
                ev->ev_fired = 1;  /* no more event expected */
        }
        return rc;
}

int
srpc_prepare_bulk (srpc_client_rpc_t *rpc)
{
        srpc_bulk_t  *bk = &rpc->crpc_bulk;
        srpc_event_t *ev = &rpc->crpc_bulkev;
        __u64        *id = &rpc->crpc_reqstmsg.msg_body.reqst.bulkid;
        int           rc;
        int           opt;

        LASSERT (bk->bk_niov <= LNET_MAX_IOV);

        if (bk->bk_niov == 0) return 0; /* nothing to do */

        opt = bk->bk_sink ? LNET_MD_OP_PUT : LNET_MD_OP_GET;
#ifdef __KERNEL__
        opt |= LNET_MD_KIOV;
#else
        opt |= LNET_MD_IOVEC;
#endif

        ev->ev_fired = 0;
        ev->ev_data  = rpc;
        ev->ev_type  = SRPC_BULK_REQ_RCVD;

        *id = srpc_next_id();

        rc = srpc_post_passive_rdma(SRPC_RDMA_PORTAL, *id,
                                    &bk->bk_iovs[0], bk->bk_niov, opt,
                                    rpc->crpc_dest, &bk->bk_mdh, ev);
        if (rc != 0) {
                LASSERT (rc == -ENOMEM);
                ev->ev_fired = 1;  /* no more event expected */
        }
        return rc;
}

int
srpc_do_bulk (srpc_server_rpc_t *rpc)
{
        srpc_event_t  *ev = &rpc->srpc_ev;
        srpc_bulk_t   *bk = rpc->srpc_bulk;
        __u64          id = rpc->srpc_reqstbuf->buf_msg.msg_body.reqst.bulkid;
        int            rc;
        int            opt;

        LASSERT (bk != NULL);

        opt = bk->bk_sink ? LNET_MD_OP_GET : LNET_MD_OP_PUT;
#ifdef __KERNEL__
        opt |= LNET_MD_KIOV;
#else
        opt |= LNET_MD_IOVEC;
#endif

        ev->ev_fired = 0;
        ev->ev_data  = rpc;
        ev->ev_type  = bk->bk_sink ? SRPC_BULK_GET_RPLD : SRPC_BULK_PUT_SENT;

        rc = srpc_post_active_rdma(SRPC_RDMA_PORTAL, id,
                                   &bk->bk_iovs[0], bk->bk_niov, opt,
                                   rpc->srpc_peer, rpc->srpc_self,
                                   &bk->bk_mdh, ev);
        if (rc != 0)
                ev->ev_fired = 1;  /* no more event expected */
        return rc;
}

/* only called from srpc_handle_rpc */
void
srpc_server_rpc_done (srpc_server_rpc_t *rpc, int status)
{
        srpc_service_t *sv = rpc->srpc_service;
        srpc_buffer_t  *buffer;

        LASSERT (status != 0 || rpc->srpc_wi.swi_state == SWI_STATE_DONE);

        rpc->srpc_status = status;

        CDEBUG_LIMIT (status == 0 ? D_NET : D_NETERROR,
                "Server RPC %p done: service %s, peer %s, status %s:%d\n",
                rpc, sv->sv_name, libcfs_id2str(rpc->srpc_peer),
                swi_state2str(rpc->srpc_wi.swi_state), status);

        if (status != 0) {
                cfs_spin_lock(&srpc_data.rpc_glock);
                srpc_data.rpc_counters.rpcs_dropped++;
                cfs_spin_unlock(&srpc_data.rpc_glock);
        }

        if (rpc->srpc_done != NULL)
                (*rpc->srpc_done) (rpc);
        LASSERT (rpc->srpc_bulk == NULL);

        cfs_spin_lock(&sv->sv_lock);

        if (rpc->srpc_reqstbuf != NULL) {
                /* NB might drop sv_lock in srpc_service_recycle_buffer, but
                 * sv won't go away for sv_active_rpcq must not be empty */
                srpc_service_recycle_buffer(sv, rpc->srpc_reqstbuf);
                rpc->srpc_reqstbuf = NULL;
        }

        cfs_list_del(&rpc->srpc_list); /* from sv->sv_active_rpcq */

        /*
         * No one can schedule me now since:
         * - I'm not on sv_active_rpcq.
         * - all LNet events have been fired.
         * Cancel pending schedules and prevent future schedule attempts:
         */
        LASSERT (rpc->srpc_ev.ev_fired);
        swi_kill_workitem(&rpc->srpc_wi);

        if (!sv->sv_shuttingdown && !cfs_list_empty(&sv->sv_blocked_msgq)) {
                buffer = cfs_list_entry(sv->sv_blocked_msgq.next,
                                    srpc_buffer_t, buf_list);
                cfs_list_del(&buffer->buf_list);

                srpc_init_server_rpc(rpc, sv, buffer);
                cfs_list_add_tail(&rpc->srpc_list, &sv->sv_active_rpcq);
                srpc_schedule_server_rpc(rpc);
        } else {
                cfs_list_add(&rpc->srpc_list, &sv->sv_free_rpcq);
        }

        cfs_spin_unlock(&sv->sv_lock);
        return;
}

/* handles an incoming RPC */
int
srpc_handle_rpc (swi_workitem_t *wi)
{
        srpc_server_rpc_t *rpc = wi->swi_workitem.wi_data;
        srpc_service_t    *sv = rpc->srpc_service;
        srpc_event_t      *ev = &rpc->srpc_ev;
        int                rc = 0;

        LASSERT (wi == &rpc->srpc_wi);

        cfs_spin_lock(&sv->sv_lock);

        if (sv->sv_shuttingdown || rpc->srpc_aborted) {
                cfs_spin_unlock(&sv->sv_lock);

                if (rpc->srpc_bulk != NULL)
                        LNetMDUnlink(rpc->srpc_bulk->bk_mdh);
                LNetMDUnlink(rpc->srpc_replymdh);

                if (ev->ev_fired) { /* no more event, OK to finish */
                        srpc_server_rpc_done(rpc, -ESHUTDOWN);
                        return 1;
                }
                return 0;
        }

        cfs_spin_unlock(&sv->sv_lock);

        switch (wi->swi_state) {
        default:
                LBUG ();
        case SWI_STATE_NEWBORN: {
                srpc_msg_t           *msg;
                srpc_generic_reply_t *reply;

                msg = &rpc->srpc_reqstbuf->buf_msg;
                reply = &rpc->srpc_replymsg.msg_body.reply;

                if (msg->msg_magic == 0) {
                        /* moaned already in srpc_lnet_ev_handler */
                        rc = EBADMSG;
                } else if (msg->msg_version != SRPC_MSG_VERSION &&
                           msg->msg_version != __swab32(SRPC_MSG_VERSION)) {
                        CWARN ("Version mismatch: %u, %u expected, from %s\n",
                               msg->msg_version, SRPC_MSG_VERSION,
                               libcfs_id2str(rpc->srpc_peer));
                        reply->status = EPROTO;
                } else {
                        reply->status = 0;
                        rc = (*sv->sv_handler) (rpc);
                        LASSERT (reply->status == 0 || !rpc->srpc_bulk);
                }

                if (rc != 0) {
                        srpc_server_rpc_done(rpc, rc);
                        return 1;
                }

                wi->swi_state = SWI_STATE_BULK_STARTED;

                if (rpc->srpc_bulk != NULL) {
                        rc = srpc_do_bulk(rpc);
                        if (rc == 0)
                                return 0; /* wait for bulk */

                        LASSERT (ev->ev_fired);
                        ev->ev_status = rc;
                }
        }
        case SWI_STATE_BULK_STARTED:
                LASSERT (rpc->srpc_bulk == NULL || ev->ev_fired);

                if (rpc->srpc_bulk != NULL) {
                        rc = ev->ev_status;

                        if (sv->sv_bulk_ready != NULL)
                                rc = (*sv->sv_bulk_ready) (rpc, rc);

                        if (rc != 0) {
                                srpc_server_rpc_done(rpc, rc);
                                return 1;
                        }
                }

                wi->swi_state = SWI_STATE_REPLY_SUBMITTED;
                rc = srpc_send_reply(rpc);
                if (rc == 0)
                        return 0; /* wait for reply */
                srpc_server_rpc_done(rpc, rc);
                return 1;

        case SWI_STATE_REPLY_SUBMITTED:
                if (!ev->ev_fired) {
                        CERROR("RPC %p: bulk %p, service %d\n",
                               rpc, rpc->srpc_bulk, rpc->srpc_service->sv_id);
                        CERROR("Event: status %d, type %d, lnet %d\n",
                               ev->ev_status, ev->ev_type, ev->ev_lnet);
                        LASSERT (ev->ev_fired);
                }

                wi->swi_state = SWI_STATE_DONE;
                srpc_server_rpc_done(rpc, ev->ev_status);
                return 1;
        }

        return 0;
}

void
srpc_client_rpc_expired (void *data)
{
        srpc_client_rpc_t *rpc = data;

        CWARN ("Client RPC expired: service %d, peer %s, timeout %d.\n",
               rpc->crpc_service, libcfs_id2str(rpc->crpc_dest),
               rpc->crpc_timeout);

        cfs_spin_lock(&rpc->crpc_lock);

        rpc->crpc_timeout = 0;
        srpc_abort_rpc(rpc, -ETIMEDOUT);

        cfs_spin_unlock(&rpc->crpc_lock);

        cfs_spin_lock(&srpc_data.rpc_glock);
        srpc_data.rpc_counters.rpcs_expired++;
        cfs_spin_unlock(&srpc_data.rpc_glock);
        return;
}

inline void
srpc_add_client_rpc_timer (srpc_client_rpc_t *rpc)
{
        stt_timer_t *timer = &rpc->crpc_timer;

        if (rpc->crpc_timeout == 0) return;

        CFS_INIT_LIST_HEAD(&timer->stt_list);
        timer->stt_data    = rpc;
        timer->stt_func    = srpc_client_rpc_expired;
        timer->stt_expires = cfs_time_add(rpc->crpc_timeout,
                                          cfs_time_current_sec());
        stt_add_timer(timer);
        return;
}

/*
 * Called with rpc->crpc_lock held.
 *
 * Upon exit the RPC expiry timer is not queued and the handler is not
 * running on any CPU. */
void
srpc_del_client_rpc_timer (srpc_client_rpc_t *rpc)
{
        /* timer not planted or already exploded */
        if (rpc->crpc_timeout == 0) return;

        /* timer sucessfully defused */
        if (stt_del_timer(&rpc->crpc_timer)) return;

#ifdef __KERNEL__
        /* timer detonated, wait for it to explode */
        while (rpc->crpc_timeout != 0) {
                cfs_spin_unlock(&rpc->crpc_lock);

                cfs_schedule();

                cfs_spin_lock(&rpc->crpc_lock);
        }
#else
        LBUG(); /* impossible in single-threaded runtime */
#endif
        return;
}

void
srpc_client_rpc_done (srpc_client_rpc_t *rpc, int status)
{
        swi_workitem_t *wi = &rpc->crpc_wi;

        LASSERT (status != 0 || wi->swi_state == SWI_STATE_DONE);

        cfs_spin_lock(&rpc->crpc_lock);

        rpc->crpc_closed = 1;
        if (rpc->crpc_status == 0)
                rpc->crpc_status = status;

        srpc_del_client_rpc_timer(rpc);

        CDEBUG_LIMIT ((status == 0) ? D_NET : D_NETERROR,
                "Client RPC done: service %d, peer %s, status %s:%d:%d\n",
                rpc->crpc_service, libcfs_id2str(rpc->crpc_dest),
                swi_state2str(wi->swi_state), rpc->crpc_aborted, status);

        /*
         * No one can schedule me now since:
         * - RPC timer has been defused.
         * - all LNet events have been fired.
         * - crpc_closed has been set, preventing srpc_abort_rpc from
         *   scheduling me.
         * Cancel pending schedules and prevent future schedule attempts:
         */
        LASSERT (!srpc_event_pending(rpc));
        swi_kill_workitem(wi);

        cfs_spin_unlock(&rpc->crpc_lock);

        (*rpc->crpc_done) (rpc);
        return;
}

/* sends an outgoing RPC */
int
srpc_send_rpc (swi_workitem_t *wi)
{
        int                rc = 0;
        srpc_client_rpc_t *rpc = wi->swi_workitem.wi_data;
        srpc_msg_t        *reply = &rpc->crpc_replymsg;
        int                do_bulk = rpc->crpc_bulk.bk_niov > 0;

        LASSERT (rpc != NULL);
        LASSERT (wi == &rpc->crpc_wi);

        cfs_spin_lock(&rpc->crpc_lock);

        if (rpc->crpc_aborted) {
                cfs_spin_unlock(&rpc->crpc_lock);
                goto abort;
        }

        cfs_spin_unlock(&rpc->crpc_lock);

        switch (wi->swi_state) {
        default:
                LBUG ();
        case SWI_STATE_NEWBORN:
                LASSERT (!srpc_event_pending(rpc));

                rc = srpc_prepare_reply(rpc);
                if (rc != 0) {
                        srpc_client_rpc_done(rpc, rc);
                        return 1;
                }

                rc = srpc_prepare_bulk(rpc);
                if (rc != 0) break;

                wi->swi_state = SWI_STATE_REQUEST_SUBMITTED;
                rc = srpc_send_request(rpc);
                break;

        case SWI_STATE_REQUEST_SUBMITTED:
                /* CAVEAT EMPTOR: rqtev, rpyev, and bulkev may come in any
                 * order; however, they're processed in a strict order:
                 * rqt, rpy, and bulk. */
                if (!rpc->crpc_reqstev.ev_fired) break;

                rc = rpc->crpc_reqstev.ev_status;
                if (rc != 0) break;

                wi->swi_state = SWI_STATE_REQUEST_SENT;
                /* perhaps more events, fall thru */
        case SWI_STATE_REQUEST_SENT: {
                srpc_msg_type_t type = srpc_service2reply(rpc->crpc_service);

                if (!rpc->crpc_replyev.ev_fired) break;

                rc = rpc->crpc_replyev.ev_status;
                if (rc != 0) break;

                if ((reply->msg_type != type &&
                     reply->msg_type != __swab32(type)) ||
                    (reply->msg_magic != SRPC_MSG_MAGIC &&
                     reply->msg_magic != __swab32(SRPC_MSG_MAGIC))) {
                        CWARN ("Bad message from %s: type %u (%d expected),"
                               " magic %u (%d expected).\n",
                               libcfs_id2str(rpc->crpc_dest),
                               reply->msg_type, type,
                               reply->msg_magic, SRPC_MSG_MAGIC);
                        rc = -EBADMSG;
                        break;
                }

                if (do_bulk && reply->msg_body.reply.status != 0) {
                        CWARN ("Remote error %d at %s, unlink bulk buffer in "
                               "case peer didn't initiate bulk transfer\n",
                               reply->msg_body.reply.status,
                               libcfs_id2str(rpc->crpc_dest));
                        LNetMDUnlink(rpc->crpc_bulk.bk_mdh);
                }

                wi->swi_state = SWI_STATE_REPLY_RECEIVED;
        }
        case SWI_STATE_REPLY_RECEIVED:
                if (do_bulk && !rpc->crpc_bulkev.ev_fired) break;

                rc = do_bulk ? rpc->crpc_bulkev.ev_status : 0;

                /* Bulk buffer was unlinked due to remote error. Clear error
                 * since reply buffer still contains valid data.
                 * NB rpc->crpc_done shouldn't look into bulk data in case of
                 * remote error. */
                if (do_bulk && rpc->crpc_bulkev.ev_lnet == LNET_EVENT_UNLINK &&
                    rpc->crpc_status == 0 && reply->msg_body.reply.status != 0)
                        rc = 0;

                wi->swi_state = SWI_STATE_DONE;
                srpc_client_rpc_done(rpc, rc);
                return 1;
        }

        if (rc != 0) {
                cfs_spin_lock(&rpc->crpc_lock);
                srpc_abort_rpc(rpc, rc);
                cfs_spin_unlock(&rpc->crpc_lock);
        }

abort:
        if (rpc->crpc_aborted) {
                LNetMDUnlink(rpc->crpc_reqstmdh);
                LNetMDUnlink(rpc->crpc_replymdh);
                LNetMDUnlink(rpc->crpc_bulk.bk_mdh);

                if (!srpc_event_pending(rpc)) {
                        srpc_client_rpc_done(rpc, -EINTR);
                        return 1;
                }
        }
        return 0;
}

srpc_client_rpc_t *
srpc_create_client_rpc (lnet_process_id_t peer, int service,
                        int nbulkiov, int bulklen,
                        void (*rpc_done)(srpc_client_rpc_t *),
                        void (*rpc_fini)(srpc_client_rpc_t *), void *priv)
{
        srpc_client_rpc_t *rpc;

        LIBCFS_ALLOC(rpc, offsetof(srpc_client_rpc_t,
                                   crpc_bulk.bk_iovs[nbulkiov]));
        if (rpc == NULL)
                return NULL;

        srpc_init_client_rpc(rpc, peer, service, nbulkiov,
                             bulklen, rpc_done, rpc_fini, priv);
        return rpc;
}

/* called with rpc->crpc_lock held */
void
srpc_abort_rpc (srpc_client_rpc_t *rpc, int why)
{
        LASSERT (why != 0);

        if (rpc->crpc_aborted || /* already aborted */
            rpc->crpc_closed)    /* callback imminent */
                return;

        CDEBUG (D_NET,
                "Aborting RPC: service %d, peer %s, state %s, why %d\n",
                rpc->crpc_service, libcfs_id2str(rpc->crpc_dest),
                swi_state2str(rpc->crpc_wi.swi_state), why);

        rpc->crpc_aborted = 1;
        rpc->crpc_status  = why;
        swi_schedule_workitem(&rpc->crpc_wi);
        return;
}

/* called with rpc->crpc_lock held */
void
srpc_post_rpc (srpc_client_rpc_t *rpc)
{
        LASSERT (!rpc->crpc_aborted);
        LASSERT (srpc_data.rpc_state == SRPC_STATE_RUNNING);
        LASSERT ((rpc->crpc_bulk.bk_len & ~CFS_PAGE_MASK) == 0);

        CDEBUG (D_NET, "Posting RPC: peer %s, service %d, timeout %d\n",
                libcfs_id2str(rpc->crpc_dest), rpc->crpc_service,
                rpc->crpc_timeout);

        srpc_add_client_rpc_timer(rpc);
        swi_schedule_workitem(&rpc->crpc_wi);
        return;
}


int
srpc_send_reply (srpc_server_rpc_t *rpc)
{
        srpc_event_t   *ev = &rpc->srpc_ev;
        srpc_msg_t     *msg = &rpc->srpc_replymsg;
        srpc_buffer_t  *buffer = rpc->srpc_reqstbuf;
        srpc_service_t *sv = rpc->srpc_service;
        __u64           rpyid;
        int             rc;

        LASSERT (buffer != NULL);
        rpyid = buffer->buf_msg.msg_body.reqst.rpyid;

        cfs_spin_lock(&sv->sv_lock);

        if (!sv->sv_shuttingdown &&
            sv->sv_id > SRPC_FRAMEWORK_SERVICE_MAX_ID) {
                /* Repost buffer before replying since test client
                 * might send me another RPC once it gets the reply */
                if (srpc_service_post_buffer(sv, buffer) != 0)
                        CWARN ("Failed to repost %s buffer\n", sv->sv_name);
                rpc->srpc_reqstbuf = NULL;
        }

        cfs_spin_unlock(&sv->sv_lock);

        ev->ev_fired = 0;
        ev->ev_data  = rpc;
        ev->ev_type  = SRPC_REPLY_SENT;

        msg->msg_magic   = SRPC_MSG_MAGIC;
        msg->msg_version = SRPC_MSG_VERSION;
        msg->msg_type    = srpc_service2reply(sv->sv_id);

        rc = srpc_post_active_rdma(SRPC_RDMA_PORTAL, rpyid, msg,
                                   sizeof(*msg), LNET_MD_OP_PUT,
                                   rpc->srpc_peer, rpc->srpc_self,
                                   &rpc->srpc_replymdh, ev);
        if (rc != 0)
                ev->ev_fired = 1;  /* no more event expected */
        return rc;
}

/* when in kernel always called with LNET_LOCK() held, and in thread context */
void
srpc_lnet_ev_handler (lnet_event_t *ev)
{
        srpc_event_t      *rpcev = ev->md.user_ptr;
        srpc_client_rpc_t *crpc;
        srpc_server_rpc_t *srpc;
        srpc_buffer_t     *buffer;
        srpc_service_t    *sv;
        srpc_msg_t        *msg;
        srpc_msg_type_t    type;

        LASSERT (!cfs_in_interrupt());

        if (ev->status != 0) {
                cfs_spin_lock(&srpc_data.rpc_glock);
                srpc_data.rpc_counters.errors++;
                cfs_spin_unlock(&srpc_data.rpc_glock);
        }

        rpcev->ev_lnet = ev->type;

        switch (rpcev->ev_type) {
        default:
                CERROR("Unknown event: status %d, type %d, lnet %d\n",
                       rpcev->ev_status, rpcev->ev_type, rpcev->ev_lnet);
                LBUG ();
        case SRPC_REQUEST_SENT:
                if (ev->status == 0 && ev->type != LNET_EVENT_UNLINK) {
                        cfs_spin_lock(&srpc_data.rpc_glock);
                        srpc_data.rpc_counters.rpcs_sent++;
                        cfs_spin_unlock(&srpc_data.rpc_glock);
                }
        case SRPC_REPLY_RCVD:
        case SRPC_BULK_REQ_RCVD:
                crpc = rpcev->ev_data;

                if (rpcev != &crpc->crpc_reqstev &&
                    rpcev != &crpc->crpc_replyev &&
                    rpcev != &crpc->crpc_bulkev) {
                        CERROR("rpcev %p, crpc %p, reqstev %p, replyev %p, bulkev %p\n",
                               rpcev, crpc, &crpc->crpc_reqstev,
                               &crpc->crpc_replyev, &crpc->crpc_bulkev);
                        CERROR("Bad event: status %d, type %d, lnet %d\n",
                               rpcev->ev_status, rpcev->ev_type, rpcev->ev_lnet);
                        LBUG ();
                }

                cfs_spin_lock(&crpc->crpc_lock);

                LASSERT (rpcev->ev_fired == 0);
                rpcev->ev_fired  = 1;
                rpcev->ev_status = (ev->type == LNET_EVENT_UNLINK) ?
                                                -EINTR : ev->status;
                swi_schedule_workitem(&crpc->crpc_wi);

                cfs_spin_unlock(&crpc->crpc_lock);
                break;

        case SRPC_REQUEST_RCVD:
                sv = rpcev->ev_data;

                LASSERT (rpcev == &sv->sv_ev);

                cfs_spin_lock(&sv->sv_lock);

                LASSERT (ev->unlinked);
                LASSERT (ev->type == LNET_EVENT_PUT ||
                         ev->type == LNET_EVENT_UNLINK);
                LASSERT (ev->type != LNET_EVENT_UNLINK ||
                         sv->sv_shuttingdown);

                buffer = container_of(ev->md.start, srpc_buffer_t, buf_msg);
                buffer->buf_peer = ev->initiator;
                buffer->buf_self = ev->target.nid;

                sv->sv_nposted_msg--;
                LASSERT (sv->sv_nposted_msg >= 0);

                if (sv->sv_shuttingdown) {
                        /* Leave buffer on sv->sv_posted_msgq since
                         * srpc_finish_service needs to traverse it. */
                        cfs_spin_unlock(&sv->sv_lock);
                        break;
                }

                cfs_list_del(&buffer->buf_list); /* from sv->sv_posted_msgq */
                msg = &buffer->buf_msg;
                type = srpc_service2request(sv->sv_id);

                if (ev->status != 0 || ev->mlength != sizeof(*msg) ||
                    (msg->msg_type != type &&
                     msg->msg_type != __swab32(type)) ||
                    (msg->msg_magic != SRPC_MSG_MAGIC &&
                     msg->msg_magic != __swab32(SRPC_MSG_MAGIC))) {
                        CERROR ("Dropping RPC (%s) from %s: "
                                "status %d mlength %d type %u magic %u.\n",
                                sv->sv_name, libcfs_id2str(ev->initiator),
                                ev->status, ev->mlength,
                                msg->msg_type, msg->msg_magic);

                        /* NB can't call srpc_service_recycle_buffer here since
                         * it may call LNetM[DE]Attach. The invalid magic tells
                         * srpc_handle_rpc to drop this RPC */
                        msg->msg_magic = 0;
                }

                if (!cfs_list_empty(&sv->sv_free_rpcq)) {
                        srpc = cfs_list_entry(sv->sv_free_rpcq.next,
                                              srpc_server_rpc_t, srpc_list);
                        cfs_list_del(&srpc->srpc_list);

                        srpc_init_server_rpc(srpc, sv, buffer);
                        cfs_list_add_tail(&srpc->srpc_list,
                                          &sv->sv_active_rpcq);
                        srpc_schedule_server_rpc(srpc);
                } else {
                        cfs_list_add_tail(&buffer->buf_list,
                                          &sv->sv_blocked_msgq);
                }

                cfs_spin_unlock(&sv->sv_lock);

                cfs_spin_lock(&srpc_data.rpc_glock);
                srpc_data.rpc_counters.rpcs_rcvd++;
                cfs_spin_unlock(&srpc_data.rpc_glock);
                break;

        case SRPC_BULK_GET_RPLD:
                LASSERT (ev->type == LNET_EVENT_SEND ||
                         ev->type == LNET_EVENT_REPLY ||
                         ev->type == LNET_EVENT_UNLINK);

                if (!ev->unlinked)
                        break; /* wait for final event */

        case SRPC_BULK_PUT_SENT:
                if (ev->status == 0 && ev->type != LNET_EVENT_UNLINK) {
                        cfs_spin_lock(&srpc_data.rpc_glock);

                        if (rpcev->ev_type == SRPC_BULK_GET_RPLD)
                                srpc_data.rpc_counters.bulk_get += ev->mlength;
                        else
                                srpc_data.rpc_counters.bulk_put += ev->mlength;

                        cfs_spin_unlock(&srpc_data.rpc_glock);
                }
        case SRPC_REPLY_SENT:
                srpc = rpcev->ev_data;
                sv = srpc->srpc_service;

                LASSERT (rpcev == &srpc->srpc_ev);

                cfs_spin_lock(&sv->sv_lock);

                rpcev->ev_fired  = 1;
                rpcev->ev_status = (ev->type == LNET_EVENT_UNLINK) ?
                                                -EINTR : ev->status;
                srpc_schedule_server_rpc(srpc);

                cfs_spin_unlock(&sv->sv_lock);
                break;
        }

        return;
}

#ifndef __KERNEL__

int
srpc_check_event (int timeout)
{
        lnet_event_t ev;
        int          rc;
        int          i;

        rc = LNetEQPoll(&srpc_data.rpc_lnet_eq, 1,
                        timeout * 1000, &ev, &i);
        if (rc == 0) return 0;

        LASSERT (rc == -EOVERFLOW || rc == 1);

        /* We can't affort to miss any events... */
        if (rc == -EOVERFLOW) {
                CERROR ("Dropped an event!!!\n");
                abort();
        }

        srpc_lnet_ev_handler(&ev);
        return 1;
}

#endif

int
srpc_startup (void)
{
        int rc;

        memset(&srpc_data, 0, sizeof(struct smoketest_rpc));
        cfs_spin_lock_init(&srpc_data.rpc_glock);

        /* 1 second pause to avoid timestamp reuse */
        cfs_pause(cfs_time_seconds(1));
        srpc_data.rpc_matchbits = ((__u64) cfs_time_current_sec()) << 48;

        srpc_data.rpc_state = SRPC_STATE_NONE;

#ifdef __KERNEL__
        rc = LNetNIInit(LUSTRE_SRV_LNET_PID);
#else
        if (the_lnet.ln_server_mode_flag)
                rc = LNetNIInit(LUSTRE_SRV_LNET_PID);
        else
                rc = LNetNIInit(getpid() | LNET_PID_USERFLAG);
#endif
        if (rc < 0) {
                CERROR ("LNetNIInit() has failed: %d\n", rc);
                return rc;
        }

        srpc_data.rpc_state = SRPC_STATE_NI_INIT;

        LNetInvalidateHandle(&srpc_data.rpc_lnet_eq);
#ifdef __KERNEL__
	rc = LNetEQAlloc(0, srpc_lnet_ev_handler, &srpc_data.rpc_lnet_eq);
#else
        rc = LNetEQAlloc(10240, LNET_EQ_HANDLER_NONE, &srpc_data.rpc_lnet_eq);
#endif
        if (rc != 0) {
                CERROR("LNetEQAlloc() has failed: %d\n", rc);
                goto bail;
        }

        rc = LNetSetLazyPortal(SRPC_FRAMEWORK_REQUEST_PORTAL);
        LASSERT (rc == 0);

        srpc_data.rpc_state = SRPC_STATE_EQ_INIT;

        rc = stt_startup();

bail:
        if (rc != 0)
                srpc_shutdown();
        else
                srpc_data.rpc_state = SRPC_STATE_RUNNING;

        return rc;
}

void
srpc_shutdown (void)
{
        int i;
        int rc;
        int state;

        state = srpc_data.rpc_state;
        srpc_data.rpc_state = SRPC_STATE_STOPPING;

        switch (state) {
        default:
                LBUG ();
        case SRPC_STATE_RUNNING:
                cfs_spin_lock(&srpc_data.rpc_glock);

                for (i = 0; i <= SRPC_SERVICE_MAX_ID; i++) {
                        srpc_service_t *sv = srpc_data.rpc_services[i];

                        LASSERTF (sv == NULL,
                                  "service not empty: id %d, name %s\n",
                                  i, sv->sv_name);
                }

                cfs_spin_unlock(&srpc_data.rpc_glock);

                stt_shutdown();

        case SRPC_STATE_EQ_INIT:
                rc = LNetClearLazyPortal(SRPC_FRAMEWORK_REQUEST_PORTAL);
                LASSERT (rc == 0);
                rc = LNetEQFree(srpc_data.rpc_lnet_eq);
                LASSERT (rc == 0); /* the EQ should have no user by now */

        case SRPC_STATE_NI_INIT:
                LNetNIFini();
                break;
        }

        return;
}
