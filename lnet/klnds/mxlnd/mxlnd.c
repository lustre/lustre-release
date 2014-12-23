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
 *
 * Copyright (c) 2012, 2014, Intel Corporation.
 *
 * Copyright (C) 2006 Myricom, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/mxlnd/mxlnd.c
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 * Author: Scott Atchley <atchley at myri.com>
 */

#include "mxlnd.h"

lnd_t the_kmxlnd = {
        .lnd_type       = MXLND,
        .lnd_startup    = mxlnd_startup,
        .lnd_shutdown   = mxlnd_shutdown,
        .lnd_ctl        = mxlnd_ctl,
        .lnd_send       = mxlnd_send,
        .lnd_recv       = mxlnd_recv,
};

kmx_data_t               kmxlnd_data;

void
mxlnd_free_pages(kmx_pages_t *p)
{
        int     npages = p->mxg_npages;
        int     i;

        CDEBUG(D_MALLOC, "freeing %d pages\n", npages);

        for (i = 0; i < npages; i++) {
                if (p->mxg_pages[i] != NULL) {
                        __free_page(p->mxg_pages[i]);
			spin_lock(&kmxlnd_data.kmx_mem_lock);
			kmxlnd_data.kmx_mem_used -= PAGE_SIZE;
			spin_unlock(&kmxlnd_data.kmx_mem_lock);
                }
        }

        MXLND_FREE(p, offsetof(kmx_pages_t, mxg_pages[npages]));
}

int
mxlnd_alloc_pages(kmx_pages_t **pp, int npages)
{
        kmx_pages_t    *p       = NULL;
        int             i       = 0;

        CDEBUG(D_MALLOC, "allocing %d pages\n", npages);

        MXLND_ALLOC(p, offsetof(kmx_pages_t, mxg_pages[npages]));
        if (p == NULL) {
                CERROR("Can't allocate descriptor for %d pages\n", npages);
                return -ENOMEM;
        }

        memset(p, 0, offsetof(kmx_pages_t, mxg_pages[npages]));
        p->mxg_npages = npages;

        for (i = 0; i < npages; i++) {
                p->mxg_pages[i] = alloc_page(GFP_KERNEL);
                if (p->mxg_pages[i] == NULL) {
                        CERROR("Can't allocate page %d of %d\n", i, npages);
                        mxlnd_free_pages(p);
                        return -ENOMEM;
                }
		spin_lock(&kmxlnd_data.kmx_mem_lock);
		kmxlnd_data.kmx_mem_used += PAGE_SIZE;
		spin_unlock(&kmxlnd_data.kmx_mem_lock);
        }

        *pp = p;
        return 0;
}

/**
 * mxlnd_ctx_init - reset ctx struct to the default values
 * @ctx - a kmx_ctx pointer
 */
void
mxlnd_ctx_init(kmx_ctx_t *ctx)
{
        if (ctx == NULL) return;

        /* do not change mxc_type */
        ctx->mxc_incarnation = 0;
        ctx->mxc_deadline = 0;
        ctx->mxc_state = MXLND_CTX_IDLE;
        if (!cfs_list_empty(&ctx->mxc_list))
                cfs_list_del_init(&ctx->mxc_list);
        /* ignore mxc_rx_list */
        if (ctx->mxc_type == MXLND_REQ_TX) {
                ctx->mxc_nid = 0;
                ctx->mxc_peer = NULL;
                ctx->mxc_conn = NULL;
        }
        /* ignore mxc_msg */
        ctx->mxc_lntmsg[0] = NULL;
        ctx->mxc_lntmsg[1] = NULL;
        ctx->mxc_msg_type = 0;
        ctx->mxc_cookie = 0LL;
        ctx->mxc_match = 0LL;
        /* ctx->mxc_seg.segment_ptr points to backing page */
        ctx->mxc_seg.segment_length = 0;
        if (ctx->mxc_seg_list != NULL) {
                LASSERT(ctx->mxc_nseg > 0);
                MXLND_FREE(ctx->mxc_seg_list, ctx->mxc_nseg * sizeof(mx_ksegment_t));
        }
        ctx->mxc_seg_list = NULL;
        ctx->mxc_nseg = 0;
        ctx->mxc_nob = 0;
        memset(&ctx->mxc_mxreq, 0, sizeof(mx_request_t));
        memset(&ctx->mxc_status, 0, sizeof(mx_status_t));
        ctx->mxc_errno = 0;
        /* ctx->mxc_get */
        /* ctx->mxc_put */

        ctx->mxc_msg->mxm_type = 0;
        ctx->mxc_msg->mxm_credits = 0;
        ctx->mxc_msg->mxm_nob = 0;

        return;
}

/**
 * mxlnd_free_txs - free kmx_txs and associated pages
 *
 * Called from mxlnd_shutdown()
 */
void
mxlnd_free_txs(void)
{
        int             i       = 0;
        kmx_ctx_t       *tx     = NULL;

        if (kmxlnd_data.kmx_tx_pages) {
                for (i = 0; i < MXLND_TX_MSGS(); i++) {
                        tx = &kmxlnd_data.kmx_txs[i];
                        if (tx->mxc_seg_list != NULL) {
                                LASSERT(tx->mxc_nseg > 0);
                                MXLND_FREE(tx->mxc_seg_list,
                                           tx->mxc_nseg *
                                           sizeof(*tx->mxc_seg_list));
                        }
                }
                MXLND_FREE(kmxlnd_data.kmx_txs,
                            MXLND_TX_MSGS() * sizeof(kmx_ctx_t));
                mxlnd_free_pages(kmxlnd_data.kmx_tx_pages);
        }

        return;
}

/**
 * mxlnd_init_txs - allocate tx descriptors then stash on txs and idle tx lists
 *
 * Called from mxlnd_startup()
 * returns 0 on success, else -ENOMEM
 */
int
mxlnd_init_txs(void)
{
        int             ret     = 0;
        int             i       = 0;
        int             ipage   = 0;
        int             offset  = 0;
        void           *addr    = NULL;
        kmx_ctx_t      *tx      = NULL;
        kmx_pages_t    *pages   = NULL;
        struct page    *page    = NULL;

        /* pre-mapped messages are not bigger than 1 page */
        CLASSERT(MXLND_MSG_SIZE <= PAGE_SIZE);

        /* No fancy arithmetic when we do the buffer calculations */
        CLASSERT (PAGE_SIZE % MXLND_MSG_SIZE == 0);

        ret = mxlnd_alloc_pages(&pages, MXLND_TX_MSG_PAGES());
        if (ret != 0) {
                CERROR("Can't allocate tx pages\n");
                return -ENOMEM;
        }
        kmxlnd_data.kmx_tx_pages = pages;

        MXLND_ALLOC(kmxlnd_data.kmx_txs, MXLND_TX_MSGS() * sizeof(kmx_ctx_t));
        if (&kmxlnd_data.kmx_txs == NULL) {
                CERROR("Can't allocate %d tx descriptors\n", MXLND_TX_MSGS());
                mxlnd_free_pages(pages);
                return -ENOMEM;
        }

        memset(kmxlnd_data.kmx_txs, 0, MXLND_TX_MSGS() * sizeof(kmx_ctx_t));

        for (i = 0; i < MXLND_TX_MSGS(); i++) {

                tx = &kmxlnd_data.kmx_txs[i];
                tx->mxc_type = MXLND_REQ_TX;

                CFS_INIT_LIST_HEAD(&tx->mxc_list);

                /* map mxc_msg to page */
                page = pages->mxg_pages[ipage];
                addr = page_address(page);
                LASSERT(addr != NULL);
                tx->mxc_msg = (kmx_msg_t *)(addr + offset);
                tx->mxc_seg.segment_ptr = MX_PA_TO_U64(virt_to_phys(tx->mxc_msg));

                mxlnd_ctx_init(tx);

                offset += MXLND_MSG_SIZE;
                LASSERT (offset <= PAGE_SIZE);

                if (offset == PAGE_SIZE) {
                        offset = 0;
                        ipage++;
                        LASSERT (ipage <= MXLND_TX_MSG_PAGES());
                }

                /* in startup(), no locks required */
                cfs_list_add_tail(&tx->mxc_list, &kmxlnd_data.kmx_tx_idle);
        }

        return 0;
}

/**
 * mxlnd_free_peers - free peers
 *
 * Called from mxlnd_shutdown()
 */
void
mxlnd_free_peers(void)
{
        int             i      = 0;
        int             count  = 0;
        kmx_peer_t     *peer   = NULL;
        kmx_peer_t     *next   = NULL;

        for (i = 0; i < MXLND_HASH_SIZE; i++) {
                cfs_list_for_each_entry_safe(peer, next,
                                             &kmxlnd_data.kmx_peers[i],
                                             mxp_list) {
                        cfs_list_del_init(&peer->mxp_list);
                        if (peer->mxp_conn) mxlnd_conn_decref(peer->mxp_conn);
                        mxlnd_peer_decref(peer);
                        count++;
                }
        }
        CDEBUG(D_NET, "%s: freed %d peers\n", __func__, count);
}

/**
 * mxlnd_init_mx - open the endpoint, set our ID, register the EAGER callback
 * @ni - the network interface
 *
 * Returns 0 on success, -1 on failure
 */
int
mxlnd_init_mx(lnet_ni_t *ni)
{
        int                     ret     = 0;
        mx_return_t             mxret;
        u32                     board   = *kmxlnd_tunables.kmx_board;
        u32                     ep_id   = *kmxlnd_tunables.kmx_ep_id;
        u64                     nic_id  = 0LL;
        char                    *ifname = NULL;
        __u32                   ip;
        __u32                   netmask;
        int                     if_up   = 0;

        mxret = mx_init();
        if (mxret != MX_SUCCESS) {
                CERROR("mx_init() failed with %s (%d)\n", mx_strerror(mxret), mxret);
                return -1;
        }

        if (ni->ni_interfaces[0] != NULL) {
                /* Use the IPoMX interface specified in 'networks=' */

                CLASSERT (LNET_MAX_INTERFACES > 1);
                if (ni->ni_interfaces[1] != NULL) {
                        CERROR("Multiple interfaces not supported\n");
                        goto failed_with_init;
                }

                ifname = ni->ni_interfaces[0];
        } else {
                ifname = *kmxlnd_tunables.kmx_default_ipif;
        }

        ret = libcfs_ipif_query(ifname, &if_up, &ip, &netmask);
        if (ret != 0) {
                CERROR("Can't query IPoMX interface %s: %d\n",
                       ifname, ret);
                goto failed_with_init;
        }

        if (!if_up) {
                CERROR("Can't query IPoMX interface %s: it's down\n",
                       ifname);
                goto failed_with_init;
        }

        mxret = mx_open_endpoint(board, ep_id, MXLND_MSG_MAGIC,
                                 NULL, 0, &kmxlnd_data.kmx_endpt);
        if (mxret != MX_SUCCESS) {
                CERROR("mx_open_endpoint() failed with %d\n", mxret);
                goto failed_with_init;
        }

	mx_get_endpoint_addr(kmxlnd_data.kmx_endpt, &kmxlnd_data.kmx_epa);
	mx_decompose_endpoint_addr(kmxlnd_data.kmx_epa, &nic_id, &ep_id);
	mxret = mx_connect(kmxlnd_data.kmx_endpt, nic_id, ep_id,
			   MXLND_MSG_MAGIC,
			   jiffies_to_msecs(MXLND_CONNECT_TIMEOUT),
			   &kmxlnd_data.kmx_epa);
	if (mxret != MX_SUCCESS) {
		CNETERR("unable to connect to myself (%s)\n", mx_strerror(mxret));
		goto failed_with_endpoint;
	}

        ni->ni_nid = LNET_MKNID(LNET_NIDNET(ni->ni_nid), ip);
        CDEBUG(D_NET, "My NID is 0x%llx\n", ni->ni_nid);

        /* this will catch all unexpected receives. */
        mxret = mx_register_unexp_handler(kmxlnd_data.kmx_endpt,
                                          (mx_unexp_handler_t) mxlnd_unexpected_recv,
                                          NULL);
        if (mxret != MX_SUCCESS) {
                CERROR("mx_register_unexp_callback() failed with %s\n",
                         mx_strerror(mxret));
                goto failed_with_endpoint;
        }
	mxret = mx_set_request_timeout(kmxlnd_data.kmx_endpt, NULL,
				       jiffies_to_msecs(MXLND_COMM_TIMEOUT));
	if (mxret != MX_SUCCESS) {
		CERROR("mx_set_request_timeout() failed with %s\n",
			mx_strerror(mxret));
		goto failed_with_endpoint;
	}
        return 0;

failed_with_endpoint:
        mx_close_endpoint(kmxlnd_data.kmx_endpt);
failed_with_init:
        mx_finalize();
        return -1;
}


/**
 * mxlnd_thread_start - spawn a kernel thread with this function
 * @fn - function pointer
 * @arg - pointer to the parameter data
 * @name - name of new thread
 *
 * Returns 0 on success and a negative value on failure
 */
int
mxlnd_thread_start(int (*fn)(void *arg), void *arg, char *name)
{
	cfs_task *task;
	int     i   = (int) ((long) arg);

	atomic_inc(&kmxlnd_data.kmx_nthreads);
	init_completion(&kmxlnd_data.kmx_completions[i]);

	task = kthread_run(fn, arg, name);
	if (IS_ERR(task)) {
		CERROR("cfs_create_thread() failed with %d\n", PTR_ERR(task));
		atomic_dec(&kmxlnd_data.kmx_nthreads);
	}
	return PTR_ERR(task);
}

/**
 * mxlnd_thread_stop - decrement thread counter
 *
 * The thread returns 0 when it detects shutdown.
 * We are simply decrementing the thread counter.
 */
void
mxlnd_thread_stop(long id)
{
	int     i       = (int) id;
	atomic_dec (&kmxlnd_data.kmx_nthreads);
	complete(&kmxlnd_data.kmx_completions[i]);
}

/**
 * mxlnd_shutdown - stop IO, clean up state
 * @ni - LNET interface handle
 *
 * No calls to the LND should be made after calling this function.
 */
void
mxlnd_shutdown (lnet_ni_t *ni)
{
	int     i               = 0;
	int     nthreads        = MXLND_NDAEMONS + *kmxlnd_tunables.kmx_n_waitd;

	LASSERT (ni == kmxlnd_data.kmx_ni);
	LASSERT (ni->ni_data == &kmxlnd_data);
	CDEBUG(D_NET, "in shutdown()\n");

	CDEBUG(D_MALLOC, "before MXLND cleanup: libcfs_kmemory %d "
			 "kmx_mem_used %ld\n", atomic_read(&libcfs_kmemory),
			 kmxlnd_data.kmx_mem_used);


	CDEBUG(D_NET, "setting shutdown = 1\n");
	atomic_set(&kmxlnd_data.kmx_shutdown, 1);

	switch (kmxlnd_data.kmx_init) {

        case MXLND_INIT_ALL:

                /* calls write_[un]lock(kmx_global_lock) */
                mxlnd_del_peer(LNET_NID_ANY);

		/* wakeup request_waitds */
		mx_wakeup(kmxlnd_data.kmx_endpt);
		up(&kmxlnd_data.kmx_tx_queue_sem);
		up(&kmxlnd_data.kmx_conn_sem);
		mxlnd_sleep(msecs_to_jiffies(2 * MSEC_PER_SEC));

                /* fall through */

        case MXLND_INIT_THREADS:

		CDEBUG(D_NET, "waiting on threads\n");
		/* wait for threads to complete */
		for (i = 0; i < nthreads; i++) {
			wait_for_completion(&kmxlnd_data.kmx_completions[i]);
		}
		LASSERT(atomic_read(&kmxlnd_data.kmx_nthreads) == 0);

                CDEBUG(D_NET, "freeing completions\n");
                MXLND_FREE(kmxlnd_data.kmx_completions,
			    nthreads * sizeof(struct completion));

                /* fall through */

        case MXLND_INIT_MX:

                CDEBUG(D_NET, "stopping mx\n");

                /* no peers left, close the endpoint */
                mx_close_endpoint(kmxlnd_data.kmx_endpt);
                mx_finalize();

                /* fall through */

        case MXLND_INIT_TXS:

                CDEBUG(D_NET, "freeing txs\n");

                /* free all txs and associated pages */
                mxlnd_free_txs();

                /* fall through */

        case MXLND_INIT_DATA:

                CDEBUG(D_NET, "freeing peers\n");

                /* peers should be gone, but check again */
                mxlnd_free_peers();

                /* conn zombies should be gone, but check again */
                mxlnd_free_conn_zombies();

                /* fall through */

        case MXLND_INIT_NOTHING:
                break;
        }
        CDEBUG(D_NET, "shutdown complete\n");

	CDEBUG(D_MALLOC, "after MXLND cleanup: libcfs_kmemory %d "
			 "kmx_mem_used %ld\n", atomic_read(&libcfs_kmemory),
			 kmxlnd_data.kmx_mem_used);

	kmxlnd_data.kmx_init = MXLND_INIT_NOTHING;
	module_put(THIS_MODULE);
	return;
}

/**
 * mxlnd_startup - initialize state, open an endpoint, start IO
 * @ni - LNET interface handle
 *
 * Initialize state, open an endpoint, start monitoring threads.
 * Should only be called once.
 */
int
mxlnd_startup (lnet_ni_t *ni)
{
        int             i               = 0;
        int             ret             = 0;
        int             nthreads        = MXLND_NDAEMONS /* tx_queued, timeoutd, connd */
                                          + *kmxlnd_tunables.kmx_n_waitd;
        struct timeval  tv;

        LASSERT (ni->ni_lnd == &the_kmxlnd);

        if (kmxlnd_data.kmx_init != MXLND_INIT_NOTHING) {
                CERROR("Only 1 instance supported\n");
                return -EPERM;
        }
	CDEBUG(D_MALLOC, "before MXLND startup: libcfs_kmemory %d "
			 "kmx_mem_used %ld\n", atomic_read(&libcfs_kmemory),
			 kmxlnd_data.kmx_mem_used);

        ni->ni_maxtxcredits = MXLND_TX_MSGS();
        ni->ni_peertxcredits = *kmxlnd_tunables.kmx_peercredits;
        if (ni->ni_maxtxcredits < ni->ni_peertxcredits)
                ni->ni_maxtxcredits = ni->ni_peertxcredits;

	try_module_get(THIS_MODULE);
	memset (&kmxlnd_data, 0, sizeof (kmxlnd_data));

        kmxlnd_data.kmx_ni = ni;
        ni->ni_data = &kmxlnd_data;

	do_gettimeofday(&tv);
	kmxlnd_data.kmx_incarnation = (((__u64)tv.tv_sec) * 1000000) + tv.tv_usec;
	CDEBUG(D_NET, "my incarnation is %llu\n", kmxlnd_data.kmx_incarnation);

	rwlock_init (&kmxlnd_data.kmx_global_lock);
	spin_lock_init (&kmxlnd_data.kmx_mem_lock);

        CFS_INIT_LIST_HEAD (&kmxlnd_data.kmx_conn_reqs);
        CFS_INIT_LIST_HEAD (&kmxlnd_data.kmx_conn_zombies);
        CFS_INIT_LIST_HEAD (&kmxlnd_data.kmx_orphan_msgs);
	spin_lock_init (&kmxlnd_data.kmx_conn_lock);
	sema_init(&kmxlnd_data.kmx_conn_sem, 0);

        for (i = 0; i < MXLND_HASH_SIZE; i++) {
                CFS_INIT_LIST_HEAD (&kmxlnd_data.kmx_peers[i]);
        }

        CFS_INIT_LIST_HEAD (&kmxlnd_data.kmx_tx_idle);
	spin_lock_init (&kmxlnd_data.kmx_tx_idle_lock);
	kmxlnd_data.kmx_tx_next_cookie = 1;
	CFS_INIT_LIST_HEAD (&kmxlnd_data.kmx_tx_queue);
	spin_lock_init (&kmxlnd_data.kmx_tx_queue_lock);
	sema_init(&kmxlnd_data.kmx_tx_queue_sem, 0);

        kmxlnd_data.kmx_init = MXLND_INIT_DATA;
        /*****************************************************/

        ret = mxlnd_init_txs();
        if (ret != 0) {
                CERROR("Can't alloc tx descs: %d\n", ret);
                goto failed;
        }
        kmxlnd_data.kmx_init = MXLND_INIT_TXS;
        /*****************************************************/

        ret = mxlnd_init_mx(ni);
        if (ret != 0) {
                CERROR("Can't init mx\n");
                goto failed;
        }

        kmxlnd_data.kmx_init = MXLND_INIT_MX;
        /*****************************************************/

        /* start threads */

        MXLND_ALLOC(kmxlnd_data.kmx_completions,
		     nthreads * sizeof(struct completion));
        if (kmxlnd_data.kmx_completions == NULL) {
                CERROR("failed to alloc kmxlnd_data.kmx_completions\n");
                goto failed;
        }
        memset(kmxlnd_data.kmx_completions, 0,
	       nthreads * sizeof(struct completion));

        CDEBUG(D_NET, "using %d %s in mx_wait_any()\n",
                *kmxlnd_tunables.kmx_n_waitd,
                *kmxlnd_tunables.kmx_n_waitd == 1 ? "thread" : "threads");

        for (i = 0; i < *kmxlnd_tunables.kmx_n_waitd; i++) {
		char                    name[24];
		memset(name, 0, sizeof(name));
		snprintf(name, sizeof(name), "mxlnd_request_waitd_%02ld", i);
                ret = mxlnd_thread_start(mxlnd_request_waitd, (void*)((long)i));
		if (ret < 0) {
			CERROR("Starting mxlnd_request_waitd[%d] "
				"failed with %d\n", i, ret);
			atomic_set(&kmxlnd_data.kmx_shutdown, 1);
			mx_wakeup(kmxlnd_data.kmx_endpt);
			for (--i; i >= 0; i--) {
				wait_for_completion(&kmxlnd_data.kmx_completions[i]);
			}
			LASSERT(atomic_read(&kmxlnd_data.kmx_nthreads) == 0);
			MXLND_FREE(kmxlnd_data.kmx_completions,
				nthreads * sizeof(struct completion));

			goto failed;
		}
	}
	ret = mxlnd_thread_start(mxlnd_tx_queued, (void *)((long)i++),
				 "mxlnd_tx_queued");
	if (ret < 0) {
		CERROR("Starting mxlnd_tx_queued failed with %d\n", ret);
		atomic_set(&kmxlnd_data.kmx_shutdown, 1);
		mx_wakeup(kmxlnd_data.kmx_endpt);
		for (--i; i >= 0; i--) {
			wait_for_completion(&kmxlnd_data.kmx_completions[i]);
		}
		LASSERT(atomic_read(&kmxlnd_data.kmx_nthreads) == 0);
		MXLND_FREE(kmxlnd_data.kmx_completions,
			nthreads * sizeof(struct completion));
		goto failed;
	}
	ret = mxlnd_thread_start(mxlnd_timeoutd, (void *)((long)i++),
				 "mxlnd_timeoutd");
	if (ret < 0) {
		CERROR("Starting mxlnd_timeoutd failed with %d\n", ret);
		atomic_set(&kmxlnd_data.kmx_shutdown, 1);
		mx_wakeup(kmxlnd_data.kmx_endpt);
		up(&kmxlnd_data.kmx_tx_queue_sem);
		for (--i; i >= 0; i--) {
			wait_for_completion(&kmxlnd_data.kmx_completions[i]);
		}
		LASSERT(atomic_read(&kmxlnd_data.kmx_nthreads) == 0);
		MXLND_FREE(kmxlnd_data.kmx_completions,
			nthreads * sizeof(struct completion));
		goto failed;
	}
	ret = mxlnd_thread_start(mxlnd_connd, (void *)((long)i++),
				 "mxlnd_connd");
	if (ret < 0) {
		CERROR("Starting mxlnd_connd failed with %d\n", ret);
		atomic_set(&kmxlnd_data.kmx_shutdown, 1);
		mx_wakeup(kmxlnd_data.kmx_endpt);
		up(&kmxlnd_data.kmx_tx_queue_sem);
		for (--i; i >= 0; i--) {
			wait_for_completion(&kmxlnd_data.kmx_completions[i]);
		}
		LASSERT(atomic_read(&kmxlnd_data.kmx_nthreads) == 0);
		MXLND_FREE(kmxlnd_data.kmx_completions,
			nthreads * sizeof(struct completion));
		goto failed;
	}

        kmxlnd_data.kmx_init = MXLND_INIT_THREADS;
        /*****************************************************/

        kmxlnd_data.kmx_init = MXLND_INIT_ALL;
        CDEBUG(D_MALLOC, "startup complete (kmx_mem_used %ld)\n", kmxlnd_data.kmx_mem_used);

        return 0;
failed:
        CERROR("mxlnd_startup failed\n");
        mxlnd_shutdown(ni);
        return (-ENETDOWN);
}

static int mxlnd_init(void)
{
        lnet_register_lnd(&the_kmxlnd);
        return 0;
}

static void mxlnd_exit(void)
{
        lnet_unregister_lnd(&the_kmxlnd);
        return;
}

module_init(mxlnd_init);
module_exit(mxlnd_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Myricom, Inc. - help@myri.com");
MODULE_DESCRIPTION("Kernel MyrinetExpress LND");
MODULE_VERSION("0.6.0");
