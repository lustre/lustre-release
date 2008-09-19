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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
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

/**
 * mxlnd_ctx_free - free ctx struct
 * @ctx - a kmx_peer pointer
 *
 * The calling function should remove the ctx from the ctx list first
 * then free it.
 */
void
mxlnd_ctx_free(struct kmx_ctx *ctx)
{
        if (ctx == NULL) return;

        if (ctx->mxc_page != NULL) {
                __free_page(ctx->mxc_page);
                spin_lock(&kmxlnd_data.kmx_global_lock);
                kmxlnd_data.kmx_mem_used -= MXLND_EAGER_SIZE;
                spin_unlock(&kmxlnd_data.kmx_global_lock);
        }

        if (ctx->mxc_seg_list != NULL) {
                LASSERT(ctx->mxc_nseg > 0);
                MXLND_FREE(ctx->mxc_seg_list, ctx->mxc_nseg * sizeof(mx_ksegment_t));
        }

        MXLND_FREE (ctx, sizeof (*ctx));
        return;
}

/**
 * mxlnd_ctx_alloc - allocate and initialize a new ctx struct
 * @ctxp - address of a kmx_ctx pointer
 *
 * Returns 0 on success and -EINVAL, -ENOMEM on failure
 */
int
mxlnd_ctx_alloc(struct kmx_ctx **ctxp, enum kmx_req_type type)
{
        int             ret     = 0;
        struct kmx_ctx  *ctx    = NULL;

        if (ctxp == NULL) return -EINVAL;

        MXLND_ALLOC(ctx, sizeof (*ctx));
        if (ctx == NULL) {
                CDEBUG(D_NETERROR, "Cannot allocate ctx\n");
                return -ENOMEM;
        }
        memset(ctx, 0, sizeof(*ctx));
        spin_lock_init(&ctx->mxc_lock);

        ctx->mxc_type = type;
        ctx->mxc_page = alloc_page (GFP_KERNEL);
        if (ctx->mxc_page == NULL) {
                CDEBUG(D_NETERROR, "Can't allocate page\n");
                ret = -ENOMEM;
                goto failed;
        }
        spin_lock(&kmxlnd_data.kmx_global_lock);
        kmxlnd_data.kmx_mem_used += MXLND_EAGER_SIZE;
        spin_unlock(&kmxlnd_data.kmx_global_lock);
        ctx->mxc_msg = (struct kmx_msg *)((char *)page_address(ctx->mxc_page));
        ctx->mxc_seg.segment_ptr = MX_PA_TO_U64(lnet_page2phys(ctx->mxc_page));
        ctx->mxc_state = MXLND_CTX_IDLE;

        *ctxp = ctx;
        return 0;

failed:
        mxlnd_ctx_free(ctx);
        return ret;
}

/**
 * mxlnd_ctx_init - reset ctx struct to the default values
 * @ctx - a kmx_ctx pointer
 */
void
mxlnd_ctx_init(struct kmx_ctx *ctx)
{
        if (ctx == NULL) return;

        /* do not change mxc_type */
        ctx->mxc_incarnation = 0;
        ctx->mxc_deadline = 0;
        ctx->mxc_state = MXLND_CTX_IDLE;
        /* ignore mxc_global_list */
        if (ctx->mxc_list.next != NULL && !list_empty(&ctx->mxc_list)) {
                if (ctx->mxc_peer != NULL) spin_lock(&ctx->mxc_lock);
                list_del_init(&ctx->mxc_list);
                if (ctx->mxc_peer != NULL) spin_unlock(&ctx->mxc_lock);
        }
        /* ignore mxc_rx_list */
        /* ignore mxc_lock */
        ctx->mxc_nid = 0;
        ctx->mxc_peer = NULL;
        ctx->mxc_conn = NULL;
        /* ignore mxc_msg */
        /* ignore mxc_page */
        ctx->mxc_lntmsg[0] = NULL;
        ctx->mxc_lntmsg[1] = NULL;
        ctx->mxc_msg_type = 0;
        ctx->mxc_cookie = 0LL;
        ctx->mxc_match = 0LL;
        /* ctx->mxc_seg.segment_ptr points to mxc_page */
        ctx->mxc_seg.segment_length = 0;
        if (ctx->mxc_seg_list != NULL) {
                LASSERT(ctx->mxc_nseg > 0);
                MXLND_FREE(ctx->mxc_seg_list, ctx->mxc_nseg * sizeof(mx_ksegment_t));
        }
        ctx->mxc_seg_list = NULL;
        ctx->mxc_nseg = 0;
        ctx->mxc_nob = 0;
        ctx->mxc_mxreq = NULL;
        memset(&ctx->mxc_status, 0, sizeof(mx_status_t));
        /* ctx->mxc_get */
        /* ctx->mxc_put */

        ctx->mxc_msg->mxm_type = 0;
        ctx->mxc_msg->mxm_credits = 0;
        ctx->mxc_msg->mxm_nob = 0;
        ctx->mxc_msg->mxm_seq = 0;

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
        struct kmx_ctx          *tx     = NULL;
        struct kmx_ctx          *next   = NULL;

        list_for_each_entry_safe(tx, next, &kmxlnd_data.kmx_txs, mxc_global_list) {
                list_del_init(&tx->mxc_global_list);
                mxlnd_ctx_free(tx);
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
        struct kmx_ctx  *tx      = NULL;

        for (i = 0; i < *kmxlnd_tunables.kmx_ntx; i++) {
                ret = mxlnd_ctx_alloc(&tx, MXLND_REQ_TX);
                if (ret != 0) {
                        mxlnd_free_txs();
                        return ret;
                }
                mxlnd_ctx_init(tx);
                /* in startup(), no locks required */
                list_add_tail(&tx->mxc_global_list, &kmxlnd_data.kmx_txs);
                list_add_tail(&tx->mxc_list, &kmxlnd_data.kmx_tx_idle);
        }
        return 0;
}

/**
 * mxlnd_free_rxs - free initial kmx_rx descriptors and associated pages
 *
 * Called from mxlnd_shutdown()
 */
void
mxlnd_free_rxs(void)
{
        struct kmx_ctx          *rx     = NULL;
        struct kmx_ctx          *next   = NULL;

        list_for_each_entry_safe(rx, next, &kmxlnd_data.kmx_rxs, mxc_global_list) {
                list_del_init(&rx->mxc_global_list);
                mxlnd_ctx_free(rx);
        }
        return;
}

/**
 * mxlnd_init_rxs - allocate initial rx descriptors 
 *
 * Called from startup(). We create MXLND_MAX_PEERS plus MXLND_NTX
 * rx descriptors. We create one for each potential peer to handle 
 * the initial connect request. We create on for each tx in case the 
 * send requires a non-eager receive.
 *
 * Returns 0 on success, else -ENOMEM
 */
int
mxlnd_init_rxs(void)
{
        int             ret     = 0;
        int             i       = 0;
        struct kmx_ctx  *rx      = NULL;

        for (i = 0; i < (*kmxlnd_tunables.kmx_ntx + *kmxlnd_tunables.kmx_max_peers); i++) {
                ret = mxlnd_ctx_alloc(&rx, MXLND_REQ_RX);
                if (ret != 0) {
                        mxlnd_free_rxs();
                        return ret;
                }
                mxlnd_ctx_init(rx);
                /* in startup(), no locks required */
                list_add_tail(&rx->mxc_global_list, &kmxlnd_data.kmx_rxs);
                list_add_tail(&rx->mxc_list, &kmxlnd_data.kmx_rx_idle);
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
        int                      i      = 0;
        struct kmx_peer         *peer   = NULL;
        struct kmx_peer         *next   = NULL;

        for (i = 0; i < MXLND_HASH_SIZE; i++) {
                list_for_each_entry_safe(peer, next, &kmxlnd_data.kmx_peers[i], mxp_peers) {
                        list_del_init(&peer->mxp_peers);
                        if (peer->mxp_conn) mxlnd_conn_decref(peer->mxp_conn);
                        mxlnd_peer_decref(peer);
                }
        }
}

int
mxlnd_host_alloc(struct kmx_host **hostp)
{
        struct kmx_host *host   = NULL;

        MXLND_ALLOC(host, sizeof (*host));
        if (host == NULL) {
                CDEBUG(D_NETERROR, "Cannot allocate host\n");
                return -1;
        }
        memset(host, 0, sizeof(*host));
        spin_lock_init(&host->mxh_lock);

        *hostp = host;

        return 0;
}

void
mxlnd_host_free(struct kmx_host *host)
{
        if (host == NULL) return;

        if (host->mxh_hostname != NULL)
                MXLND_FREE(host->mxh_hostname, strlen(host->mxh_hostname) + 1);

        MXLND_FREE(host, sizeof(*host));
        return;
}

/**
 * mxlnd_free_hosts - free kmx_hosts
 *
 * Called from mxlnd_shutdown()
 */
void
mxlnd_free_hosts(void)
{
        struct kmx_host         *host   = NULL;
        struct kmx_host         *next   = NULL;

        list_for_each_entry_safe(host, next, &kmxlnd_data.kmx_hosts, mxh_list) {
                list_del_init(&host->mxh_list);
                mxlnd_host_free(host);
        }
        return;
}

#define xstr(s) #s
#define str(s) xstr(s)
#define MXLND_MAX_BOARD 4       /* we expect hosts to have fewer NICs than this */
#define MXLND_MAX_EP_ID 16      /* we expect hosts to have less than this endpoints */

/* this parses a line that consists of:
 * 
 * IP              HOSTNAME           BOARD        ENDPOINT ID
 * 169.192.0.113   mds01              0            3
 * 
 * By default MX uses the alias (short hostname). If you override
 * it using mx_hostname to use the FQDN or some other name, the hostname
 * here must match exactly.
 */

/* MX_MAX_HOSTNAME_LEN = 80. See myriexpress.h */
int
mxlnd_parse_line(char *line)
{
        int             i               = 0;
        int             ret             = 0;
        int             len             = 0;
        u32             ip[4]           = { 0, 0, 0, 0 };
        char            hostname[MX_MAX_HOSTNAME_LEN];
        u32             board           = -1;
        u32             ep_id           = -1;
        struct kmx_host *host           = NULL;

        if (line == NULL) return -1;

        len = strlen(line);

        if (len == 0) return -1;

        /* convert tabs to spaces */
        for (i = 0; i < len; i++) {
                if (line[i] == '\t') line[i] = ' ';
        }

        memset(&hostname, 0 , sizeof(hostname));
        ret = sscanf(line, "%d.%d.%d.%d %" str(MX_MAX_HOSTNAME_LEN) "s %d %d", 
                     &ip[0], &ip[1], &ip[2], &ip[3], hostname, &board, &ep_id);

        if (ret != 7) {
                return -1;
        }

        /* check for valid values */
        /* we assume a valid IP address (all <= 255), number of NICs,
         * and number of endpoint IDs */
        if (ip[0] > 255 || ip [1] > 255 || ip[2] > 255 || ip[3] > 255 ||
            board > MXLND_MAX_BOARD || ep_id > MXLND_MAX_EP_ID) {
                CDEBUG(D_NETERROR, "Illegal value in \"%s\". Ignoring "
                                   "this host.\n", line);
                return -1;
        }

        ret = mxlnd_host_alloc(&host);
        if (ret != 0) return -1;

        host->mxh_addr = ((ip[0]<<24)|(ip[1]<<16)|(ip[2]<<8)|ip[3]);
        len = strlen(hostname);
        MXLND_ALLOC(host->mxh_hostname, len + 1);
        if (host->mxh_hostname == NULL) {
                mxlnd_host_free(host);
                return -ENOMEM;
        }
        memset(host->mxh_hostname, 0, len + 1);
        strncpy(host->mxh_hostname, hostname, len);
        host->mxh_board = board;
        host->mxh_ep_id = ep_id;

        spin_lock(&kmxlnd_data.kmx_hosts_lock);
        list_add_tail(&host->mxh_list, &kmxlnd_data.kmx_hosts);
        spin_unlock(&kmxlnd_data.kmx_hosts_lock);

        return 0;
}

void
mxlnd_print_hosts(void)
{
#if MXLND_DEBUG
        struct kmx_host         *host   = NULL;

        list_for_each_entry(host, &kmxlnd_data.kmx_hosts, mxh_list) {
                int             ip[4];
                u32             addr    = host->mxh_addr;

                ip[0] = (addr >> 24) & 0xff;
                ip[1] = (addr >> 16) & 0xff;
                ip[2] = (addr >>  8) & 0xff;
                ip[3] = addr & 0xff;
                CDEBUG(D_NET, "\tip= %d.%d.%d.%d\n\thost= %s\n\tboard= %d\n\tep_id= %d\n\n",
                            ip[0], ip[1], ip[2], ip[3],
                            host->mxh_hostname, host->mxh_board, host->mxh_ep_id);
        }
#endif
        return;
}

#define MXLND_BUFSIZE (PAGE_SIZE - 1)

int
mxlnd_parse_hosts(char *filename)
{
        int             ret             = 0;
        s32             size            = 0;
        s32             bufsize         = MXLND_BUFSIZE;
        s32             allocd          = 0;
        loff_t          offset          = 0;
        struct file     *filp           = NULL;
        struct inode    *inode          = NULL;
        char            *buf            = NULL;
        s32             buf_off         = 0;
        char            *sep            = NULL;
        char            *line           = NULL;

        if (filename == NULL) return -1;

        filp = filp_open(filename, O_RDONLY, 0);
        if (IS_ERR(filp)) {
                CERROR("filp_open() failed for %s\n", filename);
                return -1;
        }

        inode = filp->f_dentry->d_inode;
        if (!S_ISREG(inode->i_mode)) {
                CERROR("%s is not a regular file\n", filename);
                return -1;
        }

        size = (s32) inode->i_size;
        if (size < MXLND_BUFSIZE) bufsize = size;
        allocd = bufsize;
        MXLND_ALLOC(buf, allocd + 1);
        if (buf == NULL) {
                CERROR("Cannot allocate buf\n");
                filp_close(filp, current->files);
                return -1;
        }

        while (offset < size) {
                memset(buf, 0, bufsize + 1);
                ret = kernel_read(filp, (unsigned long) offset, buf, (unsigned long) bufsize);
                if (ret < 0) {
                        CDEBUG(D_NETERROR, "kernel_read() returned %d - closing %s\n", ret, filename);
                        filp_close(filp, current->files);
                        MXLND_FREE(buf, allocd + 1);
                        return -1;
                }

                if (ret < bufsize) bufsize = ret;
                buf_off = 0;
                while (buf_off < bufsize) {
                        sep = strchr(buf + buf_off, '\n');
                        if (sep != NULL) {
                                /* we have a line */
                                line = buf + buf_off;
                                *sep = '\0';
                                ret = mxlnd_parse_line(line);
                                if (ret != 0 && strlen(line) != 0) {
                                        CDEBUG(D_NETERROR, "Failed to parse \"%s\". Ignoring this host.\n", line);
                                }
                                buf_off += strlen(line) + 1;
                        } else {
                                /* last line or we need to read more */
                                line = buf + buf_off;
                                ret = mxlnd_parse_line(line);
                                if (ret != 0) {
                                        bufsize -= strlen(line) + 1;
                                }
                                buf_off += strlen(line) + 1;
                        }
                }
                offset += bufsize;
                bufsize = MXLND_BUFSIZE;
        }

        MXLND_FREE(buf, allocd + 1);
        filp_close(filp, current->files);
        mxlnd_print_hosts();

        return 0;
}

/**
 * mxlnd_init_mx - open the endpoint, set out ID, register the EAGER callback
 * @ni - the network interface
 *
 * Returns 0 on success, -1 on failure
 */
int
mxlnd_init_mx(lnet_ni_t *ni)
{
        int                     ret     = 0;
        int                     found   = 0;
        mx_return_t             mxret;
        mx_endpoint_addr_t      addr;
        u32                     board   = *kmxlnd_tunables.kmx_board;
        u32                     ep_id   = *kmxlnd_tunables.kmx_ep_id;
        u64                     nic_id  = 0LL;
        struct kmx_host         *host   = NULL;

        mxret = mx_init();
        if (mxret != MX_SUCCESS) {
                CERROR("mx_init() failed with %s (%d)\n", mx_strerror(mxret), mxret);
                return -1;
        }

        ret = mxlnd_parse_hosts(*kmxlnd_tunables.kmx_hosts);
        if (ret != 0) {
                if (*kmxlnd_tunables.kmx_hosts != NULL) {
                        CERROR("mxlnd_parse_hosts(%s) failed\n", *kmxlnd_tunables.kmx_hosts);
                }
                mx_finalize();
                return -1;
        }

        list_for_each_entry(host, &kmxlnd_data.kmx_hosts, mxh_list) {
                if (strcmp(host->mxh_hostname, system_utsname.nodename) == 0) {
                        /* override the defaults and module parameters with 
                         * the info from the hosts file */
                        board = host->mxh_board;
                        ep_id = host->mxh_ep_id;
                        kmxlnd_data.kmx_localhost = host;
                        CDEBUG(D_NET, "my hostname is %s board %d ep_id %d\n", kmxlnd_data.kmx_localhost->mxh_hostname, kmxlnd_data.kmx_localhost->mxh_board, kmxlnd_data.kmx_localhost->mxh_ep_id);
                        found = 1;
                        break;
                }
        }

        if (found == 0) {
                CERROR("no host entry found for localhost\n");
                mx_finalize();
                return -1;
        }

        mxret = mx_open_endpoint(board, ep_id, MXLND_MSG_MAGIC, 
                                 NULL, 0, &kmxlnd_data.kmx_endpt);
        if (mxret != MX_SUCCESS) {
                CERROR("mx_open_endpoint() failed with %d\n", mxret);
                mx_finalize();
                return -1;
        }

        mx_get_endpoint_addr(kmxlnd_data.kmx_endpt, &addr);
        mx_decompose_endpoint_addr(addr, &nic_id, &ep_id);

        LASSERT(host != NULL);
        ni->ni_nid = LNET_MKNID(LNET_NIDNET(ni->ni_nid), host->mxh_addr);

        CDEBUG(D_NET, "My NID is 0x%llx\n", ni->ni_nid);

        /* this will catch all unexpected receives. */
        mxret = mx_register_unexp_handler(kmxlnd_data.kmx_endpt,
                                          (mx_unexp_handler_t) mxlnd_unexpected_recv,
                                          NULL);
        if (mxret != MX_SUCCESS) {
                CERROR("mx_register_unexp_callback() failed with %s\n", 
                         mx_strerror(mxret));
                mx_close_endpoint(kmxlnd_data.kmx_endpt);
                mx_finalize();
                return -1;
        }
        mxret = mx_set_request_timeout(kmxlnd_data.kmx_endpt, NULL, MXLND_COMM_TIMEOUT/HZ*1000);
        if (mxret != MX_SUCCESS) {
                CERROR("mx_set_request_timeout() failed with %s\n", 
                        mx_strerror(mxret));
                mx_close_endpoint(kmxlnd_data.kmx_endpt);
                mx_finalize();
                return -1;
        }
        return 0;
}


/**
 * mxlnd_thread_start - spawn a kernel thread with this function
 * @fn - function pointer
 * @arg - pointer to the parameter data
 *
 * Returns 0 on success and a negative value on failure
 */
int
mxlnd_thread_start(int (*fn)(void *arg), void *arg)
{
        int     pid = 0;
        int     i   = (int) ((long) arg);

        atomic_inc(&kmxlnd_data.kmx_nthreads);
        init_completion(&kmxlnd_data.kmx_completions[i]);

        pid = kernel_thread (fn, arg, 0);
        if (pid < 0) {
                CERROR("kernel_thread() failed with %d\n", pid);
                atomic_dec(&kmxlnd_data.kmx_nthreads);
        }
        return pid;
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
        int     nthreads        = 2 + *kmxlnd_tunables.kmx_n_waitd;

        LASSERT (ni == kmxlnd_data.kmx_ni);
        LASSERT (ni->ni_data == &kmxlnd_data);
        CDEBUG(D_NET, "in shutdown()\n");

        CDEBUG(D_MALLOC, "before MXLND cleanup: libcfs_kmemory %d "
                         "kmx_mem_used %ld\n", atomic_read (&libcfs_kmemory), 
                         kmxlnd_data.kmx_mem_used);

        switch (kmxlnd_data.kmx_init) {

        case MXLND_INIT_ALL:

                CDEBUG(D_NET, "setting shutdown = 1\n");
                /* set shutdown and wakeup request_waitds */
                kmxlnd_data.kmx_shutdown = 1;
                mb();
                mx_wakeup(kmxlnd_data.kmx_endpt);
                up(&kmxlnd_data.kmx_tx_queue_sem);
                mxlnd_sleep(2 * HZ);

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
                            MXLND_NCOMPLETIONS * sizeof(struct completion));

                /* fall through */

        case MXLND_INIT_MX:

                CDEBUG(D_NET, "stopping mx\n");

                /* wakeup waiters if they missed the above.
                 * close endpoint to stop all traffic.
                 * this will cancel and cleanup all requests, etc. */

                mx_wakeup(kmxlnd_data.kmx_endpt);
                mx_close_endpoint(kmxlnd_data.kmx_endpt);
                mx_finalize();

                CDEBUG(D_NET, "mxlnd_free_hosts();\n");
                mxlnd_free_hosts();

                /* fall through */

        case MXLND_INIT_RXS:

                CDEBUG(D_NET, "freeing rxs\n");

                /* free all rxs and associated pages */
                mxlnd_free_rxs();

                /* fall through */

        case MXLND_INIT_TXS:

                CDEBUG(D_NET, "freeing txs\n");

                /* free all txs and associated pages */
                mxlnd_free_txs();

                /* fall through */

        case MXLND_INIT_DATA:

                CDEBUG(D_NET, "freeing peers\n");

                /* free peer list */
                mxlnd_free_peers();

                /* fall through */

        case MXLND_INIT_NOTHING:
                break;
        }
        CDEBUG(D_NET, "shutdown complete\n");

        CDEBUG(D_MALLOC, "after MXLND cleanup: libcfs_kmemory %d "
                         "kmx_mem_used %ld\n", atomic_read (&libcfs_kmemory), 
                         kmxlnd_data.kmx_mem_used);

        kmxlnd_data.kmx_init = MXLND_INIT_NOTHING;
        PORTAL_MODULE_UNUSE;
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
        int             nthreads        = 2; /* for timeoutd and tx_queued */
        struct timeval  tv;

        LASSERT (ni->ni_lnd == &the_kmxlnd);

        if (kmxlnd_data.kmx_init != MXLND_INIT_NOTHING) {
                CERROR("Only 1 instance supported\n");
                return -EPERM;
        }
        CDEBUG(D_MALLOC, "before MXLND startup: libcfs_kmemory %d "
                         "kmx_mem_used %ld\n", atomic_read (&libcfs_kmemory), 
                         kmxlnd_data.kmx_mem_used);

        /* reserve 1/2 of tx for connect request messages */
        ni->ni_maxtxcredits = *kmxlnd_tunables.kmx_ntx / 2;
        ni->ni_peertxcredits = *kmxlnd_tunables.kmx_credits;
        if (ni->ni_maxtxcredits < ni->ni_peertxcredits)
                ni->ni_maxtxcredits = ni->ni_peertxcredits;

        PORTAL_MODULE_USE;
        memset (&kmxlnd_data, 0, sizeof (kmxlnd_data));

        kmxlnd_data.kmx_ni = ni;
        ni->ni_data = &kmxlnd_data;

        do_gettimeofday(&tv);
        kmxlnd_data.kmx_incarnation = (((__u64)tv.tv_sec) * 1000000) + tv.tv_usec;
        CDEBUG(D_NET, "my incarnation is %lld\n", kmxlnd_data.kmx_incarnation);

        spin_lock_init (&kmxlnd_data.kmx_global_lock);

        INIT_LIST_HEAD (&kmxlnd_data.kmx_conn_req);
        spin_lock_init (&kmxlnd_data.kmx_conn_lock);
        sema_init(&kmxlnd_data.kmx_conn_sem, 0);

        INIT_LIST_HEAD (&kmxlnd_data.kmx_hosts);
        spin_lock_init (&kmxlnd_data.kmx_hosts_lock);

        for (i = 0; i < MXLND_HASH_SIZE; i++) {
                INIT_LIST_HEAD (&kmxlnd_data.kmx_peers[i]);
        }
        rwlock_init (&kmxlnd_data.kmx_peers_lock);

        INIT_LIST_HEAD (&kmxlnd_data.kmx_txs);
        INIT_LIST_HEAD (&kmxlnd_data.kmx_tx_idle);
        spin_lock_init (&kmxlnd_data.kmx_tx_idle_lock);
        kmxlnd_data.kmx_tx_next_cookie = 1;
        INIT_LIST_HEAD (&kmxlnd_data.kmx_tx_queue);
        spin_lock_init (&kmxlnd_data.kmx_tx_queue_lock);
        sema_init(&kmxlnd_data.kmx_tx_queue_sem, 0);

        INIT_LIST_HEAD (&kmxlnd_data.kmx_rxs);
        spin_lock_init (&kmxlnd_data.kmx_rxs_lock);
        INIT_LIST_HEAD (&kmxlnd_data.kmx_rx_idle);
        spin_lock_init (&kmxlnd_data.kmx_rx_idle_lock);

        kmxlnd_data.kmx_init = MXLND_INIT_DATA;
        /*****************************************************/

        ret = mxlnd_init_txs();
        if (ret != 0) {
                CERROR("Can't alloc tx descs: %d\n", ret);
                goto failed;
        }
        kmxlnd_data.kmx_init = MXLND_INIT_TXS;
        /*****************************************************/

        ret = mxlnd_init_rxs();
        if (ret != 0) {
                CERROR("Can't alloc rx descs: %d\n", ret);
                goto failed;
        }
        kmxlnd_data.kmx_init = MXLND_INIT_RXS;
        /*****************************************************/

        ret = mxlnd_init_mx(ni);
        if (ret != 0) {
                CERROR("Can't init mx\n");
                goto failed;
        }

        kmxlnd_data.kmx_init = MXLND_INIT_MX;
        /*****************************************************/

        /* start threads */

        nthreads += *kmxlnd_tunables.kmx_n_waitd;
        MXLND_ALLOC (kmxlnd_data.kmx_completions,
                     nthreads * sizeof(struct completion));
        if (kmxlnd_data.kmx_completions == NULL) {
                CERROR("failed to alloc kmxlnd_data.kmx_completions\n");
                goto failed;
        }
        memset(kmxlnd_data.kmx_completions, 0, 
               nthreads * sizeof(struct completion));

        {
                CDEBUG(D_NET, "using %d %s in mx_wait_any()\n",
                        *kmxlnd_tunables.kmx_n_waitd, 
                        *kmxlnd_tunables.kmx_n_waitd == 1 ? "thread" : "threads");

                for (i = 0; i < *kmxlnd_tunables.kmx_n_waitd; i++) {
                        ret = mxlnd_thread_start(mxlnd_request_waitd, (void*)((long)i));
                        if (ret < 0) {
                                CERROR("Starting mxlnd_request_waitd[%d] failed with %d\n", i, ret);
                                kmxlnd_data.kmx_shutdown = 1;
                                mx_wakeup(kmxlnd_data.kmx_endpt);
                                for (--i; i >= 0; i--) {
                                        wait_for_completion(&kmxlnd_data.kmx_completions[i]);
                                }
                                LASSERT(atomic_read(&kmxlnd_data.kmx_nthreads) == 0);
                                MXLND_FREE(kmxlnd_data.kmx_completions, 
                                        MXLND_NCOMPLETIONS * sizeof(struct completion));

                                goto failed;
                        }
                }
                ret = mxlnd_thread_start(mxlnd_tx_queued, (void*)((long)i++));
                if (ret < 0) {
                        CERROR("Starting mxlnd_tx_queued failed with %d\n", ret);
                        kmxlnd_data.kmx_shutdown = 1;
                        mx_wakeup(kmxlnd_data.kmx_endpt);
                        for (--i; i >= 0; i--) {
                                wait_for_completion(&kmxlnd_data.kmx_completions[i]);
                        }
                        LASSERT(atomic_read(&kmxlnd_data.kmx_nthreads) == 0);
                        MXLND_FREE(kmxlnd_data.kmx_completions, 
                                MXLND_NCOMPLETIONS * sizeof(struct completion));
                        goto failed;
                }
                ret = mxlnd_thread_start(mxlnd_timeoutd, (void*)((long)i++));
                if (ret < 0) {
                        CERROR("Starting mxlnd_timeoutd failed with %d\n", ret);
                        kmxlnd_data.kmx_shutdown = 1;
                        mx_wakeup(kmxlnd_data.kmx_endpt);
                        up(&kmxlnd_data.kmx_tx_queue_sem);
                        for (--i; i >= 0; i--) {
                                wait_for_completion(&kmxlnd_data.kmx_completions[i]);
                        }
                        LASSERT(atomic_read(&kmxlnd_data.kmx_nthreads) == 0);
                        MXLND_FREE(kmxlnd_data.kmx_completions, 
                                MXLND_NCOMPLETIONS * sizeof(struct completion));
                        goto failed;
                }
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
MODULE_VERSION("0.5.0");
