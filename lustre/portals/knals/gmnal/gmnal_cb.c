/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Based on ksocknal and qswnal
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *  Author: Robert Read  <rread@datarithm.net>
 *
 *   This file is part of Portals, http://www.sf.net/projects/sandiaportals/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Portals; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* TODO
 * preallocate send buffers, store on list
 * put receive buffers on queue, handle with receive threads
 * use routing
 */

#include "gmnal.h"

extern kgmnal_rx_t *kgm_add_recv(kgmnal_data_t *,int);

static kgmnal_tx_t *
get_trans(void)
{
        kgmnal_tx_t *t;
        PORTAL_ALLOC(t, (sizeof(kgmnal_tx_t)));
        return t;
}

static void
put_trans(kgmnal_tx_t *t)
{
        PORTAL_FREE(t, sizeof(kgmnal_tx_t));
}

int
kgmnal_ispeer (ptl_nid_t nid)
{
   unsigned int gmnid = (unsigned int)nid;
   unsigned int nnids;

   gm_max_node_id_in_use(kgmnal_data.kgm_port, &nnids);

   return ((ptl_nid_t)gmnid == nid &&/* didn't lose high bits on conversion ? */
           gmnid < nnids); /* it's in this machine */
}

/*
 *  LIB functions follow
 *
 */
static int
kgmnal_read (nal_cb_t *nal, void *private, void *dst_addr, user_ptr src_addr,
             size_t len)
{
        CDEBUG(D_NET, "0x%Lx: reading %ld bytes from %p -> %p\n",
               nal->ni.nid, (long)len, src_addr, dst_addr );
        memcpy( dst_addr, src_addr, len );
        return 0;
}

static int
kgmnal_write(nal_cb_t *nal, void *private, user_ptr dst_addr, void *src_addr,
             size_t len)
{
        CDEBUG(D_NET, "0x%Lx: writing %ld bytes from %p -> %p\n",
               nal->ni.nid, (long)len, src_addr, dst_addr );
        memcpy( dst_addr, src_addr, len );
        return 0;
}

static void *
kgmnal_malloc(nal_cb_t *nal, size_t len)
{
        void *buf;

        PORTAL_ALLOC(buf, len);
        return buf;
}

static void
kgmnal_free(nal_cb_t *nal, void *buf, size_t len)
{
        PORTAL_FREE(buf, len);
}

static void
kgmnal_printf(nal_cb_t *nal, const char *fmt, ...)
{
        va_list                ap;
        char msg[256];

        if (portal_debug & D_NET) {
                va_start( ap, fmt );
                vsnprintf( msg, sizeof(msg), fmt, ap );
                va_end( ap );

                printk("CPUId: %d %s",smp_processor_id(), msg);
        }
}


static void
kgmnal_cli(nal_cb_t *nal, unsigned long *flags)
{
        kgmnal_data_t *data= nal->nal_data;

        spin_lock_irqsave(&data->kgm_dispatch_lock,*flags);
}


static void
kgmnal_sti(nal_cb_t *nal, unsigned long *flags)
{
        kgmnal_data_t *data= nal->nal_data;

        spin_unlock_irqrestore(&data->kgm_dispatch_lock,*flags);
}


static int
kgmnal_dist(nal_cb_t *nal, ptl_nid_t nid, unsigned long *dist)
{
        /* network distance doesn't mean much for this nal */
        if ( nal->ni.nid == nid ) {
                *dist = 0;
        } else {
                *dist = 1;
        }

        return 0;
}

/* FIXME rmr: add rounting code here */
static void
kgmnal_tx_done(kgmnal_tx_t  *trans, int error)
{
        lib_finalize(trans->ktx_nal, trans->ktx_private, trans->ktx_cookie);

        gm_dma_free(kgmnal_data.kgm_port, trans->ktx_buffer);

        trans->ktx_buffer = NULL;
        trans->ktx_len = 0;

        put_trans(trans);
}
static char * gm_error_strings[GM_NUM_STATUS_CODES] = {
        [GM_SUCCESS] = "GM_SUCCESS",
        [GM_SEND_TIMED_OUT] = "GM_SEND_TIMED_OUT",
        [GM_SEND_REJECTED] = "GM_SEND_REJECTED",
        [GM_SEND_TARGET_PORT_CLOSED] = "GM_SEND_TARGET_PORT_CLOSED",
        [GM_SEND_TARGET_NODE_UNREACHABLE] = "GM_SEND_TARGET_NODE_UNREACHABLE",
        [GM_SEND_DROPPED] = "GM_SEND_DROPPED",
        [GM_SEND_PORT_CLOSED] = "GM_SEND_PORT_CLOSED",
};

inline char * get_error(int status)
{
        if (gm_error_strings[status] != NULL)
                return gm_error_strings[status];
        else
                return "Unknown error";
}

static void
kgmnal_errhandler(struct gm_port *p, void *context, gm_status_t status)
{
        CDEBUG(D_NET,"error callback: ktx %p status %d\n", context, status);
}

static void
kgmnal_txhandler(struct gm_port *p, void *context, gm_status_t status)
{
        kgmnal_tx_t *ktx = (kgmnal_tx_t *)context;
        int err = 0;

        LASSERT (p != NULL);
        LASSERT (ktx != NULL);

        CDEBUG(D_NET,"ktx %p status %d nid 0x%x pid %d\n", ktx, status,
                ktx->ktx_tgt_node, ktx->ktx_tgt_port_id);

        switch((int)status) {
        case GM_SUCCESS:        /* normal */
                break;
        case GM_SEND_TIMED_OUT: /* application error */
        case GM_SEND_REJECTED:  /* size of msg unacceptable */
        case GM_SEND_TARGET_PORT_CLOSED:
                CERROR("%s (%d):\n", get_error(status), status);
                gm_resume_sending(kgmnal_data.kgm_port, ktx->ktx_priority,
                                  ktx->ktx_tgt_node, ktx->ktx_tgt_port_id,
                                  kgmnal_errhandler, NULL);
                err = -EIO;
                break;
        case GM_SEND_TARGET_NODE_UNREACHABLE:
        case GM_SEND_PORT_CLOSED:
                CERROR("%s (%d):\n", get_error(status), status);
                gm_drop_sends(kgmnal_data.kgm_port, ktx->ktx_priority,
                              ktx->ktx_tgt_node, ktx->ktx_tgt_port_id,
                              kgmnal_errhandler, NULL);
                err = -EIO;
                break;
        case GM_SEND_DROPPED:
                CERROR("%s (%d):\n", get_error(status), status);
                err = -EIO;
                break;
        default:
                CERROR("Unknown status: %d\n", status);
                err = -EIO;
                break;
        }

        kgmnal_tx_done(ktx, err);
}

/*
 */

static int
kgmnal_send(nal_cb_t        *nal,
           void            *private,
           lib_msg_t       *cookie,
           ptl_hdr_t       *hdr,
           int              type,
           ptl_nid_t        nid,
           ptl_pid_t        pid,
           int              options,
           unsigned int     niov,
           lib_md_iov_t    *iov,
           size_t           len)
{
        /*
         * ipnal assumes that this is the private as passed to lib_dispatch..
         * so do we :/
         */
        kgmnal_tx_t *ktx=NULL;
        int rc=0;
        void * buf;
        int buf_len = sizeof(ptl_hdr_t) + len;
        int buf_size = 0;

        LASSERT ((options & PTL_MD_KIOV) == 0);
        
        PROF_START(gmnal_send);


        CDEBUG(D_NET, "sending %d bytes from %p to nid: 0x%Lx pid %d\n",
               len, iov, nid, KGM_PORT_NUM);

        /* ensure there is an available tx handle */

        /* save transaction info to trans for later finalize and cleanup */
        ktx = get_trans();
        if (ktx == NULL) {
                rc = -ENOMEM;
                goto send_exit;
        }

        /* hmmm... GM doesn't support vectored write, so need to allocate buffer to coalesce
           header and data.
           Also, memory must be dma'able or registered with GM. */

        if (buf_len <= MSG_LEN_SMALL) {
                buf_size = MSG_SIZE_SMALL;
        } else if (buf_len <= MSG_LEN_LARGE) {
                buf_size = MSG_SIZE_LARGE;
        } else {
                printk("kgmnal:request exceeds TX MTU size (%d).\n",
                       MSG_SIZE_LARGE);
                rc = -1;
                goto send_exit;
        }

               buf = gm_dma_malloc(kgmnal_data.kgm_port, buf_len);
        if (buf == NULL) {
                rc = -ENOMEM;
                goto send_exit;
        }
        memcpy(buf, hdr, sizeof(ptl_hdr_t));

        if (len != 0)
                lib_copy_iov2buf(((char *)buf) + sizeof (ptl_hdr_t), 
                                 options, niov, iov, len);

        ktx->ktx_nal = nal;
        ktx->ktx_private = private;
        ktx->ktx_cookie = cookie;
        ktx->ktx_len = buf_len;
        ktx->ktx_size = buf_size;
        ktx->ktx_buffer = buf;
        ktx->ktx_priority = GM_LOW_PRIORITY;
        ktx->ktx_tgt_node = nid;
        ktx->ktx_tgt_port_id = KGM_PORT_NUM;

        CDEBUG(D_NET, "gm_send %d bytes (size %d) from %p to nid: 0x%Lx "
               "pid %d pri %d\n", buf_len, buf_size, iov, nid, KGM_PORT_NUM,
               GM_LOW_PRIORITY);

        gm_send_with_callback(kgmnal_data.kgm_port, buf, buf_size,
                              buf_len, GM_LOW_PRIORITY,
                              nid, KGM_PORT_NUM,
                              kgmnal_txhandler, ktx);

        PROF_FINISH(gmnal_send);
 send_exit:
        return rc;
}
void
kgmnal_fwd_packet (void *arg, kpr_fwd_desc_t *fwd)
{
        CERROR ("forwarding not implemented\n");
}

void
kqswnal_fwd_callback (void *arg, int error)
{
        CERROR ("forwarding not implemented\n");
}


static inline void
kgmnal_requeue_rx(kgmnal_rx_t *krx)
{
        gm_provide_receive_buffer(kgmnal_data.kgm_port, krx->krx_buffer,
                                  krx->krx_size, krx->krx_priority);
}

/* Process a received portals packet */

/* Receive Interrupt Handler */
static void kgmnal_rx(kgmnal_data_t *kgm, unsigned long len, unsigned int size,
                      void * buf, unsigned int pri)
{
        ptl_hdr_t  *hdr = buf;
        kgmnal_rx_t krx;

        CDEBUG(D_NET,"buf %p, len %ld\n", buf, len);

        if ( len < sizeof( ptl_hdr_t ) ) {
                /* XXX what's this for? */
                if (kgm->kgm_shuttingdown)
                        return;
                CERROR("kgmnal: did not receive complete portal header, "
                       "len= %ld", len);
                gm_provide_receive_buffer(kgm->kgm_port, buf, size, pri);
                return;
        }

       /* might want to use seperate threads to handle receive */
        krx.krx_buffer = buf;
        krx.krx_len = len;
        krx.krx_size = size;
        krx.krx_priority = pri;

        if ( hdr->dest_nid == kgmnal_lib.ni.nid ) {
                PROF_START(lib_parse);
                lib_parse(&kgmnal_lib, (ptl_hdr_t *)krx.krx_buffer, &krx);
                PROF_FINISH(lib_parse);
        } else if (kgmnal_ispeer(hdr->dest_nid)) {
                /* should have gone direct to peer */
                CERROR("dropping packet from 0x%llx to 0x%llx: target is "
                       "a peer", hdr->src_nid, hdr->dest_nid);
                kgmnal_requeue_rx(&krx);
        } else {
                /* forward to gateway */
                CERROR("forwarding not implemented yet");
                kgmnal_requeue_rx(&krx);
        }

        return;
}


static int kgmnal_recv(nal_cb_t     *nal,
                      void         *private,
                      lib_msg_t    *cookie,
                      int           options,
                      unsigned int  niov,
                      lib_md_iov_t *iov,
                      size_t        mlen,
                      size_t        rlen)
{
        kgmnal_rx_t *krx = private;

        LASSERT ((options & PTL_MD_KIOV) == 0);

        CDEBUG(D_NET,"mlen=%d, rlen=%d\n", mlen, rlen);

        /* What was actually received must be >= what sender claims to
         * have sent.  This is an LASSERT, since lib-move doesn't
         * check cb return code yet. */
        LASSERT (krx->krx_len >= sizeof (ptl_hdr_t) + rlen);
        LASSERT (mlen <= rlen);

        PROF_START(gmnal_recv);

        if(mlen != 0) {
                PROF_START(memcpy);
                lib_copy_buf2iov (options, niov, iov, 
                                  krx->krx_buffer + sizeof (ptl_hdr_t), mlen);
                PROF_FINISH(memcpy);
        }

        PROF_START(lib_finalize);
        lib_finalize(nal, private, cookie);
        PROF_FINISH(lib_finalize);

        kgmnal_requeue_rx(krx);

        PROF_FINISH(gmnal_recv);

        return rlen;
}


static void kgmnal_shutdown(void * none)
{
        CERROR("called\n");
        return;
}

/*
 * Set terminate and use alarm to wake up the recv thread.
 */
static void  recv_shutdown(kgmnal_data_t *kgm)
{
        gm_alarm_t alarm;

        kgm->kgm_shuttingdown = 1;
        gm_initialize_alarm(&alarm);
        gm_set_alarm(kgm->kgm_port, &alarm, 1, kgmnal_shutdown, NULL);
}

int kgmnal_end(kgmnal_data_t *kgm)
{

        /* wait for sends to finish ? */
        /* remove receive buffers */
        /* shutdown receive thread */

        recv_shutdown(kgm);

        return 0;
}

/* Used only for the spinner */
int kgmnal_recv_thread(void *arg)
{
        kgmnal_data_t *kgm = arg;

        LASSERT(kgm != NULL);

        kportal_daemonize("kgmnal_rx");
        
        while(1) {
                gm_recv_event_t *e;
                int priority = GM_LOW_PRIORITY;
                if (kgm->kgm_shuttingdown)
                        break;

                e = gm_blocking_receive_no_spin(kgm->kgm_port);
                if (e == NULL) {
                        CERROR("gm_blocking_receive returned NULL\n");
                        break;
                }

                switch(gm_ntohc(e->recv.type)) {
                case GM_HIGH_RECV_EVENT:
                        priority = GM_HIGH_PRIORITY;
                        /* fall through */
                case GM_RECV_EVENT:
                        kgmnal_rx(kgm, gm_ntohl(e->recv.length),
                                  gm_ntohc(e->recv.size),
                                  gm_ntohp(e->recv.buffer), priority);
                        break;
                case GM_ALARM_EVENT:
                        CERROR("received alarm");
                        gm_unknown(kgm->kgm_port, e);
                        break;
                case GM_BAD_SEND_DETECTED_EVENT: /* ?? */
                        CERROR("received bad send!\n");
                        break;
                default:
                        gm_unknown(kgm->kgm_port, e);
                }
        }

        CERROR("shuttting down.\n");
        return 0;
}

nal_cb_t kgmnal_lib = {
        nal_data: &kgmnal_data,                /* NAL private data */
        cb_send: kgmnal_send,
        cb_recv: kgmnal_recv,
        cb_read: kgmnal_read,
        cb_write: kgmnal_write,
        cb_malloc: kgmnal_malloc,
        cb_free: kgmnal_free,
        cb_printf: kgmnal_printf,
        cb_cli: kgmnal_cli,
        cb_sti: kgmnal_sti,
        cb_dist: kgmnal_dist
};
