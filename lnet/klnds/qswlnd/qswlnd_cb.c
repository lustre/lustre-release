/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 2012, Intel Corporation.
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 *
 * This file is part of Portals, http://www.lustre.org
 *
 * Portals is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * Portals is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Portals; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "qswlnd.h"

void
kqswnal_notify_peer_down(kqswnal_tx_t *ktx)
{
        time_t             then;

        then = cfs_time_current_sec() -
                cfs_duration_sec(cfs_time_current() -
                                 ktx->ktx_launchtime);

        lnet_notify(kqswnal_data.kqn_ni, ktx->ktx_nid, 0, then);
}

void
kqswnal_unmap_tx (kqswnal_tx_t *ktx)
{
        int      i;

        ktx->ktx_rail = -1;                     /* unset rail */

        if (ktx->ktx_nmappedpages == 0)
                return;
        
        CDEBUG(D_NET, "%p unloading %d frags starting at %d\n",
               ktx, ktx->ktx_nfrag, ktx->ktx_firsttmpfrag);

        for (i = ktx->ktx_firsttmpfrag; i < ktx->ktx_nfrag; i++)
                ep_dvma_unload(kqswnal_data.kqn_ep,
                               kqswnal_data.kqn_ep_tx_nmh,
                               &ktx->ktx_frags[i]);

        ktx->ktx_nmappedpages = 0;
}

int
kqswnal_map_tx_kiov (kqswnal_tx_t *ktx, int offset, int nob, 
                     unsigned int niov, lnet_kiov_t *kiov)
{
        int       nfrags    = ktx->ktx_nfrag;
        int       nmapped   = ktx->ktx_nmappedpages;
        int       maxmapped = ktx->ktx_npages;
        __u32     basepage  = ktx->ktx_basepage + nmapped;
        char     *ptr;

        EP_RAILMASK railmask;
        int         rail;

        if (ktx->ktx_rail < 0)
                ktx->ktx_rail = ep_xmtr_prefrail(kqswnal_data.kqn_eptx,
                                                 EP_RAILMASK_ALL,
                                                 kqswnal_nid2elanid(ktx->ktx_nid));
        rail = ktx->ktx_rail;
        if (rail < 0) {
                CERROR("No rails available for %s\n", libcfs_nid2str(ktx->ktx_nid));
                return (-ENETDOWN);
        }
        railmask = 1 << rail;

        LASSERT (nmapped <= maxmapped);
        LASSERT (nfrags >= ktx->ktx_firsttmpfrag);
        LASSERT (nfrags <= EP_MAXFRAG);
        LASSERT (niov > 0);
        LASSERT (nob > 0);

        /* skip complete frags before 'offset' */
        while (offset >= kiov->kiov_len) {
                offset -= kiov->kiov_len;
                kiov++;
                niov--;
                LASSERT (niov > 0);
        }

        do {
                int  fraglen = kiov->kiov_len - offset;

                /* each page frag is contained in one page */
                LASSERT (kiov->kiov_offset + kiov->kiov_len <= PAGE_SIZE);

                if (fraglen > nob)
                        fraglen = nob;

                nmapped++;
                if (nmapped > maxmapped) {
                        CERROR("Can't map message in %d pages (max %d)\n",
                               nmapped, maxmapped);
                        return (-EMSGSIZE);
                }

                if (nfrags == EP_MAXFRAG) {
                        CERROR("Message too fragmented in Elan VM (max %d frags)\n",
                               EP_MAXFRAG);
                        return (-EMSGSIZE);
                }

                /* XXX this is really crap, but we'll have to kmap until
                 * EKC has a page (rather than vaddr) mapping interface */

                ptr = ((char *)kmap (kiov->kiov_page)) + kiov->kiov_offset + offset;

                CDEBUG(D_NET,
                       "%p[%d] loading %p for %d, page %d, %d total\n",
                        ktx, nfrags, ptr, fraglen, basepage, nmapped);

                ep_dvma_load(kqswnal_data.kqn_ep, NULL,
                             ptr, fraglen,
                             kqswnal_data.kqn_ep_tx_nmh, basepage,
                             &railmask, &ktx->ktx_frags[nfrags]);

                if (nfrags == ktx->ktx_firsttmpfrag ||
                    !ep_nmd_merge(&ktx->ktx_frags[nfrags - 1],
                                  &ktx->ktx_frags[nfrags - 1],
                                  &ktx->ktx_frags[nfrags])) {
                        /* new frag if this is the first or can't merge */
                        nfrags++;
                }

                kunmap (kiov->kiov_page);
                
                /* keep in loop for failure case */
                ktx->ktx_nmappedpages = nmapped;

                basepage++;
                kiov++;
                niov--;
                nob -= fraglen;
                offset = 0;

                /* iov must not run out before end of data */
                LASSERT (nob == 0 || niov > 0);

        } while (nob > 0);

        ktx->ktx_nfrag = nfrags;
        CDEBUG (D_NET, "%p got %d frags over %d pages\n",
                ktx, ktx->ktx_nfrag, ktx->ktx_nmappedpages);

        return (0);
}

#if KQSW_CKSUM
__u32
kqswnal_csum_kiov (__u32 csum, int offset, int nob, 
                   unsigned int niov, lnet_kiov_t *kiov)
{
        char     *ptr;

        if (nob == 0)
                return csum;

        LASSERT (niov > 0);
        LASSERT (nob > 0);

        /* skip complete frags before 'offset' */
        while (offset >= kiov->kiov_len) {
                offset -= kiov->kiov_len;
                kiov++;
                niov--;
                LASSERT (niov > 0);
        }

        do {
                int  fraglen = kiov->kiov_len - offset;

                /* each page frag is contained in one page */
                LASSERT (kiov->kiov_offset + kiov->kiov_len <= PAGE_SIZE);

                if (fraglen > nob)
                        fraglen = nob;

                ptr = ((char *)kmap (kiov->kiov_page)) + kiov->kiov_offset + offset;

                csum = kqswnal_csum(csum, ptr, fraglen);

                kunmap (kiov->kiov_page);
                
                kiov++;
                niov--;
                nob -= fraglen;
                offset = 0;

                /* iov must not run out before end of data */
                LASSERT (nob == 0 || niov > 0);

        } while (nob > 0);

        return csum;
}
#endif

int
kqswnal_map_tx_iov (kqswnal_tx_t *ktx, int offset, int nob, 
                    unsigned int niov, struct iovec *iov)
{
        int       nfrags    = ktx->ktx_nfrag;
        int       nmapped   = ktx->ktx_nmappedpages;
        int       maxmapped = ktx->ktx_npages;
        __u32     basepage  = ktx->ktx_basepage + nmapped;

        EP_RAILMASK railmask;
        int         rail;
        
        if (ktx->ktx_rail < 0)
                ktx->ktx_rail = ep_xmtr_prefrail(kqswnal_data.kqn_eptx,
                                                 EP_RAILMASK_ALL,
                                                 kqswnal_nid2elanid(ktx->ktx_nid));
        rail = ktx->ktx_rail;
        if (rail < 0) {
                CERROR("No rails available for %s\n", libcfs_nid2str(ktx->ktx_nid));
                return (-ENETDOWN);
        }
        railmask = 1 << rail;

        LASSERT (nmapped <= maxmapped);
        LASSERT (nfrags >= ktx->ktx_firsttmpfrag);
        LASSERT (nfrags <= EP_MAXFRAG);
        LASSERT (niov > 0);
        LASSERT (nob > 0);

        /* skip complete frags before offset */
        while (offset >= iov->iov_len) {
                offset -= iov->iov_len;
                iov++;
                niov--;
                LASSERT (niov > 0);
        }
        
        do {
                int  fraglen = iov->iov_len - offset;
                long npages;
                
                if (fraglen > nob)
                        fraglen = nob;
                npages = kqswnal_pages_spanned (iov->iov_base, fraglen);

                nmapped += npages;
                if (nmapped > maxmapped) {
                        CERROR("Can't map message in %d pages (max %d)\n",
                               nmapped, maxmapped);
                        return (-EMSGSIZE);
                }

                if (nfrags == EP_MAXFRAG) {
                        CERROR("Message too fragmented in Elan VM (max %d frags)\n",
                               EP_MAXFRAG);
                        return (-EMSGSIZE);
                }

                CDEBUG(D_NET,
                       "%p[%d] loading %p for %d, pages %d for %ld, %d total\n",
                       ktx, nfrags, iov->iov_base + offset, fraglen, 
                       basepage, npages, nmapped);

                ep_dvma_load(kqswnal_data.kqn_ep, NULL,
                             iov->iov_base + offset, fraglen,
                             kqswnal_data.kqn_ep_tx_nmh, basepage,
                             &railmask, &ktx->ktx_frags[nfrags]);

                if (nfrags == ktx->ktx_firsttmpfrag ||
                    !ep_nmd_merge(&ktx->ktx_frags[nfrags - 1],
                                  &ktx->ktx_frags[nfrags - 1],
                                  &ktx->ktx_frags[nfrags])) {
                        /* new frag if this is the first or can't merge */
                        nfrags++;
                }

                /* keep in loop for failure case */
                ktx->ktx_nmappedpages = nmapped;

                basepage += npages;
                iov++;
                niov--;
                nob -= fraglen;
                offset = 0;

                /* iov must not run out before end of data */
                LASSERT (nob == 0 || niov > 0);

        } while (nob > 0);

        ktx->ktx_nfrag = nfrags;
        CDEBUG (D_NET, "%p got %d frags over %d pages\n",
                ktx, ktx->ktx_nfrag, ktx->ktx_nmappedpages);

        return (0);
}

#if KQSW_CKSUM
__u32
kqswnal_csum_iov (__u32 csum, int offset, int nob, 
                  unsigned int niov, struct iovec *iov)
{
        if (nob == 0)
                return csum;
        
        LASSERT (niov > 0);
        LASSERT (nob > 0);

        /* skip complete frags before offset */
        while (offset >= iov->iov_len) {
                offset -= iov->iov_len;
                iov++;
                niov--;
                LASSERT (niov > 0);
        }
        
        do {
                int  fraglen = iov->iov_len - offset;
                
                if (fraglen > nob)
                        fraglen = nob;

                csum = kqswnal_csum(csum, iov->iov_base + offset, fraglen);

                iov++;
                niov--;
                nob -= fraglen;
                offset = 0;

                /* iov must not run out before end of data */
                LASSERT (nob == 0 || niov > 0);

        } while (nob > 0);

        return csum;
}
#endif

void
kqswnal_put_idle_tx (kqswnal_tx_t *ktx)
{
	unsigned long     flags;

	kqswnal_unmap_tx(ktx);			/* release temporary mappings */
	ktx->ktx_state = KTX_IDLE;

	spin_lock_irqsave(&kqswnal_data.kqn_idletxd_lock, flags);

	cfs_list_del(&ktx->ktx_list);		/* take off active list */
	cfs_list_add(&ktx->ktx_list, &kqswnal_data.kqn_idletxds);

	spin_unlock_irqrestore(&kqswnal_data.kqn_idletxd_lock, flags);
}

kqswnal_tx_t *
kqswnal_get_idle_tx (void)
{
	unsigned long  flags;
	kqswnal_tx_t  *ktx;

	spin_lock_irqsave(&kqswnal_data.kqn_idletxd_lock, flags);

	if (kqswnal_data.kqn_shuttingdown ||
	    cfs_list_empty(&kqswnal_data.kqn_idletxds)) {
		spin_unlock_irqrestore(&kqswnal_data.kqn_idletxd_lock, flags);

		return NULL;
	}

        ktx = cfs_list_entry (kqswnal_data.kqn_idletxds.next, kqswnal_tx_t,
                              ktx_list);
        cfs_list_del (&ktx->ktx_list);

        cfs_list_add (&ktx->ktx_list, &kqswnal_data.kqn_activetxds);
        ktx->ktx_launcher = current->pid;
        cfs_atomic_inc(&kqswnal_data.kqn_pending_txs);

	spin_unlock_irqrestore(&kqswnal_data.kqn_idletxd_lock, flags);

        /* Idle descs can't have any mapped (as opposed to pre-mapped) pages */
        LASSERT (ktx->ktx_nmappedpages == 0);
        return (ktx);
}

void
kqswnal_tx_done_in_thread_context (kqswnal_tx_t *ktx)
{
        lnet_msg_t    *lnetmsg0 = NULL;
        lnet_msg_t    *lnetmsg1 = NULL;
        int            status0  = 0;
        int            status1  = 0;
        kqswnal_rx_t  *krx;

        LASSERT (!cfs_in_interrupt());

        if (ktx->ktx_status == -EHOSTDOWN)
                kqswnal_notify_peer_down(ktx);

        switch (ktx->ktx_state) {
        case KTX_RDMA_FETCH:                    /* optimized PUT/REPLY handled */
                krx      = (kqswnal_rx_t *)ktx->ktx_args[0];
                lnetmsg0 = (lnet_msg_t *)ktx->ktx_args[1];
                status0  = ktx->ktx_status;
#if KQSW_CKSUM
                if (status0 == 0) {             /* RDMA succeeded */
                        kqswnal_msg_t *msg;
                        __u32          csum;

                        msg = (kqswnal_msg_t *)
                              page_address(krx->krx_kiov[0].kiov_page);

                        csum = (lnetmsg0->msg_kiov != NULL) ?
                               kqswnal_csum_kiov(krx->krx_cksum,
                                                 lnetmsg0->msg_offset,
                                                 lnetmsg0->msg_wanted,
                                                 lnetmsg0->msg_niov,
                                                 lnetmsg0->msg_kiov) :
                               kqswnal_csum_iov(krx->krx_cksum,
                                                lnetmsg0->msg_offset,
                                                lnetmsg0->msg_wanted,
                                                lnetmsg0->msg_niov,
                                                lnetmsg0->msg_iov);

                        /* Can only check csum if I got it all */
                        if (lnetmsg0->msg_wanted == lnetmsg0->msg_len &&
                            csum != msg->kqm_cksum) {
                                ktx->ktx_status = -EIO;
                                krx->krx_rpc_reply.msg.status = -EIO;
                                CERROR("RDMA checksum failed %u(%u) from %s\n",
                                       csum, msg->kqm_cksum,
                                       libcfs_nid2str(kqswnal_rx_nid(krx)));
                        }
                }
#endif       
                LASSERT (krx->krx_state == KRX_COMPLETING);
                kqswnal_rx_decref (krx);
                break;

        case KTX_RDMA_STORE:       /* optimized GET handled */
        case KTX_PUTTING:          /* optimized PUT sent */
        case KTX_SENDING:          /* normal send */
                lnetmsg0 = (lnet_msg_t *)ktx->ktx_args[1];
                status0  = ktx->ktx_status;
                break;

        case KTX_GETTING:          /* optimized GET sent & payload received */
                /* Complete the GET with success since we can't avoid
                 * delivering a REPLY event; we committed to it when we
                 * launched the GET */
                lnetmsg0 = (lnet_msg_t *)ktx->ktx_args[1];
                status0  = 0;
                lnetmsg1 = (lnet_msg_t *)ktx->ktx_args[2];
                status1  = ktx->ktx_status;
#if KQSW_CKSUM
                if (status1 == 0) {             /* RDMA succeeded */
                        lnet_msg_t   *lnetmsg0 = (lnet_msg_t *)ktx->ktx_args[1];
                        lnet_libmd_t *md = lnetmsg0->msg_md;
                        __u32         csum;
                
                        csum = ((md->md_options & LNET_MD_KIOV) != 0) ? 
                               kqswnal_csum_kiov(~0, 0,
                                                 md->md_length,
                                                 md->md_niov, 
                                                 md->md_iov.kiov) :
                               kqswnal_csum_iov(~0, 0,
                                                md->md_length,
                                                md->md_niov,
                                                md->md_iov.iov);

                        if (csum != ktx->ktx_cksum) {
                                CERROR("RDMA checksum failed %u(%u) from %s\n",
                                       csum, ktx->ktx_cksum,
                                       libcfs_nid2str(ktx->ktx_nid));
                                status1 = -EIO;
                        }
                }
#endif                
                break;

        default:
                LASSERT (0);
        }

        kqswnal_put_idle_tx (ktx);

        lnet_finalize (kqswnal_data.kqn_ni, lnetmsg0, status0);
        if (lnetmsg1 != NULL)
                lnet_finalize (kqswnal_data.kqn_ni, lnetmsg1, status1);
}

void
kqswnal_tx_done (kqswnal_tx_t *ktx, int status)
{
        unsigned long      flags;

        ktx->ktx_status = status;

        if (!cfs_in_interrupt()) {
                kqswnal_tx_done_in_thread_context(ktx);
                return;
        }

        /* Complete the send in thread context */
	spin_lock_irqsave(&kqswnal_data.kqn_sched_lock, flags);

	cfs_list_add_tail(&ktx->ktx_schedlist,
			   &kqswnal_data.kqn_donetxds);
	cfs_waitq_signal(&kqswnal_data.kqn_sched_waitq);

	spin_unlock_irqrestore(&kqswnal_data.kqn_sched_lock, flags);
}

static void
kqswnal_txhandler(EP_TXD *txd, void *arg, int status)
{
        kqswnal_tx_t         *ktx = (kqswnal_tx_t *)arg;
        kqswnal_rpc_reply_t  *reply;

        LASSERT (txd != NULL);
        LASSERT (ktx != NULL);

        CDEBUG(D_NET, "txd %p, arg %p status %d\n", txd, arg, status);

        if (status != EP_SUCCESS) {

                CNETERR("Tx completion to %s failed: %d\n",
                        libcfs_nid2str(ktx->ktx_nid), status);

                status = -EHOSTDOWN;

        } else switch (ktx->ktx_state) {

        case KTX_GETTING:
        case KTX_PUTTING:
                /* RPC complete! */
                reply = (kqswnal_rpc_reply_t *)ep_txd_statusblk(txd);
                if (reply->msg.magic == 0) {    /* "old" peer */
                        status = reply->msg.status;
                        break;
                }
                
                if (reply->msg.magic != LNET_PROTO_QSW_MAGIC) {
                        if (reply->msg.magic != swab32(LNET_PROTO_QSW_MAGIC)) {
                                CERROR("%s unexpected rpc reply magic %08x\n",
                                       libcfs_nid2str(ktx->ktx_nid),
                                       reply->msg.magic);
                                status = -EPROTO;
                                break;
                        }

                        __swab32s(&reply->msg.status);
                        __swab32s(&reply->msg.version);
                        
                        if (ktx->ktx_state == KTX_GETTING) {
                                __swab32s(&reply->msg.u.get.len);
                                __swab32s(&reply->msg.u.get.cksum);
                        }
                }
                        
                status = reply->msg.status;
                if (status != 0) {
                        CERROR("%s RPC status %08x\n",
                               libcfs_nid2str(ktx->ktx_nid), status);
                        break;
                }

                if (ktx->ktx_state == KTX_GETTING) {
                        lnet_set_reply_msg_len(kqswnal_data.kqn_ni,
                                               (lnet_msg_t *)ktx->ktx_args[2],
                                               reply->msg.u.get.len);
#if KQSW_CKSUM
                        ktx->ktx_cksum = reply->msg.u.get.cksum;
#endif
                }
                break;
                
        case KTX_SENDING:
                status = 0;
                break;
                
        default:
                LBUG();
                break;
        }

        kqswnal_tx_done(ktx, status);
}

int
kqswnal_launch (kqswnal_tx_t *ktx)
{
        /* Don't block for transmit descriptor if we're in interrupt context */
        int   attr = cfs_in_interrupt() ? (EP_NO_SLEEP | EP_NO_ALLOC) : 0;
        int   dest = kqswnal_nid2elanid (ktx->ktx_nid);
        unsigned long flags;
        int   rc;

        ktx->ktx_launchtime = cfs_time_current();

        if (kqswnal_data.kqn_shuttingdown)
                return (-ESHUTDOWN);

        LASSERT (dest >= 0);                    /* must be a peer */

        if (ktx->ktx_nmappedpages != 0)
                attr = EP_SET_PREFRAIL(attr, ktx->ktx_rail);

        switch (ktx->ktx_state) {
        case KTX_GETTING:
        case KTX_PUTTING:
                if (the_lnet.ln_testprotocompat != 0) {
                        kqswnal_msg_t *msg = (kqswnal_msg_t *)ktx->ktx_buffer;

                        /* single-shot proto test:
                         * Future version queries will use an RPC, so I'll
                         * co-opt one of the existing ones */
                        LNET_LOCK();
                        if ((the_lnet.ln_testprotocompat & 1) != 0) {
                                msg->kqm_version++;
                                the_lnet.ln_testprotocompat &= ~1;
                        }
                        if ((the_lnet.ln_testprotocompat & 2) != 0) {
                                msg->kqm_magic = LNET_PROTO_MAGIC;
                                the_lnet.ln_testprotocompat &= ~2;
                        }
                        LNET_UNLOCK();
                }

                /* NB ktx_frag[0] is the GET/PUT hdr + kqswnal_remotemd_t.
                 * The other frags are the payload, awaiting RDMA */
                rc = ep_transmit_rpc(kqswnal_data.kqn_eptx, dest,
                                     ktx->ktx_port, attr,
                                     kqswnal_txhandler, ktx,
                                     NULL, ktx->ktx_frags, 1);
                break;

        case KTX_SENDING:
                rc = ep_transmit_message(kqswnal_data.kqn_eptx, dest,
                                         ktx->ktx_port, attr,
                                         kqswnal_txhandler, ktx,
                                         NULL, ktx->ktx_frags, ktx->ktx_nfrag);
                break;

        default:
                LBUG();
                rc = -EINVAL;                   /* no compiler warning please */
                break;
        }

        switch (rc) {
        case EP_SUCCESS: /* success */
                return (0);

        case EP_ENOMEM: /* can't allocate ep txd => queue for later */
		spin_lock_irqsave(&kqswnal_data.kqn_sched_lock, flags);

		cfs_list_add_tail(&ktx->ktx_schedlist,
				  &kqswnal_data.kqn_delayedtxds);
		cfs_waitq_signal(&kqswnal_data.kqn_sched_waitq);

		spin_unlock_irqrestore(&kqswnal_data.kqn_sched_lock,
                                            flags);
                return (0);

        default: /* fatal error */
                CNETERR ("Tx to %s failed: %d\n",
                        libcfs_nid2str(ktx->ktx_nid), rc);
                kqswnal_notify_peer_down(ktx);
                return (-EHOSTUNREACH);
        }
}

#if 0
static char *
hdr_type_string (lnet_hdr_t *hdr)
{
        switch (hdr->type) {
        case LNET_MSG_ACK:
                return ("ACK");
        case LNET_MSG_PUT:
                return ("PUT");
        case LNET_MSG_GET:
                return ("GET");
        case LNET_MSG_REPLY:
                return ("REPLY");
        default:
                return ("<UNKNOWN>");
        }
}

static void
kqswnal_cerror_hdr(lnet_hdr_t * hdr)
{
        char *type_str = hdr_type_string (hdr);

        CERROR("P3 Header at %p of type %s length %d\n", hdr, type_str,
               le32_to_cpu(hdr->payload_length));
        CERROR("    From nid/pid "LPU64"/%u\n", le64_to_cpu(hdr->src_nid),
               le32_to_cpu(hdr->src_pid));
        CERROR("    To nid/pid "LPU64"/%u\n", le64_to_cpu(hdr->dest_nid),
               le32_to_cpu(hdr->dest_pid));

        switch (le32_to_cpu(hdr->type)) {
        case LNET_MSG_PUT:
                CERROR("    Ptl index %d, ack md "LPX64"."LPX64", "
                       "match bits "LPX64"\n",
                       le32_to_cpu(hdr->msg.put.ptl_index),
                       hdr->msg.put.ack_wmd.wh_interface_cookie,
                       hdr->msg.put.ack_wmd.wh_object_cookie,
                       le64_to_cpu(hdr->msg.put.match_bits));
                CERROR("    offset %d, hdr data "LPX64"\n",
                       le32_to_cpu(hdr->msg.put.offset),
                       hdr->msg.put.hdr_data);
                break;

        case LNET_MSG_GET:
                CERROR("    Ptl index %d, return md "LPX64"."LPX64", "
                       "match bits "LPX64"\n",
                       le32_to_cpu(hdr->msg.get.ptl_index),
                       hdr->msg.get.return_wmd.wh_interface_cookie,
                       hdr->msg.get.return_wmd.wh_object_cookie,
                       hdr->msg.get.match_bits);
                CERROR("    Length %d, src offset %d\n",
                       le32_to_cpu(hdr->msg.get.sink_length),
                       le32_to_cpu(hdr->msg.get.src_offset));
                break;

        case LNET_MSG_ACK:
                CERROR("    dst md "LPX64"."LPX64", manipulated length %d\n",
                       hdr->msg.ack.dst_wmd.wh_interface_cookie,
                       hdr->msg.ack.dst_wmd.wh_object_cookie,
                       le32_to_cpu(hdr->msg.ack.mlength));
                break;

        case LNET_MSG_REPLY:
                CERROR("    dst md "LPX64"."LPX64"\n",
                       hdr->msg.reply.dst_wmd.wh_interface_cookie,
                       hdr->msg.reply.dst_wmd.wh_object_cookie);
        }

}                               /* end of print_hdr() */
#endif

int
kqswnal_check_rdma (int nlfrag, EP_NMD *lfrag,
                    int nrfrag, EP_NMD *rfrag)
{
        int  i;

        if (nlfrag != nrfrag) {
                CERROR("Can't cope with unequal # frags: %d local %d remote\n",
                       nlfrag, nrfrag);
                return (-EINVAL);
        }
        
        for (i = 0; i < nlfrag; i++)
                if (lfrag[i].nmd_len != rfrag[i].nmd_len) {
                        CERROR("Can't cope with unequal frags %d(%d):"
                               " %d local %d remote\n",
                               i, nlfrag, lfrag[i].nmd_len, rfrag[i].nmd_len);
                        return (-EINVAL);
                }
        
        return (0);
}

kqswnal_remotemd_t *
kqswnal_get_portalscompat_rmd (kqswnal_rx_t *krx)
{
        /* Check that the RMD sent after the "raw" LNET header in a
         * portals-compatible QSWLND message is OK */
        char               *buffer = (char *)page_address(krx->krx_kiov[0].kiov_page);
        kqswnal_remotemd_t *rmd = (kqswnal_remotemd_t *)(buffer + sizeof(lnet_hdr_t));

        /* Note RDMA addresses are sent in native endian-ness in the "old"
         * portals protocol so no swabbing... */

        if (buffer + krx->krx_nob < (char *)(rmd + 1)) {
                /* msg too small to discover rmd size */
                CERROR ("Incoming message [%d] too small for RMD (%d needed)\n",
                        krx->krx_nob, (int)(((char *)(rmd + 1)) - buffer));
                return (NULL);
        }

        if (buffer + krx->krx_nob < (char *)&rmd->kqrmd_frag[rmd->kqrmd_nfrag]) {
                /* rmd doesn't fit in the incoming message */
                CERROR ("Incoming message [%d] too small for RMD[%d] (%d needed)\n",
                        krx->krx_nob, rmd->kqrmd_nfrag,
                        (int)(((char *)&rmd->kqrmd_frag[rmd->kqrmd_nfrag]) - buffer));
                return (NULL);
        }

        return (rmd);
}

void
kqswnal_rdma_store_complete (EP_RXD *rxd) 
{
        int           status = ep_rxd_status(rxd);
        kqswnal_tx_t *ktx = (kqswnal_tx_t *)ep_rxd_arg(rxd);
        kqswnal_rx_t *krx = (kqswnal_rx_t *)ktx->ktx_args[0];
        
        CDEBUG((status == EP_SUCCESS) ? D_NET : D_ERROR,
               "rxd %p, ktx %p, status %d\n", rxd, ktx, status);

        LASSERT (ktx->ktx_state == KTX_RDMA_STORE);
        LASSERT (krx->krx_rxd == rxd);
        LASSERT (krx->krx_rpc_reply_needed);

        krx->krx_rpc_reply_needed = 0;
        kqswnal_rx_decref (krx);

        /* free ktx & finalize() its lnet_msg_t */
        kqswnal_tx_done(ktx, (status == EP_SUCCESS) ? 0 : -ECONNABORTED);
}

void
kqswnal_rdma_fetch_complete (EP_RXD *rxd) 
{
        /* Completed fetching the PUT/REPLY data */
        int           status = ep_rxd_status(rxd);
        kqswnal_tx_t *ktx = (kqswnal_tx_t *)ep_rxd_arg(rxd);
        kqswnal_rx_t *krx = (kqswnal_rx_t *)ktx->ktx_args[0];
        
        CDEBUG((status == EP_SUCCESS) ? D_NET : D_ERROR,
               "rxd %p, ktx %p, status %d\n", rxd, ktx, status);

        LASSERT (ktx->ktx_state == KTX_RDMA_FETCH);
        LASSERT (krx->krx_rxd == rxd);
        /* RPC completes with failure by default */
        LASSERT (krx->krx_rpc_reply_needed);
        LASSERT (krx->krx_rpc_reply.msg.status != 0);

        if (status == EP_SUCCESS) {
                krx->krx_rpc_reply.msg.status = 0;
                status = 0;
        } else {
                /* Abandon RPC since get failed */
                krx->krx_rpc_reply_needed = 0;
                status = -ECONNABORTED;
        }

        /* krx gets decref'd in kqswnal_tx_done_in_thread_context() */
        LASSERT (krx->krx_state == KRX_PARSE);
        krx->krx_state = KRX_COMPLETING;

        /* free ktx & finalize() its lnet_msg_t */
        kqswnal_tx_done(ktx, status);
}

int
kqswnal_rdma (kqswnal_rx_t *krx, lnet_msg_t *lntmsg,
              int type, kqswnal_remotemd_t *rmd,
              unsigned int niov, struct iovec *iov, lnet_kiov_t *kiov,
              unsigned int offset, unsigned int len)
{
        kqswnal_tx_t       *ktx;
        int                 eprc;
        int                 rc;

        /* Not both mapped and paged payload */
        LASSERT (iov == NULL || kiov == NULL);
        /* RPC completes with failure by default */
        LASSERT (krx->krx_rpc_reply_needed);
        LASSERT (krx->krx_rpc_reply.msg.status != 0);

        if (len == 0) {
                /* data got truncated to nothing. */
                lnet_finalize(kqswnal_data.kqn_ni, lntmsg, 0);
                /* Let kqswnal_rx_done() complete the RPC with success */
                krx->krx_rpc_reply.msg.status = 0;
                return (0);
        }
        
        /* NB I'm using 'ktx' just to map the local RDMA buffers; I'm not
           actually sending a portals message with it */
        ktx = kqswnal_get_idle_tx();
        if (ktx == NULL) {
                CERROR ("Can't get txd for RDMA with %s\n",
                        libcfs_nid2str(kqswnal_rx_nid(krx)));
                return (-ENOMEM);
        }

        ktx->ktx_state   = type;
        ktx->ktx_nid     = kqswnal_rx_nid(krx);
        ktx->ktx_args[0] = krx;
        ktx->ktx_args[1] = lntmsg;

        LASSERT (cfs_atomic_read(&krx->krx_refcount) > 0);
        /* Take an extra ref for the completion callback */
        cfs_atomic_inc(&krx->krx_refcount);

        /* Map on the rail the RPC prefers */
        ktx->ktx_rail = ep_rcvr_prefrail(krx->krx_eprx,
                                         ep_rxd_railmask(krx->krx_rxd));

        /* Start mapping at offset 0 (we're not mapping any headers) */
        ktx->ktx_nfrag = ktx->ktx_firsttmpfrag = 0;
        
        if (kiov != NULL)
                rc = kqswnal_map_tx_kiov(ktx, offset, len, niov, kiov);
        else
                rc = kqswnal_map_tx_iov(ktx, offset, len, niov, iov);

        if (rc != 0) {
                CERROR ("Can't map local RDMA data: %d\n", rc);
                goto out;
        }

        rc = kqswnal_check_rdma (ktx->ktx_nfrag, ktx->ktx_frags,
                                 rmd->kqrmd_nfrag, rmd->kqrmd_frag);
        if (rc != 0) {
                CERROR ("Incompatible RDMA descriptors\n");
                goto out;
        }

        switch (type) {
        default:
                LBUG();
                
        case KTX_RDMA_STORE:
                krx->krx_rpc_reply.msg.status    = 0;
                krx->krx_rpc_reply.msg.magic     = LNET_PROTO_QSW_MAGIC;
                krx->krx_rpc_reply.msg.version   = QSWLND_PROTO_VERSION;
                krx->krx_rpc_reply.msg.u.get.len = len;
#if KQSW_CKSUM
                krx->krx_rpc_reply.msg.u.get.cksum = (kiov != NULL) ?
                            kqswnal_csum_kiov(~0, offset, len, niov, kiov) :
                            kqswnal_csum_iov(~0, offset, len, niov, iov);
                if (*kqswnal_tunables.kqn_inject_csum_error == 4) {
                        krx->krx_rpc_reply.msg.u.get.cksum++;
                        *kqswnal_tunables.kqn_inject_csum_error = 0;
                }
#endif
                eprc = ep_complete_rpc(krx->krx_rxd, 
                                       kqswnal_rdma_store_complete, ktx, 
                                       &krx->krx_rpc_reply.ep_statusblk, 
                                       ktx->ktx_frags, rmd->kqrmd_frag, 
                                       rmd->kqrmd_nfrag);
                if (eprc != EP_SUCCESS) {
                        CERROR("can't complete RPC: %d\n", eprc);
                        /* don't re-attempt RPC completion */
                        krx->krx_rpc_reply_needed = 0;
                        rc = -ECONNABORTED;
                }
                break;
                
        case KTX_RDMA_FETCH:
                eprc = ep_rpc_get (krx->krx_rxd, 
                                   kqswnal_rdma_fetch_complete, ktx,
                                   rmd->kqrmd_frag, ktx->ktx_frags, ktx->ktx_nfrag);
                if (eprc != EP_SUCCESS) {
                        CERROR("ep_rpc_get failed: %d\n", eprc);
                        /* Don't attempt RPC completion: 
                         * EKC nuked it when the get failed */
                        krx->krx_rpc_reply_needed = 0;
                        rc = -ECONNABORTED;
                }
                break;
        }

 out:
        if (rc != 0) {
                kqswnal_rx_decref(krx);                 /* drop callback's ref */
                kqswnal_put_idle_tx (ktx);
        }

        cfs_atomic_dec(&kqswnal_data.kqn_pending_txs);
        return (rc);
}

int
kqswnal_send (lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg)
{
        lnet_hdr_t       *hdr = &lntmsg->msg_hdr;
        int               type = lntmsg->msg_type;
        lnet_process_id_t target = lntmsg->msg_target;
        int               target_is_router = lntmsg->msg_target_is_router;
        int               routing = lntmsg->msg_routing;
        unsigned int      payload_niov = lntmsg->msg_niov;
        struct iovec     *payload_iov = lntmsg->msg_iov;
        lnet_kiov_t      *payload_kiov = lntmsg->msg_kiov;
        unsigned int      payload_offset = lntmsg->msg_offset;
        unsigned int      payload_nob = lntmsg->msg_len;
        int               nob;
        kqswnal_tx_t     *ktx;
        int               rc;

        /* NB 1. hdr is in network byte order */
        /*    2. 'private' depends on the message type */
        
        CDEBUG(D_NET, "sending %u bytes in %d frags to %s\n",
               payload_nob, payload_niov, libcfs_id2str(target));

        LASSERT (payload_nob == 0 || payload_niov > 0);
        LASSERT (payload_niov <= LNET_MAX_IOV);

        /* It must be OK to kmap() if required */
        LASSERT (payload_kiov == NULL || !cfs_in_interrupt ());
        /* payload is either all vaddrs or all pages */
        LASSERT (!(payload_kiov != NULL && payload_iov != NULL));

        if (kqswnal_nid2elanid (target.nid) < 0) {
                CERROR("%s not in my cluster\n", libcfs_nid2str(target.nid));
                return -EIO;
        }

        /* I may not block for a transmit descriptor if I might block the
         * router, receiver, or an interrupt handler. */
        ktx = kqswnal_get_idle_tx();
        if (ktx == NULL) {
                CERROR ("Can't get txd for msg type %d for %s\n",
                        type, libcfs_nid2str(target.nid));
                return (-ENOMEM);
        }

        ktx->ktx_state   = KTX_SENDING;
        ktx->ktx_nid     = target.nid;
        ktx->ktx_args[0] = private;
        ktx->ktx_args[1] = lntmsg;
        ktx->ktx_args[2] = NULL;    /* set when a GET commits to REPLY */

        /* The first frag will be the pre-mapped buffer. */
        ktx->ktx_nfrag = ktx->ktx_firsttmpfrag = 1;

        if ((!target_is_router &&               /* target.nid is final dest */
             !routing &&                        /* I'm the source */
             type == LNET_MSG_GET &&            /* optimize GET? */
             *kqswnal_tunables.kqn_optimized_gets != 0 &&
             lntmsg->msg_md->md_length >= 
             *kqswnal_tunables.kqn_optimized_gets) ||
            ((type == LNET_MSG_PUT ||            /* optimize PUT? */
              type == LNET_MSG_REPLY) &&         /* optimize REPLY? */
             *kqswnal_tunables.kqn_optimized_puts != 0 &&
             payload_nob >= *kqswnal_tunables.kqn_optimized_puts)) {
                lnet_libmd_t       *md = lntmsg->msg_md;
                kqswnal_msg_t      *msg = (kqswnal_msg_t *)ktx->ktx_buffer;
                lnet_hdr_t         *mhdr;
                kqswnal_remotemd_t *rmd;

                /* Optimised path: I send over the Elan vaddrs of the local
                 * buffers, and my peer DMAs directly to/from them.
                 *
                 * First I set up ktx as if it was going to send this
                 * payload, (it needs to map it anyway).  This fills
                 * ktx_frags[1] and onward with the network addresses
                 * of the buffer frags. */

                /* Send an RDMA message */
                msg->kqm_magic = LNET_PROTO_QSW_MAGIC;
                msg->kqm_version = QSWLND_PROTO_VERSION;
                msg->kqm_type = QSWLND_MSG_RDMA;

                mhdr = &msg->kqm_u.rdma.kqrm_hdr;
                rmd  = &msg->kqm_u.rdma.kqrm_rmd;

                *mhdr = *hdr;
                nob = (((char *)rmd) - ktx->ktx_buffer);

                if (type == LNET_MSG_GET) {
                        if ((md->md_options & LNET_MD_KIOV) != 0) 
                                rc = kqswnal_map_tx_kiov (ktx, 0, md->md_length,
                                                          md->md_niov, md->md_iov.kiov);
                        else
                                rc = kqswnal_map_tx_iov (ktx, 0, md->md_length,
                                                         md->md_niov, md->md_iov.iov);
                        ktx->ktx_state = KTX_GETTING;
                } else {
                        if (payload_kiov != NULL)
                                rc = kqswnal_map_tx_kiov(ktx, 0, payload_nob,
                                                         payload_niov, payload_kiov);
                        else
                                rc = kqswnal_map_tx_iov(ktx, 0, payload_nob,
                                                        payload_niov, payload_iov);
                        ktx->ktx_state = KTX_PUTTING;
                }

                if (rc != 0)
                        goto out;

                rmd->kqrmd_nfrag = ktx->ktx_nfrag - 1;
                nob += offsetof(kqswnal_remotemd_t,
                                kqrmd_frag[rmd->kqrmd_nfrag]);
                LASSERT (nob <= KQSW_TX_BUFFER_SIZE);

                memcpy(&rmd->kqrmd_frag[0], &ktx->ktx_frags[1],
                       rmd->kqrmd_nfrag * sizeof(EP_NMD));

                ep_nmd_subset(&ktx->ktx_frags[0], &ktx->ktx_ebuffer, 0, nob);
#if KQSW_CKSUM
                msg->kqm_nob   = nob + payload_nob;
                msg->kqm_cksum = 0;
                msg->kqm_cksum = kqswnal_csum(~0, (char *)msg, nob);
#endif
                if (type == LNET_MSG_GET) {
                        /* Allocate reply message now while I'm in thread context */
                        ktx->ktx_args[2] = lnet_create_reply_msg (
                                kqswnal_data.kqn_ni, lntmsg);
                        if (ktx->ktx_args[2] == NULL)
                                goto out;

                        /* NB finalizing the REPLY message is my
                         * responsibility now, whatever happens. */
#if KQSW_CKSUM
                        if (*kqswnal_tunables.kqn_inject_csum_error ==  3) {
                                msg->kqm_cksum++;
                                *kqswnal_tunables.kqn_inject_csum_error = 0;
                        }

                } else if (payload_kiov != NULL) {
                        /* must checksum payload after header so receiver can
                         * compute partial header cksum before swab.  Sadly
                         * this causes 2 rounds of kmap */
                        msg->kqm_cksum =
                                kqswnal_csum_kiov(msg->kqm_cksum, 0, payload_nob,
                                                  payload_niov, payload_kiov);
                        if (*kqswnal_tunables.kqn_inject_csum_error ==  2) {
                                msg->kqm_cksum++;
                                *kqswnal_tunables.kqn_inject_csum_error = 0;
                        }
                } else {
                        msg->kqm_cksum =
                                kqswnal_csum_iov(msg->kqm_cksum, 0, payload_nob,
                                                 payload_niov, payload_iov);
                        if (*kqswnal_tunables.kqn_inject_csum_error ==  2) {
                                msg->kqm_cksum++;
                                *kqswnal_tunables.kqn_inject_csum_error = 0;
                        }
#endif
                }
                
        } else if (payload_nob <= *kqswnal_tunables.kqn_tx_maxcontig) {
                lnet_hdr_t    *mhdr;
                char          *payload;
                kqswnal_msg_t *msg = (kqswnal_msg_t *)ktx->ktx_buffer;

                /* single frag copied into the pre-mapped buffer */
                msg->kqm_magic = LNET_PROTO_QSW_MAGIC;
                msg->kqm_version = QSWLND_PROTO_VERSION;
                msg->kqm_type = QSWLND_MSG_IMMEDIATE;

                mhdr = &msg->kqm_u.immediate.kqim_hdr;
                payload = msg->kqm_u.immediate.kqim_payload;

                *mhdr = *hdr;
                nob = (payload - ktx->ktx_buffer) + payload_nob;

                ep_nmd_subset(&ktx->ktx_frags[0], &ktx->ktx_ebuffer, 0, nob);

                if (payload_kiov != NULL)
                        lnet_copy_kiov2flat(KQSW_TX_BUFFER_SIZE, payload, 0,
                                            payload_niov, payload_kiov, 
                                            payload_offset, payload_nob);
                else
                        lnet_copy_iov2flat(KQSW_TX_BUFFER_SIZE, payload, 0,
                                           payload_niov, payload_iov, 
                                           payload_offset, payload_nob);
#if KQSW_CKSUM
                msg->kqm_nob   = nob;
                msg->kqm_cksum = 0;
                msg->kqm_cksum = kqswnal_csum(~0, (char *)msg, nob);
                if (*kqswnal_tunables.kqn_inject_csum_error == 1) {
                        msg->kqm_cksum++;
                        *kqswnal_tunables.kqn_inject_csum_error = 0;
                }
#endif
        } else {
                lnet_hdr_t    *mhdr;
                kqswnal_msg_t *msg = (kqswnal_msg_t *)ktx->ktx_buffer;

                /* multiple frags: first is hdr in pre-mapped buffer */
                msg->kqm_magic = LNET_PROTO_QSW_MAGIC;
                msg->kqm_version = QSWLND_PROTO_VERSION;
                msg->kqm_type = QSWLND_MSG_IMMEDIATE;

                mhdr = &msg->kqm_u.immediate.kqim_hdr;
                nob = offsetof(kqswnal_msg_t, kqm_u.immediate.kqim_payload);

                *mhdr = *hdr;

                ep_nmd_subset(&ktx->ktx_frags[0], &ktx->ktx_ebuffer, 0, nob);

                if (payload_kiov != NULL)
                        rc = kqswnal_map_tx_kiov (ktx, payload_offset, payload_nob, 
                                                  payload_niov, payload_kiov);
                else
                        rc = kqswnal_map_tx_iov (ktx, payload_offset, payload_nob,
                                                 payload_niov, payload_iov);
                if (rc != 0)
                        goto out;

#if KQSW_CKSUM
                msg->kqm_nob   = nob + payload_nob;
                msg->kqm_cksum = 0;
                msg->kqm_cksum = kqswnal_csum(~0, (char *)msg, nob);

                msg->kqm_cksum = (payload_kiov != NULL) ?
                                 kqswnal_csum_kiov(msg->kqm_cksum,
                                                   payload_offset, payload_nob,
                                                   payload_niov, payload_kiov) :
                                 kqswnal_csum_iov(msg->kqm_cksum,
                                                  payload_offset, payload_nob,
                                                  payload_niov, payload_iov);

                if (*kqswnal_tunables.kqn_inject_csum_error == 1) {
                        msg->kqm_cksum++;
                        *kqswnal_tunables.kqn_inject_csum_error = 0;
                }
#endif
                nob += payload_nob;
        }

        ktx->ktx_port = (nob <= KQSW_SMALLMSG) ?
                        EP_MSG_SVC_PORTALS_SMALL : EP_MSG_SVC_PORTALS_LARGE;

        rc = kqswnal_launch (ktx);

 out:
        CDEBUG_LIMIT(rc == 0? D_NET :D_NETERROR, "%s %d bytes to %s%s: rc %d\n",
                     routing ? (rc == 0 ? "Routed" : "Failed to route") :
                               (rc == 0 ? "Sent" : "Failed to send"),
                     nob, libcfs_nid2str(target.nid),
                     target_is_router ? "(router)" : "", rc);

        if (rc != 0) {
                lnet_msg_t *repmsg = (lnet_msg_t *)ktx->ktx_args[2];
                int         state = ktx->ktx_state;

                kqswnal_put_idle_tx (ktx);

                if (state == KTX_GETTING && repmsg != NULL) {
                        /* We committed to reply, but there was a problem
                         * launching the GET.  We can't avoid delivering a
                         * REPLY event since we committed above, so we
                         * pretend the GET succeeded but the REPLY
                         * failed. */
                        rc = 0;
                        lnet_finalize (kqswnal_data.kqn_ni, lntmsg, 0);
                        lnet_finalize (kqswnal_data.kqn_ni, repmsg, -EIO);
                }
                
        }
        
        cfs_atomic_dec(&kqswnal_data.kqn_pending_txs);
        return (rc == 0 ? 0 : -EIO);
}

void
kqswnal_requeue_rx (kqswnal_rx_t *krx)
{
        LASSERT (cfs_atomic_read(&krx->krx_refcount) == 0);
        LASSERT (!krx->krx_rpc_reply_needed);

        krx->krx_state = KRX_POSTED;

        if (kqswnal_data.kqn_shuttingdown) {
                /* free EKC rxd on shutdown */
                ep_complete_receive(krx->krx_rxd);
        } else {
                /* repost receive */
                ep_requeue_receive(krx->krx_rxd, 
                                   kqswnal_rxhandler, krx,
                                   &krx->krx_elanbuffer, 0);
        }
}

void
kqswnal_rpc_complete (EP_RXD *rxd)
{
        int           status = ep_rxd_status(rxd);
        kqswnal_rx_t *krx    = (kqswnal_rx_t *)ep_rxd_arg(rxd);
        
        CDEBUG((status == EP_SUCCESS) ? D_NET : D_ERROR,
               "rxd %p, krx %p, status %d\n", rxd, krx, status);

        LASSERT (krx->krx_rxd == rxd);
        LASSERT (krx->krx_rpc_reply_needed);
        
        krx->krx_rpc_reply_needed = 0;
        kqswnal_requeue_rx (krx);
}

void
kqswnal_rx_done (kqswnal_rx_t *krx) 
{
        int           rc;

        LASSERT (cfs_atomic_read(&krx->krx_refcount) == 0);

        if (krx->krx_rpc_reply_needed) {
                /* We've not completed the peer's RPC yet... */
                krx->krx_rpc_reply.msg.magic   = LNET_PROTO_QSW_MAGIC;
                krx->krx_rpc_reply.msg.version = QSWLND_PROTO_VERSION;

                LASSERT (!cfs_in_interrupt());

                rc = ep_complete_rpc(krx->krx_rxd, 
                                     kqswnal_rpc_complete, krx,
                                     &krx->krx_rpc_reply.ep_statusblk, 
                                     NULL, NULL, 0);
                if (rc == EP_SUCCESS)
                        return;

                CERROR("can't complete RPC: %d\n", rc);
                krx->krx_rpc_reply_needed = 0;
        }

        kqswnal_requeue_rx(krx);
}
        
void
kqswnal_parse (kqswnal_rx_t *krx)
{
        lnet_ni_t      *ni = kqswnal_data.kqn_ni;
        kqswnal_msg_t  *msg = (kqswnal_msg_t *)page_address(krx->krx_kiov[0].kiov_page);
        lnet_nid_t      fromnid = kqswnal_rx_nid(krx);
        int             swab;
        int             n;
        int             i;
        int             nob;
        int             rc;

        LASSERT (cfs_atomic_read(&krx->krx_refcount) == 1);

        if (krx->krx_nob < offsetof(kqswnal_msg_t, kqm_u)) {
                CERROR("Short message %d received from %s\n",
                       krx->krx_nob, libcfs_nid2str(fromnid));
                goto done;
        }

        swab = msg->kqm_magic == __swab32(LNET_PROTO_QSW_MAGIC);

        if (swab || msg->kqm_magic == LNET_PROTO_QSW_MAGIC) {
#if KQSW_CKSUM
                __u32 csum0;
                __u32 csum1;

                /* csum byte array before swab */
                csum1 = msg->kqm_cksum;
                msg->kqm_cksum = 0;
                csum0 = kqswnal_csum_kiov(~0, 0, krx->krx_nob,
                                          krx->krx_npages, krx->krx_kiov);
                msg->kqm_cksum = csum1;
#endif

                if (swab) {
                        __swab16s(&msg->kqm_version);
                        __swab16s(&msg->kqm_type);
#if KQSW_CKSUM
                        __swab32s(&msg->kqm_cksum);
                        __swab32s(&msg->kqm_nob);
#endif
                }

                if (msg->kqm_version != QSWLND_PROTO_VERSION) {
                        /* Future protocol version compatibility support!
                         * The next qswlnd-specific protocol rev will first
                         * send an RPC to check version.
                         * 1.4.6 and 1.4.7.early reply with a status
                         * block containing its current version.
                         * Later versions send a failure (-ve) status +
                         * magic/version */

                        if (!krx->krx_rpc_reply_needed) {
                                CERROR("Unexpected version %d from %s\n",
                                       msg->kqm_version, libcfs_nid2str(fromnid));
                                goto done;
                        }

                        LASSERT (krx->krx_rpc_reply.msg.status == -EPROTO);
                        goto done;
                }

                switch (msg->kqm_type) {
                default:
                        CERROR("Bad request type %x from %s\n",
                               msg->kqm_type, libcfs_nid2str(fromnid));
                        goto done;

                case QSWLND_MSG_IMMEDIATE:
                        if (krx->krx_rpc_reply_needed) {
                                /* Should have been a simple message */
                                CERROR("IMMEDIATE sent as RPC from %s\n",
                                       libcfs_nid2str(fromnid));
                                goto done;
                        }

                        nob = offsetof(kqswnal_msg_t, kqm_u.immediate.kqim_payload);
                        if (krx->krx_nob < nob) {
                                CERROR("Short IMMEDIATE %d(%d) from %s\n",
                                       krx->krx_nob, nob, libcfs_nid2str(fromnid));
                                goto done;
                        }

#if KQSW_CKSUM
                        if (csum0 != msg->kqm_cksum) {
                                CERROR("Bad IMMEDIATE checksum %08x(%08x) from %s\n",
                                       csum0, msg->kqm_cksum, libcfs_nid2str(fromnid));
                                CERROR("nob %d (%d)\n", krx->krx_nob, msg->kqm_nob);
                                goto done;
                        }
#endif
                        rc = lnet_parse(ni, &msg->kqm_u.immediate.kqim_hdr,
                                        fromnid, krx, 0);
                        if (rc < 0)
                                goto done;
                        return;

                case QSWLND_MSG_RDMA:
                        if (!krx->krx_rpc_reply_needed) {
                                /* Should have been a simple message */
                                CERROR("RDMA sent as simple message from %s\n",
                                       libcfs_nid2str(fromnid));
                                goto done;
                        }

                        nob = offsetof(kqswnal_msg_t,
                                       kqm_u.rdma.kqrm_rmd.kqrmd_frag[0]);
                        if (krx->krx_nob < nob) {
                                CERROR("Short RDMA message %d(%d) from %s\n",
                                       krx->krx_nob, nob, libcfs_nid2str(fromnid));
                                goto done;
                        }

                        if (swab)
                                __swab32s(&msg->kqm_u.rdma.kqrm_rmd.kqrmd_nfrag);

                        n = msg->kqm_u.rdma.kqrm_rmd.kqrmd_nfrag;
                        nob = offsetof(kqswnal_msg_t,
                                       kqm_u.rdma.kqrm_rmd.kqrmd_frag[n]);

                        if (krx->krx_nob < nob) {
                                CERROR("short RDMA message %d(%d) from %s\n",
                                       krx->krx_nob, nob, libcfs_nid2str(fromnid));
                                goto done;
                        }

                        if (swab) {
                                for (i = 0; i < n; i++) {
                                        EP_NMD *nmd = &msg->kqm_u.rdma.kqrm_rmd.kqrmd_frag[i];

                                        __swab32s(&nmd->nmd_addr);
                                        __swab32s(&nmd->nmd_len);
                                        __swab32s(&nmd->nmd_attr);
                                }
                        }

#if KQSW_CKSUM
                        krx->krx_cksum = csum0; /* stash checksum so far */
#endif
                        rc = lnet_parse(ni, &msg->kqm_u.rdma.kqrm_hdr,
                                        fromnid, krx, 1);
                        if (rc < 0)
                                goto done;
                        return;
                }
                /* Not Reached */
        }

        if (msg->kqm_magic == LNET_PROTO_MAGIC ||
            msg->kqm_magic == __swab32(LNET_PROTO_MAGIC)) {
                /* Future protocol version compatibility support!
                 * When LNET unifies protocols over all LNDs, the first thing a
                 * peer will send will be a version query RPC.  
                 * 1.4.6 and 1.4.7.early reply with a status block containing
                 * LNET_PROTO_QSW_MAGIC..
                 * Later versions send a failure (-ve) status +
                 * magic/version */

                if (!krx->krx_rpc_reply_needed) {
                        CERROR("Unexpected magic %08x from %s\n",
                               msg->kqm_magic, libcfs_nid2str(fromnid));
                        goto done;
                }

                LASSERT (krx->krx_rpc_reply.msg.status == -EPROTO);
                goto done;
        }

        CERROR("Unrecognised magic %08x from %s\n",
               msg->kqm_magic, libcfs_nid2str(fromnid));
 done:
        kqswnal_rx_decref(krx);
}

/* Receive Interrupt Handler: posts to schedulers */
void 
kqswnal_rxhandler(EP_RXD *rxd)
{
        unsigned long flags;
        int           nob    = ep_rxd_len (rxd);
        int           status = ep_rxd_status (rxd);
        kqswnal_rx_t *krx    = (kqswnal_rx_t *)ep_rxd_arg (rxd);
        CDEBUG(D_NET, "kqswnal_rxhandler: rxd %p, krx %p, nob %d, status %d\n",
               rxd, krx, nob, status);

        LASSERT (krx != NULL);
        LASSERT (krx->krx_state == KRX_POSTED);
        
        krx->krx_state = KRX_PARSE;
        krx->krx_rxd = rxd;
        krx->krx_nob = nob;

        /* RPC reply iff rpc request received without error */
        krx->krx_rpc_reply_needed = ep_rxd_isrpc(rxd) &&
                                    (status == EP_SUCCESS ||
                                     status == EP_MSG_TOO_BIG);

        /* Default to failure if an RPC reply is requested but not handled */
        krx->krx_rpc_reply.msg.status = -EPROTO;
        cfs_atomic_set (&krx->krx_refcount, 1);

        if (status != EP_SUCCESS) {
                /* receives complete with failure when receiver is removed */
                if (status == EP_SHUTDOWN)
                        LASSERT (kqswnal_data.kqn_shuttingdown);
                else
                        CERROR("receive status failed with status %d nob %d\n",
                               ep_rxd_status(rxd), nob);
                kqswnal_rx_decref(krx);
                return;
        }

        if (!cfs_in_interrupt()) {
                kqswnal_parse(krx);
                return;
        }

	spin_lock_irqsave(&kqswnal_data.kqn_sched_lock, flags);

	cfs_list_add_tail(&krx->krx_list, &kqswnal_data.kqn_readyrxds);
	cfs_waitq_signal(&kqswnal_data.kqn_sched_waitq);

	spin_unlock_irqrestore(&kqswnal_data.kqn_sched_lock, flags);
}

int
kqswnal_recv (lnet_ni_t     *ni,
              void          *private,
              lnet_msg_t    *lntmsg,
              int            delayed,
              unsigned int   niov,
              struct iovec  *iov,
              lnet_kiov_t   *kiov,
              unsigned int   offset,
              unsigned int   mlen,
              unsigned int   rlen)
{
        kqswnal_rx_t       *krx = (kqswnal_rx_t *)private;
        lnet_nid_t          fromnid;
        kqswnal_msg_t      *msg;
        lnet_hdr_t         *hdr;
        kqswnal_remotemd_t *rmd;
        int                 msg_offset;
        int                 rc;

        LASSERT (!cfs_in_interrupt ());             /* OK to map */
        /* Either all pages or all vaddrs */
        LASSERT (!(kiov != NULL && iov != NULL));

        fromnid = LNET_MKNID(LNET_NIDNET(ni->ni_nid), ep_rxd_node(krx->krx_rxd));
        msg = (kqswnal_msg_t *)page_address(krx->krx_kiov[0].kiov_page);

        if (krx->krx_rpc_reply_needed) {
                /* optimized (rdma) request sent as RPC */

                LASSERT (msg->kqm_type == QSWLND_MSG_RDMA);
                hdr = &msg->kqm_u.rdma.kqrm_hdr;
                rmd = &msg->kqm_u.rdma.kqrm_rmd;

                /* NB header is still in wire byte order */

                switch (le32_to_cpu(hdr->type)) {
                        case LNET_MSG_PUT:
                        case LNET_MSG_REPLY:
                                /* This is an optimized PUT/REPLY */
                                rc = kqswnal_rdma(krx, lntmsg, 
                                                  KTX_RDMA_FETCH, rmd,
                                                  niov, iov, kiov, offset, mlen);
                                break;

                        case LNET_MSG_GET:
#if KQSW_CKSUM
                                if (krx->krx_cksum != msg->kqm_cksum) {
                                        CERROR("Bad GET checksum %08x(%08x) from %s\n",
                                               krx->krx_cksum, msg->kqm_cksum,
                                               libcfs_nid2str(fromnid));
                                        rc = -EIO;
                                        break;
                                }
#endif                                
                                if (lntmsg == NULL) {
                                        /* No buffer match: my decref will
                                         * complete the RPC with failure */
                                        rc = 0;
                                } else {
                                        /* Matched something! */
                                        rc = kqswnal_rdma(krx, lntmsg,
                                                          KTX_RDMA_STORE, rmd,
                                                          lntmsg->msg_niov,
                                                          lntmsg->msg_iov,
                                                          lntmsg->msg_kiov,
                                                          lntmsg->msg_offset,
                                                          lntmsg->msg_len);
                                }
                                break;

                        default:
                                CERROR("Bad RPC type %d\n",
                                       le32_to_cpu(hdr->type));
                                rc = -EPROTO;
                                break;
                }

                kqswnal_rx_decref(krx);
                return rc;
        }

        LASSERT (msg->kqm_type == QSWLND_MSG_IMMEDIATE);
        msg_offset = offsetof(kqswnal_msg_t, kqm_u.immediate.kqim_payload);
        
        if (krx->krx_nob < msg_offset + rlen) {
                CERROR("Bad message size from %s: have %d, need %d + %d\n",
                       libcfs_nid2str(fromnid), krx->krx_nob,
                       msg_offset, rlen);
                kqswnal_rx_decref(krx);
                return -EPROTO;
        }

        if (kiov != NULL)
                lnet_copy_kiov2kiov(niov, kiov, offset,
                                    krx->krx_npages, krx->krx_kiov, 
                                    msg_offset, mlen);
        else
                lnet_copy_kiov2iov(niov, iov, offset,
                                   krx->krx_npages, krx->krx_kiov, 
                                   msg_offset, mlen);

        lnet_finalize(ni, lntmsg, 0);
        kqswnal_rx_decref(krx);
        return 0;
}

int
kqswnal_thread_start(int (*fn)(void *arg), void *arg, char *name)
{
	cfs_task_t *task = cfs_thread_run(fn, arg, name);

	if (IS_ERR(task))
		return PTR_ERR(task);

	cfs_atomic_inc(&kqswnal_data.kqn_nthreads);
	return 0;
}

void
kqswnal_thread_fini (void)
{
        cfs_atomic_dec (&kqswnal_data.kqn_nthreads);
}

int
kqswnal_scheduler (void *arg)
{
        kqswnal_rx_t    *krx;
        kqswnal_tx_t    *ktx;
        unsigned long    flags;
        int              rc;
        int              counter = 0;
        int              did_something;

        cfs_block_allsigs ();

	spin_lock_irqsave(&kqswnal_data.kqn_sched_lock, flags);

        for (;;)
        {
                did_something = 0;

                if (!cfs_list_empty (&kqswnal_data.kqn_readyrxds))
                {
                        krx = cfs_list_entry(kqswnal_data.kqn_readyrxds.next,
                                             kqswnal_rx_t, krx_list);
                        cfs_list_del (&krx->krx_list);
			spin_unlock_irqrestore(&kqswnal_data.kqn_sched_lock,
                                                   flags);

                        LASSERT (krx->krx_state == KRX_PARSE);
                        kqswnal_parse (krx);

                        did_something = 1;
			spin_lock_irqsave(&kqswnal_data.kqn_sched_lock,
                                              flags);
                }

                if (!cfs_list_empty (&kqswnal_data.kqn_donetxds))
                {
                        ktx = cfs_list_entry(kqswnal_data.kqn_donetxds.next,
                                             kqswnal_tx_t, ktx_schedlist);
                        cfs_list_del_init (&ktx->ktx_schedlist);
			spin_unlock_irqrestore(&kqswnal_data.kqn_sched_lock,
                                                   flags);

                        kqswnal_tx_done_in_thread_context(ktx);

                        did_something = 1;
			spin_lock_irqsave(&kqswnal_data.kqn_sched_lock,
                                               flags);
                }

                if (!cfs_list_empty (&kqswnal_data.kqn_delayedtxds))
                {
                        ktx = cfs_list_entry(kqswnal_data.kqn_delayedtxds.next,
                                             kqswnal_tx_t, ktx_schedlist);
                        cfs_list_del_init (&ktx->ktx_schedlist);
			spin_unlock_irqrestore(&kqswnal_data.kqn_sched_lock,
                                                   flags);

                        rc = kqswnal_launch (ktx);
                        if (rc != 0) {
                                CERROR("Failed delayed transmit to %s: %d\n", 
                                       libcfs_nid2str(ktx->ktx_nid), rc);
                                kqswnal_tx_done (ktx, rc);
                        }
                        cfs_atomic_dec (&kqswnal_data.kqn_pending_txs);

                        did_something = 1;
			spin_lock_irqsave(&kqswnal_data.kqn_sched_lock,
                                               flags);
                }

                /* nothing to do or hogging CPU */
                if (!did_something || counter++ == KQSW_RESCHED) {
			spin_unlock_irqrestore(&kqswnal_data.kqn_sched_lock,
                                                   flags);

                        counter = 0;

                        if (!did_something) {
                                if (kqswnal_data.kqn_shuttingdown == 2) {
                                        /* We only exit in stage 2 of shutdown
                                         * when there's nothing left to do */
                                        break;
                                }
                                cfs_wait_event_interruptible_exclusive (
                                        kqswnal_data.kqn_sched_waitq,
                                        kqswnal_data.kqn_shuttingdown == 2 ||
                                        !cfs_list_empty(&kqswnal_data. \
                                                        kqn_readyrxds) ||
                                        !cfs_list_empty(&kqswnal_data. \
                                                        kqn_donetxds) ||
                                        !cfs_list_empty(&kqswnal_data. \
                                                        kqn_delayedtxds, rc));
                                LASSERT (rc == 0);
                        } else if (need_resched())
                                cfs_schedule ();

			spin_lock_irqsave(&kqswnal_data.kqn_sched_lock,
                                               flags);
                }
        }

        kqswnal_thread_fini ();
        return (0);
}
