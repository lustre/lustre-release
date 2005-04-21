/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Eric Barton <eric@bartonsoftware.com>
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
 *
 */

#include "qswnal.h"

void
kqswnal_notify_peer_down(kqswnal_tx_t *ktx)
{
        struct timeval     now;
        time_t             then;

        do_gettimeofday (&now);
        then = now.tv_sec - (jiffies - ktx->ktx_launchtime)/HZ;

        kpr_notify(&kqswnal_data.kqn_router, ktx->ktx_nid, 0, then);
}

void
kqswnal_unmap_tx (kqswnal_tx_t *ktx)
{
#if MULTIRAIL_EKC
        int      i;

        ktx->ktx_rail = -1;                     /* unset rail */
#endif

        if (ktx->ktx_nmappedpages == 0)
                return;
        
#if MULTIRAIL_EKC
        CDEBUG(D_NET, "%p unloading %d frags starting at %d\n",
               ktx, ktx->ktx_nfrag, ktx->ktx_firsttmpfrag);

        for (i = ktx->ktx_firsttmpfrag; i < ktx->ktx_nfrag; i++)
                ep_dvma_unload(kqswnal_data.kqn_ep,
                               kqswnal_data.kqn_ep_tx_nmh,
                               &ktx->ktx_frags[i]);
#else
        CDEBUG (D_NET, "%p[%d] unloading pages %d for %d\n",
                ktx, ktx->ktx_nfrag, ktx->ktx_basepage, ktx->ktx_nmappedpages);

        LASSERT (ktx->ktx_nmappedpages <= ktx->ktx_npages);
        LASSERT (ktx->ktx_basepage + ktx->ktx_nmappedpages <=
                 kqswnal_data.kqn_eptxdmahandle->NumDvmaPages);

        elan3_dvma_unload(kqswnal_data.kqn_ep->DmaState,
                          kqswnal_data.kqn_eptxdmahandle,
                          ktx->ktx_basepage, ktx->ktx_nmappedpages);
#endif
        ktx->ktx_nmappedpages = 0;
}

int
kqswnal_map_tx_kiov (kqswnal_tx_t *ktx, int offset, int nob, int niov, ptl_kiov_t *kiov)
{
        int       nfrags    = ktx->ktx_nfrag;
        int       nmapped   = ktx->ktx_nmappedpages;
        int       maxmapped = ktx->ktx_npages;
        uint32_t  basepage  = ktx->ktx_basepage + nmapped;
        char     *ptr;
#if MULTIRAIL_EKC
        EP_RAILMASK railmask;
        int         rail;

        if (ktx->ktx_rail < 0)
                ktx->ktx_rail = ep_xmtr_prefrail(kqswnal_data.kqn_eptx,
                                                 EP_RAILMASK_ALL,
                                                 kqswnal_nid2elanid(ktx->ktx_nid));
        rail = ktx->ktx_rail;
        if (rail < 0) {
                CERROR("No rails available for "LPX64"\n", ktx->ktx_nid);
                return (-ENETDOWN);
        }
        railmask = 1 << rail;
#endif
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

#if MULTIRAIL_EKC
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
#else
                elan3_dvma_kaddr_load (kqswnal_data.kqn_ep->DmaState,
                                       kqswnal_data.kqn_eptxdmahandle,
                                       ptr, fraglen,
                                       basepage, &ktx->ktx_frags[nfrags].Base);

                if (nfrags > 0 &&                /* previous frag mapped */
                    ktx->ktx_frags[nfrags].Base == /* contiguous with this one */
                    (ktx->ktx_frags[nfrags-1].Base + ktx->ktx_frags[nfrags-1].Len))
                        /* just extend previous */
                        ktx->ktx_frags[nfrags - 1].Len += fraglen;
                else {
                        ktx->ktx_frags[nfrags].Len = fraglen;
                        nfrags++;                /* new frag */
                }
#endif

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

int
kqswnal_map_tx_iov (kqswnal_tx_t *ktx, int offset, int nob, 
                    int niov, struct iovec *iov)
{
        int       nfrags    = ktx->ktx_nfrag;
        int       nmapped   = ktx->ktx_nmappedpages;
        int       maxmapped = ktx->ktx_npages;
        uint32_t  basepage  = ktx->ktx_basepage + nmapped;
#if MULTIRAIL_EKC
        EP_RAILMASK railmask;
        int         rail;
        
        if (ktx->ktx_rail < 0)
                ktx->ktx_rail = ep_xmtr_prefrail(kqswnal_data.kqn_eptx,
                                                 EP_RAILMASK_ALL,
                                                 kqswnal_nid2elanid(ktx->ktx_nid));
        rail = ktx->ktx_rail;
        if (rail < 0) {
                CERROR("No rails available for "LPX64"\n", ktx->ktx_nid);
                return (-ENETDOWN);
        }
        railmask = 1 << rail;
#endif
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

#if MULTIRAIL_EKC
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
#else
                elan3_dvma_kaddr_load (kqswnal_data.kqn_ep->DmaState,
                                       kqswnal_data.kqn_eptxdmahandle,
                                       iov->iov_base + offset, fraglen,
                                       basepage, &ktx->ktx_frags[nfrags].Base);

                if (nfrags > 0 &&                /* previous frag mapped */
                    ktx->ktx_frags[nfrags].Base == /* contiguous with this one */
                    (ktx->ktx_frags[nfrags-1].Base + ktx->ktx_frags[nfrags-1].Len))
                        /* just extend previous */
                        ktx->ktx_frags[nfrags - 1].Len += fraglen;
                else {
                        ktx->ktx_frags[nfrags].Len = fraglen;
                        nfrags++;                /* new frag */
                }
#endif

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


void
kqswnal_put_idle_tx (kqswnal_tx_t *ktx)
{
        kpr_fwd_desc_t   *fwd = NULL;
        unsigned long     flags;

        kqswnal_unmap_tx (ktx);                 /* release temporary mappings */
        ktx->ktx_state = KTX_IDLE;

        spin_lock_irqsave (&kqswnal_data.kqn_idletxd_lock, flags);

        list_del (&ktx->ktx_list);              /* take off active list */

        if (ktx->ktx_isnblk) {
                /* reserved for non-blocking tx */
                list_add (&ktx->ktx_list, &kqswnal_data.kqn_nblk_idletxds);
                spin_unlock_irqrestore (&kqswnal_data.kqn_idletxd_lock, flags);
                return;
        }

        list_add (&ktx->ktx_list, &kqswnal_data.kqn_idletxds);

        /* anything blocking for a tx descriptor? */
        if (!kqswnal_data.kqn_shuttingdown &&
            !list_empty(&kqswnal_data.kqn_idletxd_fwdq)) /* forwarded packet? */
        {
                CDEBUG(D_NET,"wakeup fwd\n");

                fwd = list_entry (kqswnal_data.kqn_idletxd_fwdq.next,
                                  kpr_fwd_desc_t, kprfd_list);
                list_del (&fwd->kprfd_list);
        }

        wake_up (&kqswnal_data.kqn_idletxd_waitq);

        spin_unlock_irqrestore (&kqswnal_data.kqn_idletxd_lock, flags);

        if (fwd == NULL)
                return;

        /* schedule packet for forwarding again */
        spin_lock_irqsave (&kqswnal_data.kqn_sched_lock, flags);

        list_add_tail (&fwd->kprfd_list, &kqswnal_data.kqn_delayedfwds);
        wake_up (&kqswnal_data.kqn_sched_waitq);

        spin_unlock_irqrestore (&kqswnal_data.kqn_sched_lock, flags);
}

kqswnal_tx_t *
kqswnal_get_idle_tx (kpr_fwd_desc_t *fwd, int may_block)
{
        unsigned long  flags;
        kqswnal_tx_t  *ktx = NULL;

        for (;;) {
                spin_lock_irqsave (&kqswnal_data.kqn_idletxd_lock, flags);

                if (kqswnal_data.kqn_shuttingdown)
                        break;

                /* "normal" descriptor is free */
                if (!list_empty (&kqswnal_data.kqn_idletxds)) {
                        ktx = list_entry (kqswnal_data.kqn_idletxds.next,
                                          kqswnal_tx_t, ktx_list);
                        break;
                }

                if (fwd != NULL)                /* forwarded packet? */
                        break;

                /* doing a local transmit */
                if (!may_block) {
                        if (list_empty (&kqswnal_data.kqn_nblk_idletxds)) {
                                CERROR ("intr tx desc pool exhausted\n");
                                break;
                        }

                        ktx = list_entry (kqswnal_data.kqn_nblk_idletxds.next,
                                          kqswnal_tx_t, ktx_list);
                        break;
                }

                /* block for idle tx */

                spin_unlock_irqrestore (&kqswnal_data.kqn_idletxd_lock, flags);

                CDEBUG (D_NET, "blocking for tx desc\n");
                wait_event (kqswnal_data.kqn_idletxd_waitq,
                            !list_empty (&kqswnal_data.kqn_idletxds) ||
                            kqswnal_data.kqn_shuttingdown);
        }

        if (ktx != NULL) {
                list_del (&ktx->ktx_list);
                list_add (&ktx->ktx_list, &kqswnal_data.kqn_activetxds);
                ktx->ktx_launcher = current->pid;
                atomic_inc(&kqswnal_data.kqn_pending_txs);
        } else if (fwd != NULL) {
                /* queue forwarded packet until idle txd available */
                CDEBUG (D_NET, "blocked fwd [%p]\n", fwd);
                list_add_tail (&fwd->kprfd_list,
                               &kqswnal_data.kqn_idletxd_fwdq);
        }

        spin_unlock_irqrestore (&kqswnal_data.kqn_idletxd_lock, flags);

        /* Idle descs can't have any mapped (as opposed to pre-mapped) pages */
        LASSERT (ktx == NULL || ktx->ktx_nmappedpages == 0);

        return (ktx);
}

void
kqswnal_tx_done (kqswnal_tx_t *ktx, int error)
{
        switch (ktx->ktx_state) {
        case KTX_FORWARDING:       /* router asked me to forward this packet */
                kpr_fwd_done (&kqswnal_data.kqn_router,
                              (kpr_fwd_desc_t *)ktx->ktx_args[0], error);
                break;

        case KTX_RDMAING:          /* optimized GET/PUT handled */
        case KTX_PUTTING:          /* optimized PUT sent */
        case KTX_SENDING:          /* normal send */
                ptl_finalize (kqswnal_data.kqn_ni, NULL,
                              (ptl_msg_t *)ktx->ktx_args[1],
                              (error == 0) ? PTL_OK : PTL_FAIL);
                break;

        case KTX_GETTING:          /* optimized GET sent & REPLY received */
                /* Complete the GET with success since we can't avoid
                 * delivering a REPLY event; we committed to it when we
                 * launched the GET */
                ptl_finalize (kqswnal_data.kqn_ni, NULL, 
                              (ptl_msg_t *)ktx->ktx_args[1], PTL_OK);
                ptl_finalize (kqswnal_data.kqn_ni, NULL,
                              (ptl_msg_t *)ktx->ktx_args[2],
                              (error == 0) ? PTL_OK : PTL_FAIL);
                break;

        default:
                LASSERT (0);
        }

        kqswnal_put_idle_tx (ktx);
}

static void
kqswnal_txhandler(EP_TXD *txd, void *arg, int status)
{
        kqswnal_tx_t      *ktx = (kqswnal_tx_t *)arg;

        LASSERT (txd != NULL);
        LASSERT (ktx != NULL);

        CDEBUG(D_NET, "txd %p, arg %p status %d\n", txd, arg, status);

        if (status != EP_SUCCESS) {

                CERROR ("Tx completion to "LPX64" failed: %d\n", 
                        ktx->ktx_nid, status);

                kqswnal_notify_peer_down(ktx);
                status = -EHOSTDOWN;

        } else switch (ktx->ktx_state) {

        case KTX_GETTING:
        case KTX_PUTTING:
                /* RPC completed OK; but what did our peer put in the status
                 * block? */
#if MULTIRAIL_EKC
                status = ep_txd_statusblk(txd)->Data[0];
#else
                status = ep_txd_statusblk(txd)->Status;
#endif
                break;
                
        case KTX_FORWARDING:
        case KTX_SENDING:
                status = 0;
                break;
                
        default:
                LBUG();
                break;
        }

        kqswnal_tx_done (ktx, status);
}

int
kqswnal_launch (kqswnal_tx_t *ktx)
{
        /* Don't block for transmit descriptor if we're in interrupt context */
        int   attr = in_interrupt() ? (EP_NO_SLEEP | EP_NO_ALLOC) : 0;
        int   dest = kqswnal_nid2elanid (ktx->ktx_nid);
        unsigned long flags;
        int   rc;

        ktx->ktx_launchtime = jiffies;

        if (kqswnal_data.kqn_shuttingdown)
                return (-ESHUTDOWN);

        LASSERT (dest >= 0);                    /* must be a peer */

#if MULTIRAIL_EKC
        if (ktx->ktx_nmappedpages != 0)
                attr = EP_SET_PREFRAIL(attr, ktx->ktx_rail);
#endif

        switch (ktx->ktx_state) {
        case KTX_GETTING:
        case KTX_PUTTING:
                /* NB ktx_frag[0] is the GET/PUT hdr + kqswnal_remotemd_t.
                 * The other frags are the payload, awaiting RDMA */
                rc = ep_transmit_rpc(kqswnal_data.kqn_eptx, dest,
                                     ktx->ktx_port, attr,
                                     kqswnal_txhandler, ktx,
                                     NULL, ktx->ktx_frags, 1);
                break;

        case KTX_FORWARDING:
        case KTX_SENDING:
#if MULTIRAIL_EKC
                rc = ep_transmit_message(kqswnal_data.kqn_eptx, dest,
                                         ktx->ktx_port, attr,
                                         kqswnal_txhandler, ktx,
                                         NULL, ktx->ktx_frags, ktx->ktx_nfrag);
#else
                rc = ep_transmit_large(kqswnal_data.kqn_eptx, dest,
                                       ktx->ktx_port, attr, 
                                       kqswnal_txhandler, ktx, 
                                       ktx->ktx_frags, ktx->ktx_nfrag);
#endif
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
                spin_lock_irqsave (&kqswnal_data.kqn_sched_lock, flags);

                list_add_tail (&ktx->ktx_delayed_list, &kqswnal_data.kqn_delayedtxds);
                wake_up (&kqswnal_data.kqn_sched_waitq);

                spin_unlock_irqrestore (&kqswnal_data.kqn_sched_lock, flags);
                return (0);

        default: /* fatal error */
                CERROR ("Tx to "LPX64" failed: %d\n", ktx->ktx_nid, rc);
                kqswnal_notify_peer_down(ktx);
                return (-EHOSTUNREACH);
        }
}

#if 0
static char *
hdr_type_string (ptl_hdr_t *hdr)
{
        switch (hdr->type) {
        case PTL_MSG_ACK:
                return ("ACK");
        case PTL_MSG_PUT:
                return ("PUT");
        case PTL_MSG_GET:
                return ("GET");
        case PTL_MSG_REPLY:
                return ("REPLY");
        default:
                return ("<UNKNOWN>");
        }
}

static void
kqswnal_cerror_hdr(ptl_hdr_t * hdr)
{
        char *type_str = hdr_type_string (hdr);

        CERROR("P3 Header at %p of type %s length %d\n", hdr, type_str,
               le32_to_cpu(hdr->payload_length));
        CERROR("    From nid/pid "LPU64"/%u\n", le64_to_cpu(hdr->src_nid),
               le32_to_cpu(hdr->src_pid));
        CERROR("    To nid/pid "LPU64"/%u\n", le64_to_cpu(hdr->dest_nid),
               le32_to_cpu(hdr->dest_pid));

        switch (le32_to_cpu(hdr->type)) {
        case PTL_MSG_PUT:
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

        case PTL_MSG_GET:
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

        case PTL_MSG_ACK:
                CERROR("    dst md "LPX64"."LPX64", manipulated length %d\n",
                       hdr->msg.ack.dst_wmd.wh_interface_cookie,
                       hdr->msg.ack.dst_wmd.wh_object_cookie,
                       le32_to_cpu(hdr->msg.ack.mlength));
                break;

        case PTL_MSG_REPLY:
                CERROR("    dst md "LPX64"."LPX64"\n",
                       hdr->msg.reply.dst_wmd.wh_interface_cookie,
                       hdr->msg.reply.dst_wmd.wh_object_cookie);
        }

}                               /* end of print_hdr() */
#endif

#if !MULTIRAIL_EKC
void
kqswnal_print_eiov (int how, char *str, int n, EP_IOVEC *iov) 
{
        int          i;

        CDEBUG (how, "%s: %d\n", str, n);
        for (i = 0; i < n; i++) {
                CDEBUG (how, "   %08x for %d\n", iov[i].Base, iov[i].Len);
        }
}

int
kqswnal_eiovs2datav (int ndv, EP_DATAVEC *dv,
                     int nsrc, EP_IOVEC *src,
                     int ndst, EP_IOVEC *dst) 
{
        int        count;
        int        nob;

        LASSERT (ndv > 0);
        LASSERT (nsrc > 0);
        LASSERT (ndst > 0);

        for (count = 0; count < ndv; count++, dv++) {

                if (nsrc == 0 || ndst == 0) {
                        if (nsrc != ndst) {
                                /* For now I'll barf on any left over entries */
                                CERROR ("mismatched src and dst iovs\n");
                                return (-EINVAL);
                        }
                        return (count);
                }

                nob = (src->Len < dst->Len) ? src->Len : dst->Len;
                dv->Len    = nob;
                dv->Source = src->Base;
                dv->Dest   = dst->Base;

                if (nob >= src->Len) {
                        src++;
                        nsrc--;
                } else {
                        src->Len -= nob;
                        src->Base += nob;
                }
                
                if (nob >= dst->Len) {
                        dst++;
                        ndst--;
                } else {
                        src->Len -= nob;
                        src->Base += nob;
                }
        }

        CERROR ("DATAVEC too small\n");
        return (-E2BIG);
}
#else
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
#endif

kqswnal_remotemd_t *
kqswnal_parse_rmd (kqswnal_rx_t *krx, int type, ptl_nid_t expected_nid)
{
        char               *buffer = (char *)page_address(krx->krx_kiov[0].kiov_page);
        ptl_hdr_t          *hdr = (ptl_hdr_t *)buffer;
        kqswnal_remotemd_t *rmd = (kqswnal_remotemd_t *)(buffer + KQSW_HDR_SIZE);
        ptl_nid_t           nid = kqswnal_rx_nid(krx);

        /* Note (1) ptl_parse has already flipped hdr.
         *      (2) RDMA addresses are sent in native endian-ness.  When
         *      EKC copes with different endian nodes, I'll fix this (and
         *      eat my hat :) */

        LASSERT (krx->krx_nob >= sizeof(*hdr));

        if (hdr->type != type) {
                CERROR ("Unexpected optimized get/put type %d (%d expected)"
                        "from "LPX64"\n", hdr->type, type, nid);
                return (NULL);
        }
        
        if (hdr->src_nid != nid) {
                CERROR ("Unexpected optimized get/put source NID "
                        LPX64" from "LPX64"\n", hdr->src_nid, nid);
                return (NULL);
        }

        LASSERT (nid == expected_nid);

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

        LASSERT (ktx->ktx_state == KTX_RDMAING);
        LASSERT (krx->krx_rxd == rxd);
        LASSERT (krx->krx_rpc_reply_needed);

        krx->krx_rpc_reply_needed = 0;
        kqswnal_rx_decref (krx);

        /* free ktx & finalize() its ptl_msg_t */
        kqswnal_tx_done(ktx, (status == EP_SUCCESS) ? 0 : -ECONNABORTED);
}

void
kqswnal_rdma_fetch_complete (EP_RXD *rxd) 
{
        /* Completed fetching the PUT data */
        int           status = ep_rxd_status(rxd);
        kqswnal_tx_t *ktx = (kqswnal_tx_t *)ep_rxd_arg(rxd);
        kqswnal_rx_t *krx = (kqswnal_rx_t *)ktx->ktx_args[0];
        unsigned long flags;
        
        CDEBUG((status == EP_SUCCESS) ? D_NET : D_ERROR,
               "rxd %p, ktx %p, status %d\n", rxd, ktx, status);

        LASSERT (ktx->ktx_state == KTX_RDMAING);
        LASSERT (krx->krx_rxd == rxd);
        /* RPC completes with failure by default */
        LASSERT (krx->krx_rpc_reply_needed);
        LASSERT (krx->krx_rpc_reply_status != 0);

        if (status == EP_SUCCESS) {
                status = krx->krx_rpc_reply_status = 0;
        } else {
                /* Abandon RPC since get failed */
                krx->krx_rpc_reply_needed = 0;
                status = -ECONNABORTED;
        }

        /* free ktx & finalize() its ptl_msg_t */
        kqswnal_tx_done(ktx, status);

        if (!in_interrupt()) {
                /* OK to complete the RPC now (iff I had the last ref) */
                kqswnal_rx_decref (krx);
                return;
        }

        LASSERT (krx->krx_state == KRX_PARSE);
        krx->krx_state = KRX_COMPLETING;

        /* Complete the RPC in thread context */
        spin_lock_irqsave (&kqswnal_data.kqn_sched_lock, flags);

        list_add_tail (&krx->krx_list, &kqswnal_data.kqn_readyrxds);
        wake_up (&kqswnal_data.kqn_sched_waitq);

        spin_unlock_irqrestore (&kqswnal_data.kqn_sched_lock, flags);
}

int
kqswnal_rdma (kqswnal_rx_t *krx, ptl_msg_t *ptlmsg, int type,
              int niov, struct iovec *iov, ptl_kiov_t *kiov,
              size_t offset, size_t len)
{
        kqswnal_remotemd_t *rmd;
        kqswnal_tx_t       *ktx;
        int                 eprc;
        int                 rc;
#if !MULTIRAIL_EKC
        EP_DATAVEC          datav[EP_MAXFRAG];
        int                 ndatav;
#endif

        LASSERT (type == PTL_MSG_GET || type == PTL_MSG_PUT);
        /* Not both mapped and paged payload */
        LASSERT (iov == NULL || kiov == NULL);
        /* RPC completes with failure by default */
        LASSERT (krx->krx_rpc_reply_needed);
        LASSERT (krx->krx_rpc_reply_status != 0);

        rmd = kqswnal_parse_rmd(krx, type, ptlmsg->msg_ev.initiator.nid);
        if (rmd == NULL)
                return (-EPROTO);

        if (len == 0) {
                /* data got truncated to nothing. */
                ptl_finalize(kqswnal_data.kqn_ni, krx, ptlmsg, PTL_OK);
                /* Let kqswnal_rx_done() complete the RPC with success */
                krx->krx_rpc_reply_status = 0;
                return (0);
        }
        
        /* NB I'm using 'ktx' just to map the local RDMA buffers; I'm not
           actually sending a portals message with it */
        ktx = kqswnal_get_idle_tx(NULL, 0);
        if (ktx == NULL) {
                CERROR ("Can't get txd for RDMA with "LPX64"\n",
                        ptlmsg->msg_ev.initiator.nid);
                return (-ENOMEM);
        }

        ktx->ktx_state   = KTX_RDMAING;
        ktx->ktx_nid     = ptlmsg->msg_ev.initiator.nid;
        ktx->ktx_args[0] = krx;
        ktx->ktx_args[1] = ptlmsg;

#if MULTIRAIL_EKC
        /* Map on the rail the RPC prefers */
        ktx->ktx_rail = ep_rcvr_prefrail(krx->krx_eprx,
                                         ep_rxd_railmask(krx->krx_rxd));
#endif

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

#if MULTIRAIL_EKC
        rc = kqswnal_check_rdma (ktx->ktx_nfrag, ktx->ktx_frags,
                                 rmd->kqrmd_nfrag, rmd->kqrmd_frag);
        if (rc != 0) {
                CERROR ("Incompatible RDMA descriptors\n");
                goto out;
        }
#else
        switch (type) {
        default:
                LBUG();

        case PTL_MSG_GET:
                ndatav = kqswnal_eiovs2datav(EP_MAXFRAG, datav,
                                             ktx->ktx_nfrag, ktx->ktx_frags,
                                             rmd->kqrmd_nfrag, rmd->kqrmd_frag);
                break;

        case PTL_MSG_PUT:
                ndatav = kqswnal_eiovs2datav(EP_MAXFRAG, datav,
                                             rmd->kqrmd_nfrag, rmd->kqrmd_frag,
                                             ktx->ktx_nfrag, ktx->ktx_frags);
                break;
        }
                
        if (ndatav < 0) {
                CERROR ("Can't create datavec: %d\n", ndatav);
                rc = ndatav;
                goto out;
        }
#endif

        LASSERT (atomic_read(&krx->krx_refcount) > 0);
        /* Take an extra ref for the completion callback */
        atomic_inc(&krx->krx_refcount);

        switch (type) {
        default:
                LBUG();

        case PTL_MSG_GET:
#if MULTIRAIL_EKC
                eprc = ep_complete_rpc(krx->krx_rxd, 
                                       kqswnal_rdma_store_complete, ktx, 
                                       &kqswnal_data.kqn_rpc_success,
                                       ktx->ktx_frags, rmd->kqrmd_frag, rmd->kqrmd_nfrag);
#else
                eprc = ep_complete_rpc (krx->krx_rxd, 
                                        kqswnal_rdma_store_complete, ktx,
                                        &kqswnal_data.kqn_rpc_success, 
                                        datav, ndatav);
                if (eprc != EP_SUCCESS) /* "old" EKC destroys rxd on failed completion */
                        krx->krx_rxd = NULL;
#endif
                if (eprc != EP_SUCCESS) {
                        CERROR("can't complete RPC: %d\n", eprc);
                        /* don't re-attempt RPC completion */
                        krx->krx_rpc_reply_needed = 0;
                        rc = -ECONNABORTED;
                }
                break;
                
        case PTL_MSG_PUT:
#if MULTIRAIL_EKC
                eprc = ep_rpc_get (krx->krx_rxd, 
                                   kqswnal_rdma_fetch_complete, ktx,
                                   rmd->kqrmd_frag, ktx->ktx_frags, ktx->ktx_nfrag);
#else
                eprc = ep_rpc_get (krx->krx_rxd,
                                   kqswnal_rdma_fetch_complete, ktx,
                                   datav, ndatav);
#endif
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

        atomic_dec(&kqswnal_data.kqn_pending_txs);
        return (rc);
}

static ptl_err_t
kqswnal_sendmsg (ptl_ni_t     *ni,
                 void         *private,
                 ptl_msg_t    *ptlmsg,
                 ptl_hdr_t    *hdr,
                 int           type,
                 ptl_nid_t     nid,
                 ptl_pid_t     pid,
                 unsigned int  payload_niov,
                 struct iovec *payload_iov,
                 ptl_kiov_t   *payload_kiov,
                 size_t        payload_offset,
                 size_t        payload_nob)
{
        kqswnal_tx_t      *ktx;
        int                rc;
        ptl_nid_t          targetnid;
#if KQSW_CHECKSUM
        int                i;
        kqsw_csum_t        csum;
        int                sumoff;
        int                sumnob;
#endif
        /* NB 1. hdr is in network byte order */
        /*    2. 'private' depends on the message type */
        
        CDEBUG(D_NET, "sending "LPSZ" bytes in %d frags to nid: "LPX64
               " pid %u\n", payload_nob, payload_niov, nid, pid);

        LASSERT (payload_nob == 0 || payload_niov > 0);
        LASSERT (payload_niov <= PTL_MD_MAX_IOV);

        /* It must be OK to kmap() if required */
        LASSERT (payload_kiov == NULL || !in_interrupt ());
        /* payload is either all vaddrs or all pages */
        LASSERT (!(payload_kiov != NULL && payload_iov != NULL));

        if (payload_nob > KQSW_MAXPAYLOAD) {
                CERROR ("request exceeds MTU size "LPSZ" (max %u).\n",
                        payload_nob, KQSW_MAXPAYLOAD);
                return (PTL_FAIL);
        }

        if (type == PTL_MSG_REPLY &&            /* can I look in 'private' */
            ((kqswnal_rx_t *)private)->krx_rpc_reply_needed) { /* is it an RPC */
                /* Must be a REPLY for an optimized GET */
                rc = kqswnal_rdma ((kqswnal_rx_t *)private, ptlmsg, PTL_MSG_GET,
                                   payload_niov, payload_iov, payload_kiov, 
                                   payload_offset, payload_nob);
                return ((rc == 0) ? PTL_OK : PTL_FAIL);
        }

        targetnid = nid;
        if (kqswnal_nid2elanid (nid) < 0) {     /* Can't send direct: find gateway? */
                rc = kpr_lookup (&kqswnal_data.kqn_router, nid, 
                                 sizeof (ptl_hdr_t) + payload_nob, &targetnid);
                if (rc != 0) {
                        CERROR("Can't route to "LPX64": router error %d\n",
                               nid, rc);
                        return (PTL_FAIL);
                }
                if (kqswnal_nid2elanid (targetnid) < 0) {
                        CERROR("Bad gateway "LPX64" for "LPX64"\n",
                               targetnid, nid);
                        return (PTL_FAIL);
                }
        }

        /* I may not block for a transmit descriptor if I might block the
         * receiver, or an interrupt handler. */
        ktx = kqswnal_get_idle_tx(NULL, !(type == PTL_MSG_ACK ||
                                          type == PTL_MSG_REPLY ||
                                          in_interrupt()));
        if (ktx == NULL) {
                CERROR ("Can't get txd for msg type %d for "LPX64"\n",
                        type, ptlmsg->msg_ev.initiator.nid);
                return (PTL_NO_SPACE);
        }

        ktx->ktx_state   = KTX_SENDING;
        ktx->ktx_nid     = targetnid;
        ktx->ktx_args[0] = private;
        ktx->ktx_args[1] = ptlmsg;
        ktx->ktx_args[2] = NULL;    /* set when a GET commits to REPLY */

        memcpy (ktx->ktx_buffer, hdr, sizeof (*hdr)); /* copy hdr from caller's stack */

#if KQSW_CHECKSUM
        csum = kqsw_csum (0, (char *)hdr, sizeof (*hdr));
        memcpy (ktx->ktx_buffer + sizeof (*hdr), &csum, sizeof (csum));
        for (csum = 0, i = 0, sumoff = payload_offset, sumnob = payload_nob; sumnob > 0; i++) {
                LASSERT(i < niov);
                if (payload_kiov != NULL) {
                        ptl_kiov_t *kiov = &payload_kiov[i];

                        if (sumoff >= kiov->kiov_len) {
                                sumoff -= kiov->kiov_len;
                        } else {
                                char *addr = ((char *)kmap (kiov->kiov_page)) +
                                             kiov->kiov_offset + sumoff;
                                int   fragnob = kiov->kiov_len - sumoff;

                                csum = kqsw_csum(csum, addr, MIN(sumnob, fragnob));
                                sumnob -= fragnob;
                                sumoff = 0;
                                kunmap(kiov->kiov_page);
                        }
                } else {
                        struct iovec *iov = &payload_iov[i];

                        if (sumoff > iov->iov_len) {
                                sumoff -= iov->iov_len;
                        } else {
                                char *addr = iov->iov_base + sumoff;
                                int   fragnob = iov->iov_len - sumoff;
                                
                                csum = kqsw_csum(csum, addr, MIN(sumnob, fragnob));
                                sumnob -= fragnob;
                                sumoff = 0;
                        }
                }
        }
        memcpy(ktx->ktx_buffer + sizeof(*hdr) + sizeof(csum), &csum, sizeof(csum));
#endif

        /* The first frag will be the pre-mapped buffer for (at least) the
         * portals header. */
        ktx->ktx_nfrag = ktx->ktx_firsttmpfrag = 1;

        if (nid == targetnid &&                 /* not forwarding */
            ((type == PTL_MSG_GET &&            /* optimize GET? */
              kqswnal_tunables.kqn_optimized_gets != 0 &&
              le32_to_cpu(hdr->msg.get.sink_length) >= kqswnal_tunables.kqn_optimized_gets) ||
             (type == PTL_MSG_PUT &&            /* optimize PUT? */
              kqswnal_tunables.kqn_optimized_puts != 0 &&
              payload_nob >= kqswnal_tunables.kqn_optimized_puts))) {
                ptl_libmd_t        *md = ptlmsg->msg_md;
                kqswnal_remotemd_t *rmd = (kqswnal_remotemd_t *)(ktx->ktx_buffer + KQSW_HDR_SIZE);
                
                /* Optimised path: I send over the Elan vaddrs of the local
                 * buffers, and my peer DMAs directly to/from them.
                 *
                 * First I set up ktx as if it was going to send this
                 * payload, (it needs to map it anyway).  This fills
                 * ktx_frags[1] and onward with the network addresses
                 * of the GET sink frags.  I copy these into ktx_buffer,
                 * immediately after the header, and send that as my
                 * message. */

                ktx->ktx_state = (type == PTL_MSG_PUT) ? KTX_PUTTING : KTX_GETTING;

                if ((ptlmsg->msg_md->md_options & PTL_MD_KIOV) != 0) 
                        rc = kqswnal_map_tx_kiov (ktx, 0, md->md_length,
                                                  md->md_niov, md->md_iov.kiov);
                else
                        rc = kqswnal_map_tx_iov (ktx, 0, md->md_length,
                                                 md->md_niov, md->md_iov.iov);
                if (rc != 0)
                        goto out;

                rmd->kqrmd_nfrag = ktx->ktx_nfrag - 1;

                payload_nob = offsetof(kqswnal_remotemd_t,
                                       kqrmd_frag[rmd->kqrmd_nfrag]);
                LASSERT (KQSW_HDR_SIZE + payload_nob <= KQSW_TX_BUFFER_SIZE);

#if MULTIRAIL_EKC
                memcpy(&rmd->kqrmd_frag[0], &ktx->ktx_frags[1],
                       rmd->kqrmd_nfrag * sizeof(EP_NMD));

                ep_nmd_subset(&ktx->ktx_frags[0], &ktx->ktx_ebuffer,
                              0, KQSW_HDR_SIZE + payload_nob);
#else
                memcpy(&rmd->kqrmd_frag[0], &ktx->ktx_frags[1],
                       rmd->kqrmd_nfrag * sizeof(EP_IOVEC));
                
                ktx->ktx_frags[0].Base = ktx->ktx_ebuffer;
                ktx->ktx_frags[0].Len = KQSW_HDR_SIZE + payload_nob;
#endif
                if (type == PTL_MSG_GET) {
                        /* Allocate reply message now while I'm in thread context */
                        ktx->ktx_args[2] = ptl_create_reply_msg (
                                kqswnal_data.kqn_ni, nid, ptlmsg);
                        if (ktx->ktx_args[2] == NULL)
                                goto out;

                        /* NB finalizing the REPLY message is my
                         * responsibility now, whatever happens. */
                }
                
        } else if (payload_nob <= KQSW_TX_MAXCONTIG) {

                /* small message: single frag copied into the pre-mapped buffer */

#if MULTIRAIL_EKC
                ep_nmd_subset(&ktx->ktx_frags[0], &ktx->ktx_ebuffer,
                              0, KQSW_HDR_SIZE + payload_nob);
#else
                ktx->ktx_frags[0].Base = ktx->ktx_ebuffer;
                ktx->ktx_frags[0].Len = KQSW_HDR_SIZE + payload_nob;
#endif
                if (payload_nob > 0) {
                        if (payload_kiov != NULL)
                                ptl_copy_kiov2buf (ktx->ktx_buffer + KQSW_HDR_SIZE,
                                                   payload_niov, payload_kiov, 
                                                   payload_offset, payload_nob);
                        else
                                ptl_copy_iov2buf (ktx->ktx_buffer + KQSW_HDR_SIZE,
                                                  payload_niov, payload_iov, 
                                                  payload_offset, payload_nob);
                }
        } else {

                /* large message: multiple frags: first is hdr in pre-mapped buffer */

#if MULTIRAIL_EKC
                ep_nmd_subset(&ktx->ktx_frags[0], &ktx->ktx_ebuffer,
                              0, KQSW_HDR_SIZE);
#else
                ktx->ktx_frags[0].Base = ktx->ktx_ebuffer;
                ktx->ktx_frags[0].Len = KQSW_HDR_SIZE;
#endif
                if (payload_kiov != NULL)
                        rc = kqswnal_map_tx_kiov (ktx, payload_offset, payload_nob, 
                                                  payload_niov, payload_kiov);
                else
                        rc = kqswnal_map_tx_iov (ktx, payload_offset, payload_nob,
                                                 payload_niov, payload_iov);
                if (rc != 0)
                        goto out;
        }
        
        ktx->ktx_port = (payload_nob <= KQSW_SMALLPAYLOAD) ?
                        EP_MSG_SVC_PORTALS_SMALL : EP_MSG_SVC_PORTALS_LARGE;

        rc = kqswnal_launch (ktx);

 out:
        CDEBUG(rc == 0 ? D_NET : D_ERROR, 
               "%s "LPSZ" bytes to "LPX64" via "LPX64": rc %d\n", 
               rc == 0 ? "Sent" : "Failed to send",
               payload_nob, nid, targetnid, rc);

        if (rc != 0) {
                if (ktx->ktx_state == KTX_GETTING &&
                    ktx->ktx_args[2] != NULL) {
                        /* We committed to reply, but there was a problem
                         * launching the GET.  We can't avoid delivering a
                         * REPLY event since we committed above, so we
                         * pretend the GET succeeded but the REPLY
                         * failed. */
                        rc = 0;
                        ptl_finalize (kqswnal_data.kqn_ni, private, ptlmsg, PTL_OK);
                        ptl_finalize (kqswnal_data.kqn_ni, private,
                                      (ptl_msg_t *)ktx->ktx_args[2], PTL_FAIL);
                }
                
                kqswnal_put_idle_tx (ktx);
        }
        
        atomic_dec(&kqswnal_data.kqn_pending_txs);
        return (rc == 0 ? PTL_OK : PTL_FAIL);
}

ptl_err_t
kqswnal_send (ptl_ni_t     *ni,
              void         *private,
              ptl_msg_t    *ptlmsg,
              ptl_hdr_t    *hdr,
              int           type,
              ptl_nid_t     nid,
              ptl_pid_t     pid,
              unsigned int  payload_niov,
              struct iovec *payload_iov,
              size_t        payload_offset,
              size_t        payload_nob)
{
        return (kqswnal_sendmsg (ni, private, ptlmsg, hdr, type, nid, pid,
                                 payload_niov, payload_iov, NULL, 
                                 payload_offset, payload_nob));
}

ptl_err_t
kqswnal_send_pages (ptl_ni_t     *ni,
                    void         *private,
                    ptl_msg_t    *ptlmsg,
                    ptl_hdr_t    *hdr,
                    int           type,
                    ptl_nid_t     nid,
                    ptl_pid_t     pid,
                    unsigned int  payload_niov,
                    ptl_kiov_t   *payload_kiov,
                    size_t        payload_offset,
                    size_t        payload_nob)
{
        return (kqswnal_sendmsg (ni, private, ptlmsg, hdr, type, nid, pid,
                                 payload_niov, NULL, payload_kiov, 
                                 payload_offset, payload_nob));
}

void
kqswnal_fwd_packet (void *arg, kpr_fwd_desc_t *fwd)
{
        int             rc;
        kqswnal_tx_t   *ktx;
        ptl_kiov_t     *kiov = fwd->kprfd_kiov;
        int             niov = fwd->kprfd_niov;
        int             nob = fwd->kprfd_nob;
        ptl_nid_t       nid = fwd->kprfd_gateway_nid;

#if KQSW_CHECKSUM
        CERROR ("checksums for forwarded packets not implemented\n");
        LBUG ();
#endif
        /* The router wants this NAL to forward a packet */
        CDEBUG (D_NET, "forwarding [%p] to "LPX64", payload: %d frags %d bytes\n",
                fwd, nid, niov, nob);

        ktx = kqswnal_get_idle_tx (fwd, 0);
        if (ktx == NULL)        /* can't get txd right now */
                return;         /* fwd will be scheduled when tx desc freed */

        if (nid == kqswnal_data.kqn_ni->ni_nid) /* gateway is me */
                nid = fwd->kprfd_target_nid;    /* target is final dest */

        if (kqswnal_nid2elanid (nid) < 0) {
                CERROR("Can't forward [%p] to "LPX64": not a peer\n", fwd, nid);
                rc = -EHOSTUNREACH;
                goto out;
        }

        /* copy hdr into pre-mapped buffer */
        memcpy(ktx->ktx_buffer, fwd->kprfd_hdr, sizeof(ptl_hdr_t));

        ktx->ktx_port    = (nob <= KQSW_SMALLPAYLOAD) ?
                           EP_MSG_SVC_PORTALS_SMALL : EP_MSG_SVC_PORTALS_LARGE;
        ktx->ktx_nid     = nid;
        ktx->ktx_state   = KTX_FORWARDING;
        ktx->ktx_args[0] = fwd;
        ktx->ktx_nfrag   = ktx->ktx_firsttmpfrag = 1;

        if (nob <= KQSW_TX_MAXCONTIG) 
        {
                /* send payload from ktx's pre-mapped contiguous buffer */
#if MULTIRAIL_EKC
                ep_nmd_subset(&ktx->ktx_frags[0], &ktx->ktx_ebuffer,
                              0, KQSW_HDR_SIZE + nob);
#else
                ktx->ktx_frags[0].Base = ktx->ktx_ebuffer;
                ktx->ktx_frags[0].Len = KQSW_HDR_SIZE + nob;
#endif
                if (nob > 0)
                        ptl_copy_kiov2buf(ktx->ktx_buffer + KQSW_HDR_SIZE,
                                          niov, kiov, 0, nob);
        }
        else
        {
                /* zero copy payload */
#if MULTIRAIL_EKC
                ep_nmd_subset(&ktx->ktx_frags[0], &ktx->ktx_ebuffer,
                              0, KQSW_HDR_SIZE);
#else
                ktx->ktx_frags[0].Base = ktx->ktx_ebuffer;
                ktx->ktx_frags[0].Len = KQSW_HDR_SIZE;
#endif
                rc = kqswnal_map_tx_kiov (ktx, 0, nob, niov, kiov);
                if (rc != 0)
                        goto out;
        }

        rc = kqswnal_launch (ktx);
 out:
        if (rc != 0) {
                CERROR ("Failed to forward [%p] to "LPX64": %d\n", fwd, nid, rc);

                /* complete now (with failure) */
                kqswnal_tx_done (ktx, rc);
        }

        atomic_dec(&kqswnal_data.kqn_pending_txs);
}

void
kqswnal_fwd_callback (void *arg, int error)
{
        kqswnal_rx_t *krx = (kqswnal_rx_t *)arg;

        /* The router has finished forwarding this packet */

        if (error != 0)
        {
                ptl_hdr_t *hdr = (ptl_hdr_t *)page_address (krx->krx_kiov[0].kiov_page);

                CERROR("Failed to route packet from "LPX64" to "LPX64": %d\n",
                       le64_to_cpu(hdr->src_nid), le64_to_cpu(hdr->dest_nid),error);
        }

        LASSERT (atomic_read(&krx->krx_refcount) == 1);
        kqswnal_rx_decref (krx);
}

void
kqswnal_requeue_rx (kqswnal_rx_t *krx)
{
        LASSERT (atomic_read(&krx->krx_refcount) == 0);
        LASSERT (!krx->krx_rpc_reply_needed);

        krx->krx_state = KRX_POSTED;

#if MULTIRAIL_EKC
        if (kqswnal_data.kqn_shuttingdown) {
                /* free EKC rxd on shutdown */
                ep_complete_receive(krx->krx_rxd);
        } else {
                /* repost receive */
                ep_requeue_receive(krx->krx_rxd, 
                                   kqswnal_rxhandler, krx,
                                   &krx->krx_elanbuffer, 0);
        }
#else                
        if (kqswnal_data.kqn_shuttingdown)
                return;

        if (krx->krx_rxd == NULL) {
                /* We had a failed ep_complete_rpc() which nukes the
                 * descriptor in "old" EKC */
                int eprc = ep_queue_receive(krx->krx_eprx, 
                                            kqswnal_rxhandler, krx,
                                            krx->krx_elanbuffer, 
                                            krx->krx_npages * PAGE_SIZE, 0);
                LASSERT (eprc == EP_SUCCESS);
                /* We don't handle failure here; it's incredibly rare
                 * (never reported?) and only happens with "old" EKC */
        } else {
                ep_requeue_receive(krx->krx_rxd, kqswnal_rxhandler, krx,
                                   krx->krx_elanbuffer, 
                                   krx->krx_npages * PAGE_SIZE);
        }
#endif
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
        EP_STATUSBLK *sblk;

        LASSERT (atomic_read(&krx->krx_refcount) == 0);

        if (krx->krx_rpc_reply_needed) {
                /* We've not completed the peer's RPC yet... */
                sblk = (krx->krx_rpc_reply_status == 0) ? 
                       &kqswnal_data.kqn_rpc_success : 
                       &kqswnal_data.kqn_rpc_failed;

                LASSERT (!in_interrupt());
#if MULTIRAIL_EKC
                rc = ep_complete_rpc(krx->krx_rxd, 
                                     kqswnal_rpc_complete, krx,
                                     sblk, NULL, NULL, 0);
                if (rc == EP_SUCCESS)
                        return;
#else
                rc = ep_complete_rpc(krx->krx_rxd, 
                                     kqswnal_rpc_complete, krx,
                                     sblk, NULL, 0);
                if (rc == EP_SUCCESS)
                        return;

                /* "old" EKC destroys rxd on failed completion */
                krx->krx_rxd = NULL;
#endif
                CERROR("can't complete RPC: %d\n", rc);
                krx->krx_rpc_reply_needed = 0;
        }

        kqswnal_requeue_rx(krx);
}
        
void
kqswnal_parse (kqswnal_rx_t *krx)
{
        ptl_hdr_t      *hdr = (ptl_hdr_t *) page_address(krx->krx_kiov[0].kiov_page);
        ptl_nid_t       dest_nid = le64_to_cpu(hdr->dest_nid);
        int             payload_nob;
        int             nob;
        int             niov;

        LASSERT (atomic_read(&krx->krx_refcount) == 1);

        if (dest_nid == kqswnal_data.kqn_ni->ni_nid) { /* It's for me :) */
                /* I ignore parse errors since I'm not consuming a byte
                 * stream */
                (void)ptl_parse (kqswnal_data.kqn_ni, hdr, krx);

                /* Drop my ref; any RDMA activity takes an additional ref */
                kqswnal_rx_decref(krx);
                return;
        }

#if KQSW_CHECKSUM
        LASSERTF (0, "checksums for forwarded packets not implemented\n");
#endif

        if (kqswnal_nid2elanid (dest_nid) >= 0)  /* should have gone direct to peer */
        {
                CERROR("dropping packet from "LPX64" for "LPX64
                       ": target is peer\n", le64_to_cpu(hdr->src_nid), dest_nid);

                kqswnal_rx_decref (krx);
                return;
        }

        nob = payload_nob = krx->krx_nob - KQSW_HDR_SIZE;
        niov = 0;
        if (nob > 0) {
                krx->krx_kiov[0].kiov_offset = KQSW_HDR_SIZE;
                krx->krx_kiov[0].kiov_len = MIN(PAGE_SIZE - KQSW_HDR_SIZE, nob);
                niov = 1;
                nob -= PAGE_SIZE - KQSW_HDR_SIZE;
                
                while (nob > 0) {
                        LASSERT (niov < krx->krx_npages);
                        
                        krx->krx_kiov[niov].kiov_offset = 0;
                        krx->krx_kiov[niov].kiov_len = MIN(PAGE_SIZE, nob);
                        niov++;
                        nob -= PAGE_SIZE;
                }
        }

        kpr_fwd_init (&krx->krx_fwd, dest_nid, 
                      hdr, payload_nob, niov, krx->krx_kiov,
                      kqswnal_fwd_callback, krx);

        kpr_fwd_start (&kqswnal_data.kqn_router, &krx->krx_fwd);
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
        krx->krx_rpc_reply_status = -EPROTO;
        atomic_set (&krx->krx_refcount, 1);

        /* must receive a whole header to be able to parse */
        if (status != EP_SUCCESS || nob < sizeof (ptl_hdr_t))
        {
                /* receives complete with failure when receiver is removed */
#if MULTIRAIL_EKC
                if (status == EP_SHUTDOWN)
                        LASSERT (kqswnal_data.kqn_shuttingdown);
                else
                        CERROR("receive status failed with status %d nob %d\n",
                               ep_rxd_status(rxd), nob);
#else
                if (!kqswnal_data.kqn_shuttingdown)
                        CERROR("receive status failed with status %d nob %d\n",
                               ep_rxd_status(rxd), nob);
#endif
                kqswnal_rx_decref(krx);
                return;
        }

        if (!in_interrupt()) {
                kqswnal_parse(krx);
                return;
        }

        spin_lock_irqsave (&kqswnal_data.kqn_sched_lock, flags);

        list_add_tail (&krx->krx_list, &kqswnal_data.kqn_readyrxds);
        wake_up (&kqswnal_data.kqn_sched_waitq);

        spin_unlock_irqrestore (&kqswnal_data.kqn_sched_lock, flags);
}

#if KQSW_CHECKSUM
void
kqswnal_csum_error (kqswnal_rx_t *krx, int ishdr)
{
        ptl_hdr_t *hdr = (ptl_hdr_t *)page_address (krx->krx_kiov[0].kiov_page);

        CERROR ("%s checksum mismatch %p: dnid "LPX64", snid "LPX64
                ", dpid %d, spid %d, type %d\n",
                ishdr ? "Header" : "Payload", krx,
                le64_to_cpu(hdr->dest_nid), le64_to_cpu(hdr->src_nid)
                le32_to_cpu(hdr->dest_pid), le32_to_cpu(hdr->src_pid),
                le32_to_cpu(hdr->type));

        switch (le32_to_cpu(hdr->type))
        {
        case PTL_MSG_ACK:
                CERROR("ACK: mlen %d dmd "LPX64"."LPX64" match "LPX64
                       " len %u\n",
                       le32_to_cpu(hdr->msg.ack.mlength),
                       hdr->msg.ack.dst_wmd.handle_cookie,
                       hdr->msg.ack.dst_wmd.handle_idx,
                       le64_to_cpu(hdr->msg.ack.match_bits),
                       le32_to_cpu(hdr->msg.ack.length));
                break;
        case PTL_MSG_PUT:
                CERROR("PUT: ptl %d amd "LPX64"."LPX64" match "LPX64
                       " len %u off %u data "LPX64"\n",
                       le32_to_cpu(hdr->msg.put.ptl_index),
                       hdr->msg.put.ack_wmd.handle_cookie,
                       hdr->msg.put.ack_wmd.handle_idx,
                       le64_to_cpu(hdr->msg.put.match_bits),
                       le32_to_cpu(hdr->msg.put.length),
                       le32_to_cpu(hdr->msg.put.offset),
                       hdr->msg.put.hdr_data);
                break;
        case PTL_MSG_GET:
                CERROR ("GET: <>\n");
                break;
        case PTL_MSG_REPLY:
                CERROR ("REPLY: <>\n");
                break;
        default:
                CERROR ("TYPE?: <>\n");
        }
}
#endif

static ptl_err_t
kqswnal_recvmsg (ptl_ni_t     *ni,
                 void         *private,
                 ptl_msg_t    *ptlmsg,
                 unsigned int  niov,
                 struct iovec *iov,
                 ptl_kiov_t   *kiov,
                 size_t        offset,
                 size_t        mlen,
                 size_t        rlen)
{
        kqswnal_rx_t *krx = (kqswnal_rx_t *)private;
        char         *buffer = page_address(krx->krx_kiov[0].kiov_page);
        ptl_hdr_t    *hdr = (ptl_hdr_t *)buffer;
        int           page;
        char         *page_ptr;
        int           page_nob;
        char         *iov_ptr;
        int           iov_nob;
        int           frag;
        int           rc;
#if KQSW_CHECKSUM
        kqsw_csum_t   senders_csum;
        kqsw_csum_t   payload_csum = 0;
        kqsw_csum_t   hdr_csum = kqsw_csum(0, hdr, sizeof(*hdr));
        size_t        csum_len = mlen;
        int           csum_frags = 0;
        int           csum_nob = 0;
        static atomic_t csum_counter;
        int           csum_verbose = (atomic_read(&csum_counter)%1000001) == 0;

        atomic_inc (&csum_counter);

        memcpy (&senders_csum, buffer + sizeof (ptl_hdr_t), sizeof (kqsw_csum_t));
        if (senders_csum != hdr_csum)
                kqswnal_csum_error (krx, 1);
#endif
        /* NB ptl_parse() has already flipped *hdr */

        CDEBUG(D_NET,"kqswnal_recv, mlen="LPSZ", rlen="LPSZ"\n", mlen, rlen);

        if (ptlmsg == NULL) {                   /* portals is discarding. */
                LASSERT (mlen == 0);
                return PTL_OK;                  /* ignored by caller! */
        }
        
        if (krx->krx_rpc_reply_needed &&
            hdr->type == PTL_MSG_PUT) {
                /* This must be an optimized PUT */
                rc = kqswnal_rdma (krx, ptlmsg, PTL_MSG_PUT,
                                   niov, iov, kiov, offset, mlen);
                return (rc == 0 ? PTL_OK : PTL_FAIL);
        }

        /* What was actually received must be >= payload. */
        LASSERT (mlen <= rlen);
        if (krx->krx_nob < KQSW_HDR_SIZE + mlen) {
                CERROR("Bad message size: have %d, need %d + %d\n",
                       krx->krx_nob, (int)KQSW_HDR_SIZE, (int)mlen);
                return (PTL_FAIL);
        }

        /* It must be OK to kmap() if required */
        LASSERT (kiov == NULL || !in_interrupt ());
        /* Either all pages or all vaddrs */
        LASSERT (!(kiov != NULL && iov != NULL));

        if (mlen != 0) {
                page     = 0;
                page_ptr = buffer + KQSW_HDR_SIZE;
                page_nob = PAGE_SIZE - KQSW_HDR_SIZE;

                LASSERT (niov > 0);

                if (kiov != NULL) {
                        /* skip complete frags */
                        while (offset >= kiov->kiov_len) {
                                offset -= kiov->kiov_len;
                                kiov++;
                                niov--;
                                LASSERT (niov > 0);
                        }
                        iov_ptr = ((char *)kmap (kiov->kiov_page)) +
                                kiov->kiov_offset + offset;
                        iov_nob = kiov->kiov_len - offset;
                } else {
                        /* skip complete frags */
                        while (offset >= iov->iov_len) {
                                offset -= iov->iov_len;
                                iov++;
                                niov--;
                                LASSERT (niov > 0);
                        }
                        iov_ptr = iov->iov_base + offset;
                        iov_nob = iov->iov_len - offset;
                }
                
                for (;;)
                {
                        frag = mlen;
                        if (frag > page_nob)
                                frag = page_nob;
                        if (frag > iov_nob)
                                frag = iov_nob;

                        memcpy (iov_ptr, page_ptr, frag);
#if KQSW_CHECKSUM
                        payload_csum = kqsw_csum (payload_csum, iov_ptr, frag);
                        csum_nob += frag;
                        csum_frags++;
#endif
                        mlen -= frag;
                        if (mlen == 0)
                                break;

                        page_nob -= frag;
                        if (page_nob != 0)
                                page_ptr += frag;
                        else
                        {
                                page++;
                                LASSERT (page < krx->krx_npages);
                                page_ptr = page_address(krx->krx_kiov[page].kiov_page);
                                page_nob = PAGE_SIZE;
                        }

                        iov_nob -= frag;
                        if (iov_nob != 0)
                                iov_ptr += frag;
                        else if (kiov != NULL) {
                                kunmap (kiov->kiov_page);
                                kiov++;
                                niov--;
                                LASSERT (niov > 0);
                                iov_ptr = ((char *)kmap (kiov->kiov_page)) + kiov->kiov_offset;
                                iov_nob = kiov->kiov_len;
                        } else {
                                iov++;
                                niov--;
                                LASSERT (niov > 0);
                                iov_ptr = iov->iov_base;
                                iov_nob = iov->iov_len;
                        }
                }

                if (kiov != NULL)
                        kunmap (kiov->kiov_page);
        }

#if KQSW_CHECKSUM
        memcpy (&senders_csum, buffer + sizeof(ptl_hdr_t) + sizeof(kqsw_csum_t), 
                sizeof(kqsw_csum_t));

        if (csum_len != rlen)
                CERROR("Unable to checksum data in user's buffer\n");
        else if (senders_csum != payload_csum)
                kqswnal_csum_error (krx, 0);

        if (csum_verbose)
                CERROR("hdr csum %lx, payload_csum %lx, csum_frags %d, "
                       "csum_nob %d\n",
                        hdr_csum, payload_csum, csum_frags, csum_nob);
#endif
        ptl_finalize(ni, private, ptlmsg, PTL_OK);

        return (PTL_OK);
}

ptl_err_t
kqswnal_recv(ptl_ni_t     *ni,
             void         *private,
             ptl_msg_t    *ptlmsg,
             unsigned int  niov,
             struct iovec *iov,
             size_t        offset,
             size_t        mlen,
             size_t        rlen)
{
        return (kqswnal_recvmsg(ni, private, ptlmsg, 
                                niov, iov, NULL, 
                                offset, mlen, rlen));
}

ptl_err_t
kqswnal_recv_pages (ptl_ni_t     *ni,
                    void         *private,
                    ptl_msg_t    *ptlmsg,
                    unsigned int  niov,
                    ptl_kiov_t   *kiov,
                    size_t        offset,
                    size_t        mlen,
                    size_t        rlen)
{
        return (kqswnal_recvmsg(ni, private, ptlmsg, 
                                niov, NULL, kiov, 
                                offset, mlen, rlen));
}

int
kqswnal_thread_start (int (*fn)(void *arg), void *arg)
{
        long    pid = kernel_thread (fn, arg, 0);

        if (pid < 0)
                return ((int)pid);

        atomic_inc (&kqswnal_data.kqn_nthreads);
        return (0);
}

void
kqswnal_thread_fini (void)
{
        atomic_dec (&kqswnal_data.kqn_nthreads);
}

int
kqswnal_scheduler (void *arg)
{
        kqswnal_rx_t    *krx;
        kqswnal_tx_t    *ktx;
        kpr_fwd_desc_t  *fwd;
        unsigned long    flags;
        int              rc;
        int              counter = 0;
        int              did_something;

        kportal_daemonize ("kqswnal_sched");
        kportal_blockallsigs ();
        
        spin_lock_irqsave (&kqswnal_data.kqn_sched_lock, flags);

        for (;;)
        {
                did_something = 0;

                if (!list_empty (&kqswnal_data.kqn_readyrxds))
                {
                        krx = list_entry(kqswnal_data.kqn_readyrxds.next,
                                         kqswnal_rx_t, krx_list);
                        list_del (&krx->krx_list);
                        spin_unlock_irqrestore(&kqswnal_data.kqn_sched_lock,
                                               flags);

                        switch (krx->krx_state) {
                        case KRX_PARSE:
                                kqswnal_parse (krx);
                                break;
                        case KRX_COMPLETING:
                                kqswnal_rx_decref (krx);
                                break;
                        default:
                                LBUG();
                        }

                        did_something = 1;
                        spin_lock_irqsave(&kqswnal_data.kqn_sched_lock, flags);
                }

                if (!list_empty (&kqswnal_data.kqn_delayedtxds))
                {
                        ktx = list_entry(kqswnal_data.kqn_delayedtxds.next,
                                         kqswnal_tx_t, ktx_delayed_list);
                        list_del_init (&ktx->ktx_delayed_list);
                        spin_unlock_irqrestore(&kqswnal_data.kqn_sched_lock,
                                               flags);

                        rc = kqswnal_launch (ktx);
                        if (rc != 0) {
                                CERROR("Failed delayed transmit to "LPX64
                                       ": %d\n", ktx->ktx_nid, rc);
                                kqswnal_tx_done (ktx, rc);
                        }
                        atomic_dec (&kqswnal_data.kqn_pending_txs);

                        did_something = 1;
                        spin_lock_irqsave (&kqswnal_data.kqn_sched_lock, flags);
                }

                if (!list_empty (&kqswnal_data.kqn_delayedfwds))
                {
                        fwd = list_entry (kqswnal_data.kqn_delayedfwds.next, kpr_fwd_desc_t, kprfd_list);
                        list_del (&fwd->kprfd_list);
                        spin_unlock_irqrestore (&kqswnal_data.kqn_sched_lock, flags);

                        /* If we're shutting down, this will just requeue fwd on kqn_idletxd_fwdq */
                        kqswnal_fwd_packet (NULL, fwd);

                        did_something = 1;
                        spin_lock_irqsave (&kqswnal_data.kqn_sched_lock, flags);
                }

                /* nothing to do or hogging CPU */
                if (!did_something || counter++ == KQSW_RESCHED) {
                        spin_unlock_irqrestore(&kqswnal_data.kqn_sched_lock,
                                               flags);

                        counter = 0;

                        if (!did_something) {
                                if (kqswnal_data.kqn_shuttingdown == 2) {
                                        /* We only exit in stage 2 of shutdown when 
                                         * there's nothing left to do */
                                        break;
                                }
                                rc = wait_event_interruptible (kqswnal_data.kqn_sched_waitq,
                                                               kqswnal_data.kqn_shuttingdown == 2 ||
                                                               !list_empty(&kqswnal_data.kqn_readyrxds) ||
                                                               !list_empty(&kqswnal_data.kqn_delayedtxds) ||
                                                               !list_empty(&kqswnal_data.kqn_delayedfwds));
                                LASSERT (rc == 0);
                        } else if (need_resched())
                                schedule ();

                        spin_lock_irqsave (&kqswnal_data.kqn_sched_lock, flags);
                }
        }

        kqswnal_thread_fini ();
        return (0);
}
