/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Eric Barton <eric@bartonsoftware.com>
 *
 * Copyright (C) 2002, Lawrence Livermore National Labs (LLNL)
 * W. Marcus Miller - Based on ksocknal
 *
 * This file is part of Portals, http://www.sf.net/projects/sandiaportals/
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

EP_STATUSBLK  kqswnal_rpc_success;
EP_STATUSBLK  kqswnal_rpc_failed;

/*
 *  LIB functions follow
 *
 */
static ptl_err_t
kqswnal_read(nal_cb_t *nal, void *private, void *dst_addr, user_ptr src_addr,
             size_t len)
{
        CDEBUG (D_NET, LPX64": reading "LPSZ" bytes from %p -> %p\n",
                nal->ni.nid, len, src_addr, dst_addr );
        memcpy( dst_addr, src_addr, len );

        return (PTL_OK);
}

static ptl_err_t
kqswnal_write(nal_cb_t *nal, void *private, user_ptr dst_addr, void *src_addr,
              size_t len)
{
        CDEBUG (D_NET, LPX64": writing "LPSZ" bytes from %p -> %p\n",
                nal->ni.nid, len, src_addr, dst_addr );
        memcpy( dst_addr, src_addr, len );

        return (PTL_OK);
}

static void *
kqswnal_malloc(nal_cb_t *nal, size_t len)
{
        void *buf;

        PORTAL_ALLOC(buf, len);
        return (buf);
}

static void
kqswnal_free(nal_cb_t *nal, void *buf, size_t len)
{
        PORTAL_FREE(buf, len);
}

static void
kqswnal_printf (nal_cb_t * nal, const char *fmt, ...)
{
        va_list ap;
        char msg[256];

        va_start (ap, fmt);
        vsnprintf (msg, sizeof (msg), fmt, ap);        /* sprint safely */
        va_end (ap);

        msg[sizeof (msg) - 1] = 0;                /* ensure terminated */

        CDEBUG (D_NET, "%s", msg);
}


static void
kqswnal_cli(nal_cb_t *nal, unsigned long *flags)
{
        kqswnal_data_t *data= nal->nal_data;

        spin_lock_irqsave(&data->kqn_statelock, *flags);
}


static void
kqswnal_sti(nal_cb_t *nal, unsigned long *flags)
{
        kqswnal_data_t *data= nal->nal_data;

        spin_unlock_irqrestore(&data->kqn_statelock, *flags);
}


static int
kqswnal_dist(nal_cb_t *nal, ptl_nid_t nid, unsigned long *dist)
{
        if (nid == nal->ni.nid)
                *dist = 0;                      /* it's me */
        else if (kqswnal_nid2elanid (nid) >= 0)
                *dist = 1;                      /* it's my peer */
        else
                *dist = 2;                      /* via router */
        return (0);
}

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
        int         rail = ep_xmtr_prefrail(kqswnal_data.kqn_eptx,
                                            EP_RAILMASK_ALL,
                                            kqswnal_nid2elanid(ktx->ktx_nid));
        
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

                /* nob exactly spans the iovs */
                LASSERT (fraglen <= nob);
                /* each frag fits in a page */
                LASSERT (kiov->kiov_offset + kiov->kiov_len <= PAGE_SIZE);

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
        int         rail = ep_xmtr_prefrail(kqswnal_data.kqn_eptx,
                                            EP_RAILMASK_ALL,
                                            kqswnal_nid2elanid(ktx->ktx_nid));
        
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
                long npages  = kqswnal_pages_spanned (iov->iov_base, fraglen);

                /* nob exactly spans the iovs */
                LASSERT (fraglen <= nob);
                
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
        if (!list_empty(&kqswnal_data.kqn_idletxd_fwdq)) /* forwarded packet? */
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

                /* "normal" descriptor is free */
                if (!list_empty (&kqswnal_data.kqn_idletxds)) {
                        ktx = list_entry (kqswnal_data.kqn_idletxds.next,
                                          kqswnal_tx_t, ktx_list);
                        break;
                }

                /* "normal" descriptor pool is empty */

                if (fwd != NULL) { /* forwarded packet => queue for idle txd */
                        CDEBUG (D_NET, "blocked fwd [%p]\n", fwd);
                        list_add_tail (&fwd->kprfd_list,
                                       &kqswnal_data.kqn_idletxd_fwdq);
                        break;
                }

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
                            !list_empty (&kqswnal_data.kqn_idletxds));
        }

        if (ktx != NULL) {
                list_del (&ktx->ktx_list);
                list_add (&ktx->ktx_list, &kqswnal_data.kqn_activetxds);
                ktx->ktx_launcher = current->pid;
        }

        spin_unlock_irqrestore (&kqswnal_data.kqn_idletxd_lock, flags);

        /* Idle descs can't have any mapped (as opposed to pre-mapped) pages */
        LASSERT (ktx == NULL || ktx->ktx_nmappedpages == 0);

        return (ktx);
}

void
kqswnal_tx_done (kqswnal_tx_t *ktx, int error)
{
        lib_msg_t     *msg;
        lib_msg_t     *repmsg = NULL;

        switch (ktx->ktx_state) {
        case KTX_FORWARDING:       /* router asked me to forward this packet */
                kpr_fwd_done (&kqswnal_data.kqn_router,
                              (kpr_fwd_desc_t *)ktx->ktx_args[0], error);
                break;

        case KTX_SENDING:          /* packet sourced locally */
                lib_finalize (&kqswnal_lib, ktx->ktx_args[0],
                              (lib_msg_t *)ktx->ktx_args[1],
                              (error == 0) ? PTL_OK : 
                              (error == -ENOMEM) ? PTL_NOSPACE : PTL_FAIL);
                break;

        case KTX_GETTING:          /* Peer has DMA-ed direct? */
                msg = (lib_msg_t *)ktx->ktx_args[1];

                if (error == 0) {
                        repmsg = lib_fake_reply_msg (&kqswnal_lib, 
                                                     ktx->ktx_nid, msg->md);
                        if (repmsg == NULL)
                                error = -ENOMEM;
                }
                
                if (error == 0) {
                        lib_finalize (&kqswnal_lib, ktx->ktx_args[0], 
                                      msg, PTL_OK);
                        lib_finalize (&kqswnal_lib, NULL, repmsg, PTL_OK);
                } else {
                        lib_finalize (&kqswnal_lib, ktx->ktx_args[0], msg,
                                      (error == -ENOMEM) ? PTL_NOSPACE : PTL_FAIL);
                }
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

        } else if (ktx->ktx_state == KTX_GETTING) {
                /* RPC completed OK; what did our peer put in the status
                 * block? */
#if MULTIRAIL_EKC
                status = ep_txd_statusblk(txd)->Data[0];
#else
                status = ep_txd_statusblk(txd)->Status;
#endif
        } else {
                status = 0;
        }

        kqswnal_tx_done (ktx, status);
}

int
kqswnal_launch (kqswnal_tx_t *ktx)
{
        /* Don't block for transmit descriptor if we're in interrupt context */
        int   attr = in_interrupt() ? (EP_NO_SLEEP | EP_NO_ALLOC) : 0;
        int   dest = kqswnal_nid2elanid (ktx->ktx_nid);
        long  flags;
        int   rc;

        ktx->ktx_launchtime = jiffies;

        LASSERT (dest >= 0);                    /* must be a peer */
        if (ktx->ktx_state == KTX_GETTING) {
                /* NB ktx_frag[0] is the GET hdr + kqswnal_remotemd_t.  The
                 * other frags are the GET sink which we obviously don't
                 * send here :) */
#if MULTIRAIL_EKC
                rc = ep_transmit_rpc(kqswnal_data.kqn_eptx, dest,
                                     ktx->ktx_port, attr,
                                     kqswnal_txhandler, ktx,
                                     NULL, ktx->ktx_frags, 1);
#else
                rc = ep_transmit_rpc(kqswnal_data.kqn_eptx, dest,
                                     ktx->ktx_port, attr, kqswnal_txhandler,
                                     ktx, NULL, ktx->ktx_frags, 1);
#endif
        } else {
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
        }

        switch (rc) {
        case EP_SUCCESS: /* success */
                return (0);

        case EP_ENOMEM: /* can't allocate ep txd => queue for later */
                LASSERT (in_interrupt());

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
               NTOH__u32(hdr->payload_length));
        CERROR("    From nid/pid "LPU64"/%u\n", NTOH__u64(hdr->src_nid),
               NTOH__u32(hdr->src_pid));
        CERROR("    To nid/pid "LPU64"/%u\n", NTOH__u64(hdr->dest_nid),
               NTOH__u32(hdr->dest_pid));

        switch (NTOH__u32(hdr->type)) {
        case PTL_MSG_PUT:
                CERROR("    Ptl index %d, ack md "LPX64"."LPX64", "
                       "match bits "LPX64"\n",
                       NTOH__u32 (hdr->msg.put.ptl_index),
                       hdr->msg.put.ack_wmd.wh_interface_cookie,
                       hdr->msg.put.ack_wmd.wh_object_cookie,
                       NTOH__u64 (hdr->msg.put.match_bits));
                CERROR("    offset %d, hdr data "LPX64"\n",
                       NTOH__u32(hdr->msg.put.offset),
                       hdr->msg.put.hdr_data);
                break;

        case PTL_MSG_GET:
                CERROR("    Ptl index %d, return md "LPX64"."LPX64", "
                       "match bits "LPX64"\n",
                       NTOH__u32 (hdr->msg.get.ptl_index),
                       hdr->msg.get.return_wmd.wh_interface_cookie,
                       hdr->msg.get.return_wmd.wh_object_cookie,
                       hdr->msg.get.match_bits);
                CERROR("    Length %d, src offset %d\n",
                       NTOH__u32 (hdr->msg.get.sink_length),
                       NTOH__u32 (hdr->msg.get.src_offset));
                break;

        case PTL_MSG_ACK:
                CERROR("    dst md "LPX64"."LPX64", manipulated length %d\n",
                       hdr->msg.ack.dst_wmd.wh_interface_cookie,
                       hdr->msg.ack.dst_wmd.wh_object_cookie,
                       NTOH__u32 (hdr->msg.ack.mlength));
                break;

        case PTL_MSG_REPLY:
                CERROR("    dst md "LPX64"."LPX64"\n",
                       hdr->msg.reply.dst_wmd.wh_interface_cookie,
                       hdr->msg.reply.dst_wmd.wh_object_cookie);
        }

}                               /* end of print_hdr() */

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
#endif

int
kqswnal_dma_reply (kqswnal_tx_t *ktx, int nfrag, 
                   struct iovec *iov, ptl_kiov_t *kiov, 
                   int offset, int nob)
{
        kqswnal_rx_t       *krx = (kqswnal_rx_t *)ktx->ktx_args[0];
        char               *buffer = (char *)page_address(krx->krx_kiov[0].kiov_page);
        kqswnal_remotemd_t *rmd = (kqswnal_remotemd_t *)(buffer + KQSW_HDR_SIZE);
        int                 rc;
#if MULTIRAIL_EKC
        int                 i;
#else
        EP_DATAVEC          datav[EP_MAXFRAG];
        int                 ndatav;
#endif
        LASSERT (krx->krx_rpc_reply_needed);
        LASSERT ((iov == NULL) != (kiov == NULL));

        /* see kqswnal_sendmsg comment regarding endian-ness */
        if (buffer + krx->krx_nob < (char *)(rmd + 1)) {
                /* msg too small to discover rmd size */
                CERROR ("Incoming message [%d] too small for RMD (%d needed)\n",
                        krx->krx_nob, (int)(((char *)(rmd + 1)) - buffer));
                return (-EINVAL);
        }
        
        if (buffer + krx->krx_nob < (char *)&rmd->kqrmd_frag[rmd->kqrmd_nfrag]) {
                /* rmd doesn't fit in the incoming message */
                CERROR ("Incoming message [%d] too small for RMD[%d] (%d needed)\n",
                        krx->krx_nob, rmd->kqrmd_nfrag,
                        (int)(((char *)&rmd->kqrmd_frag[rmd->kqrmd_nfrag]) - buffer));
                return (-EINVAL);
        }

        /* Map the source data... */
        ktx->ktx_nfrag = ktx->ktx_firsttmpfrag = 0;
        if (kiov != NULL)
                rc = kqswnal_map_tx_kiov (ktx, offset, nob, nfrag, kiov);
        else
                rc = kqswnal_map_tx_iov (ktx, offset, nob, nfrag, iov);

        if (rc != 0) {
                CERROR ("Can't map source data: %d\n", rc);
                return (rc);
        }

#if MULTIRAIL_EKC
        if (ktx->ktx_nfrag != rmd->kqrmd_nfrag) {
                CERROR("Can't cope with unequal # frags: %d local %d remote\n",
                       ktx->ktx_nfrag, rmd->kqrmd_nfrag);
                return (-EINVAL);
        }
        
        for (i = 0; i < rmd->kqrmd_nfrag; i++)
                if (ktx->ktx_frags[i].nmd_len != rmd->kqrmd_frag[i].nmd_len) {
                        CERROR("Can't cope with unequal frags %d(%d):"
                               " %d local %d remote\n",
                               i, rmd->kqrmd_nfrag, 
                               ktx->ktx_frags[i].nmd_len, 
                               rmd->kqrmd_frag[i].nmd_len);
                        return (-EINVAL);
                }
#else
        ndatav = kqswnal_eiovs2datav (EP_MAXFRAG, datav,
                                      ktx->ktx_nfrag, ktx->ktx_frags,
                                      rmd->kqrmd_nfrag, rmd->kqrmd_frag);
        if (ndatav < 0) {
                CERROR ("Can't create datavec: %d\n", ndatav);
                return (ndatav);
        }
#endif

        /* Our caller will start to race with kqswnal_dma_reply_complete... */
        LASSERT (atomic_read (&krx->krx_refcount) == 1);
        atomic_set (&krx->krx_refcount, 2);

#if MULTIRAIL_EKC
        rc = ep_complete_rpc(krx->krx_rxd, kqswnal_dma_reply_complete, ktx, 
                             &kqswnal_rpc_success,
                             ktx->ktx_frags, rmd->kqrmd_frag, rmd->kqrmd_nfrag);
        if (rc == EP_SUCCESS)
                return (0);

        /* Well we tried... */
        krx->krx_rpc_reply_needed = 0;
#else
        rc = ep_complete_rpc (krx->krx_rxd, kqswnal_dma_reply_complete, ktx,
                              &kqswnal_rpc_success, datav, ndatav);
        if (rc == EP_SUCCESS)
                return (0);

        /* "old" EKC destroys rxd on failed completion */
        krx->krx_rxd = NULL;
#endif

        CERROR("can't complete RPC: %d\n", rc);

        /* reset refcount back to 1: we're not going to be racing with
         * kqswnal_dma_reply_complete. */
        atomic_set (&krx->krx_refcount, 1);

        return (-ECONNABORTED);
}

static ptl_err_t
kqswnal_sendmsg (nal_cb_t     *nal,
                 void         *private,
                 lib_msg_t    *libmsg,
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
                kqswnal_cerror_hdr (hdr);
                return (PTL_NOSPACE);
        }

        ktx->ktx_nid     = targetnid;
        ktx->ktx_args[0] = private;
        ktx->ktx_args[1] = libmsg;

        if (type == PTL_MSG_REPLY &&
            ((kqswnal_rx_t *)private)->krx_rpc_reply_needed) {
                if (nid != targetnid ||
                    kqswnal_nid2elanid(nid) != 
                    ep_rxd_node(((kqswnal_rx_t *)private)->krx_rxd)) {
                        CERROR("Optimized reply nid conflict: "
                               "nid "LPX64" via "LPX64" elanID %d\n",
                               nid, targetnid,
                               ep_rxd_node(((kqswnal_rx_t *)private)->krx_rxd));
                        return (PTL_FAIL);
                }

                /* peer expects RPC completion with GET data */
                rc = kqswnal_dma_reply (ktx, payload_niov, 
                                        payload_iov, payload_kiov, 
                                        payload_offset, payload_nob);
                if (rc == 0)
                        return (PTL_OK);
                
                CERROR ("Can't DMA reply to "LPX64": %d\n", nid, rc);
                kqswnal_put_idle_tx (ktx);
                return (PTL_FAIL);
        }

        memcpy (ktx->ktx_buffer, hdr, sizeof (*hdr)); /* copy hdr from caller's stack */
        ktx->ktx_wire_hdr = (ptl_hdr_t *)ktx->ktx_buffer;

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

        if (kqswnal_data.kqn_optimized_gets &&
            type == PTL_MSG_GET &&              /* doing a GET */
            nid == targetnid) {                 /* not forwarding */
                lib_md_t           *md = libmsg->md;
                kqswnal_remotemd_t *rmd = (kqswnal_remotemd_t *)(ktx->ktx_buffer + KQSW_HDR_SIZE);
                
                /* Optimised path: I send over the Elan vaddrs of the get
                 * sink buffers, and my peer DMAs directly into them.
                 *
                 * First I set up ktx as if it was going to send this
                 * payload, (it needs to map it anyway).  This fills
                 * ktx_frags[1] and onward with the network addresses
                 * of the GET sink frags.  I copy these into ktx_buffer,
                 * immediately after the header, and send that as my GET
                 * message.
                 *
                 * Note that the addresses are sent in native endian-ness.
                 * When EKC copes with different endian nodes, I'll fix
                 * this (and eat my hat :) */

                ktx->ktx_nfrag = ktx->ktx_firsttmpfrag = 1;
                ktx->ktx_state = KTX_GETTING;

                if ((libmsg->md->options & PTL_MD_KIOV) != 0) 
                        rc = kqswnal_map_tx_kiov (ktx, 0, md->length,
                                                  md->md_niov, md->md_iov.kiov);
                else
                        rc = kqswnal_map_tx_iov (ktx, 0, md->length,
                                                 md->md_niov, md->md_iov.iov);

                if (rc < 0) {
                        kqswnal_put_idle_tx (ktx);
                        return (PTL_FAIL);
                }

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
        } else if (payload_nob <= KQSW_TX_MAXCONTIG) {

                /* small message: single frag copied into the pre-mapped buffer */

                ktx->ktx_nfrag = ktx->ktx_firsttmpfrag = 1;
                ktx->ktx_state = KTX_SENDING;
#if MULTIRAIL_EKC
                ep_nmd_subset(&ktx->ktx_frags[0], &ktx->ktx_ebuffer,
                              0, KQSW_HDR_SIZE + payload_nob);
#else
                ktx->ktx_frags[0].Base = ktx->ktx_ebuffer;
                ktx->ktx_frags[0].Len = KQSW_HDR_SIZE + payload_nob;
#endif
                if (payload_nob > 0) {
                        if (payload_kiov != NULL)
                                lib_copy_kiov2buf (ktx->ktx_buffer + KQSW_HDR_SIZE,
                                                   payload_niov, payload_kiov, 
                                                   payload_offset, payload_nob);
                        else
                                lib_copy_iov2buf (ktx->ktx_buffer + KQSW_HDR_SIZE,
                                                  payload_niov, payload_iov, 
                                                  payload_offset, payload_nob);
                }
        } else {

                /* large message: multiple frags: first is hdr in pre-mapped buffer */

                ktx->ktx_nfrag = ktx->ktx_firsttmpfrag = 1;
                ktx->ktx_state = KTX_SENDING;
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
                if (rc != 0) {
                        kqswnal_put_idle_tx (ktx);
                        return (PTL_FAIL);
                }
        }
        
        ktx->ktx_port = (payload_nob <= KQSW_SMALLPAYLOAD) ?
                        EP_MSG_SVC_PORTALS_SMALL : EP_MSG_SVC_PORTALS_LARGE;

        rc = kqswnal_launch (ktx);
        if (rc != 0) {                    /* failed? */
                CERROR ("Failed to send packet to "LPX64": %d\n", targetnid, rc);
                kqswnal_put_idle_tx (ktx);
                return (PTL_FAIL);
        }

        CDEBUG(D_NET, "sent "LPSZ" bytes to "LPX64" via "LPX64"\n", 
               payload_nob, nid, targetnid);
        return (PTL_OK);
}

static ptl_err_t
kqswnal_send (nal_cb_t     *nal,
              void         *private,
              lib_msg_t    *libmsg,
              ptl_hdr_t    *hdr,
              int           type,
              ptl_nid_t     nid,
              ptl_pid_t     pid,
              unsigned int  payload_niov,
              struct iovec *payload_iov,
              size_t        payload_offset,
              size_t        payload_nob)
{
        return (kqswnal_sendmsg (nal, private, libmsg, hdr, type, nid, pid,
                                 payload_niov, payload_iov, NULL, 
                                 payload_offset, payload_nob));
}

static ptl_err_t
kqswnal_send_pages (nal_cb_t     *nal,
                    void         *private,
                    lib_msg_t    *libmsg,
                    ptl_hdr_t    *hdr,
                    int           type,
                    ptl_nid_t     nid,
                    ptl_pid_t     pid,
                    unsigned int  payload_niov,
                    ptl_kiov_t   *payload_kiov,
                    size_t        payload_offset,
                    size_t        payload_nob)
{
        return (kqswnal_sendmsg (nal, private, libmsg, hdr, type, nid, pid,
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

        if (nid == kqswnal_lib.ni.nid)          /* gateway is me */
                nid = fwd->kprfd_target_nid;    /* target is final dest */

        if (kqswnal_nid2elanid (nid) < 0) {
                CERROR("Can't forward [%p] to "LPX64": not a peer\n", fwd, nid);
                rc = -EHOSTUNREACH;
                goto failed;
        }

        /* copy hdr into pre-mapped buffer */
        memcpy(ktx->ktx_buffer, fwd->kprfd_hdr, sizeof(ptl_hdr_t));
        ktx->ktx_wire_hdr = (ptl_hdr_t *)ktx->ktx_buffer;

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
                        lib_copy_kiov2buf(ktx->ktx_buffer + KQSW_HDR_SIZE,
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
                        goto failed;
        }

        rc = kqswnal_launch (ktx);
        if (rc == 0)
                return;

 failed:
        LASSERT (rc != 0);
        CERROR ("Failed to forward [%p] to "LPX64": %d\n", fwd, nid, rc);

        kqswnal_put_idle_tx (ktx);
        /* complete now (with failure) */
        kpr_fwd_done (&kqswnal_data.kqn_router, fwd, rc);
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
                       NTOH__u64(hdr->src_nid), NTOH__u64(hdr->dest_nid),error);
        }

        kqswnal_requeue_rx (krx);
}

void
kqswnal_dma_reply_complete (EP_RXD *rxd) 
{
        int           status = ep_rxd_status(rxd);
        kqswnal_tx_t *ktx = (kqswnal_tx_t *)ep_rxd_arg(rxd);
        kqswnal_rx_t *krx = (kqswnal_rx_t *)ktx->ktx_args[0];
        lib_msg_t    *msg = (lib_msg_t *)ktx->ktx_args[1];
        
        CDEBUG((status == EP_SUCCESS) ? D_NET : D_ERROR,
               "rxd %p, ktx %p, status %d\n", rxd, ktx, status);

        LASSERT (krx->krx_rxd == rxd);
        LASSERT (krx->krx_rpc_reply_needed);

        krx->krx_rpc_reply_needed = 0;
        kqswnal_rx_done (krx);

        lib_finalize (&kqswnal_lib, NULL, msg,
                      (status == EP_SUCCESS) ? PTL_OK : PTL_FAIL);
        kqswnal_put_idle_tx (ktx);
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
kqswnal_requeue_rx (kqswnal_rx_t *krx) 
{
        int   rc;

        LASSERT (atomic_read(&krx->krx_refcount) == 0);

        if (krx->krx_rpc_reply_needed) {

                /* We failed to complete the peer's optimized GET (e.g. we
                 * couldn't map the source buffers).  We complete the
                 * peer's EKC rpc now with failure. */
#if MULTIRAIL_EKC
                rc = ep_complete_rpc(krx->krx_rxd, kqswnal_rpc_complete, krx,
                                     &kqswnal_rpc_failed, NULL, NULL, 0);
                if (rc == EP_SUCCESS)
                        return;
                
                CERROR("can't complete RPC: %d\n", rc);
#else
                if (krx->krx_rxd != NULL) {
                        /* We didn't try (and fail) to complete earlier... */
                        rc = ep_complete_rpc(krx->krx_rxd, 
                                             kqswnal_rpc_complete, krx,
                                             &kqswnal_rpc_failed, NULL, 0);
                        if (rc == EP_SUCCESS)
                                return;

                        CERROR("can't complete RPC: %d\n", rc);
                }
                
                /* NB the old ep_complete_rpc() frees rxd on failure, so we
                 * have to requeue from scratch here, unless we're shutting
                 * down */
                if (kqswnal_data.kqn_shuttingdown)
                        return;

                rc = ep_queue_receive(krx->krx_eprx, kqswnal_rxhandler, krx,
                                      krx->krx_elanbuffer, 
                                      krx->krx_npages * PAGE_SIZE, 0);
                LASSERT (rc == EP_SUCCESS);
                /* We don't handle failure here; it's incredibly rare
                 * (never reported?) and only happens with "old" EKC */
                return;
#endif
        }

#if MULTIRAIL_EKC
        if (kqswnal_data.kqn_shuttingdown) {
                /* free EKC rxd on shutdown */
                ep_complete_receive(krx->krx_rxd);
        } else {
                /* repost receive */
                ep_requeue_receive(krx->krx_rxd, kqswnal_rxhandler, krx,
                                   &krx->krx_elanbuffer, 0);
        }
#else                
        /* don't actually requeue on shutdown */
        if (!kqswnal_data.kqn_shuttingdown) 
                ep_requeue_receive(krx->krx_rxd, kqswnal_rxhandler, krx,
                                   krx->krx_elanbuffer, krx->krx_npages * PAGE_SIZE);
#endif
}
        
void
kqswnal_rx (kqswnal_rx_t *krx)
{
        ptl_hdr_t      *hdr = (ptl_hdr_t *) page_address(krx->krx_kiov[0].kiov_page);
        ptl_nid_t       dest_nid = NTOH__u64 (hdr->dest_nid);
        int             payload_nob;
        int             nob;
        int             niov;

        LASSERT (atomic_read(&krx->krx_refcount) == 0);

        if (dest_nid == kqswnal_lib.ni.nid) { /* It's for me :) */
                atomic_set(&krx->krx_refcount, 1);
                lib_parse (&kqswnal_lib, hdr, krx);
                kqswnal_rx_done(krx);
                return;
        }

#if KQSW_CHECKSUM
        CERROR ("checksums for forwarded packets not implemented\n");
        LBUG ();
#endif
        if (kqswnal_nid2elanid (dest_nid) >= 0)  /* should have gone direct to peer */
        {
                CERROR("dropping packet from "LPX64" for "LPX64
                       ": target is peer\n", NTOH__u64(hdr->src_nid), dest_nid);

                kqswnal_requeue_rx (krx);
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
        long          flags;
        int           nob    = ep_rxd_len (rxd);
        int           status = ep_rxd_status (rxd);
        kqswnal_rx_t *krx    = (kqswnal_rx_t *)ep_rxd_arg (rxd);

        CDEBUG(D_NET, "kqswnal_rxhandler: rxd %p, krx %p, nob %d, status %d\n",
               rxd, krx, nob, status);

        LASSERT (krx != NULL);

        krx->krx_rxd = rxd;
        krx->krx_nob = nob;
#if MULTIRAIL_EKC
        krx->krx_rpc_reply_needed = (status != EP_SHUTDOWN) && ep_rxd_isrpc(rxd);
#else
        krx->krx_rpc_reply_needed = ep_rxd_isrpc(rxd);
#endif
        
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
                kqswnal_requeue_rx (krx);
                return;
        }

        if (!in_interrupt()) {
                kqswnal_rx (krx);
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
                NTOH__u64(hdr->dest_nid), NTOH__u64(hdr->src_nid)
                NTOH__u32(hdr->dest_pid), NTOH__u32(hdr->src_pid),
                NTOH__u32(hdr->type));

        switch (NTOH__u32 (hdr->type))
        {
        case PTL_MSG_ACK:
                CERROR("ACK: mlen %d dmd "LPX64"."LPX64" match "LPX64
                       " len %u\n",
                       NTOH__u32(hdr->msg.ack.mlength),
                       hdr->msg.ack.dst_wmd.handle_cookie,
                       hdr->msg.ack.dst_wmd.handle_idx,
                       NTOH__u64(hdr->msg.ack.match_bits),
                       NTOH__u32(hdr->msg.ack.length));
                break;
        case PTL_MSG_PUT:
                CERROR("PUT: ptl %d amd "LPX64"."LPX64" match "LPX64
                       " len %u off %u data "LPX64"\n",
                       NTOH__u32(hdr->msg.put.ptl_index),
                       hdr->msg.put.ack_wmd.handle_cookie,
                       hdr->msg.put.ack_wmd.handle_idx,
                       NTOH__u64(hdr->msg.put.match_bits),
                       NTOH__u32(hdr->msg.put.length),
                       NTOH__u32(hdr->msg.put.offset),
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
kqswnal_recvmsg (nal_cb_t     *nal,
                 void         *private,
                 lib_msg_t    *libmsg,
                 unsigned int  niov,
                 struct iovec *iov,
                 ptl_kiov_t   *kiov,
                 size_t        offset,
                 size_t        mlen,
                 size_t        rlen)
{
        kqswnal_rx_t *krx = (kqswnal_rx_t *)private;
        char         *buffer = page_address(krx->krx_kiov[0].kiov_page);
        int           page;
        char         *page_ptr;
        int           page_nob;
        char         *iov_ptr;
        int           iov_nob;
        int           frag;
#if KQSW_CHECKSUM
        kqsw_csum_t   senders_csum;
        kqsw_csum_t   payload_csum = 0;
        kqsw_csum_t   hdr_csum = kqsw_csum(0, buffer, sizeof(ptl_hdr_t));
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
        CDEBUG(D_NET,"kqswnal_recv, mlen="LPSZ", rlen="LPSZ"\n", mlen, rlen);

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
        lib_finalize(nal, private, libmsg, PTL_OK);

        return (PTL_OK);
}

static ptl_err_t
kqswnal_recv(nal_cb_t     *nal,
             void         *private,
             lib_msg_t    *libmsg,
             unsigned int  niov,
             struct iovec *iov,
             size_t        offset,
             size_t        mlen,
             size_t        rlen)
{
        return (kqswnal_recvmsg(nal, private, libmsg, 
                                niov, iov, NULL, 
                                offset, mlen, rlen));
}

static ptl_err_t
kqswnal_recv_pages (nal_cb_t     *nal,
                    void         *private,
                    lib_msg_t    *libmsg,
                    unsigned int  niov,
                    ptl_kiov_t   *kiov,
                    size_t        offset,
                    size_t        mlen,
                    size_t        rlen)
{
        return (kqswnal_recvmsg(nal, private, libmsg, 
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
        atomic_inc (&kqswnal_data.kqn_nthreads_running);
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
        long             flags;
        int              rc;
        int              counter = 0;
        int              shuttingdown = 0;
        int              did_something;

        kportal_daemonize ("kqswnal_sched");
        kportal_blockallsigs ();
        
        spin_lock_irqsave (&kqswnal_data.kqn_sched_lock, flags);

        for (;;)
        {
                if (kqswnal_data.kqn_shuttingdown != shuttingdown) {

                        if (kqswnal_data.kqn_shuttingdown == 2)
                                break;
                
                        /* During stage 1 of shutdown we are still responsive
                         * to receives */

                        atomic_dec (&kqswnal_data.kqn_nthreads_running);
                        shuttingdown = kqswnal_data.kqn_shuttingdown;
                }

                did_something = 0;

                if (!list_empty (&kqswnal_data.kqn_readyrxds))
                {
                        krx = list_entry(kqswnal_data.kqn_readyrxds.next,
                                         kqswnal_rx_t, krx_list);
                        list_del (&krx->krx_list);
                        spin_unlock_irqrestore(&kqswnal_data.kqn_sched_lock,
                                               flags);

                        kqswnal_rx (krx);

                        did_something = 1;
                        spin_lock_irqsave(&kqswnal_data.kqn_sched_lock, flags);
                }

                if (!shuttingdown &&
                    !list_empty (&kqswnal_data.kqn_delayedtxds))
                {
                        ktx = list_entry(kqswnal_data.kqn_delayedtxds.next,
                                         kqswnal_tx_t, ktx_list);
                        list_del_init (&ktx->ktx_delayed_list);
                        spin_unlock_irqrestore(&kqswnal_data.kqn_sched_lock,
                                               flags);

                        rc = kqswnal_launch (ktx);
                        if (rc != 0)          /* failed: ktx_nid down? */
                        {
                                CERROR("Failed delayed transmit to "LPX64
                                       ": %d\n", ktx->ktx_nid, rc);
                                kqswnal_tx_done (ktx, rc);
                        }

                        did_something = 1;
                        spin_lock_irqsave (&kqswnal_data.kqn_sched_lock, flags);
                }

                if (!shuttingdown &
                    !list_empty (&kqswnal_data.kqn_delayedfwds))
                {
                        fwd = list_entry (kqswnal_data.kqn_delayedfwds.next, kpr_fwd_desc_t, kprfd_list);
                        list_del (&fwd->kprfd_list);
                        spin_unlock_irqrestore (&kqswnal_data.kqn_sched_lock, flags);

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
                                rc = wait_event_interruptible (kqswnal_data.kqn_sched_waitq,
                                                               kqswnal_data.kqn_shuttingdown != shuttingdown ||
                                                               !list_empty(&kqswnal_data.kqn_readyrxds) ||
                                                               !list_empty(&kqswnal_data.kqn_delayedtxds) ||
                                                               !list_empty(&kqswnal_data.kqn_delayedfwds));
                                LASSERT (rc == 0);
                        } else if (current->need_resched)
                                schedule ();

                        spin_lock_irqsave (&kqswnal_data.kqn_sched_lock, flags);
                }
        }

        spin_unlock_irqrestore (&kqswnal_data.kqn_sched_lock, flags);

        kqswnal_thread_fini ();
        return (0);
}

nal_cb_t kqswnal_lib =
{
        nal_data:       &kqswnal_data,         /* NAL private data */
        cb_send:        kqswnal_send,
        cb_send_pages:  kqswnal_send_pages,
        cb_recv:        kqswnal_recv,
        cb_recv_pages:  kqswnal_recv_pages,
        cb_read:        kqswnal_read,
        cb_write:       kqswnal_write,
        cb_malloc:      kqswnal_malloc,
        cb_free:        kqswnal_free,
        cb_printf:      kqswnal_printf,
        cb_cli:         kqswnal_cli,
        cb_sti:         kqswnal_sti,
        cb_dist:        kqswnal_dist
};
