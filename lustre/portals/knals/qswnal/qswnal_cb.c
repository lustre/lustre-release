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

/*
 *  LIB functions follow
 *
 */
static int
kqswnal_read(nal_cb_t *nal, void *private, void *dst_addr, user_ptr src_addr,
             size_t len)
{
        CDEBUG (D_NET, LPX64": reading "LPSZ" bytes from %p -> %p\n",
                nal->ni.nid, len, src_addr, dst_addr );
        memcpy( dst_addr, src_addr, len );

        return (0);
}

static int
kqswnal_write(nal_cb_t *nal, void *private, user_ptr dst_addr, void *src_addr,
              size_t len)
{
        CDEBUG (D_NET, LPX64": writing "LPSZ" bytes from %p -> %p\n",
                nal->ni.nid, len, src_addr, dst_addr );
        memcpy( dst_addr, src_addr, len );

        return (0);
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
kqswnal_unmap_tx (kqswnal_tx_t *ktx)
{
        if (ktx->ktx_nmappedpages == 0)
                return;

        CDEBUG (D_NET, "%p[%d] unloading pages %d for %d\n",
                ktx, ktx->ktx_nfrag, ktx->ktx_basepage, ktx->ktx_nmappedpages);

        LASSERT (ktx->ktx_nmappedpages <= ktx->ktx_npages);
        LASSERT (ktx->ktx_basepage + ktx->ktx_nmappedpages <=
                 kqswnal_data.kqn_eptxdmahandle->NumDvmaPages);

        elan3_dvma_unload(kqswnal_data.kqn_epdev->DmaState,
                          kqswnal_data.kqn_eptxdmahandle,
                          ktx->ktx_basepage, ktx->ktx_nmappedpages);
        ktx->ktx_nmappedpages = 0;
}

int
kqswnal_map_tx_kiov (kqswnal_tx_t *ktx, int nob, int niov, ptl_kiov_t *kiov)
{
        int       nfrags    = ktx->ktx_nfrag;
        int       nmapped   = ktx->ktx_nmappedpages;
        int       maxmapped = ktx->ktx_npages;
        uint32_t  basepage  = ktx->ktx_basepage + nmapped;
        char     *ptr;
        
        LASSERT (nmapped <= maxmapped);
        LASSERT (nfrags <= EP_MAXFRAG);
        LASSERT (niov > 0);
        LASSERT (nob > 0);
        
        do {
                int  fraglen = kiov->kiov_len;

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

                ptr = ((char *)kmap (kiov->kiov_page)) + kiov->kiov_offset;

                CDEBUG(D_NET,
                       "%p[%d] loading %p for %d, page %d, %d total\n",
                        ktx, nfrags, ptr, fraglen, basepage, nmapped);

                elan3_dvma_kaddr_load (kqswnal_data.kqn_epdev->DmaState,
                                       kqswnal_data.kqn_eptxdmahandle,
                                       ptr, fraglen,
                                       basepage, &ktx->ktx_frags.iov[nfrags].Base);

                kunmap (kiov->kiov_page);
                
                /* keep in loop for failure case */
                ktx->ktx_nmappedpages = nmapped;

                if (nfrags > 0 &&                /* previous frag mapped */
                    ktx->ktx_frags.iov[nfrags].Base == /* contiguous with this one */
                    (ktx->ktx_frags.iov[nfrags-1].Base + ktx->ktx_frags.iov[nfrags-1].Len))
                        /* just extend previous */
                        ktx->ktx_frags.iov[nfrags - 1].Len += fraglen;
                else {
                        ktx->ktx_frags.iov[nfrags].Len = fraglen;
                        nfrags++;                /* new frag */
                }

                basepage++;
                kiov++;
                niov--;
                nob -= fraglen;

                /* iov must not run out before end of data */
                LASSERT (nob == 0 || niov > 0);

        } while (nob > 0);

        ktx->ktx_nfrag = nfrags;
        CDEBUG (D_NET, "%p got %d frags over %d pages\n",
                ktx, ktx->ktx_nfrag, ktx->ktx_nmappedpages);

        return (0);
}

int
kqswnal_map_tx_iov (kqswnal_tx_t *ktx, int nob, int niov, struct iovec *iov)
{
        int       nfrags    = ktx->ktx_nfrag;
        int       nmapped   = ktx->ktx_nmappedpages;
        int       maxmapped = ktx->ktx_npages;
        uint32_t  basepage  = ktx->ktx_basepage + nmapped;

        LASSERT (nmapped <= maxmapped);
        LASSERT (nfrags <= EP_MAXFRAG);
        LASSERT (niov > 0);
        LASSERT (nob > 0);

        do {
                int  fraglen = iov->iov_len;
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
                        ktx, nfrags, iov->iov_base, fraglen, basepage, npages,
                        nmapped);

                elan3_dvma_kaddr_load (kqswnal_data.kqn_epdev->DmaState,
                                       kqswnal_data.kqn_eptxdmahandle,
                                       iov->iov_base, fraglen,
                                       basepage, &ktx->ktx_frags.iov[nfrags].Base);
                /* keep in loop for failure case */
                ktx->ktx_nmappedpages = nmapped;

                if (nfrags > 0 &&                /* previous frag mapped */
                    ktx->ktx_frags.iov[nfrags].Base == /* contiguous with this one */
                    (ktx->ktx_frags.iov[nfrags-1].Base + ktx->ktx_frags.iov[nfrags-1].Len))
                        /* just extend previous */
                        ktx->ktx_frags.iov[nfrags - 1].Len += fraglen;
                else {
                        ktx->ktx_frags.iov[nfrags].Len = fraglen;
                        nfrags++;                /* new frag */
                }

                basepage += npages;
                iov++;
                niov--;
                nob -= fraglen;

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
        struct list_head *idle = ktx->ktx_idle;
        unsigned long     flags;

        kqswnal_unmap_tx (ktx);                /* release temporary mappings */
        ktx->ktx_state = KTX_IDLE;

        spin_lock_irqsave (&kqswnal_data.kqn_idletxd_lock, flags);

        list_add (&ktx->ktx_list, idle);

        /* reserved for non-blocking tx */
        if (idle == &kqswnal_data.kqn_nblk_idletxds) {
                spin_unlock_irqrestore (&kqswnal_data.kqn_idletxd_lock, flags);
                return;
        }

        /* anything blocking for a tx descriptor? */
        if (!list_empty(&kqswnal_data.kqn_idletxd_fwdq)) /* forwarded packet? */
        {
                CDEBUG(D_NET,"wakeup fwd\n");

                fwd = list_entry (kqswnal_data.kqn_idletxd_fwdq.next,
                                  kpr_fwd_desc_t, kprfd_list);
                list_del (&fwd->kprfd_list);
        }

        if (waitqueue_active (&kqswnal_data.kqn_idletxd_waitq))  /* process? */
        {
                /* local sender waiting for tx desc */
                CDEBUG(D_NET,"wakeup process\n");
                wake_up (&kqswnal_data.kqn_idletxd_waitq);
        }

        spin_unlock_irqrestore (&kqswnal_data.kqn_idletxd_lock, flags);

        if (fwd == NULL)
                return;

        /* schedule packet for forwarding again */
        spin_lock_irqsave (&kqswnal_data.kqn_sched_lock, flags);

        list_add_tail (&fwd->kprfd_list, &kqswnal_data.kqn_delayedfwds);
        if (waitqueue_active (&kqswnal_data.kqn_sched_waitq))
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
                        list_del (&ktx->ktx_list);
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
                        list_del (&ktx->ktx_list);
                        break;
                }

                /* block for idle tx */

                spin_unlock_irqrestore (&kqswnal_data.kqn_idletxd_lock, flags);

                CDEBUG (D_NET, "blocking for tx desc\n");
                wait_event (kqswnal_data.kqn_idletxd_waitq,
                            !list_empty (&kqswnal_data.kqn_idletxds));
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
        lib_msg_t     *repmsg;

        switch (ktx->ktx_state) {
        case KTX_FORWARDING:       /* router asked me to forward this packet */
                kpr_fwd_done (&kqswnal_data.kqn_router,
                              (kpr_fwd_desc_t *)ktx->ktx_args[0], error);
                break;

        case KTX_SENDING:          /* packet sourced locally */
                lib_finalize (&kqswnal_lib, ktx->ktx_args[0],
                              (lib_msg_t *)ktx->ktx_args[1]);
                break;

        case KTX_GETTING:          /* Peer has DMA-ed direct? */
                LASSERT (KQSW_OPTIMIZE_GETS);
                msg = (lib_msg_t *)ktx->ktx_args[1];
                repmsg = NULL;

                if (error == 0) 
                        repmsg = lib_fake_reply_msg (&kqswnal_lib, 
                                                     ktx->ktx_nid, msg->md);
                
                lib_finalize (&kqswnal_lib, ktx->ktx_args[0], msg);

                if (repmsg != NULL) 
                        lib_finalize (&kqswnal_lib, NULL, repmsg);
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

        if (status != EP_SUCCESS)
        {
                CERROR ("kqswnal: Transmit failed with %d\n", status);
                status = -EIO;

        } else if (ktx->ktx_state == KTX_GETTING) {
                /* RPC completed OK; what did our peer put in the status
                 * block? */
                LASSERT (KQSW_OPTIMIZE_GETS);
                status = ep_txd_statusblk(txd)->Status;
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
        
        LASSERT (dest >= 0);                    /* must be a peer */
        if (ktx->ktx_state == KTX_GETTING) {
                LASSERT (KQSW_OPTIMIZE_GETS);
                rc = ep_transmit_rpc(kqswnal_data.kqn_eptx, dest,
                                     ktx->ktx_port, attr, kqswnal_txhandler,
                                     ktx, NULL, ktx->ktx_frags.iov, ktx->ktx_nfrag);
        } else {
                rc = ep_transmit_large(kqswnal_data.kqn_eptx, dest,
                                       ktx->ktx_port, attr, kqswnal_txhandler,
                                       ktx, ktx->ktx_frags.iov, ktx->ktx_nfrag);
        }

        if (rc != ENOMEM)
                return (rc);

        /* can't allocate ep txd => queue for later */

        LASSERT (in_interrupt());      /* not called by thread (not looping) */

        spin_lock_irqsave (&kqswnal_data.kqn_sched_lock, flags);

        list_add_tail (&ktx->ktx_list, &kqswnal_data.kqn_delayedtxds);
        if (waitqueue_active (&kqswnal_data.kqn_sched_waitq))
                wake_up (&kqswnal_data.kqn_sched_waitq);

        spin_unlock_irqrestore (&kqswnal_data.kqn_sched_lock, flags);

        return (0);
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

        CERROR("P3 Header at %p of type %s\n", hdr, type_str);
        CERROR("    From nid/pid "LPU64"/%u", NTOH__u64(hdr->src_nid),
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
                CERROR("    Length %d, offset %d, hdr data "LPX64"\n",
                       NTOH__u32(PTL_HDR_LENGTH(hdr)),
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
                CERROR("    dst md "LPX64"."LPX64", length %d\n",
                       hdr->msg.reply.dst_wmd.wh_interface_cookie,
                       hdr->msg.reply.dst_wmd.wh_object_cookie,
                       NTOH__u32 (PTL_HDR_LENGTH(hdr)));
        }

}                               /* end of print_hdr() */

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

int
kqswnal_dma_reply (kqswnal_tx_t *ktx, int nfrag, 
                   struct iovec *iov, ptl_kiov_t *kiov, int nob)
{
        kqswnal_rx_t       *krx = (kqswnal_rx_t *)ktx->ktx_args[0];
        char               *buffer = (char *)page_address(krx->krx_pages[0]);
        kqswnal_remotemd_t *rmd = (kqswnal_remotemd_t *)(buffer + KQSW_HDR_SIZE);
        EP_IOVEC            eiov[EP_MAXFRAG];
        EP_STATUSBLK        blk;
        int                 rc;

        LASSERT (ep_rxd_isrpc(krx->krx_rxd) && !krx->krx_rpc_completed);
        LASSERT ((iov == NULL) != (kiov == NULL));

        /* see .*_pack_k?iov comment regarding endian-ness */
        if (buffer + krx->krx_nob < (char *)(rmd + 1)) {
                /* msg too small to discover rmd size */
                CERROR ("Incoming message [%d] too small for RMD (%d needed)\n",
                        krx->krx_nob, ((char *)(rmd + 1)) - buffer);
                return (-EINVAL);
        }
        
        if (buffer + krx->krx_nob < (char *)&rmd->kqrmd_eiov[rmd->kqrmd_neiov]) {
                /* rmd doesn't fit in the incoming message */
                CERROR ("Incoming message [%d] too small for RMD[%d] (%d needed)\n",
                        krx->krx_nob, rmd->kqrmd_neiov,
                        ((char *)&rmd->kqrmd_eiov[rmd->kqrmd_neiov]) - buffer);
                return (-EINVAL);
        }

        /* Ghastly hack part 1, uses the existing procedures to map the source data... */
        ktx->ktx_nfrag = 0;
        if (kiov != NULL)
                rc = kqswnal_map_tx_kiov (ktx, nob, nfrag, kiov);
        else
                rc = kqswnal_map_tx_iov (ktx, nob, nfrag, iov);

        if (rc != 0) {
                CERROR ("Can't map source data: %d\n", rc);
                return (rc);
        }

        /* Ghastly hack part 2, copy out eiov so we can create the datav; Ugghh... */
        memcpy (eiov, ktx->ktx_frags.iov, ktx->ktx_nfrag * sizeof (eiov[0]));

        rc = kqswnal_eiovs2datav (EP_MAXFRAG, ktx->ktx_frags.datav,
                                  ktx->ktx_nfrag, eiov,
                                  rmd->kqrmd_neiov, rmd->kqrmd_eiov);
        if (rc < 0) {
                CERROR ("Can't create datavec: %d\n", rc);
                return (rc);
        }
        ktx->ktx_nfrag = rc;

        memset (&blk, 0, sizeof (blk));         /* zero blk.Status */

        /* Our caller will start to race with kqswnal_rpc_complete... */
        LASSERT (atomic_read (&krx->krx_refcount) == 1);
        atomic_set (&krx->krx_refcount, 2);

        rc = ep_complete_rpc (krx->krx_rxd, kqswnal_reply_complete, ktx,
                              &blk, ktx->ktx_frags.datav, ktx->ktx_nfrag);
        if (rc == ESUCCESS)
                return (0);

        /* reset refcount back to 1: we're not going to be racing with
         * kqswnal_rely_complete. */
        atomic_set (&krx->krx_refcount, 1);
        return (-ECONNABORTED);
}

static int
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
                 size_t        payload_nob)
{
        kqswnal_tx_t      *ktx;
        int                rc;
        ptl_nid_t          targetnid;
#if KQSW_CHECKSUM
        int                i;
        kqsw_csum_t        csum;
        int                sumnob;
#endif
        
        /* NB, the return code from this procedure is ignored.
         * If we can't send, we must still complete with lib_finalize().
         * We'll have to wait for 3.2 to return an error event.
         */

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
                lib_finalize (&kqswnal_lib, private, libmsg);
                return (-1);
        }

        targetnid = nid;
        if (kqswnal_nid2elanid (nid) < 0) {     /* Can't send direct: find gateway? */
                rc = kpr_lookup (&kqswnal_data.kqn_router, nid, &targetnid);
                if (rc != 0) {
                        CERROR("Can't route to "LPX64": router error %d\n",
                               nid, rc);
                        lib_finalize (&kqswnal_lib, private, libmsg);
                        return (-1);
                }
                if (kqswnal_nid2elanid (targetnid) < 0) {
                        CERROR("Bad gateway "LPX64" for "LPX64"\n",
                               targetnid, nid);
                        lib_finalize (&kqswnal_lib, private, libmsg);
                        return (-1);
                }
        }

        /* I may not block for a transmit descriptor if I might block the
         * receiver, or an interrupt handler. */
        ktx = kqswnal_get_idle_tx(NULL, !(type == PTL_MSG_ACK ||
                                          type == PTL_MSG_REPLY ||
                                          in_interrupt()));
        if (ktx == NULL) {
                kqswnal_cerror_hdr (hdr);
                lib_finalize (&kqswnal_lib, private, libmsg);
                return (-1);
        }

        ktx->ktx_args[0] = private;
        ktx->ktx_args[1] = libmsg;

#if KQSW_OPTIMIZE_GETS
        if (type == PTL_MSG_REPLY &&
            ep_rxd_isrpc(((kqswnal_rx_t *)private)->krx_rxd)) {
                /* peer expects RPC completion with GET data */
                rc = kqswnal_dma_reply (ktx,
                                        payload_niov, payload_iov, 
                                        payload_kiov, payload_nob);
                if (rc == 0)
                        return (0);
                
                CERROR ("Can't DMA reply to "LPX64": %d\n", nid, rc);
                kqswnal_put_idle_tx (ktx);
                lib_finalize (&kqswnal_lib, private, libmsg);
                return (-1);
        }
#endif

        memcpy (ktx->ktx_buffer, hdr, sizeof (*hdr)); /* copy hdr from caller's stack */

#if KQSW_CHECKSUM
        csum = kqsw_csum (0, (char *)hdr, sizeof (*hdr));
        memcpy (ktx->ktx_buffer + sizeof (*hdr), &csum, sizeof (csum));
        for (csum = 0, i = 0, sumnob = payload_nob; sumnob > 0; i++) {
                if (payload_kiov != NULL) {
                        ptl_kiov_t *kiov = &payload_kiov[i];
                        char       *addr = ((char *)kmap (kiov->kiov_page)) +
                                           kiov->kiov_offset;
                        
                        csum = kqsw_csum (csum, addr, MIN (sumnob, kiov->kiov_len));
                        sumnob -= kiov->kiov_len;
                } else {
                        struct iovec *iov = &payload_iov[i];

                        csum = kqsw_csum (csum, iov->iov_base, MIN (sumnob, kiov->iov_len));
                        sumnob -= iov->iov_len;
                }
        }
        memcpy(ktx->ktx_buffer +sizeof(*hdr) +sizeof(csum), &csum,sizeof(csum));
#endif
        
        /* Set up first frag from pre-mapped buffer (it's at least the
         * portals header) */
        ktx->ktx_frags.iov[0].Base = ktx->ktx_ebuffer;
        ktx->ktx_frags.iov[0].Len = KQSW_HDR_SIZE;
        ktx->ktx_nfrag = 1;
        ktx->ktx_state = KTX_SENDING;   /* => lib_finalize() on completion */

#if KQSW_OPTIMIZE_GETS
        if (type == PTL_MSG_GET &&              /* doing a GET */
            nid == targetnid) {                 /* not forwarding */
                lib_md_t           *md = libmsg->md;
                kqswnal_remotemd_t *rmd = (kqswnal_remotemd_t *)(ktx->ktx_buffer + KQSW_HDR_SIZE);
                
                /* Optimised path: I send over the Elan vaddrs of the get
                 * sink buffers, and my peer DMAs directly into them.
                 *
                 * First I set up ktx as if it was going to send this
                 * payload, (it needs to map it anyway).  This fills
                 * ktx_frags.iov[1] and onward with the network addresses
                 * of the get sink frags.  I copy these into ktx_buffer,
                 * immediately after the header, and send that as my GET
                 * message.
                 *
                 * Note that the addresses are sent in native endian-ness.
                 * When EKC copes with different endian nodes, I'll fix
                 * this (and eat my hat :) */

                if ((libmsg->md->options & PTL_MD_KIOV) != 0) 
                        rc = kqswnal_map_tx_kiov (ktx, md->length,
                                                  md->md_niov, md->md_iov.kiov);
                else
                        rc = kqswnal_map_tx_iov (ktx, md->length,
                                                 md->md_niov, md->md_iov.iov);

                if (rc < 0) {
                        kqswnal_put_idle_tx (ktx);
                        lib_finalize (&kqswnal_lib, private, libmsg);
                        return (-1);
                }

                rmd->kqrmd_neiov = ktx->ktx_nfrag - 1;
                memcpy (&rmd->kqrmd_eiov[0], &ktx->ktx_frags.iov[1],
                        rmd->kqrmd_neiov * sizeof (EP_IOVEC));

                ktx->ktx_nfrag = 1;
                ktx->ktx_frags.iov[0].Len += offsetof (kqswnal_remotemd_t,
                                                       kqrmd_eiov[rmd->kqrmd_neiov]);
                ktx->ktx_state = KTX_GETTING;
                payload_nob = rc;

        } else 
#endif
        if (payload_nob > 0) { /* got some payload (something more to do) */
                /* make a single contiguous message? */
                if (payload_nob <= KQSW_TX_MAXCONTIG) {
                        /* copy payload to ktx_buffer, immediately after hdr */
                        if (payload_kiov != NULL)
                                lib_copy_kiov2buf (ktx->ktx_buffer + KQSW_HDR_SIZE,
                                                   payload_niov, payload_kiov, payload_nob);
                        else
                                lib_copy_iov2buf (ktx->ktx_buffer + KQSW_HDR_SIZE,
                                                  payload_niov, payload_iov, payload_nob);
                        /* first frag includes payload */
                        ktx->ktx_frags.iov[0].Len += payload_nob;
                } else {
                        if (payload_kiov != NULL)
                                rc = kqswnal_map_tx_kiov (ktx, payload_nob, 
                                                          payload_niov, payload_kiov);
                        else
                                rc = kqswnal_map_tx_iov (ktx, payload_nob,
                                                         payload_niov, payload_iov);
                        if (rc != 0) {
                                kqswnal_put_idle_tx (ktx);
                                lib_finalize (&kqswnal_lib, private, libmsg);
                                return (-1);
                        }
                } 
        }

        ktx->ktx_nid  = targetnid;
        ktx->ktx_port = (payload_nob <= KQSW_SMALLPAYLOAD) ?
                        EP_SVC_LARGE_PORTALS_SMALL : EP_SVC_LARGE_PORTALS_LARGE;

        rc = kqswnal_launch (ktx);
        if (rc != 0) {                    /* failed? */
                CERROR ("Failed to send packet to "LPX64": %d\n", targetnid, rc);
                kqswnal_put_idle_tx (ktx);
                lib_finalize (&kqswnal_lib, private, libmsg);
                return (-1);
        }

        CDEBUG(D_NET, "send to "LPSZ" bytes to "LPX64"\n", payload_nob, targetnid);
        return (0);
}

static int
kqswnal_send (nal_cb_t     *nal,
              void         *private,
              lib_msg_t    *libmsg,
              ptl_hdr_t    *hdr,
              int           type,
              ptl_nid_t     nid,
              ptl_pid_t     pid,
              unsigned int  payload_niov,
              struct iovec *payload_iov,
              size_t        payload_nob)
{
        return (kqswnal_sendmsg (nal, private, libmsg, hdr, type, nid, pid,
                                 payload_niov, payload_iov, NULL, payload_nob));
}

static int
kqswnal_send_pages (nal_cb_t     *nal,
                    void         *private,
                    lib_msg_t    *libmsg,
                    ptl_hdr_t    *hdr,
                    int           type,
                    ptl_nid_t     nid,
                    ptl_pid_t     pid,
                    unsigned int  payload_niov,
                    ptl_kiov_t   *payload_kiov,
                    size_t        payload_nob)
{
        return (kqswnal_sendmsg (nal, private, libmsg, hdr, type, nid, pid,
                                 payload_niov, NULL, payload_kiov, payload_nob));
}

int kqswnal_fwd_copy_contig = 0;

void
kqswnal_fwd_packet (void *arg, kpr_fwd_desc_t *fwd)
{
        int             rc;
        kqswnal_tx_t   *ktx;
        struct iovec   *iov = fwd->kprfd_iov;
        int             niov = fwd->kprfd_niov;
        int             nob = fwd->kprfd_nob;
        ptl_nid_t       nid = fwd->kprfd_gateway_nid;

#if KQSW_CHECKSUM
        CERROR ("checksums for forwarded packets not implemented\n");
        LBUG ();
#endif
        /* The router wants this NAL to forward a packet */
        CDEBUG (D_NET, "forwarding [%p] to "LPX64", %d frags %d bytes\n",
                fwd, nid, niov, nob);

        LASSERT (niov > 0);
        
        ktx = kqswnal_get_idle_tx (fwd, FALSE);
        if (ktx == NULL)        /* can't get txd right now */
                return;         /* fwd will be scheduled when tx desc freed */

        if (nid == kqswnal_lib.ni.nid)          /* gateway is me */
                nid = fwd->kprfd_target_nid;    /* target is final dest */

        if (kqswnal_nid2elanid (nid) < 0) {
                CERROR("Can't forward [%p] to "LPX64": not a peer\n", fwd, nid);
                rc = -EHOSTUNREACH;
                goto failed;
        }

        if (nob > KQSW_NRXMSGBYTES_LARGE) {
                CERROR ("Can't forward [%p] to "LPX64
                        ": size %d bigger than max packet size %ld\n",
                        fwd, nid, nob, (long)KQSW_NRXMSGBYTES_LARGE);
                rc = -EMSGSIZE;
                goto failed;
        }

        if ((kqswnal_fwd_copy_contig || niov > 1) &&
            nob <= KQSW_TX_BUFFER_SIZE) 
        {
                /* send from ktx's pre-allocated/mapped contiguous buffer? */
                lib_copy_iov2buf (ktx->ktx_buffer, niov, iov, nob);
                ktx->ktx_frags.iov[0].Base = ktx->ktx_ebuffer; /* already mapped */
                ktx->ktx_frags.iov[0].Len = nob;
                ktx->ktx_nfrag = 1;
        }
        else
        {
                /* zero copy */
                ktx->ktx_nfrag = 0;       /* no frags mapped yet */
                rc = kqswnal_map_tx_iov (ktx, nob, niov, iov);
                if (rc != 0)
                        goto failed;
        }

        ktx->ktx_port    = (nob <= (sizeof (ptl_hdr_t) + KQSW_SMALLPAYLOAD)) ?
                        EP_SVC_LARGE_PORTALS_SMALL : EP_SVC_LARGE_PORTALS_LARGE;
        ktx->ktx_nid     = nid;
        ktx->ktx_state   = KTX_FORWARDING; /* kpr_put_packet() on completion */
        ktx->ktx_args[0] = fwd;

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
                ptl_hdr_t *hdr = (ptl_hdr_t *)page_address (krx->krx_pages[0]);

                CERROR("Failed to route packet from "LPX64" to "LPX64": %d\n",
                       NTOH__u64(hdr->src_nid), NTOH__u64(hdr->dest_nid),error);
        }

        kqswnal_requeue_rx (krx);
}

void
kqswnal_reply_complete (EP_RXD *rxd) 
{
        int           status = ep_rxd_status(rxd);
        kqswnal_tx_t *ktx = (kqswnal_tx_t *)ep_rxd_arg(rxd);
        kqswnal_rx_t *krx = (kqswnal_rx_t *)ktx->ktx_args[0];
        lib_msg_t    *msg = (lib_msg_t *)ktx->ktx_args[1];
        
        CDEBUG((status == EP_SUCCESS) ? D_NET : D_ERROR,
               "rxd %p, ktx %p, status %d\n", rxd, ktx, status);

        LASSERT (krx->krx_rxd == rxd);

        krx->krx_rpc_completed = 1;
        kqswnal_requeue_rx (krx);

        lib_finalize (&kqswnal_lib, NULL, msg);
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
        
        krx->krx_rpc_completed = 1;
        kqswnal_requeue_rx (krx);
}

void
kqswnal_requeue_rx (kqswnal_rx_t *krx)
{
        EP_STATUSBLK  blk;
        int           rc;

        LASSERT (atomic_read (&krx->krx_refcount) > 0);
        if (!atomic_dec_and_test (&krx->krx_refcount))
                return;

        if (!ep_rxd_isrpc(krx->krx_rxd) ||
            krx->krx_rpc_completed) {

                /* don't actually requeue on shutdown */
                if (kqswnal_data.kqn_shuttingdown)
                        return;
                
                ep_requeue_receive (krx->krx_rxd, kqswnal_rxhandler, krx,
                                    krx->krx_elanaddr, krx->krx_npages * PAGE_SIZE);
                return;
        }

        /* Sender wanted an RPC, but we didn't complete it (we must have
         * dropped the sender's message).  We complete it now with
         * failure... */
        memset (&blk, 0, sizeof (blk));
        blk.Status = -ECONNREFUSED;

        atomic_set (&krx->krx_refcount, 1);

        rc = ep_complete_rpc (krx->krx_rxd, 
                              kqswnal_rpc_complete, krx,
                              &blk, NULL, 0);
        if (rc == ESUCCESS) {
                /* callback will call me again to requeue, having set
                 * krx_rpc_completed... */
                return;
        }

        CERROR("can't complete RPC: %d\n", rc);

        /* we don't actually requeue on shutdown */
        if (kqswnal_data.kqn_shuttingdown)
                return;

        /* NB ep_complete_rpc() frees rxd on failure, so we have to requeue
         * from scratch here... */
        rc = ep_queue_receive(krx->krx_eprx, kqswnal_rxhandler, krx,
                              krx->krx_elanaddr, 
                              krx->krx_npages * PAGE_SIZE, 0);

        LASSERT (rc == ESUCCESS);
        /* This needs to be fixed by ep_complete_rpc NOT freeing
         * krx->krx_rxd on failure so we can just ep_requeue_receive() */
}

void
kqswnal_rx (kqswnal_rx_t *krx)
{
        ptl_hdr_t      *hdr = (ptl_hdr_t *) page_address (krx->krx_pages[0]);
        ptl_nid_t       dest_nid = NTOH__u64 (hdr->dest_nid);
        int             nob;
        int             niov;

        if (dest_nid == kqswnal_lib.ni.nid) { /* It's for me :) */
                /* NB krx requeued when lib_parse() calls back kqswnal_recv */
                lib_parse (&kqswnal_lib, hdr, krx);
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

        /* NB forwarding may destroy iov; rebuild every time */
        for (nob = krx->krx_nob, niov = 0; nob > 0; nob -= PAGE_SIZE, niov++)
        {
                LASSERT (niov < krx->krx_npages);
                krx->krx_iov[niov].iov_base= page_address(krx->krx_pages[niov]);
                krx->krx_iov[niov].iov_len = MIN(PAGE_SIZE, nob);
        }

        kpr_fwd_init (&krx->krx_fwd, dest_nid,
                      krx->krx_nob, niov, krx->krx_iov,
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
        LASSERT (atomic_read (&krx->krx_refcount) == 0);
        atomic_set (&krx->krx_refcount, 1);
        krx->krx_rpc_completed = 0;
        
        /* must receive a whole header to be able to parse */
        if (status != EP_SUCCESS || nob < sizeof (ptl_hdr_t))
        {
                /* receives complete with failure when receiver is removed */
                if (!kqswnal_data.kqn_shuttingdown)
                        CERROR("receive status failed with status %d nob %d\n",
                               ep_rxd_status(rxd), nob);

                kqswnal_requeue_rx (krx);
                return;
        }

        if (!in_interrupt()) {
                kqswnal_rx (krx);
                return;
        }

        spin_lock_irqsave (&kqswnal_data.kqn_sched_lock, flags);

        list_add_tail (&krx->krx_list, &kqswnal_data.kqn_readyrxds);
        if (waitqueue_active (&kqswnal_data.kqn_sched_waitq))
                wake_up (&kqswnal_data.kqn_sched_waitq);

        spin_unlock_irqrestore (&kqswnal_data.kqn_sched_lock, flags);
}

#if KQSW_CHECKSUM
void
kqswnal_csum_error (kqswnal_rx_t *krx, int ishdr)
{
        ptl_hdr_t *hdr = (ptl_hdr_t *)page_address (krx->krx_pages[0]);

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

static int
kqswnal_recvmsg (nal_cb_t     *nal,
                 void         *private,
                 lib_msg_t    *libmsg,
                 unsigned int  niov,
                 struct iovec *iov,
                 ptl_kiov_t   *kiov,
                 size_t        mlen,
                 size_t        rlen)
{
        kqswnal_rx_t *krx = (kqswnal_rx_t *)private;
        int           page;
        char         *page_ptr;
        int           page_nob;
        char         *iov_ptr;
        int           iov_nob;
        int           frag;
#if KQSW_CHECKSUM
        kqsw_csum_t   senders_csum;
        kqsw_csum_t   payload_csum = 0;
        kqsw_csum_t   hdr_csum = kqsw_csum(0, page_address(krx->krx_pages[0]),
                                           sizeof(ptl_hdr_t));
        size_t        csum_len = mlen;
        int           csum_frags = 0;
        int           csum_nob = 0;
        static atomic_t csum_counter;
        int           csum_verbose = (atomic_read(&csum_counter)%1000001) == 0;

        atomic_inc (&csum_counter);

        memcpy (&senders_csum, ((char *)page_address (krx->krx_pages[0])) +
                                sizeof (ptl_hdr_t), sizeof (kqsw_csum_t));
        if (senders_csum != hdr_csum)
                kqswnal_csum_error (krx, 1);
#endif
        CDEBUG(D_NET,"kqswnal_recv, mlen="LPSZ", rlen="LPSZ"\n", mlen, rlen);

        /* What was actually received must be >= payload.
         * This is an LASSERT, as lib_finalize() doesn't have a completion status. */
        LASSERT (krx->krx_nob >= KQSW_HDR_SIZE + mlen);
        LASSERT (mlen <= rlen);

        /* It must be OK to kmap() if required */
        LASSERT (kiov == NULL || !in_interrupt ());
        /* Either all pages or all vaddrs */
        LASSERT (!(kiov != NULL && iov != NULL));
        
        if (mlen != 0)
        {
                page     = 0;
                page_ptr = ((char *) page_address(krx->krx_pages[0])) +
                        KQSW_HDR_SIZE;
                page_nob = PAGE_SIZE - KQSW_HDR_SIZE;

                LASSERT (niov > 0);
                if (kiov != NULL) {
                        iov_ptr = ((char *)kmap (kiov->kiov_page)) + kiov->kiov_offset;
                        iov_nob = kiov->kiov_len;
                } else {
                        iov_ptr = iov->iov_base;
                        iov_nob = iov->iov_len;
                }

                for (;;)
                {
                        /* We expect the iov to exactly match mlen */
                        LASSERT (iov_nob <= mlen);
                        
                        frag = MIN (page_nob, iov_nob);
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
                                page_ptr = page_address(krx->krx_pages[page]);
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
        memcpy (&senders_csum, ((char *)page_address (krx->krx_pages[0])) +
                sizeof(ptl_hdr_t) + sizeof(kqsw_csum_t), sizeof(kqsw_csum_t));

        if (csum_len != rlen)
                CERROR("Unable to checksum data in user's buffer\n");
        else if (senders_csum != payload_csum)
                kqswnal_csum_error (krx, 0);

        if (csum_verbose)
                CERROR("hdr csum %lx, payload_csum %lx, csum_frags %d, "
                       "csum_nob %d\n",
                        hdr_csum, payload_csum, csum_frags, csum_nob);
#endif
        lib_finalize(nal, private, libmsg);

        kqswnal_requeue_rx (krx);

        return (rlen);
}

static int
kqswnal_recv(nal_cb_t     *nal,
             void         *private,
             lib_msg_t    *libmsg,
             unsigned int  niov,
             struct iovec *iov,
             size_t        mlen,
             size_t        rlen)
{
        return (kqswnal_recvmsg (nal, private, libmsg, niov, iov, NULL, mlen, rlen));
}

static int
kqswnal_recv_pages (nal_cb_t     *nal,
                    void         *private,
                    lib_msg_t    *libmsg,
                    unsigned int  niov,
                    ptl_kiov_t   *kiov,
                    size_t        mlen,
                    size_t        rlen)
{
        return (kqswnal_recvmsg (nal, private, libmsg, niov, NULL, kiov, mlen, rlen));
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
        long             flags;
        int              rc;
        int              counter = 0;
        int              did_something;

        kportal_daemonize ("kqswnal_sched");
        kportal_blockallsigs ();
        
        spin_lock_irqsave (&kqswnal_data.kqn_sched_lock, flags);

        while (!kqswnal_data.kqn_shuttingdown)
        {
                did_something = FALSE;

                if (!list_empty (&kqswnal_data.kqn_readyrxds))
                {
                        krx = list_entry(kqswnal_data.kqn_readyrxds.next,
                                         kqswnal_rx_t, krx_list);
                        list_del (&krx->krx_list);
                        spin_unlock_irqrestore(&kqswnal_data.kqn_sched_lock,
                                               flags);

                        kqswnal_rx (krx);

                        did_something = TRUE;
                        spin_lock_irqsave(&kqswnal_data.kqn_sched_lock, flags);
                }

                if (!list_empty (&kqswnal_data.kqn_delayedtxds))
                {
                        ktx = list_entry(kqswnal_data.kqn_delayedtxds.next,
                                         kqswnal_tx_t, ktx_list);
                        list_del (&ktx->ktx_list);
                        spin_unlock_irqrestore(&kqswnal_data.kqn_sched_lock,
                                               flags);

                        rc = kqswnal_launch (ktx);
                        if (rc != 0)          /* failed: ktx_nid down? */
                        {
                                CERROR("Failed delayed transmit to "LPX64
                                       ": %d\n", ktx->ktx_nid, rc);
                                kqswnal_tx_done (ktx, rc);
                        }

                        did_something = TRUE;
                        spin_lock_irqsave (&kqswnal_data.kqn_sched_lock, flags);
                }

                if (!list_empty (&kqswnal_data.kqn_delayedfwds))
                {
                        fwd = list_entry (kqswnal_data.kqn_delayedfwds.next, kpr_fwd_desc_t, kprfd_list);
                        list_del (&fwd->kprfd_list);
                        spin_unlock_irqrestore (&kqswnal_data.kqn_sched_lock, flags);

                        kqswnal_fwd_packet (NULL, fwd);

                        did_something = TRUE;
                        spin_lock_irqsave (&kqswnal_data.kqn_sched_lock, flags);
                }

                    /* nothing to do or hogging CPU */
                if (!did_something || counter++ == KQSW_RESCHED) {
                        spin_unlock_irqrestore(&kqswnal_data.kqn_sched_lock,
                                               flags);

                        counter = 0;

                        if (!did_something) {
                                rc = wait_event_interruptible (kqswnal_data.kqn_sched_waitq,
                                                               kqswnal_data.kqn_shuttingdown ||
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
