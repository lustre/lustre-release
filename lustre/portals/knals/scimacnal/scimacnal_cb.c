/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:cindent:
 *
 * Copyright (C) 2003 High Performance Computing Center North (HPC2N)
 *   Author: Niklas Edmundsson <nikke@hpc2n.umu.se>

 *
 * This file is part of Portals, http://www.sf.net/projects/lustre/
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

#include "scimacnal.h"

static int 
kscimacnal_read (nal_cb_t *nal, void *private,
                void *dst_addr, user_ptr src_addr, size_t len)
{
        CDEBUG(D_NET, "0x%Lx: reading %ld bytes from %p -> %p\n",
               nal->ni.nid, (long)len, src_addr, dst_addr );
        memcpy( dst_addr, src_addr, len );
        return 0;
}


static int 
kscimacnal_write(nal_cb_t *nal, void *private,
                user_ptr dst_addr, void *src_addr, size_t len)
{
        CDEBUG(D_NET, "0x%Lx: writing %ld bytes from %p -> %p\n",
               nal->ni.nid, (long)len, src_addr, dst_addr );
        memcpy( dst_addr, src_addr, len );
        return 0;
}


static void *
kscimacnal_malloc(nal_cb_t *nal, size_t len)
{
        void *buf;

        PORTAL_ALLOC(buf, len);
        return buf;
}


static void 
kscimacnal_free(nal_cb_t *nal, void *buf, size_t len)
{
        PORTAL_FREE(buf, len);
}


static void 
kscimacnal_printf(nal_cb_t *nal, const char *fmt, ...)
{
        va_list         ap;
        char msg[256]; 

        if (portal_debug & D_NET) {
                va_start( ap, fmt );
                vsnprintf( msg, sizeof(msg), fmt, ap );
                va_end( ap );

                printk("CPUId: %d %s",smp_processor_id(), msg);
        }
}


static void 
kscimacnal_cli(nal_cb_t *nal, unsigned long *flags)
{
        kscimacnal_data_t *data= nal->nal_data;

        spin_lock_irqsave(&data->ksci_dispatch_lock,*flags);
}


static void 
kscimacnal_sti(nal_cb_t *nal, unsigned long *flags)
{
        kscimacnal_data_t *data= nal->nal_data; 

        spin_unlock_irqrestore(&data->ksci_dispatch_lock,*flags);
}


static int 
kscimacnal_dist(nal_cb_t *nal, ptl_nid_t nid, unsigned long *dist)
{
        /* FIXME: Network distance has a meaning, but is there no easy
         * way to figure it out (depends on routing) */

        if ( nal->ni.nid == nid ) {
                *dist = 0;
        } else {
                *dist = 1;
        }

        return 0;
}


static
char * get_mac_error(mac_status_t status) 
{
        switch(status) {
                case MAC_MSG_STAT_OK:
                        return "MAC_MSG_STAT_OK";
                case MAC_MSG_STAT_FREED:
                        return "MAC_MSG_STAT_FREED";
                case MAC_MSG_STAT_ABORTED:
                        return "MAC_MSG_STAT_ABORTED";
                case MAC_MSG_STAT_TIMEDOUT:
                        return "MAC_MSG_STAT_TIMEDOUT";
                case MAC_MSG_STAT_NODEUNREACH:
                        return "MAC_MSG_STAT_NODEUNREACH";
                case MAC_MSG_STAT_NETDOWN:
                        return "MAC_MSG_STAT_NETDOWN";
                case MAC_MSG_STAT_RESET:
                        return "MAC_MSG_STAT_RESET";
                case MAC_MSG_STAT_INITFAILED:
                        return "MAC_MSG_STAT_INITFAILED";
                case MAC_MSG_STAT_SYNCFAILED:
                        return "MAC_MSG_STAT_SYNCFAILED";
                case MAC_MSG_STAT_BADPROTO:
                        return "MAC_MSG_STAT_BADPROTO";
                case MAC_MSG_STAT_NOBUFSPACE:
                        return "MAC_MSG_STAT_NOBUFSPACE";
                case MAC_MSG_STAT_CONGESTION:
                        return "MAC_MSG_STAT_CONGESTION";
                case MAC_MSG_STAT_OTHER:
                        return "MAC_MSG_STAT_OTHER";
                default:
                        return "Unknown error";
        }
}


/* FIXME add routing code here ? */

/* Called by ScaMac when transmission is complete  (ie. message is released) */
static void 
kscimacnal_txrelease(mac_mblk_t *msg, mac_msg_status_t status, void *context)
{
        kscimacnal_tx_t *ktx = (kscimacnal_tx_t *)context;
        int err=0;
        
        LASSERT (ktx != NULL);

        /* Euh, there is no feedback when transmission fails?! */
        switch(status) {
                case MAC_MSG_STAT_OK:        /* normal */
                        break;
                default:
                        CERROR("%s (%d):\n", get_mac_error(status), status);
                        err = -EIO;
                        break;
        }

        lib_finalize(ktx->ktx_nal, ktx->ktx_private, ktx->ktx_cookie);

        PORTAL_FREE(ktx, (sizeof(kscimacnal_tx_t)));
}


/* Called by portals when it wants to send a message.
 * Since ScaMAC has it's own TX thread we don't bother setting up our own. */
static int 
kscimacnal_send(nal_cb_t        *nal,
           void            *private,
           lib_msg_t       *cookie,
           ptl_hdr_t       *hdr,
           int              type, 
           ptl_nid_t        nid,
           ptl_pid_t        pid,
           unsigned int     payload_niov,
           struct iovec    *payload_iov,
           size_t           payload_len)
{
        kscimacnal_tx_t    *ktx=NULL;
        kscimacnal_data_t  *ksci = nal->nal_data;
        int              rc=0;
        int              buf_len = sizeof(ptl_hdr_t) + payload_len;
        mac_mblk_t      *msg=NULL, *lastblk, *newblk;
        unsigned long   physaddr;
        

        CDEBUG(D_NET, "sending %d bytes from %p to nid 0x%Lx niov: %d\n",
               payload_len, payload_iov, nid, payload_niov);

        LASSERT(ksci != NULL);

        LASSERT(hdr != NULL);

        /* Do real check if we can send this */
        if (buf_len > mac_get_mtusize(ksci->ksci_machandle)) {
                CERROR("kscimacnal:request exceeds TX MTU size (%ld).\n",
                                mac_get_mtusize(ksci->ksci_machandle));
                return -EINVAL;
        }


        /* save transaction info for later finalize and cleanup */
        PORTAL_ALLOC(ktx, (sizeof(kscimacnal_tx_t)));
        if (!ktx) {
                return -ENOMEM;
        }

        /* *SIGH* hdr is a stack variable in the calling function, so we
         * need to copy it to a buffer. Zerocopy magic (or is it just
         * deferred memcpy?) is annoying sometimes.  */
        memcpy(&ktx->ktx_hdr, hdr, sizeof(ptl_hdr_t));

        /* First, put the header in the main message mblk */
        msg = mac_alloc_mblk(&ktx->ktx_hdr, sizeof(ptl_hdr_t),
                        kscimacnal_txrelease, ktx);
        if (!msg) {
                PORTAL_FREE(ktx, (sizeof(kscimacnal_tx_t)));
                return -ENOMEM;
        }
        mac_put_mblk(msg, sizeof(ptl_hdr_t));
        lastblk=msg;

        /* Allocate additional mblks for each iov as needed.
         * Essentially lib_copy_iov2buf with a twist or two */
        while (payload_len > 0)
        {
                ptl_size_t nob;

                LASSERT (payload_niov > 0);

                nob = MIN (payload_iov->iov_len, payload_len);

                /* We don't need a callback on the additional mblks, since
                 * all release callbacks seems to be called when the entire
                 * message has been sent */
                newblk=mac_alloc_mblk(payload_iov->iov_base, nob, NULL, NULL);
                if(!newblk) {
                        mac_free_msg(msg);
                        PORTAL_FREE(ktx, (sizeof(kscimacnal_tx_t)));
                        return -ENOMEM;
                }
                mac_put_mblk(newblk, nob);
                mac_link_mblk(lastblk, newblk);
                lastblk=newblk;

                payload_len -= nob;
                payload_niov--;
                payload_iov++;
        }

        ktx->ktx_nal = nal;
        ktx->ktx_private = private;
        ktx->ktx_cookie = cookie;

        CDEBUG(D_NET, "mac_send %d bytes to nid: 0x%Lx\n", buf_len, nid);

        physaddr = htonl(nid);

        if((rc=mac_send(ksci->ksci_machandle, msg,
                                        (mac_physaddr_t *) &physaddr))) {
                CERROR("kscimacnal: mac_send() failed, rc=%d\n", rc);
                mac_free_msg(msg);
                PORTAL_FREE(ktx, (sizeof(kscimacnal_tx_t)));
                return rc;
        }

        return 0;
}


void
kscimacnal_fwd_packet (void *arg, kpr_fwd_desc_t *fwd)
{
        CERROR ("forwarding not implemented\n");
}


/* Process a received portals packet */
/* Called by the ScaMac RX thread when a packet is received */
void
kscimacnal_rx(mac_handle_t *handle, mac_mblk_t *msg, mac_msg_type_t type,
                void *userdata)
{
        ptl_hdr_t       *hdr = NULL;
        kscimacnal_rx_t     krx; 
        mac_size_t       size;
        kscimacnal_data_t  *ksci = userdata;

        LASSERT(ksci != NULL);

        if ( !ksci->ksci_init || ksci->ksci_shuttingdown || 
                    type == MAC_MSG_TYPE_CTRL || type == MAC_MSG_TYPE_OTHER ) {
                /* We're not interested in messages not for us, ignore */
                mac_free_msg(msg);
                return;
        }

        size = mac_msg_size(msg);

        CDEBUG(D_NET,"msg %p type %d, size %ld bytes (%ld mblks)\n", 
                        msg, type, size, mac_msg_mblks(msg));

        if( size < sizeof( ptl_hdr_t ) ) {
                /* XXX what's this for? */
                if (ksci->ksci_shuttingdown)
                        return;
                CERROR("kscimacnal: did not receive complete portal header,"
                                "size= %ld\n", size);
                /* Free the message before exiting */
                mac_free_msg(msg);
                return;
        }

        /* Provide everything we know */
        krx.handle = handle;
        krx.msg = msg;
        krx.type = type;
        krx.userdata = userdata;

        /* mac_msg_next returns the next mblk with unread data */
        hdr = mac_get_mblk(mac_msg_next(msg), sizeof(ptl_hdr_t) );

        if(!hdr) {
                CERROR("kscimacnal: no data block in message %p\n", msg);
                mac_free_msg(msg);
                return;
        }

        if ( hdr->dest_nid == kscimacnal_lib.ni.nid ) {
                PROF_START(lib_parse);
                /* sets wanted_len, iovs etc and calls our callback */
                lib_parse(&kscimacnal_lib, hdr, &krx);
                PROF_FINISH(lib_parse);
#if 0 /* FIXME: Is it possible to detect this? */
        } else if (kgmnal_ispeer(hdr->dest_nid)) {
                /* should have gone direct to peer */
                CERROR("dropping packet from 0x%llx to 0x%llx:"
                                "target is a  peer\n",
                                hdr->src_nid, hdr->dest_nid);
                kgmnal_requeue_rx(&krx);
#endif /* if 0 FIXME */
        } else {
                /* forward to gateway */
                CERROR("forwarding not implemented, mynid=0x%llx dest=0x%llx\n",
                                kscimacnal_lib.ni.nid, hdr->dest_nid);
        }

        mac_free_msg(msg);

        CDEBUG(D_NET, "msg %p: Done\n", msg);
}


/* Called by portals to process a recieved packet */
static int kscimacnal_recv(nal_cb_t     *nal, 
                      void         *private, 
                      lib_msg_t    *cookie, 
                      unsigned int  niov, 
                      struct iovec *iov, 
                      size_t        mlen, 
                      size_t        rlen)
{
        kscimacnal_rx_t    *krx = private;
        mac_mblk_t      *mblk;
        void            *src;
        mac_size_t       pkt_len;
        ptl_size_t       iovused=0;

        LASSERT (krx != NULL);
        LASSERT (krx->msg != NULL);

        CDEBUG(D_NET,"msg %p: mlen=%d, rlen=%d, niov=%d\n",
                        krx->msg, mlen, rlen, niov);

        /* What was actually received must be >= what sender claims to have
         * sent.  This is an LASSERT, since lib-move doesn't check cb return
         * code yet. Also, rlen seems to be negative when mlen==0 so don't
         * assert on that.
         */
        LASSERT (mlen==0 || mac_msg_size(krx->msg) >= sizeof(ptl_hdr_t)+rlen);
        LASSERT (mlen==0 || mlen <= rlen);

        PROF_START(memcpy);

        /* mac_msg_next returns next mblk with unread data (ie. can
         * be same mblk */
        while (mlen != 0 && (mblk = mac_msg_next(krx->msg))) {
                pkt_len = mac_mblk_len(mblk);
                src = mac_get_mblk(mblk, pkt_len); /* Next unread block */

                CDEBUG(D_NET,"msg %p: mblk: %p pkt_len: %ld  src: %p\n",
                                krx->msg, mblk, pkt_len, src);

                LASSERT(src != NULL);

                /* Essentially lib_copy_buf2iov but with continuation support,
                 * we "gracefully" thrash the argument vars ;) */
                while (pkt_len > 0) {
                        ptl_size_t nob;

                        LASSERT (niov > 0);

                        LASSERT(iovused < iov->iov_len);

                        nob = MIN (iov->iov_len-iovused, pkt_len);
                        CDEBUG(D_NET, "iovbase: %p iovlen: %d src: %p  nob: %d "
                                        "iovused: %d\n",
                                        iov->iov_base, iov->iov_len,
                                        src, nob, iovused);

                        memcpy (iov->iov_base+iovused, src, nob);
                        pkt_len -= nob;
                        src += nob;

                        if(nob+iovused < iov->iov_len) {
                                /* We didn't use all of the iov */
                                iovused+=nob;
                        }
                        else {
                                niov--;
                                iov++;
                                iovused=0;
                        }
                }
        }
        PROF_FINISH(memcpy);

        CDEBUG(D_NET, "Calling lib_finalize.\n");

        PROF_START(lib_finalize);
        lib_finalize(nal, private, cookie);
        PROF_FINISH(lib_finalize);

        CDEBUG(D_NET, "Done.\n");

        return rlen;
}


nal_cb_t kscimacnal_lib = {
        nal_data:       &kscimacnal_data,               /* NAL private data */
        cb_send:         kscimacnal_send,
        cb_send_pages:   NULL,                  /* Ignore for now */
        cb_recv:         kscimacnal_recv,
        cb_recv_pages:   NULL,
        cb_read:         kscimacnal_read,
        cb_write:        kscimacnal_write,
        cb_malloc:       kscimacnal_malloc,
        cb_free:         kscimacnal_free,
        cb_printf:       kscimacnal_printf,
        cb_cli:          kscimacnal_cli,
        cb_sti:          kscimacnal_sti,
        cb_dist:         kscimacnal_dist
};
