/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lib/lib-move.c
 * Data movement routines
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *  Copyright (c) 2001-2002 Sandia National Laboratories
 *
 *   This file is part of Portals, http://www.sf.net/projects/sandiaportals/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2.1 of the GNU Lesser General
 *   Public License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with Portals; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef __KERNEL__
# include <stdio.h>
#else
# define DEBUG_SUBSYSTEM S_PORTALS
# include <linux/kp30.h>
#endif
#include <portals/p30.h>
#include <portals/lib-p30.h>
#include <portals/arg-blocks.h>

/*
 * Right now it does not check access control lists.
 *
 * We only support one MD per ME, which is how the Portals 3.1 spec is written.
 * All previous complication is removed.
 */

static lib_me_t *
lib_find_me(nal_cb_t *nal, int index, int op_mask, ptl_nid_t src_nid,
            ptl_pid_t src_pid, ptl_size_t rlength, ptl_size_t roffset,
            ptl_match_bits_t match_bits, ptl_size_t *mlength_out,
            ptl_size_t *offset_out, int *unlink_out)
{
        lib_ni_t         *ni = &nal->ni;
        struct list_head *match_list = &ni->tbl.tbl[index];
        struct list_head *tmp;
        lib_me_t         *me;
        lib_md_t         *md;
        ptl_size_t        mlength;
        ptl_size_t        offset;

        ENTRY;

        CDEBUG (D_NET, "Request from "LPU64".%d of length %d into portal %d "
                "MB="LPX64"\n", src_nid, src_pid, rlength, index, match_bits);

        if (index < 0 || index >= ni->tbl.size) {
                CERROR("Invalid portal %d not in [0-%d]\n",
                       index, ni->tbl.size);
                goto failed;
        }

        list_for_each (tmp, match_list) {
                me = list_entry(tmp, lib_me_t, me_list);
                md = me->md;

                 /* ME attached but MD not attached yet */
                if (md == NULL)
                        continue;

                LASSERT (me == md->me);

                /* MD deactivated */
                if (md->threshold == 0)
                        continue;

                /* mismatched MD op */
                if ((md->options & op_mask) == 0)
                        continue;

                /* mismatched ME nid/pid? */
                if (me->match_id.nid != PTL_NID_ANY &&
                    me->match_id.nid != src_nid)
                        continue;

                if (me->match_id.pid != PTL_PID_ANY &&
                    me->match_id.pid != src_pid)
                        continue;

                /* mismatched ME matchbits? */
                if (((me->match_bits ^ match_bits) & ~me->ignore_bits) != 0)
                        continue;

                /* Hurrah! This _is_ a match; check it out... */

                if ((md->options & PTL_MD_MANAGE_REMOTE) == 0)
                        offset = md->offset;
                else
                        offset = roffset;

                mlength = md->length - offset;
                if ((md->options & PTL_MD_MAX_SIZE) != 0 &&
                    mlength > md->max_size)
                        mlength = md->max_size;

                if (rlength <= mlength) {        /* fits in allowed space */
                        mlength = rlength;
                } else if ((md->options & PTL_MD_TRUNCATE) == 0) {
                        /* this packet _really_ is too big */
                        CERROR("Matching packet %d too big: %d left, "
                               "%d allowed\n", rlength, md->length - offset,
                               mlength);
                        goto failed;
                }

                md->offset = offset + mlength;

                *offset_out = offset;
                *mlength_out = mlength;
                *unlink_out = ((md->options & PTL_MD_AUTO_UNLINK) != 0 &&
                               md->offset >= (md->length - md->max_size));
                RETURN (me);
        }

 failed:
        CERROR (LPU64": Dropping %s from "LPU64".%d portal %d match "LPX64
                " offset %d length %d: no match\n",
                ni->nid, (op_mask == PTL_MD_OP_GET) ? "GET" : "PUT",
                src_nid, src_pid, index, match_bits, roffset, rlength);
        RETURN(NULL);
}

int do_PtlFailNid (nal_cb_t *nal, void *private, void *v_args, void *v_ret)
{
        PtlFailNid_in     *args = v_args;
        PtlFailNid_out    *ret  = v_ret;
        lib_test_peer_t   *tp;
        unsigned long      flags;
        struct list_head  *el;
        struct list_head  *next;
        struct list_head   cull;
        
        if (args->threshold != 0) {
                /* Adding a new entry */
                tp = (lib_test_peer_t *)nal->cb_malloc (nal, sizeof (*tp));
                if (tp == NULL)
                        return (ret->rc = PTL_FAIL);
                
                tp->tp_nid = args->nid;
                tp->tp_threshold = args->threshold;
                
                state_lock (nal, &flags);
                list_add (&tp->tp_list, &nal->ni.ni_test_peers);
                state_unlock (nal, &flags);
                return (ret->rc = PTL_OK);
        }
        
        /* removing entries */
        INIT_LIST_HEAD (&cull);
        
        state_lock (nal, &flags);

        list_for_each_safe (el, next, &nal->ni.ni_test_peers) {
                tp = list_entry (el, lib_test_peer_t, tp_list);
                
                if (tp->tp_threshold == 0 ||    /* needs culling anyway */
                    args->nid == PTL_NID_ANY || /* removing all entries */
                    tp->tp_nid == args->nid)    /* matched this one */
                {
                        list_del (&tp->tp_list);
                        list_add (&tp->tp_list, &cull);
                }
        }
        
        state_unlock (nal, &flags);
                
        while (!list_empty (&cull)) {
                tp = list_entry (cull.next, lib_test_peer_t, tp_list);

                list_del (&tp->tp_list);
                nal->cb_free (nal, tp, sizeof (*tp));
        }
        return (ret->rc = PTL_OK);
}

static int
fail_peer (nal_cb_t *nal, ptl_nid_t nid, int outgoing) 
{
        lib_test_peer_t  *tp;
        struct list_head *el;
        struct list_head *next;
        unsigned long     flags;
        struct list_head  cull;
        int               fail = 0;

        INIT_LIST_HEAD (&cull);
        
        state_lock (nal, &flags);

        list_for_each_safe (el, next, &nal->ni.ni_test_peers) {
                tp = list_entry (el, lib_test_peer_t, tp_list);

                if (tp->tp_threshold == 0) {
                        /* zombie entry */
                        if (outgoing) {
                                /* only cull zombies on outgoing tests,
                                 * since we may be at interrupt priority on
                                 * incoming messages. */
                                list_del (&tp->tp_list);
                                list_add (&tp->tp_list, &cull);
                        }
                        continue;
                }
                        
                if (tp->tp_nid == PTL_NID_ANY || /* fail every peer */
                    nid == tp->tp_nid) {        /* fail this peer */
                        fail = 1;
                        
                        if (tp->tp_threshold != PTL_MD_THRESH_INF) {
                                tp->tp_threshold--;
                                if (outgoing &&
                                    tp->tp_threshold == 0) {
                                        /* see above */
                                        list_del (&tp->tp_list);
                                        list_add (&tp->tp_list, &cull);
                                }
                        }
                        break;
                }
        }
        
        state_unlock (nal, &flags);

        while (!list_empty (&cull)) {
                tp = list_entry (cull.next, lib_test_peer_t, tp_list);
                list_del (&tp->tp_list);
                
                nal->cb_free (nal, tp, sizeof (*tp));
        }

        return (fail);
}

ptl_size_t
lib_iov_nob (int niov, struct iovec *iov)
{
        ptl_size_t nob = 0;
        
        while (niov-- > 0)
                nob += (iov++)->iov_len;
        
        return (nob);
}

void
lib_copy_iov2buf (char *dest, int niov, struct iovec *iov, ptl_size_t len)
{
        ptl_size_t nob;

        while (len > 0)
        {
                LASSERT (niov > 0);
                nob = MIN (iov->iov_len, len);
                memcpy (dest, iov->iov_base, nob);

                len -= nob;
                dest += nob;
                niov--;
                iov++;
        }
}

void
lib_copy_buf2iov (int niov, struct iovec *iov, char *src, ptl_size_t len)
{
        ptl_size_t nob;

        while (len > 0)
        {
                LASSERT (niov > 0);
                nob = MIN (iov->iov_len, len);
                memcpy (iov->iov_base, src, nob);
                
                len -= nob;
                src += nob;
                niov--;
                iov++;
        }
}

static int
lib_extract_iov (struct iovec *dst, lib_md_t *md,
                 ptl_size_t offset, ptl_size_t len)
{
        /* Initialise 'dst' to the subset of 'src' starting at 'offset',
         * for exactly 'len' bytes, and return the number of entries.
         * NB not destructive to 'src' */
        int             src_niov = md->md_niov;  
        struct iovec   *src = md->md_iov.iov;
        ptl_size_t      frag_len;
        int             dst_niov;

        LASSERT (len >= 0);
        LASSERT (offset >= 0);
        LASSERT (offset + len <= md->length);
        
        if (len == 0)                           /* no data => */
                return (0);                     /* no frags */

        LASSERT (src_niov > 0);
        while (offset >= src->iov_len) {      /* skip initial frags */
                offset -= src->iov_len;
                src_niov--;
                src++;
                LASSERT (src_niov > 0);
        }

        dst_niov = 1;
        for (;;) {
                LASSERT (src_niov > 0);
                LASSERT (dst_niov <= PTL_MD_MAX_IOV);
                
                frag_len = src->iov_len - offset;
                dst->iov_base = ((char *)src->iov_base) + offset;

                if (len <= frag_len) {
                        dst->iov_len = len;
                        return (dst_niov);
                }
                
                dst->iov_len = frag_len;

                len -= frag_len;
                dst++;
                src++;
                dst_niov++;
                src_niov--;
                offset = 0;
        }
}

#ifndef __KERNEL__
ptl_size_t
lib_kiov_nob (int niov, ptl_kiov_t *kiov) 
{
        LASSERT (0);
        return (0);
}

void
lib_copy_kiov2buf (char *dest, int niov, ptl_kiov_t *kiov, ptl_size_t len)
{
        LASSERT (0);
}

void
lib_copy_buf2kiov (int niov, ptl_kiov_t *kiov, char *dest, ptl_size_t len)
{
        LASSERT (0);
}

static int
lib_extract_kiov (ptl_kiov_t *dst, lib_md_t *md,
                  ptl_size_t offset, ptl_size_t len)
{
        LASSERT (0);
}

#else

ptl_size_t
lib_kiov_nob (int niov, ptl_kiov_t *kiov) 
{
        ptl_size_t  nob = 0;

        while (niov-- > 0)
                nob += (kiov++)->kiov_len;

        return (nob);
}

void
lib_copy_kiov2buf (char *dest, int niov, ptl_kiov_t *kiov, ptl_size_t len)
{
        ptl_size_t  nob;
        char       *addr;
        
        LASSERT (!in_interrupt ());
        while (len > 0)
        {
                LASSERT (niov > 0);
                nob = MIN (kiov->kiov_len, len);
                
                addr = ((char *)kmap (kiov->kiov_page)) + kiov->kiov_offset;
                memcpy (dest, addr, nob);
                kunmap (kiov->kiov_page);
                
                len -= nob;
                dest += nob;
                niov--;
                kiov++;
        }
}

void
lib_copy_buf2kiov (int niov, ptl_kiov_t *kiov, char *src, ptl_size_t len)
{
        ptl_size_t  nob;
        char       *addr;

        LASSERT (!in_interrupt ());
        while (len > 0)
        {
                LASSERT (niov > 0);
                nob = MIN (kiov->kiov_len, len);
                
                addr = ((char *)kmap (kiov->kiov_page)) + kiov->kiov_offset;
                memcpy (addr, src, nob);
                kunmap (kiov->kiov_page);
                
                len -= nob;
                src += nob;
                niov--;
                kiov++;
        }
}

static int
lib_extract_kiov (ptl_kiov_t *dst, lib_md_t *md,
                  ptl_size_t offset, ptl_size_t len)
{
        /* Initialise 'dst' to the subset of 'src' starting at 'offset',
         * for exactly 'len' bytes, and return the number of entries.
         * NB not destructive to 'src' */
        int             src_niov = md->md_niov;  
        ptl_kiov_t     *src = md->md_iov.kiov;
        ptl_size_t      frag_len;
        int             dst_niov;

        LASSERT (len >= 0);
        LASSERT (offset >= 0);
        LASSERT (offset + len <= md->length);
        
        if (len == 0)                           /* no data => */
                return (0);                     /* no frags */

        LASSERT (src_niov > 0);
        while (offset >= src->kiov_len) {      /* skip initial frags */
                offset -= src->kiov_len;
                src_niov--;
                src++;
                LASSERT (src_niov > 0);
        }

        dst_niov = 1;
        for (;;) {
                LASSERT (src_niov > 0);
                LASSERT (dst_niov <= PTL_MD_MAX_IOV);
                
                frag_len = src->kiov_len - offset;
                dst->kiov_page = src->kiov_page;
                dst->kiov_offset = src->kiov_offset + offset;

                if (len <= frag_len) {
                        dst->kiov_len = len;
                        LASSERT (dst->kiov_offset + dst->kiov_len <= PAGE_SIZE);
                        return (dst_niov);
                }

                dst->kiov_len = frag_len;
                LASSERT (dst->kiov_offset + dst->kiov_len <= PAGE_SIZE);

                len -= frag_len;
                dst++;
                src++;
                dst_niov++;
                src_niov--;
                offset = 0;
        }
}
#endif

void
lib_recv (nal_cb_t *nal, void *private, lib_msg_t *msg, lib_md_t *md,
          ptl_size_t offset, ptl_size_t mlen, ptl_size_t rlen)
{
        int   niov;

        if (mlen == 0)
                nal->cb_recv (nal, private, msg, 0, NULL, 0, rlen);
        else if ((md->options & PTL_MD_KIOV) == 0) {
                niov = lib_extract_iov (msg->msg_iov.iov, md, offset, mlen);
                nal->cb_recv (nal, private, msg,
                              niov, msg->msg_iov.iov, mlen, rlen);
        } else {
                niov = lib_extract_kiov (msg->msg_iov.kiov, md, offset, mlen);
                nal->cb_recv_pages (nal, private, msg, 
                                    niov, msg->msg_iov.kiov, mlen, rlen);
        }
}

int
lib_send (nal_cb_t *nal, void *private, lib_msg_t *msg,
          ptl_hdr_t *hdr, int type, ptl_nid_t nid, ptl_pid_t pid,
          lib_md_t *md, ptl_size_t offset, ptl_size_t len) 
{
        int   niov;

        if (len == 0)
                return (nal->cb_send (nal, private, msg, 
                                      hdr, type, nid, pid,
                                      0, NULL, 0));
        
        if ((md->options & PTL_MD_KIOV) == 0) {
                niov = lib_extract_iov (msg->msg_iov.iov, md, offset, len);
                return (nal->cb_send (nal, private, msg, 
                                      hdr, type, nid, pid,
                                      niov, msg->msg_iov.iov, len));
        }

        niov = lib_extract_kiov (msg->msg_iov.kiov, md, offset, len);
        return (nal->cb_send_pages (nal, private, msg, 
                                    hdr, type, nid, pid,
                                    niov, msg->msg_iov.kiov, len));
}

static lib_msg_t *
get_new_msg (nal_cb_t *nal, lib_md_t *md)
{
        /* ALWAYS called holding the state_lock */
        lib_counters_t *counters = &nal->ni.counters;
        lib_msg_t      *msg      = lib_msg_alloc (nal);

        if (msg == NULL)
                return (NULL);

        memset (msg, 0, sizeof (*msg));

        msg->send_ack = 0;

        msg->md = md;
        msg->ev.arrival_time = get_cycles();
        md->pending++;
        if (md->threshold != PTL_MD_THRESH_INF) {
                LASSERT (md->threshold > 0);
                md->threshold--;
        }

        counters->msgs_alloc++;
        if (counters->msgs_alloc > counters->msgs_max)
                counters->msgs_max = counters->msgs_alloc;

        list_add (&msg->msg_list, &nal->ni.ni_active_msgs);

        return (msg);
}


/*
 * Incoming messages have a ptl_msg_t object associated with them
 * by the library.  This object encapsulates the state of the
 * message and allows the NAL to do non-blocking receives or sends
 * of long messages.
 *
 */
static int parse_put(nal_cb_t * nal, ptl_hdr_t * hdr, void *private)
{
        lib_ni_t        *ni = &nal->ni;
        ptl_size_t       mlength = 0;
        ptl_size_t       offset = 0;
        int              unlink = 0;
        lib_me_t        *me;
        lib_md_t        *md;
        lib_msg_t       *msg;
        unsigned long    flags;

        /* Convert put fields to host byte order */
        hdr->msg.put.match_bits = NTOH__u64 (hdr->msg.put.match_bits);
        hdr->msg.put.ptl_index = NTOH__u32 (hdr->msg.put.ptl_index);
        hdr->msg.put.offset = NTOH__u32 (hdr->msg.put.offset);

        state_lock(nal, &flags);

        me = lib_find_me(nal, hdr->msg.put.ptl_index, PTL_MD_OP_PUT,
                         hdr->src_nid, hdr->src_pid,
                         PTL_HDR_LENGTH (hdr), hdr->msg.put.offset,
                         hdr->msg.put.match_bits,
                         &mlength, &offset, &unlink);
        if (me == NULL)
                goto drop;

        md = me->md;
        CDEBUG(D_NET, "Incoming put index %x from "LPU64"/%u of length %d/%d "
               "into md "LPX64" [%d] + %d\n", hdr->msg.put.ptl_index,
               hdr->src_nid, hdr->src_pid, mlength, PTL_HDR_LENGTH(hdr), 
               md->md_lh.lh_cookie, md->md_niov, offset);

        msg = get_new_msg (nal, md);
        if (msg == NULL) {
                CERROR(LPU64": Dropping PUT from "LPU64": can't allocate msg\n",
                       ni->nid, hdr->src_nid);
                goto drop;
        }

        if (!ptl_is_wire_handle_none(&hdr->msg.put.ack_wmd) &&
            !(md->options & PTL_MD_ACK_DISABLE)) {
                msg->send_ack = 1;
                msg->ack_wmd = hdr->msg.put.ack_wmd;
                msg->nid = hdr->src_nid;
                msg->pid = hdr->src_pid;
                msg->ev.match_bits = hdr->msg.put.match_bits;
        }

        if (md->eq) {
                msg->ev.type = PTL_EVENT_PUT;
                msg->ev.initiator.nid = hdr->src_nid;
                msg->ev.initiator.pid = hdr->src_pid;
                msg->ev.portal = hdr->msg.put.ptl_index;
                msg->ev.match_bits = hdr->msg.put.match_bits;
                msg->ev.rlength = PTL_HDR_LENGTH(hdr);
                msg->ev.mlength = mlength;
                msg->ev.offset = offset;
                msg->ev.hdr_data = hdr->msg.put.hdr_data;

                /* NB if this match has exhausted the MD, we can't be sure
                 * that this event will the the last one associated with
                 * this MD in the event queue (another message already
                 * matching this ME/MD could end up being last).  So we
                 * remember the ME handle anyway and check again when we're
                 * allocating our slot in the event queue.
                 */
                ptl_me2handle (&msg->ev.unlinked_me, me);

                lib_md_deconstruct(nal, md, &msg->ev.mem_desc);
        }

        ni->counters.recv_count++;
        ni->counters.recv_length += mlength;

        /* only unlink after MD's pending count has been bumped
         * in get_new_msg() otherwise lib_me_unlink() will nuke it */
        if (unlink) {
                md->md_flags |= PTL_MD_FLAG_AUTO_UNLINKED;
                lib_me_unlink (nal, me);
        }

        state_unlock(nal, &flags);

        lib_recv (nal, private, msg, md, offset, mlength, PTL_HDR_LENGTH (hdr));
        return 0;

 drop:
        nal->ni.counters.drop_count++;
        nal->ni.counters.drop_length += PTL_HDR_LENGTH(hdr);
        state_unlock (nal, &flags);
        lib_recv (nal, private, NULL, NULL, 0, 0, PTL_HDR_LENGTH (hdr));
        return -1;
}

static int parse_get(nal_cb_t * nal, ptl_hdr_t * hdr, void *private)
{
        lib_ni_t        *ni = &nal->ni;
        ptl_size_t       mlength = 0;
        ptl_size_t       offset = 0;
        int              unlink = 0;
        lib_me_t        *me;
        lib_md_t        *md;
        lib_msg_t       *msg;
        ptl_hdr_t        reply;
        unsigned long    flags;
        int              rc;

        /* Convert get fields to host byte order */
        hdr->msg.get.match_bits = NTOH__u64 (hdr->msg.get.match_bits);
        hdr->msg.get.ptl_index = NTOH__u32 (hdr->msg.get.ptl_index);
        hdr->msg.get.sink_length = NTOH__u32 (hdr->msg.get.sink_length);
        hdr->msg.get.src_offset = NTOH__u32 (hdr->msg.get.src_offset);

        /* compatibility check until field is deleted */
        if (hdr->msg.get.return_offset != 0)
                CERROR("Unexpected non-zero get.return_offset %x from "
                       LPU64"\n", hdr->msg.get.return_offset, hdr->src_nid);

        state_lock(nal, &flags);

        me = lib_find_me(nal, hdr->msg.get.ptl_index, PTL_MD_OP_GET,
                         hdr->src_nid, hdr->src_pid,
                         hdr->msg.get.sink_length, hdr->msg.get.src_offset,
                         hdr->msg.get.match_bits,
                         &mlength, &offset, &unlink);
        if (me == NULL)
                goto drop;

        md = me->md;
        CDEBUG(D_NET, "Incoming get index %d from "LPU64".%u of length %d/%d "
               "from md "LPX64" [%d] + %d\n", hdr->msg.get.ptl_index,
               hdr->src_nid, hdr->src_pid, mlength, PTL_HDR_LENGTH(hdr), 
               md->md_lh.lh_cookie, md->md_niov, offset);

        msg = get_new_msg (nal, md);
        if (msg == NULL) {
                CERROR(LPU64": Dropping GET from "LPU64": can't allocate msg\n",
                       ni->nid, hdr->src_nid);
                goto drop;
        }

        if (md->eq) {
                msg->ev.type = PTL_EVENT_GET;
                msg->ev.initiator.nid = hdr->src_nid;
                msg->ev.initiator.pid = hdr->src_pid;
                msg->ev.portal = hdr->msg.get.ptl_index;
                msg->ev.match_bits = hdr->msg.get.match_bits;
                msg->ev.rlength = PTL_HDR_LENGTH(hdr);
                msg->ev.mlength = mlength;
                msg->ev.offset = offset;
                msg->ev.hdr_data = 0;

                /* NB if this match has exhausted the MD, we can't be sure
                 * that this event will the the last one associated with
                 * this MD in the event queue (another message already
                 * matching this ME/MD could end up being last).  So we
                 * remember the ME handle anyway and check again when we're
                 * allocating our slot in the event queue.
                 */
                ptl_me2handle (&msg->ev.unlinked_me, me);

                lib_md_deconstruct(nal, md, &msg->ev.mem_desc);
        }

        ni->counters.send_count++;
        ni->counters.send_length += mlength;

        /* only unlink after MD's refcount has been bumped
         * in get_new_msg() otherwise lib_me_unlink() will nuke it */
        if (unlink) {
                md->md_flags |= PTL_MD_FLAG_AUTO_UNLINKED;
                lib_me_unlink (nal, me);
        }

        state_unlock(nal, &flags);

        memset (&reply, 0, sizeof (reply));
        reply.type     = HTON__u32 (PTL_MSG_REPLY);
        reply.dest_nid = HTON__u64 (hdr->src_nid);
        reply.src_nid  = HTON__u64 (ni->nid);
        reply.dest_pid = HTON__u32 (hdr->src_pid);
        reply.src_pid  = HTON__u32 (ni->pid);
        PTL_HDR_LENGTH(&reply) = HTON__u32 (mlength);

        reply.msg.reply.dst_wmd = hdr->msg.get.return_wmd;

        rc = lib_send (nal, private, msg, &reply, PTL_MSG_REPLY, 
                       hdr->src_nid, hdr->src_pid, md, offset, mlength);
        if (rc != 0) {
                CERROR(LPU64": Dropping GET from "LPU64": send REPLY failed\n",
                       ni->nid, hdr->src_nid);
                state_lock (nal, &flags);
                goto drop;
        }

        /* Complete the incoming message */
        lib_recv (nal, private, NULL, NULL, 0, 0, PTL_HDR_LENGTH (hdr));
        return (rc);
 drop:
        ni->counters.drop_count++;
        ni->counters.drop_length += hdr->msg.get.sink_length;
        state_unlock(nal, &flags);
        lib_recv (nal, private, NULL, NULL, 0, 0, PTL_HDR_LENGTH (hdr));
        return -1;
}

static int parse_reply(nal_cb_t * nal, ptl_hdr_t * hdr, void *private)
{
        lib_ni_t        *ni = &nal->ni;
        lib_md_t        *md;
        int              rlength;
        int              length;
        lib_msg_t       *msg;
        unsigned long    flags;

        /* compatibility check until field is deleted */
        if (hdr->msg.reply.dst_offset != 0)
                CERROR("Unexpected non-zero reply.dst_offset %x from "LPU64"\n",
                       hdr->msg.reply.dst_offset, hdr->src_nid);

        state_lock(nal, &flags);

        /* NB handles only looked up by creator (no flips) */
        md = ptl_wire_handle2md(&hdr->msg.reply.dst_wmd, nal);
        if (md == NULL || md->threshold == 0) {
                CERROR (LPU64": Dropping REPLY from "LPU64" for %s MD "LPX64"."LPX64"\n",
                        ni->nid, hdr->src_nid,
                        md == NULL ? "invalid" : "inactive",
                        hdr->msg.reply.dst_wmd.wh_interface_cookie,
                        hdr->msg.reply.dst_wmd.wh_object_cookie);
                goto drop;
        }

        LASSERT (md->offset == 0);

        length = rlength = PTL_HDR_LENGTH(hdr);

        if (length > md->length) {
                if ((md->options & PTL_MD_TRUNCATE) == 0) {
                        CERROR (LPU64": Dropping REPLY from "LPU64
                                " length %d for MD "LPX64" would overflow (%d)\n",
                                ni->nid, hdr->src_nid, length,
                                hdr->msg.reply.dst_wmd.wh_object_cookie,
                                md->length);
                        goto drop;
                }
                length = md->length;
        }

        CDEBUG(D_NET, "Reply from "LPU64" of length %d/%d into md "LPX64"\n",
               hdr->src_nid, length, rlength, 
               hdr->msg.reply.dst_wmd.wh_object_cookie);

        msg = get_new_msg (nal, md);
        if (msg == NULL) {
                CERROR(LPU64": Dropping REPLY from "LPU64": can't "
                       "allocate msg\n", ni->nid, hdr->src_nid);
                goto drop;
        }

        if (md->eq) {
                msg->ev.type = PTL_EVENT_REPLY;
                msg->ev.initiator.nid = hdr->src_nid;
                msg->ev.initiator.pid = hdr->src_pid;
                msg->ev.rlength = rlength;
                msg->ev.mlength = length;
                msg->ev.offset = 0;

                lib_md_deconstruct(nal, md, &msg->ev.mem_desc);
        }

        ni->counters.recv_count++;
        ni->counters.recv_length += length;

        state_unlock(nal, &flags);

        lib_recv (nal, private, msg, md, 0, length, rlength);
        return 0;

 drop:
        nal->ni.counters.drop_count++;
        nal->ni.counters.drop_length += PTL_HDR_LENGTH(hdr);
        state_unlock (nal, &flags);
        lib_recv (nal, private, NULL, NULL, 0, 0, PTL_HDR_LENGTH (hdr));
        return -1;
}

static int parse_ack(nal_cb_t * nal, ptl_hdr_t * hdr, void *private)
{
        lib_ni_t *ni = &nal->ni;
        lib_md_t *md;
        lib_msg_t *msg = NULL;
        unsigned long flags;

        /* Convert ack fields to host byte order */
        hdr->msg.ack.match_bits = NTOH__u64 (hdr->msg.ack.match_bits);
        hdr->msg.ack.mlength = NTOH__u32 (hdr->msg.ack.mlength);

        state_lock(nal, &flags);

        /* NB handles only looked up by creator (no flips) */
        md = ptl_wire_handle2md(&hdr->msg.ack.dst_wmd, nal);
        if (md == NULL || md->threshold == 0) {
                CERROR(LPU64": Dropping ACK from "LPU64" to %s MD "
                       LPX64"."LPX64"\n", ni->nid, hdr->src_nid, 
                       (md == NULL) ? "invalid" : "inactive",
                       hdr->msg.ack.dst_wmd.wh_interface_cookie,
                       hdr->msg.ack.dst_wmd.wh_object_cookie);
                goto drop;
        }

        CDEBUG(D_NET, LPU64": ACK from "LPU64" into md "LPX64"\n",
               ni->nid, hdr->src_nid, 
               hdr->msg.ack.dst_wmd.wh_object_cookie);

        msg = get_new_msg (nal, md);
        if (msg == NULL) {
                CERROR(LPU64": Dropping ACK from "LPU64": can't allocate msg\n",
                       ni->nid, hdr->src_nid);
                goto drop;
        }

        if (md->eq) {
                msg->ev.type = PTL_EVENT_ACK;
                msg->ev.initiator.nid = hdr->src_nid;
                msg->ev.initiator.pid = hdr->src_pid;
                msg->ev.mlength = hdr->msg.ack.mlength;
                msg->ev.match_bits = hdr->msg.ack.match_bits;

                lib_md_deconstruct(nal, md, &msg->ev.mem_desc);
        }

        ni->counters.recv_count++;
        state_unlock(nal, &flags);
        lib_recv (nal, private, msg, NULL, 0, 0, PTL_HDR_LENGTH (hdr));
        return 0;

 drop:
        nal->ni.counters.drop_count++;
        state_unlock (nal, &flags);
        lib_recv (nal, private, NULL, NULL, 0, 0, PTL_HDR_LENGTH (hdr));
        return -1;
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
        case PTL_MSG_HELLO:
                return ("HELLO");
        default:
                return ("<UNKNOWN>");
        }
}

void print_hdr(nal_cb_t * nal, ptl_hdr_t * hdr)
{
        char *type_str = hdr_type_string (hdr);

        nal->cb_printf(nal, "P3 Header at %p of type %s\n", hdr, type_str);
        nal->cb_printf(nal, "    From nid/pid %Lu/%Lu", hdr->src_nid,
                       hdr->src_pid);
        nal->cb_printf(nal, "    To nid/pid %Lu/%Lu\n", hdr->dest_nid,
                       hdr->dest_pid);

        switch (hdr->type) {
        default:
                break;

        case PTL_MSG_PUT:
                nal->cb_printf(nal,
                               "    Ptl index %d, ack md "LPX64"."LPX64", "
                               "match bits "LPX64"\n",
                               hdr->msg.put.ptl_index,
                               hdr->msg.put.ack_wmd.wh_interface_cookie,
                               hdr->msg.put.ack_wmd.wh_object_cookie,
                               hdr->msg.put.match_bits);
                nal->cb_printf(nal,
                               "    Length %d, offset %d, hdr data "LPX64"\n",
                               PTL_HDR_LENGTH(hdr), hdr->msg.put.offset,
                               hdr->msg.put.hdr_data);
                break;

        case PTL_MSG_GET:
                nal->cb_printf(nal,
                               "    Ptl index %d, return md "LPX64"."LPX64", "
                               "match bits "LPX64"\n", hdr->msg.get.ptl_index,
                               hdr->msg.get.return_wmd.wh_interface_cookie,
                               hdr->msg.get.return_wmd.wh_object_cookie,
                               hdr->msg.get.match_bits);
                nal->cb_printf(nal,
                               "    Length %d, src offset %d\n",
                               hdr->msg.get.sink_length,
                               hdr->msg.get.src_offset);
                break;

        case PTL_MSG_ACK:
                nal->cb_printf(nal, "    dst md "LPX64"."LPX64", "
                               "manipulated length %d\n",
                               hdr->msg.ack.dst_wmd.wh_interface_cookie,
                               hdr->msg.ack.dst_wmd.wh_object_cookie,
                               hdr->msg.ack.mlength);
                break;

        case PTL_MSG_REPLY:
                nal->cb_printf(nal, "    dst md "LPX64"."LPX64", "
                               "length %d\n",
                               hdr->msg.reply.dst_wmd.wh_interface_cookie,
                               hdr->msg.reply.dst_wmd.wh_object_cookie,
                               PTL_HDR_LENGTH(hdr));
        }

}                               /* end of print_hdr() */


int lib_parse(nal_cb_t * nal, ptl_hdr_t * hdr, void *private)
{
        unsigned long  flags;

        /* NB static check; optimizer will elide this if it's right */
        LASSERT (offsetof (ptl_hdr_t, msg.ack.length) ==
                 offsetof (ptl_hdr_t, msg.put.length));
        LASSERT (offsetof (ptl_hdr_t, msg.ack.length) ==
                 offsetof (ptl_hdr_t, msg.get.length));
        LASSERT (offsetof (ptl_hdr_t, msg.ack.length) ==
                 offsetof (ptl_hdr_t, msg.reply.length));

        /* convert common fields to host byte order */
        hdr->dest_nid = NTOH__u64 (hdr->dest_nid);
        hdr->src_nid = NTOH__u64 (hdr->src_nid);
        hdr->dest_pid = NTOH__u32 (hdr->dest_pid);
        hdr->src_pid = NTOH__u32 (hdr->src_pid);
        hdr->type = NTOH__u32 (hdr->type);
        PTL_HDR_LENGTH(hdr) = NTOH__u32 (PTL_HDR_LENGTH(hdr));
#if 0
        nal->cb_printf(nal, "%d: lib_parse: nal=%p hdr=%p type=%d\n",
                       nal->ni.nid, nal, hdr, hdr->type);
        print_hdr(nal, hdr);
#endif
        if (hdr->type == PTL_MSG_HELLO) {
                /* dest_nid is really ptl_magicversion_t */
                ptl_magicversion_t *mv = (ptl_magicversion_t *)&hdr->dest_nid;

                CERROR (LPU64": Dropping unexpected HELLO message: "
                        "magic %d, version %d.%d from "LPD64"\n",
                        nal->ni.nid, mv->magic, 
                        mv->version_major, mv->version_minor,
                        hdr->src_nid);
                lib_recv (nal, private, NULL, NULL, 0, 0, PTL_HDR_LENGTH (hdr));
                return (-1);
        }
        
        if (hdr->dest_nid != nal->ni.nid) {
                CERROR(LPU64": Dropping %s message from "LPU64" to "LPU64
                       " (not me)\n", nal->ni.nid, hdr_type_string (hdr),
                       hdr->src_nid, hdr->dest_nid);

                state_lock (nal, &flags);
                nal->ni.counters.drop_count++;
                nal->ni.counters.drop_length += PTL_HDR_LENGTH(hdr);
                state_unlock (nal, &flags);

                lib_recv (nal, private, NULL, NULL, 0, 0, PTL_HDR_LENGTH (hdr));
                return (-1);
        }

        if (!list_empty (&nal->ni.ni_test_peers) && /* normally we don't */
            fail_peer (nal, hdr->src_nid, 0))      /* shall we now? */
        {
                CERROR(LPU64": Dropping incoming %s from "LPU64
                       ": simulated failure\n",
                       nal->ni.nid, hdr_type_string (hdr), 
                       hdr->src_nid);
                return (-1);
        }
        
        switch (hdr->type) {
        case PTL_MSG_ACK:
                return (parse_ack(nal, hdr, private));
        case PTL_MSG_PUT:
                return (parse_put(nal, hdr, private));
                break;
        case PTL_MSG_GET:
                return (parse_get(nal, hdr, private));
                break;
        case PTL_MSG_REPLY:
                return (parse_reply(nal, hdr, private));
                break;
        default:
                CERROR(LPU64": Dropping <unknown> message from "LPU64
                       ": Bad type=0x%x\n",  nal->ni.nid, hdr->src_nid,
                       hdr->type);

                lib_recv (nal, private, NULL, NULL, 0, 0, PTL_HDR_LENGTH (hdr));
                return (-1);
        }
}


int do_PtlPut(nal_cb_t * nal, void *private, void *v_args, void *v_ret)
{
        /*
         * Incoming:
         *      ptl_handle_md_t md_in
         *      ptl_ack_req_t ack_req_in
         *      ptl_process_id_t target_in
         *      ptl_pt_index_t portal_in
         *      ptl_ac_index_t cookie_in
         *      ptl_match_bits_t match_bits_in
         *      ptl_size_t offset_in
         *
         * Outgoing:
         */

        PtlPut_in *args = v_args;
        PtlPut_out *ret = v_ret;
        ptl_hdr_t hdr;

        lib_ni_t *ni = &nal->ni;
        lib_md_t *md;
        lib_msg_t *msg = NULL;
        ptl_process_id_t *id = &args->target_in;
        unsigned long flags;

        if (!list_empty (&nal->ni.ni_test_peers) && /* normally we don't */
            fail_peer (nal, id->nid, 1))           /* shall we now? */
        {
                CERROR(LPU64": Dropping PUT to "LPU64": simulated failure\n",
                       nal->ni.nid, id->nid);
                return (ret->rc = PTL_INV_PROC);
        }
        
        ret->rc = PTL_OK;
        state_lock(nal, &flags);
        md = ptl_handle2md(&args->md_in, nal);
        if (md == NULL || !md->threshold) {
                state_unlock(nal, &flags);
                return ret->rc = PTL_INV_MD;
        }

        CDEBUG(D_NET, "PtlPut -> %Lu: %lu\n", (unsigned long long)id->nid,
               (unsigned long)id->pid);

        memset (&hdr, 0, sizeof (hdr));
        hdr.type     = HTON__u32 (PTL_MSG_PUT);
        hdr.dest_nid = HTON__u64 (id->nid);
        hdr.src_nid  = HTON__u64 (ni->nid);
        hdr.dest_pid = HTON__u32 (id->pid);
        hdr.src_pid  = HTON__u32 (ni->pid);
        PTL_HDR_LENGTH(&hdr) = HTON__u32 (md->length);

        /* NB handles only looked up by creator (no flips) */
        if (args->ack_req_in == PTL_ACK_REQ) {
                hdr.msg.put.ack_wmd.wh_interface_cookie = ni->ni_interface_cookie;
                hdr.msg.put.ack_wmd.wh_object_cookie = md->md_lh.lh_cookie;
        } else {
                hdr.msg.put.ack_wmd = PTL_WIRE_HANDLE_NONE;
        }

        hdr.msg.put.match_bits = HTON__u64 (args->match_bits_in);
        hdr.msg.put.ptl_index = HTON__u32 (args->portal_in);
        hdr.msg.put.offset = HTON__u32 (args->offset_in);
        hdr.msg.put.hdr_data = args->hdr_data_in;

        ni->counters.send_count++;
        ni->counters.send_length += md->length;

        msg = get_new_msg (nal, md);
        if (msg == NULL) {
                CERROR("BAD: could not allocate msg!\n");
                state_unlock(nal, &flags);
                return ret->rc = PTL_NOSPACE;
        }

        /*
         * If this memory descriptor has an event queue associated with
         * it we need to allocate a message state object and record the
         * information about this operation that will be recorded into
         * event queue once the message has been completed.
         *
         * NB. We're now committed to the GET, since we just marked the MD
         * busy.  Callers who observe this (by getting PTL_MD_INUSE from
         * PtlMDUnlink()) expect a completion event to tell them when the
         * MD becomes idle. 
         */
        if (md->eq) {
                msg->ev.type = PTL_EVENT_SENT;
                msg->ev.initiator.nid = ni->nid;
                msg->ev.initiator.pid = ni->pid;
                msg->ev.portal = args->portal_in;
                msg->ev.match_bits = args->match_bits_in;
                msg->ev.rlength = md->length;
                msg->ev.mlength = md->length;
                msg->ev.offset = args->offset_in;
                msg->ev.hdr_data = args->hdr_data_in;

                lib_md_deconstruct(nal, md, &msg->ev.mem_desc);
        }

        state_unlock(nal, &flags);
        
        lib_send (nal, private, msg, &hdr, PTL_MSG_PUT,
                  id->nid, id->pid, md, 0, md->length);

        return ret->rc = PTL_OK;
}


int do_PtlGet(nal_cb_t * nal, void *private, void *v_args, void *v_ret)
{
        /*
         * Incoming:
         *      ptl_handle_md_t md_in
         *      ptl_process_id_t target_in
         *      ptl_pt_index_t portal_in
         *      ptl_ac_index_t cookie_in
         *      ptl_match_bits_t match_bits_in
         *      ptl_size_t offset_in
         *
         * Outgoing:
         */

        PtlGet_in *args = v_args;
        PtlGet_out *ret = v_ret;
        ptl_hdr_t hdr;
        lib_msg_t *msg = NULL;
        lib_ni_t *ni = &nal->ni;
        ptl_process_id_t *id = &args->target_in;
        lib_md_t *md;
        unsigned long flags;

        if (!list_empty (&nal->ni.ni_test_peers) && /* normally we don't */
            fail_peer (nal, id->nid, 1))           /* shall we now? */
        {
                CERROR(LPU64": Dropping PUT to "LPU64": simulated failure\n",
                       nal->ni.nid, id->nid);
                return (ret->rc = PTL_INV_PROC);
        }
        
        state_lock(nal, &flags);
        md = ptl_handle2md(&args->md_in, nal);
        if (md == NULL || !md->threshold) {
                state_unlock(nal, &flags);
                return ret->rc = PTL_INV_MD;
        }

        LASSERT (md->offset == 0);

        CDEBUG(D_NET, "PtlGet -> %Lu: %lu\n", (unsigned long long)id->nid,
               (unsigned long)id->pid);

        memset (&hdr, 0, sizeof (hdr));
        hdr.type     = HTON__u32 (PTL_MSG_GET);
        hdr.dest_nid = HTON__u64 (id->nid);
        hdr.src_nid  = HTON__u64 (ni->nid);
        hdr.dest_pid = HTON__u32 (id->pid);
        hdr.src_pid  = HTON__u32 (ni->pid);
        PTL_HDR_LENGTH(&hdr) = 0;

        /* NB handles only looked up by creator (no flips) */
        hdr.msg.get.return_wmd.wh_interface_cookie = ni->ni_interface_cookie;
        hdr.msg.get.return_wmd.wh_object_cookie = md->md_lh.lh_cookie;

        hdr.msg.get.match_bits = HTON__u64 (args->match_bits_in);
        hdr.msg.get.ptl_index = HTON__u32 (args->portal_in);
        hdr.msg.get.src_offset = HTON__u32 (args->offset_in);
        hdr.msg.get.sink_length = HTON__u32 (md->length);

        ni->counters.send_count++;

        msg = get_new_msg (nal, md);
        if (msg == NULL) {
                CERROR("do_PtlGet: BAD - could not allocate cookie!\n");
                state_unlock(nal, &flags);
                return ret->rc = PTL_NOSPACE;
        }

        /*
         * If this memory descriptor has an event queue associated with
         * it we must allocate a message state object that will record
         * the information to be filled in once the message has been
         * completed.  More information is in the do_PtlPut() comments.
         *
         * NB. We're now committed to the GET, since we just marked the MD
         * busy.  Callers who observe this (by getting PTL_MD_INUSE from
         * PtlMDUnlink()) expect a completion event to tell them when the
         * MD becomes idle. 
         */
        if (md->eq) {
                msg->ev.type = PTL_EVENT_SENT;
                msg->ev.initiator.nid = ni->nid;
                msg->ev.initiator.pid = ni->pid;
                msg->ev.portal = args->portal_in;
                msg->ev.match_bits = args->match_bits_in;
                msg->ev.rlength = md->length;
                msg->ev.mlength = md->length;
                msg->ev.offset = args->offset_in;
                msg->ev.hdr_data = 0;

                lib_md_deconstruct(nal, md, &msg->ev.mem_desc);
        }

        state_unlock(nal, &flags);

        lib_send (nal, private, msg, &hdr, PTL_MSG_GET,
                  id->nid, id->pid, NULL, 0, 0);

        return ret->rc = PTL_OK;
}
