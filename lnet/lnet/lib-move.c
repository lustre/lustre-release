/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lib/lib-move.c
 * Data movement routines
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *  Copyright (c) 2001-2002 Sandia National Laboratories
 *
 *   This file is part of Lustre, http://www.sf.net/projects/lustre/
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
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

/* forward ref */
static void lib_commit_md (nal_cb_t *nal, lib_md_t *md, lib_msg_t *msg);

static lib_md_t *
lib_match_md(nal_cb_t *nal, int index, int op_mask, 
             ptl_nid_t src_nid, ptl_pid_t src_pid, 
             ptl_size_t rlength, ptl_size_t roffset,
             ptl_match_bits_t match_bits, lib_msg_t *msg,
             ptl_size_t *mlength_out, ptl_size_t *offset_out)
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

                /* mismatched MD op */
                if ((md->options & op_mask) == 0)
                        continue;

                /* MD exhausted */
                if (lib_md_exhausted(md))
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

                if ((md->options & PTL_MD_MAX_SIZE) != 0) {
                        mlength = md->max_size;
                        LASSERT (md->offset + mlength <= md->length);
                } else {
                        mlength = md->length - offset;
                }

                if (rlength <= mlength) {        /* fits in allowed space */
                        mlength = rlength;
                } else if ((md->options & PTL_MD_TRUNCATE) == 0) {
                        /* this packet _really_ is too big */
                        CERROR("Matching packet %d too big: %d left, "
                               "%d allowed\n", rlength, md->length - offset,
                               mlength);
                        goto failed;
                }

                /* Commit to this ME/MD */
                CDEBUG(D_NET, "Incoming %s index %x from "LPU64"/%u of "
                       "length %d/%d into md "LPX64" [%d] + %d\n", 
                       (op_mask == PTL_MD_OP_PUT) ? "put" : "get",
                       index, src_nid, src_pid, mlength, rlength, 
                       md->md_lh.lh_cookie, md->md_niov, offset);

                lib_commit_md(nal, md, msg);
                md->offset = offset + mlength;

                /* NB Caller sets ev.type and ev.hdr_data */
                msg->ev.initiator.nid = src_nid;
                msg->ev.initiator.pid = src_pid;
                msg->ev.portal = index;
                msg->ev.match_bits = match_bits;
                msg->ev.rlength = rlength;
                msg->ev.mlength = mlength;
                msg->ev.offset = offset;

                lib_md_deconstruct(nal, md, &msg->ev.mem_desc);

                *offset_out = offset;
                *mlength_out = mlength;

                /* Auto-unlink NOW, so the ME gets unlinked if required.
                 * We bumped md->pending above so the MD just gets flagged
                 * for unlink when it is finalized. */
                if ((md->md_flags & PTL_MD_FLAG_AUTO_UNLINK) != 0 &&
                    lib_md_exhausted(md))
                        lib_md_unlink(nal, md);

                RETURN (md);
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
lib_copy_iov2buf (char *dest, int niov, struct iovec *iov, 
                  ptl_size_t offset, ptl_size_t len)
{
        ptl_size_t nob;

        if (len == 0)
                return;
        
        /* skip complete frags before 'offset' */
        LASSERT (niov > 0);
        while (offset >= iov->iov_len) {
                offset -= iov->iov_len;
                iov++;
                niov--;
                LASSERT (niov > 0);
        }
                
        do {
                LASSERT (niov > 0);
                nob = MIN (iov->iov_len - offset, len);
                memcpy (dest, iov->iov_base + offset, nob);

                len -= nob;
                dest += nob;
                niov--;
                iov++;
                offset = 0;
        } while (len > 0);
}

void
lib_copy_buf2iov (int niov, struct iovec *iov, ptl_size_t offset, 
                  char *src, ptl_size_t len)
{
        ptl_size_t nob;

        if (len == 0)
                return;

        /* skip complete frags before 'offset' */
        LASSERT (niov > 0);
        while (offset >= iov->iov_len) {
                offset -= iov->iov_len;
                iov++;
                niov--;
                LASSERT (niov > 0);
        }
        
        do {
                LASSERT (niov > 0);
                nob = MIN (iov->iov_len - offset, len);
                memcpy (iov->iov_base + offset, src, nob);
                
                len -= nob;
                src += nob;
                niov--;
                iov++;
                offset = 0;
        } while (len > 0);
}

int
lib_extract_iov (int dst_niov, struct iovec *dst,
                 int src_niov, struct iovec *src,
                 ptl_size_t offset, ptl_size_t len)
{
        /* Initialise 'dst' to the subset of 'src' starting at 'offset',
         * for exactly 'len' bytes, and return the number of entries.
         * NB not destructive to 'src' */
        ptl_size_t      frag_len;
        int             niov;

        if (len == 0)                           /* no data => */
                return (0);                     /* no frags */

        LASSERT (src_niov > 0);
        while (offset >= src->iov_len) {      /* skip initial frags */
                offset -= src->iov_len;
                src_niov--;
                src++;
                LASSERT (src_niov > 0);
        }

        niov = 1;
        for (;;) {
                LASSERT (src_niov > 0);
                LASSERT (niov <= dst_niov);
                
                frag_len = src->iov_len - offset;
                dst->iov_base = ((char *)src->iov_base) + offset;

                if (len <= frag_len) {
                        dst->iov_len = len;
                        return (niov);
                }
                
                dst->iov_len = frag_len;

                len -= frag_len;
                dst++;
                src++;
                niov++;
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
lib_copy_kiov2buf (char *dest, int niov, ptl_kiov_t *kiov, 
                   ptl_size_t offset, ptl_size_t len)
{
        LASSERT (0);
}

void
lib_copy_buf2kiov (int niov, ptl_kiov_t *kiov, ptl_size_t offset,
                   char *src, ptl_size_t len)
{
        LASSERT (0);
}

int
lib_extract_kiov (int dst_niov, ptl_kiov_t *dst, 
                  int src_niov, ptl_kiov_t *src,
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
lib_copy_kiov2buf (char *dest, int niov, ptl_kiov_t *kiov, 
                   ptl_size_t offset, ptl_size_t len)
{
        ptl_size_t  nob;
        char       *addr;

        if (len == 0)
                return;
        
        LASSERT (!in_interrupt ());

        LASSERT (niov > 0);
        while (offset > kiov->kiov_len) {
                offset -= kiov->kiov_len;
                kiov++;
                niov--;
                LASSERT (niov > 0);
        }
        
        do{
                LASSERT (niov > 0);
                nob = MIN (kiov->kiov_len - offset, len);
                
                addr = ((char *)kmap (kiov->kiov_page)) + kiov->kiov_offset + offset;
                memcpy (dest, addr, nob);
                kunmap (kiov->kiov_page);
                
                len -= nob;
                dest += nob;
                niov--;
                kiov++;
                offset = 0;
        } while (len > 0);
}

void
lib_copy_buf2kiov (int niov, ptl_kiov_t *kiov, ptl_size_t offset,
                   char *src, ptl_size_t len)
{
        ptl_size_t  nob;
        char       *addr;

        if (len == 0)
                return;

        LASSERT (!in_interrupt ());

        LASSERT (niov > 0);
        while (offset >= kiov->kiov_len) {
                offset -= kiov->kiov_len;
                kiov++;
                niov--;
                LASSERT (niov > 0);
        }
        
        do {
                LASSERT (niov > 0);
                nob = MIN (kiov->kiov_len - offset, len);
                
                addr = ((char *)kmap (kiov->kiov_page)) + kiov->kiov_offset + offset;
                memcpy (addr, src, nob);
                kunmap (kiov->kiov_page);
                
                len -= nob;
                src += nob;
                niov--;
                kiov++;
                offset = 0;
        } while (len > 0);
}

int
lib_extract_kiov (int dst_niov, ptl_kiov_t *dst, 
                  int src_niov, ptl_kiov_t *src,
                  ptl_size_t offset, ptl_size_t len)
{
        /* Initialise 'dst' to the subset of 'src' starting at 'offset',
         * for exactly 'len' bytes, and return the number of entries.
         * NB not destructive to 'src' */
        ptl_size_t      frag_len;
        int             niov;

        if (len == 0)                           /* no data => */
                return (0);                     /* no frags */

        LASSERT (src_niov > 0);
        while (offset >= src->kiov_len) {      /* skip initial frags */
                offset -= src->kiov_len;
                src_niov--;
                src++;
                LASSERT (src_niov > 0);
        }

        niov = 1;
        for (;;) {
                LASSERT (src_niov > 0);
                LASSERT (niov <= dst_niov);
                
                frag_len = src->kiov_len - offset;
                dst->kiov_page = src->kiov_page;
                dst->kiov_offset = src->kiov_offset + offset;

                if (len <= frag_len) {
                        dst->kiov_len = len;
                        LASSERT (dst->kiov_offset + dst->kiov_len <= PAGE_SIZE);
                        return (niov);
                }

                dst->kiov_len = frag_len;
                LASSERT (dst->kiov_offset + dst->kiov_len <= PAGE_SIZE);

                len -= frag_len;
                dst++;
                src++;
                niov++;
                src_niov--;
                offset = 0;
        }
}
#endif

ptl_err_t
lib_recv (nal_cb_t *nal, void *private, lib_msg_t *msg, lib_md_t *md,
          ptl_size_t offset, ptl_size_t mlen, ptl_size_t rlen)
{
        if (mlen == 0)
                return (nal->cb_recv(nal, private, msg,
                                     0, NULL,
                                     offset, mlen, rlen));

        if ((md->options & PTL_MD_KIOV) == 0)
                return (nal->cb_recv(nal, private, msg,
                                     md->md_niov, md->md_iov.iov, 
                                     offset, mlen, rlen));

        return (nal->cb_recv_pages(nal, private, msg, 
                                   md->md_niov, md->md_iov.kiov,
                                   offset, mlen, rlen));
}

ptl_err_t
lib_send (nal_cb_t *nal, void *private, lib_msg_t *msg,
          ptl_hdr_t *hdr, int type, ptl_nid_t nid, ptl_pid_t pid,
          lib_md_t *md, ptl_size_t offset, ptl_size_t len) 
{
        if (len == 0)
                return (nal->cb_send(nal, private, msg,
                                     hdr, type, nid, pid,
                                     0, NULL,
                                     offset, len));
        
        if ((md->options & PTL_MD_KIOV) == 0)
                return (nal->cb_send(nal, private, msg, 
                                     hdr, type, nid, pid,
                                     md->md_niov, md->md_iov.iov,
                                     offset, len));

        return (nal->cb_send_pages(nal, private, msg, 
                                   hdr, type, nid, pid,
                                   md->md_niov, md->md_iov.kiov,
                                   offset, len));
}

static void
lib_commit_md (nal_cb_t *nal, lib_md_t *md, lib_msg_t *msg)
{
        /* ALWAYS called holding the state_lock */
        lib_counters_t *counters = &nal->ni.counters;

        /* Here, we commit the MD to a network OP by marking it busy and
         * decrementing its threshold.  Come what may, the network "owns"
         * the MD until a call to lib_finalize() signals completion. */
        msg->md = md;
         
        md->pending++;
        if (md->threshold != PTL_MD_THRESH_INF) {
                LASSERT (md->threshold > 0);
                md->threshold--;
        }

        counters->msgs_alloc++;
        if (counters->msgs_alloc > counters->msgs_max)
                counters->msgs_max = counters->msgs_alloc;

        list_add (&msg->msg_list, &nal->ni.ni_active_msgs);
}

static void
lib_drop_message (nal_cb_t *nal, void *private, ptl_hdr_t *hdr)
{
        unsigned long flags;

        /* CAVEAT EMPTOR: this only drops messages that we've not committed
         * to receive (init_msg() not called) and therefore can't cause an
         * event. */
        
        state_lock(nal, &flags);
        nal->ni.counters.drop_count++;
        nal->ni.counters.drop_length += hdr->payload_length;
        state_unlock(nal, &flags);

        /* NULL msg => if NAL calls lib_finalize it will be a noop */
        (void) lib_recv(nal, private, NULL, NULL, 0, 0, hdr->payload_length);
}

/*
 * Incoming messages have a ptl_msg_t object associated with them
 * by the library.  This object encapsulates the state of the
 * message and allows the NAL to do non-blocking receives or sends
 * of long messages.
 *
 */
static ptl_err_t
parse_put(nal_cb_t *nal, ptl_hdr_t *hdr, void *private, lib_msg_t *msg)
{
        lib_ni_t        *ni = &nal->ni;
        ptl_size_t       mlength = 0;
        ptl_size_t       offset = 0;
        ptl_err_t        rc;
        lib_md_t        *md;
        unsigned long    flags;
                
        /* Convert put fields to host byte order */
        hdr->msg.put.match_bits = NTOH__u64 (hdr->msg.put.match_bits);
        hdr->msg.put.ptl_index = NTOH__u32 (hdr->msg.put.ptl_index);
        hdr->msg.put.offset = NTOH__u32 (hdr->msg.put.offset);

        state_lock(nal, &flags);

        md = lib_match_md(nal, hdr->msg.put.ptl_index, PTL_MD_OP_PUT,
                          hdr->src_nid, hdr->src_pid,
                          hdr->payload_length, hdr->msg.put.offset,
                          hdr->msg.put.match_bits, msg,
                          &mlength, &offset);
        if (md == NULL) {
                state_unlock(nal, &flags);
                return (PTL_FAIL);
        }

        msg->ev.type = PTL_EVENT_PUT_END;
        msg->ev.hdr_data = hdr->msg.put.hdr_data;

        if (!ptl_is_wire_handle_none(&hdr->msg.put.ack_wmd) &&
            !(md->options & PTL_MD_ACK_DISABLE)) {
                msg->ack_wmd = hdr->msg.put.ack_wmd;
        }

        ni->counters.recv_count++;
        ni->counters.recv_length += mlength;

        state_unlock(nal, &flags);

        rc = lib_recv(nal, private, msg, md, offset, mlength,
                      hdr->payload_length);
        if (rc != PTL_OK)
                CERROR(LPU64": error on receiving PUT from "LPU64": %d\n",
                       ni->nid, hdr->src_nid, rc);

        return (rc);
}

static ptl_err_t
parse_get(nal_cb_t *nal, ptl_hdr_t *hdr, void *private, lib_msg_t *msg)
{
        lib_ni_t        *ni = &nal->ni;
        ptl_size_t       mlength = 0;
        ptl_size_t       offset = 0;
        lib_md_t        *md;
        ptl_hdr_t        reply;
        unsigned long    flags;
        int              rc;

        /* Convert get fields to host byte order */
        hdr->msg.get.match_bits = NTOH__u64 (hdr->msg.get.match_bits);
        hdr->msg.get.ptl_index = NTOH__u32 (hdr->msg.get.ptl_index);
        hdr->msg.get.sink_length = NTOH__u32 (hdr->msg.get.sink_length);
        hdr->msg.get.src_offset = NTOH__u32 (hdr->msg.get.src_offset);

        state_lock(nal, &flags);

        md = lib_match_md(nal, hdr->msg.get.ptl_index, PTL_MD_OP_GET,
                          hdr->src_nid, hdr->src_pid,
                          hdr->msg.get.sink_length, hdr->msg.get.src_offset,
                          hdr->msg.get.match_bits, msg,
                          &mlength, &offset);
        if (md == NULL) {
                state_unlock(nal, &flags);
                return (PTL_FAIL);
        }

        msg->ev.type = PTL_EVENT_GET_END;
        msg->ev.hdr_data = 0;

        ni->counters.send_count++;
        ni->counters.send_length += mlength;

        state_unlock(nal, &flags);

        memset (&reply, 0, sizeof (reply));
        reply.type     = HTON__u32 (PTL_MSG_REPLY);
        reply.dest_nid = HTON__u64 (hdr->src_nid);
        reply.src_nid  = HTON__u64 (ni->nid);
        reply.dest_pid = HTON__u32 (hdr->src_pid);
        reply.src_pid  = HTON__u32 (ni->pid);
        reply.payload_length = HTON__u32 (mlength);

        reply.msg.reply.dst_wmd = hdr->msg.get.return_wmd;

        /* NB call lib_send() _BEFORE_ lib_recv() completes the incoming
         * message.  Some NALs _require_ this to implement optimized GET */

        rc = lib_send (nal, private, msg, &reply, PTL_MSG_REPLY, 
                       hdr->src_nid, hdr->src_pid, md, offset, mlength);
        if (rc != PTL_OK)
                CERROR(LPU64": Unable to send REPLY for GET from "LPU64": %d\n",
                       ni->nid, hdr->src_nid, rc);

        /* Discard any junk after the hdr */
        (void) lib_recv(nal, private, NULL, NULL, 0, 0, hdr->payload_length);

        return (rc);
}

static ptl_err_t
parse_reply(nal_cb_t *nal, ptl_hdr_t *hdr, void *private, lib_msg_t *msg)
{
        lib_ni_t        *ni = &nal->ni;
        lib_md_t        *md;
        int              rlength;
        int              length;
        unsigned long    flags;
        ptl_err_t        rc;

        state_lock(nal, &flags);

        /* NB handles only looked up by creator (no flips) */
        md = ptl_wire_handle2md(&hdr->msg.reply.dst_wmd, nal);
        if (md == NULL || md->threshold == 0) {
                CERROR (LPU64": Dropping REPLY from "LPU64" for %s MD "LPX64"."LPX64"\n",
                        ni->nid, hdr->src_nid,
                        md == NULL ? "invalid" : "inactive",
                        hdr->msg.reply.dst_wmd.wh_interface_cookie,
                        hdr->msg.reply.dst_wmd.wh_object_cookie);

                state_unlock(nal, &flags);
                return (PTL_FAIL);
        }

        LASSERT (md->offset == 0);

        length = rlength = hdr->payload_length;

        if (length > md->length) {
                if ((md->options & PTL_MD_TRUNCATE) == 0) {
                        CERROR (LPU64": Dropping REPLY from "LPU64
                                " length %d for MD "LPX64" would overflow (%d)\n",
                                ni->nid, hdr->src_nid, length,
                                hdr->msg.reply.dst_wmd.wh_object_cookie,
                                md->length);
                        state_unlock(nal, &flags);
                        return (PTL_FAIL);
                }
                length = md->length;
        }

        CDEBUG(D_NET, "Reply from "LPU64" of length %d/%d into md "LPX64"\n",
               hdr->src_nid, length, rlength, 
               hdr->msg.reply.dst_wmd.wh_object_cookie);

        lib_commit_md(nal, md, msg);

        msg->ev.type = PTL_EVENT_REPLY_END;
        msg->ev.initiator.nid = hdr->src_nid;
        msg->ev.initiator.pid = hdr->src_pid;
        msg->ev.rlength = rlength;
        msg->ev.mlength = length;
        msg->ev.offset = 0;

        lib_md_deconstruct(nal, md, &msg->ev.mem_desc);

        ni->counters.recv_count++;
        ni->counters.recv_length += length;

        state_unlock(nal, &flags);

        rc = lib_recv(nal, private, msg, md, 0, length, rlength);
        if (rc != PTL_OK)
                CERROR(LPU64": error on receiving REPLY from "LPU64": %d\n",
                       ni->nid, hdr->src_nid, rc);

        return (rc);
}

static ptl_err_t
parse_ack(nal_cb_t *nal, ptl_hdr_t *hdr, void *private, lib_msg_t *msg)
{
        lib_ni_t      *ni = &nal->ni;
        lib_md_t      *md;
        unsigned long  flags;

        /* Convert ack fields to host byte order */
        hdr->msg.ack.match_bits = NTOH__u64 (hdr->msg.ack.match_bits);
        hdr->msg.ack.mlength = NTOH__u32 (hdr->msg.ack.mlength);

        state_lock(nal, &flags);

        /* NB handles only looked up by creator (no flips) */
        md = ptl_wire_handle2md(&hdr->msg.ack.dst_wmd, nal);
        if (md == NULL || md->threshold == 0) {
                CDEBUG(D_INFO, LPU64": Dropping ACK from "LPU64" to %s MD "
                       LPX64"."LPX64"\n", ni->nid, hdr->src_nid, 
                       (md == NULL) ? "invalid" : "inactive",
                       hdr->msg.ack.dst_wmd.wh_interface_cookie,
                       hdr->msg.ack.dst_wmd.wh_object_cookie);

                state_unlock(nal, &flags);
                return (PTL_FAIL);
        }

        CDEBUG(D_NET, LPU64": ACK from "LPU64" into md "LPX64"\n",
               ni->nid, hdr->src_nid, 
               hdr->msg.ack.dst_wmd.wh_object_cookie);

        lib_commit_md(nal, md, msg);

        msg->ev.type = PTL_EVENT_ACK;
        msg->ev.initiator.nid = hdr->src_nid;
        msg->ev.initiator.pid = hdr->src_pid;
        msg->ev.mlength = hdr->msg.ack.mlength;
        msg->ev.match_bits = hdr->msg.ack.match_bits;

        lib_md_deconstruct(nal, md, &msg->ev.mem_desc);

        ni->counters.recv_count++;

        state_unlock(nal, &flags);
        
        /* We have received and matched up the ack OK, create the
         * completion event now... */
        lib_finalize(nal, private, msg, PTL_OK);

        /* ...and now discard any junk after the hdr */
        (void) lib_recv(nal, private, NULL, NULL, 0, 0, hdr->payload_length);
 
       return (PTL_OK);
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
                               hdr->payload_length, hdr->msg.put.offset,
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
                               hdr->payload_length);
        }

}                               /* end of print_hdr() */


void 
lib_parse(nal_cb_t *nal, ptl_hdr_t *hdr, void *private)
{
        unsigned long  flags;
        ptl_err_t      rc;
        lib_msg_t     *msg;
        
        /* convert common fields to host byte order */
        hdr->dest_nid = NTOH__u64 (hdr->dest_nid);
        hdr->src_nid = NTOH__u64 (hdr->src_nid);
        hdr->dest_pid = NTOH__u32 (hdr->dest_pid);
        hdr->src_pid = NTOH__u32 (hdr->src_pid);
        hdr->type = NTOH__u32 (hdr->type);
        hdr->payload_length = NTOH__u32(hdr->payload_length);
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
                lib_drop_message(nal, private, hdr);
                return;
        }
        
        if (hdr->dest_nid != nal->ni.nid) {
                CERROR(LPU64": Dropping %s message from "LPU64" to "LPU64
                       " (not me)\n", nal->ni.nid, hdr_type_string (hdr),
                       hdr->src_nid, hdr->dest_nid);
                lib_drop_message(nal, private, hdr);
                return;
        }

        if (!list_empty (&nal->ni.ni_test_peers) && /* normally we don't */
            fail_peer (nal, hdr->src_nid, 0))      /* shall we now? */
        {
                CERROR(LPU64": Dropping incoming %s from "LPU64
                       ": simulated failure\n",
                       nal->ni.nid, hdr_type_string (hdr), 
                       hdr->src_nid);
                lib_drop_message(nal, private, hdr);
                return;
        }

        msg = lib_msg_alloc(nal);
        if (msg == NULL) {
                CERROR(LPU64": Dropping incoming %s from "LPU64
                       ": can't allocate a lib_msg_t\n",
                       nal->ni.nid, hdr_type_string (hdr), 
                       hdr->src_nid);
                lib_drop_message(nal, private, hdr);
                return;
        }

        switch (hdr->type) {
        case PTL_MSG_ACK:
                rc = parse_ack(nal, hdr, private, msg);
                break;
        case PTL_MSG_PUT:
                rc = parse_put(nal, hdr, private, msg);
                break;
        case PTL_MSG_GET:
                rc = parse_get(nal, hdr, private, msg);
                break;
        case PTL_MSG_REPLY:
                rc = parse_reply(nal, hdr, private, msg);
                break;
        default:
                CERROR(LPU64": Dropping <unknown> message from "LPU64
                       ": Bad type=0x%x\n",  nal->ni.nid, hdr->src_nid,
                       hdr->type);
                rc = PTL_FAIL;
                break;
        }
                
        if (rc != PTL_OK) {
                if (msg->md != NULL) {
                        /* committed... */
                        lib_finalize(nal, private, msg, rc);
                } else {
                        state_lock(nal, &flags);
                        lib_msg_free(nal, msg); /* expects state_lock held */
                        state_unlock(nal, &flags);

                        lib_drop_message(nal, private, hdr);
                }
        }
}

int 
do_PtlPut(nal_cb_t *nal, void *private, void *v_args, void *v_ret)
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

        PtlPut_in        *args = v_args;
        ptl_process_id_t *id = &args->target_in;
        PtlPut_out       *ret = v_ret;
        lib_ni_t         *ni = &nal->ni;
        lib_msg_t        *msg;
        ptl_hdr_t         hdr;
        lib_md_t         *md;
        unsigned long     flags;
        int               rc;
        
        if (!list_empty (&nal->ni.ni_test_peers) && /* normally we don't */
            fail_peer (nal, id->nid, 1))           /* shall we now? */
        {
                CERROR(LPU64": Dropping PUT to "LPU64": simulated failure\n",
                       nal->ni.nid, id->nid);
                return (ret->rc = PTL_PROCESS_INVALID);
        }

        msg = lib_msg_alloc(nal);
        if (msg == NULL) {
                CERROR(LPU64": Dropping PUT to "LPU64": ENOMEM on lib_msg_t\n",
                       ni->nid, id->nid);
                return (ret->rc = PTL_NO_SPACE);
        }

        state_lock(nal, &flags);

        md = ptl_handle2md(&args->md_in, nal);
        if (md == NULL || md->threshold == 0) {
                lib_msg_free(nal, msg);
                state_unlock(nal, &flags);
        
                return (ret->rc = PTL_MD_INVALID);
        }

        CDEBUG(D_NET, "PtlPut -> %Lu: %lu\n", (unsigned long long)id->nid,
               (unsigned long)id->pid);

        memset (&hdr, 0, sizeof (hdr));
        hdr.type     = HTON__u32 (PTL_MSG_PUT);
        hdr.dest_nid = HTON__u64 (id->nid);
        hdr.src_nid  = HTON__u64 (ni->nid);
        hdr.dest_pid = HTON__u32 (id->pid);
        hdr.src_pid  = HTON__u32 (ni->pid);
        hdr.payload_length = HTON__u32 (md->length);

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

        lib_commit_md(nal, md, msg);
        
        msg->ev.type = PTL_EVENT_SEND_END;
        msg->ev.initiator.nid = ni->nid;
        msg->ev.initiator.pid = ni->pid;
        msg->ev.portal = args->portal_in;
        msg->ev.match_bits = args->match_bits_in;
        msg->ev.rlength = md->length;
        msg->ev.mlength = md->length;
        msg->ev.offset = args->offset_in;
        msg->ev.hdr_data = args->hdr_data_in;

        lib_md_deconstruct(nal, md, &msg->ev.mem_desc);

        ni->counters.send_count++;
        ni->counters.send_length += md->length;

        state_unlock(nal, &flags);
        
        rc = lib_send (nal, private, msg, &hdr, PTL_MSG_PUT,
                       id->nid, id->pid, md, 0, md->length);
        if (rc != PTL_OK) {
                CERROR(LPU64": error sending PUT to "LPU64": %d\n",
                       ni->nid, id->nid, rc);
                lib_finalize (nal, private, msg, rc);
        }
        
        /* completion will be signalled by an event */
        return ret->rc = PTL_OK;
}

lib_msg_t * 
lib_create_reply_msg (nal_cb_t *nal, ptl_nid_t peer_nid, lib_msg_t *getmsg)
{
        /* The NAL can DMA direct to the GET md (i.e. no REPLY msg).  This
         * returns a msg for the NAL to pass to lib_finalize() when the sink
         * data has been received.
         *
         * CAVEAT EMPTOR: 'getmsg' is the original GET, which is freed when
         * lib_finalize() is called on it, so the NAL must call this first */

        lib_ni_t        *ni = &nal->ni;
        lib_msg_t       *msg = lib_msg_alloc(nal);
        lib_md_t        *getmd = getmsg->md;
        unsigned long    flags;

        state_lock(nal, &flags);

        LASSERT (getmd->pending > 0);

        if (msg == NULL) {
                CERROR ("Dropping REPLY from "LPU64": can't allocate msg\n",
                        peer_nid);
                goto drop;
        }

        if (getmd->threshold == 0) {
                CERROR ("Dropping REPLY from "LPU64" for inactive MD %p\n",
                        peer_nid, getmd);
                goto drop_msg;
        }

        LASSERT (getmd->offset == 0);

        CDEBUG(D_NET, "Reply from "LPU64" md %p\n", peer_nid, getmd);

        lib_commit_md (nal, getmd, msg);

        msg->ev.type = PTL_EVENT_REPLY_END;
        msg->ev.initiator.nid = peer_nid;
        msg->ev.initiator.pid = 0;      /* XXX FIXME!!! */
        msg->ev.rlength = msg->ev.mlength = getmd->length;
        msg->ev.offset = 0;

        lib_md_deconstruct(nal, getmd, &msg->ev.mem_desc);

        ni->counters.recv_count++;
        ni->counters.recv_length += getmd->length;

        state_unlock(nal, &flags);

        return msg;

 drop_msg:
        lib_msg_free(nal, msg);
 drop:
        nal->ni.counters.drop_count++;
        nal->ni.counters.drop_length += getmd->length;

        state_unlock (nal, &flags);

        return NULL;
}

int 
do_PtlGet(nal_cb_t *nal, void *private, void *v_args, void *v_ret)
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

        PtlGet_in        *args = v_args;
        ptl_process_id_t *id = &args->target_in;
        PtlGet_out       *ret = v_ret;
        lib_ni_t         *ni = &nal->ni;
        lib_msg_t        *msg;
        ptl_hdr_t         hdr;
        lib_md_t         *md;
        unsigned long     flags;
        int               rc;
        
        if (!list_empty (&nal->ni.ni_test_peers) && /* normally we don't */
            fail_peer (nal, id->nid, 1))           /* shall we now? */
        {
                CERROR(LPU64": Dropping PUT to "LPU64": simulated failure\n",
                       nal->ni.nid, id->nid);
                return (ret->rc = PTL_PROCESS_INVALID);
        }

        msg = lib_msg_alloc(nal);
        if (msg == NULL) {
                CERROR(LPU64": Dropping GET to "LPU64": ENOMEM on lib_msg_t\n",
                       ni->nid, id->nid);
                return (ret->rc = PTL_NO_SPACE);
        }

        state_lock(nal, &flags);

        md = ptl_handle2md(&args->md_in, nal);
        if (md == NULL || !md->threshold) {
                lib_msg_free(nal, msg);
                state_unlock(nal, &flags);

                return ret->rc = PTL_MD_INVALID;
        }

        CDEBUG(D_NET, "PtlGet -> %Lu: %lu\n", (unsigned long long)id->nid,
               (unsigned long)id->pid);

        memset (&hdr, 0, sizeof (hdr));
        hdr.type     = HTON__u32 (PTL_MSG_GET);
        hdr.dest_nid = HTON__u64 (id->nid);
        hdr.src_nid  = HTON__u64 (ni->nid);
        hdr.dest_pid = HTON__u32 (id->pid);
        hdr.src_pid  = HTON__u32 (ni->pid);
        hdr.payload_length = 0;

        /* NB handles only looked up by creator (no flips) */
        hdr.msg.get.return_wmd.wh_interface_cookie = ni->ni_interface_cookie;
        hdr.msg.get.return_wmd.wh_object_cookie = md->md_lh.lh_cookie;

        hdr.msg.get.match_bits = HTON__u64 (args->match_bits_in);
        hdr.msg.get.ptl_index = HTON__u32 (args->portal_in);
        hdr.msg.get.src_offset = HTON__u32 (args->offset_in);
        hdr.msg.get.sink_length = HTON__u32 (md->length);

        lib_commit_md(nal, md, msg);

        msg->ev.type = PTL_EVENT_SEND_END;
        msg->ev.initiator.nid = ni->nid;
        msg->ev.initiator.pid = ni->pid;
        msg->ev.portal = args->portal_in;
        msg->ev.match_bits = args->match_bits_in;
        msg->ev.rlength = md->length;
        msg->ev.mlength = md->length;
        msg->ev.offset = args->offset_in;
        msg->ev.hdr_data = 0;

        lib_md_deconstruct(nal, md, &msg->ev.mem_desc);

        ni->counters.send_count++;

        state_unlock(nal, &flags);

        rc = lib_send (nal, private, msg, &hdr, PTL_MSG_GET,
                       id->nid, id->pid, NULL, 0, 0);
        if (rc != PTL_OK) {
                CERROR(LPU64": error sending GET to "LPU64": %d\n",
                       ni->nid, id->nid, rc);
                lib_finalize (nal, private, msg, rc);
        }
        
        /* completion will be signalled by an event */
        return ret->rc = PTL_OK;
}

void lib_assert_wire_constants (void)
{
        /* Wire protocol assertions generated by 'wirecheck'
         * running on Linux robert.bartonsoftware.com 2.4.20-18.9 #1 Thu May 29 06:54:41 EDT 2003 i68
         * with gcc version 3.2.2 20030222 (Red Hat Linux 3.2.2-5) */


        /* Constants... */
        LASSERT (PORTALS_PROTO_MAGIC == 0xeebc0ded);
        LASSERT (PORTALS_PROTO_VERSION_MAJOR == 0);
        LASSERT (PORTALS_PROTO_VERSION_MINOR == 3);
        LASSERT (PTL_MSG_ACK == 0);
        LASSERT (PTL_MSG_PUT == 1);
        LASSERT (PTL_MSG_GET == 2);
        LASSERT (PTL_MSG_REPLY == 3);
        LASSERT (PTL_MSG_HELLO == 4);

        /* Checks for struct ptl_handle_wire_t */
        LASSERT ((int)sizeof(ptl_handle_wire_t) == 16);
        LASSERT (offsetof(ptl_handle_wire_t, wh_interface_cookie) == 0);
        LASSERT ((int)sizeof(((ptl_handle_wire_t *)0)->wh_interface_cookie) == 8);
        LASSERT (offsetof(ptl_handle_wire_t, wh_object_cookie) == 8);
        LASSERT ((int)sizeof(((ptl_handle_wire_t *)0)->wh_object_cookie) == 8);

        /* Checks for struct ptl_magicversion_t */
        LASSERT ((int)sizeof(ptl_magicversion_t) == 8);
        LASSERT (offsetof(ptl_magicversion_t, magic) == 0);
        LASSERT ((int)sizeof(((ptl_magicversion_t *)0)->magic) == 4);
        LASSERT (offsetof(ptl_magicversion_t, version_major) == 4);
        LASSERT ((int)sizeof(((ptl_magicversion_t *)0)->version_major) == 2);
        LASSERT (offsetof(ptl_magicversion_t, version_minor) == 6);
        LASSERT ((int)sizeof(((ptl_magicversion_t *)0)->version_minor) == 2);

        /* Checks for struct ptl_hdr_t */
        LASSERT ((int)sizeof(ptl_hdr_t) == 72);
        LASSERT (offsetof(ptl_hdr_t, dest_nid) == 0);
        LASSERT ((int)sizeof(((ptl_hdr_t *)0)->dest_nid) == 8);
        LASSERT (offsetof(ptl_hdr_t, src_nid) == 8);
        LASSERT ((int)sizeof(((ptl_hdr_t *)0)->src_nid) == 8);
        LASSERT (offsetof(ptl_hdr_t, dest_pid) == 16);
        LASSERT ((int)sizeof(((ptl_hdr_t *)0)->dest_pid) == 4);
        LASSERT (offsetof(ptl_hdr_t, src_pid) == 20);
        LASSERT ((int)sizeof(((ptl_hdr_t *)0)->src_pid) == 4);
        LASSERT (offsetof(ptl_hdr_t, type) == 24);
        LASSERT ((int)sizeof(((ptl_hdr_t *)0)->type) == 4);
        LASSERT (offsetof(ptl_hdr_t, payload_length) == 28);
        LASSERT ((int)sizeof(((ptl_hdr_t *)0)->payload_length) == 4);
        LASSERT (offsetof(ptl_hdr_t, msg) == 32);
        LASSERT ((int)sizeof(((ptl_hdr_t *)0)->msg) == 40);

        /* Ack */
        LASSERT (offsetof(ptl_hdr_t, msg.ack.dst_wmd) == 32);
        LASSERT ((int)sizeof(((ptl_hdr_t *)0)->msg.ack.dst_wmd) == 16);
        LASSERT (offsetof(ptl_hdr_t, msg.ack.match_bits) == 48);
        LASSERT ((int)sizeof(((ptl_hdr_t *)0)->msg.ack.match_bits) == 8);
        LASSERT (offsetof(ptl_hdr_t, msg.ack.mlength) == 56);
        LASSERT ((int)sizeof(((ptl_hdr_t *)0)->msg.ack.mlength) == 4);

        /* Put */
        LASSERT (offsetof(ptl_hdr_t, msg.put.ack_wmd) == 32);
        LASSERT ((int)sizeof(((ptl_hdr_t *)0)->msg.put.ack_wmd) == 16);
        LASSERT (offsetof(ptl_hdr_t, msg.put.match_bits) == 48);
        LASSERT ((int)sizeof(((ptl_hdr_t *)0)->msg.put.match_bits) == 8);
        LASSERT (offsetof(ptl_hdr_t, msg.put.hdr_data) == 56);
        LASSERT ((int)sizeof(((ptl_hdr_t *)0)->msg.put.hdr_data) == 8);
        LASSERT (offsetof(ptl_hdr_t, msg.put.ptl_index) == 64);
        LASSERT ((int)sizeof(((ptl_hdr_t *)0)->msg.put.ptl_index) == 4);
        LASSERT (offsetof(ptl_hdr_t, msg.put.offset) == 68);
        LASSERT ((int)sizeof(((ptl_hdr_t *)0)->msg.put.offset) == 4);

        /* Get */
        LASSERT (offsetof(ptl_hdr_t, msg.get.return_wmd) == 32);
        LASSERT ((int)sizeof(((ptl_hdr_t *)0)->msg.get.return_wmd) == 16);
        LASSERT (offsetof(ptl_hdr_t, msg.get.match_bits) == 48);
        LASSERT ((int)sizeof(((ptl_hdr_t *)0)->msg.get.match_bits) == 8);
        LASSERT (offsetof(ptl_hdr_t, msg.get.ptl_index) == 56);
        LASSERT ((int)sizeof(((ptl_hdr_t *)0)->msg.get.ptl_index) == 4);
        LASSERT (offsetof(ptl_hdr_t, msg.get.src_offset) == 60);
        LASSERT ((int)sizeof(((ptl_hdr_t *)0)->msg.get.src_offset) == 4);
        LASSERT (offsetof(ptl_hdr_t, msg.get.sink_length) == 64);
        LASSERT ((int)sizeof(((ptl_hdr_t *)0)->msg.get.sink_length) == 4);

        /* Reply */
        LASSERT (offsetof(ptl_hdr_t, msg.reply.dst_wmd) == 32);
        LASSERT ((int)sizeof(((ptl_hdr_t *)0)->msg.reply.dst_wmd) == 16);

        /* Hello */
        LASSERT (offsetof(ptl_hdr_t, msg.hello.incarnation) == 32);
        LASSERT ((int)sizeof(((ptl_hdr_t *)0)->msg.hello.incarnation) == 8);
        LASSERT (offsetof(ptl_hdr_t, msg.hello.type) == 40);
        LASSERT ((int)sizeof(((ptl_hdr_t *)0)->msg.hello.type) == 4);
}
