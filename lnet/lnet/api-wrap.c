/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * api/api-wrap.c
 * User-level wrappers that dispatch across the protection boundaries
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

# define DEBUG_SUBSYSTEM S_PORTALS
#include <portals/api-support.h>

static int do_forward(ptl_handle_any_t any_h, int cmd, void *argbuf,
                      int argsize, void *retbuf, int retsize)
{
        nal_t *nal;

        if (!ptl_init) {
                fprintf(stderr, "PtlGetId: Not initialized\n");
                return PTL_NOINIT;
        }

        nal = ptl_hndl2nal(&any_h);
        if (!nal)
                return PTL_INV_HANDLE;

        nal->forward(nal, cmd, argbuf, argsize, retbuf, retsize);

        return PTL_OK;
}

int PtlGetId(ptl_handle_ni_t ni_handle, ptl_process_id_t *id)
{
        PtlGetId_in args;
        PtlGetId_out ret;
        int rc;

        args.handle_in = ni_handle;

        rc = do_forward(ni_handle, PTL_GETID, &args, sizeof(args), &ret,
                        sizeof(ret));
        if (rc != PTL_OK)
                return rc;
        
        if (id)
                *id = ret.id_out;

        return ret.rc;
}

int PtlFailNid (ptl_handle_ni_t interface, ptl_nid_t nid, unsigned int threshold) 
{
        PtlFailNid_in  args;
        PtlFailNid_out ret;
        int            rc;
        
        args.interface = interface;
        args.nid       = nid;
        args.threshold = threshold;
        
        rc = do_forward (interface, PTL_FAILNID, 
                         &args, sizeof(args), &ret, sizeof (ret));

        return ((rc != PTL_OK) ? rc : ret.rc);
}

int PtlNIStatus(ptl_handle_ni_t interface_in, ptl_sr_index_t register_in,
                ptl_sr_value_t * status_out)
{
        PtlNIStatus_in args;
        PtlNIStatus_out ret;
        int rc;

        args.interface_in = interface_in;
        args.register_in = register_in;

        rc = do_forward(interface_in, PTL_NISTATUS, &args, sizeof(args), &ret,
                        sizeof(ret));

        if (rc != PTL_OK)
                return rc;

        if (status_out)
                *status_out = ret.status_out;

        return ret.rc;
}

int PtlNIDist(ptl_handle_ni_t interface_in, ptl_process_id_t process_in,
              unsigned long *distance_out)
{
        PtlNIDist_in args;
        PtlNIDist_out ret;
        int rc;

        args.interface_in = interface_in;
        args.process_in = process_in;

        rc = do_forward(interface_in, PTL_NIDIST, &args, sizeof(args), &ret,
                        sizeof(ret));

        if (rc != PTL_OK)
                return rc;

        if (distance_out)
                *distance_out = ret.distance_out;

        return ret.rc;
}



unsigned int PtlNIDebug(ptl_handle_ni_t ni, unsigned int mask_in)
{
        PtlNIDebug_in args;
        PtlNIDebug_out ret;
        int rc;

        args.mask_in = mask_in;

        rc = do_forward(ni, PTL_NIDEBUG, &args, sizeof(args), &ret,
                        sizeof(ret));

        if (rc != PTL_OK)
                return rc;

        return ret.rc;
}

int PtlMEAttach(ptl_handle_ni_t interface_in, ptl_pt_index_t index_in,
                ptl_process_id_t match_id_in, ptl_match_bits_t match_bits_in,
                ptl_match_bits_t ignore_bits_in, ptl_unlink_t unlink_in,
                ptl_ins_pos_t pos_in, ptl_handle_me_t * handle_out)
{
        PtlMEAttach_in args;
        PtlMEAttach_out ret;
        int rc;

        args.interface_in = interface_in;
        args.index_in = index_in;
        args.match_id_in = match_id_in;
        args.match_bits_in = match_bits_in;
        args.ignore_bits_in = ignore_bits_in;
        args.unlink_in = unlink_in;
        args.position_in = pos_in;

        rc = do_forward(interface_in, PTL_MEATTACH, &args, sizeof(args), &ret,
                        sizeof(ret));

        if (rc != PTL_OK)
                return rc;

        if (handle_out) {
                handle_out->nal_idx = interface_in.nal_idx;
                handle_out->cookie = ret.handle_out.cookie;
        }

        return ret.rc;
}

int PtlMEInsert(ptl_handle_me_t current_in, ptl_process_id_t match_id_in,
                ptl_match_bits_t match_bits_in, ptl_match_bits_t ignore_bits_in,
                ptl_unlink_t unlink_in, ptl_ins_pos_t position_in,
                ptl_handle_me_t * handle_out)
{
        PtlMEInsert_in args;
        PtlMEInsert_out ret;
        int rc;

        args.current_in = current_in;
        args.match_id_in = match_id_in;
        args.match_bits_in = match_bits_in;
        args.ignore_bits_in = ignore_bits_in;
        args.unlink_in = unlink_in;
        args.position_in = position_in;

        rc = do_forward(current_in, PTL_MEINSERT, &args, sizeof(args), &ret,
                        sizeof(ret));

        if (rc != PTL_OK)
                return (rc == PTL_INV_HANDLE) ? PTL_INV_ME : rc;

        if (handle_out) {
                handle_out->nal_idx = current_in.nal_idx;
                handle_out->cookie = ret.handle_out.cookie;
        }
        return ret.rc;
}

int PtlMEUnlink(ptl_handle_me_t current_in)
{
        PtlMEUnlink_in args;
        PtlMEUnlink_out ret;
        int rc;

        args.current_in = current_in;
        args.unlink_in = PTL_RETAIN;

        rc = do_forward(current_in, PTL_MEUNLINK, &args, sizeof(args), &ret,
                        sizeof(ret));

        if (rc != PTL_OK)
                return (rc == PTL_INV_HANDLE) ? PTL_INV_ME : rc;

        return ret.rc;
}

int PtlTblDump(ptl_handle_ni_t ni, int index_in)
{
        PtlTblDump_in args;
        PtlTblDump_out ret;
        int rc;

        args.index_in = index_in;

        rc = do_forward(ni, PTL_TBLDUMP, &args, sizeof(args), &ret,
                        sizeof(ret));

        if (rc != PTL_OK)
                return rc;

        return ret.rc;
}

int PtlMEDump(ptl_handle_me_t current_in)
{
        PtlMEDump_in args;
        PtlMEDump_out ret;
        int rc;

        args.current_in = current_in;

        rc = do_forward(current_in, PTL_MEDUMP, &args, sizeof(args), &ret,
                        sizeof(ret));

        if (rc != PTL_OK)
                return (rc == PTL_INV_HANDLE) ? PTL_INV_ME : rc;

        return ret.rc;
}

static int validate_md(ptl_handle_any_t current_in, ptl_md_t md_in)
{
        nal_t *nal;
        int rc;
        int i;

        if (!ptl_init) {
                fprintf(stderr, "PtlMDAttach/Bind/Update: Not initialized\n");
                return PTL_NOINIT;
        }

        nal = ptl_hndl2nal(&current_in);
        if (!nal)
                return PTL_INV_HANDLE;

        if (nal->validate != NULL)                /* nal->validate not a NOOP */
        {
                if ((md_in.options & PTL_MD_IOV) == 0)        /* contiguous */
                {
                        rc = nal->validate (nal, md_in.start, md_in.length);
                        if (rc)
                                return (PTL_SEGV);
                }
                else
                {
                        struct iovec *iov = (struct iovec *)md_in.start;

                        for (i = 0; i < md_in.niov; i++, iov++)
                        {
                                rc = nal->validate (nal, iov->iov_base, iov->iov_len);
                                if (rc)
                                        return (PTL_SEGV);
                        }
                }
        }

        return 0;
}

static ptl_handle_eq_t md2eq (ptl_md_t *md)
{
        if (PtlHandleEqual (md->eventq, PTL_EQ_NONE))
                return (PTL_EQ_NONE);
        
        return (ptl_handle2usereq (&md->eventq)->cb_eq_handle);
}


int PtlMDAttach(ptl_handle_me_t me_in, ptl_md_t md_in,
                ptl_unlink_t unlink_in, ptl_handle_md_t * handle_out)
{
        PtlMDAttach_in args;
        PtlMDAttach_out ret;
        int rc;

        rc = validate_md(me_in, md_in);
        if (rc == PTL_OK) {
                args.eq_in = md2eq(&md_in);
                args.me_in = me_in;
                args.md_in = md_in;
                args.unlink_in = unlink_in;
                
                rc = do_forward(me_in, PTL_MDATTACH, 
                                &args, sizeof(args), &ret, sizeof(ret));
        }

        if (rc != PTL_OK)
                return (rc == PTL_INV_HANDLE) ? PTL_INV_ME : rc;

        if (handle_out) {
                handle_out->nal_idx = me_in.nal_idx;
                handle_out->cookie = ret.handle_out.cookie;
        }
        return ret.rc;
}



int PtlMDBind(ptl_handle_ni_t ni_in, ptl_md_t md_in,
                       ptl_handle_md_t * handle_out)
{
        PtlMDBind_in args;
        PtlMDBind_out ret;
        int rc;

        rc = validate_md(ni_in, md_in);
        if (rc != PTL_OK)
                return rc;

        args.eq_in = md2eq(&md_in);
        args.ni_in = ni_in;
        args.md_in = md_in;

        rc = do_forward(ni_in, PTL_MDBIND, 
                        &args, sizeof(args), &ret, sizeof(ret));

        if (rc != PTL_OK)
                return rc;

        if (handle_out) {
                handle_out->nal_idx = ni_in.nal_idx;
                handle_out->cookie = ret.handle_out.cookie;
        }
        return ret.rc;
}

int PtlMDUpdate(ptl_handle_md_t md_in, ptl_md_t *old_inout,
                ptl_md_t *new_inout, ptl_handle_eq_t testq_in)
{
        PtlMDUpdate_internal_in args;
        PtlMDUpdate_internal_out ret;
        int rc;

        args.md_in = md_in;

        if (old_inout) {
                args.old_inout = *old_inout;
                args.old_inout_valid = 1;
        } else
                args.old_inout_valid = 0;

        if (new_inout) {
                rc = validate_md (md_in, *new_inout);
                if (rc != PTL_OK)
                        return (rc == PTL_INV_HANDLE) ? PTL_INV_MD : rc;
                args.new_inout = *new_inout;
                args.new_inout_valid = 1;
        } else
                args.new_inout_valid = 0;

        if (PtlHandleEqual (testq_in, PTL_EQ_NONE)) {
                args.testq_in = PTL_EQ_NONE;
                args.sequence_in = -1;
        } else {
                ptl_eq_t *eq = ptl_handle2usereq (&testq_in);
                
                args.testq_in = eq->cb_eq_handle;
                args.sequence_in = eq->sequence;
        }

        rc = do_forward(md_in, PTL_MDUPDATE, &args, sizeof(args), &ret,
                        sizeof(ret));
        if (rc != PTL_OK)
                return (rc == PTL_INV_HANDLE) ? PTL_INV_MD : rc;

        if (old_inout)
                *old_inout = ret.old_inout;

        return ret.rc;
}

int PtlMDUnlink(ptl_handle_md_t md_in)
{
        PtlMDUnlink_in args;
        PtlMDUnlink_out ret;
        int rc;

        args.md_in = md_in;
        rc = do_forward(md_in, PTL_MDUNLINK, &args, sizeof(args), &ret,
                        sizeof(ret));
        if (rc != PTL_OK)
                return (rc == PTL_INV_HANDLE) ? PTL_INV_MD : rc;

        return ret.rc;
}

int PtlEQAlloc(ptl_handle_ni_t interface, ptl_size_t count,
               int (*callback) (ptl_event_t * event),
               ptl_handle_eq_t * handle_out)
{
        ptl_eq_t *eq = NULL;
        ptl_event_t *ev = NULL;
        PtlEQAlloc_in args;
        PtlEQAlloc_out ret;
        int rc, i;
        nal_t *nal;

        if (!ptl_init)
                return PTL_NOINIT;
        
        nal = ptl_hndl2nal (&interface);
        if (nal == NULL)
                return PTL_INV_HANDLE;

        if (count != LOWEST_BIT_SET(count)) {   /* not a power of 2 already */
                do {                    /* knock off all but the top bit... */
                        count &= ~LOWEST_BIT_SET (count);
                } while (count != LOWEST_BIT_SET(count));

                count <<= 1;                             /* ...and round up */
        }

        if (count == 0)        /* catch bad parameter / overflow on roundup */
                return (PTL_VAL_FAILED);

        PORTAL_ALLOC(ev, count * sizeof(ptl_event_t));
        if (!ev)
                return PTL_NOSPACE;

        for (i = 0; i < count; i++)
                ev[i].sequence = 0;

        if (nal->validate != NULL) {
                rc = nal->validate(nal, ev, count * sizeof(ptl_event_t));
                if (rc != PTL_OK)
                        goto fail;
        }

        args.ni_in = interface;
        args.count_in = count;
        args.base_in = ev;
        args.len_in = count * sizeof(*ev);
        args.callback_in = callback;

        rc = do_forward(interface, PTL_EQALLOC, &args, sizeof(args), &ret,
                        sizeof(ret));
        if (rc != PTL_OK)
                goto fail;
        if (ret.rc)
                GOTO(fail, rc = ret.rc);

        PORTAL_ALLOC(eq, sizeof(*eq));
        if (!eq) {
                rc = PTL_NOSPACE;
                goto fail;
        }

        eq->sequence = 1;
        eq->size = count;
        eq->base = ev;

        /* EQ handles are a little wierd.  PtlEQGet() just looks at the
         * queued events in shared memory.  It doesn't want to do_forward()
         * at all, so the cookie in the EQ handle we pass out of here is
         * simply a pointer to the event queue we just set up.  We stash
         * the handle returned by do_forward(), so we can pass it back via
         * do_forward() when we need to. */

        eq->cb_eq_handle.nal_idx = interface.nal_idx;
        eq->cb_eq_handle.cookie = ret.handle_out.cookie;

        handle_out->nal_idx = interface.nal_idx;
        handle_out->cookie = (__u64)((unsigned long)eq);
        return PTL_OK;

fail:
        PORTAL_FREE(ev, count * sizeof(ptl_event_t));
        return rc;
}

int PtlEQFree(ptl_handle_eq_t eventq)
{
        PtlEQFree_in args;
        PtlEQFree_out ret;
        ptl_eq_t *eq;
        int rc;

        eq = ptl_handle2usereq (&eventq);
        args.eventq_in = eq->cb_eq_handle;

        rc = do_forward(eq->cb_eq_handle, PTL_EQFREE, &args,
                        sizeof(args), &ret, sizeof(ret));

        /* XXX we're betting rc == PTL_OK here */
        PORTAL_FREE(eq->base, eq->size * sizeof(ptl_event_t));
        PORTAL_FREE(eq, sizeof(*eq));

        return rc;
}

int PtlACEntry(ptl_handle_ni_t ni_in, ptl_ac_index_t index_in,
               ptl_process_id_t match_id_in, ptl_pt_index_t portal_in)
{
        PtlACEntry_in args;
        PtlACEntry_out ret;
        int rc;

        /*
         * Copy arguments into the argument block to
         * hand to the forwarding object
         */
        args.ni_in = ni_in;
        args.index_in = index_in;
        args.match_id_in = match_id_in;
        args.portal_in = portal_in;

        rc = do_forward(ni_in, PTL_ACENTRY, &args, sizeof(args), &ret,
                        sizeof(ret));

        return (rc != PTL_OK) ? rc : ret.rc;
}

int PtlPut(ptl_handle_md_t md_in, ptl_ack_req_t ack_req_in,
           ptl_process_id_t target_in, ptl_pt_index_t portal_in,
           ptl_ac_index_t cookie_in, ptl_match_bits_t match_bits_in,
           ptl_size_t offset_in, ptl_hdr_data_t hdr_data_in)
{
        PtlPut_in args;
        PtlPut_out ret;
        int rc;

        /*
         * Copy arguments into the argument block to
         * hand to the forwarding object
         */
        args.md_in = md_in;
        args.ack_req_in = ack_req_in;
        args.target_in = target_in;
        args.portal_in = portal_in;
        args.cookie_in = cookie_in;
        args.match_bits_in = match_bits_in;
        args.offset_in = offset_in;
        args.hdr_data_in = hdr_data_in;

        rc = do_forward(md_in, PTL_PUT, &args, sizeof(args), &ret, sizeof(ret));

        return (rc != PTL_OK) ? rc : ret.rc;
}

int PtlGet(ptl_handle_md_t md_in, ptl_process_id_t target_in,
           ptl_pt_index_t portal_in, ptl_ac_index_t cookie_in,
           ptl_match_bits_t match_bits_in, ptl_size_t offset_in)
{
        PtlGet_in args;
        PtlGet_out ret;
        int rc;

        /*
         * Copy arguments into the argument block to
         * hand to the forwarding object
         */
        args.md_in = md_in;
        args.target_in = target_in;
        args.portal_in = portal_in;
        args.cookie_in = cookie_in;
        args.match_bits_in = match_bits_in;
        args.offset_in = offset_in;

        rc = do_forward(md_in, PTL_GET, &args, sizeof(args), &ret, sizeof(ret));

        return (rc != PTL_OK) ? rc : ret.rc;
}
