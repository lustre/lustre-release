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

void PtlSnprintHandle(char *str, int len, ptl_handle_any_t h)
{
        snprintf(str, len, "0x%lx."LPX64, h.nal_idx, h.cookie);
}

int PtlNIHandle(ptl_handle_any_t handle_in, ptl_handle_ni_t *ni_out)
{
        if (!ptl_init)
                return PTL_NO_INIT;
        
        if (ptl_hndl2nal(&handle_in) == NULL)
                return PTL_HANDLE_INVALID;
        
        *ni_out = handle_in;
        return PTL_OK;
}

int PtlGetId(ptl_handle_ni_t ni_handle, ptl_process_id_t *id)
{
        nal_t     *nal;

        if (!ptl_init)
                return PTL_NO_INIT;
        
        nal = ptl_hndl2nal(&ni_handle);
        if (nal == NULL)
                return PTL_NI_INVALID;

        return nal->nal_get_id(nal, id);
}

int PtlGetUid(ptl_handle_ni_t ni_handle, ptl_uid_t *uid)
{
        nal_t     *nal;

        if (!ptl_init)
                return PTL_NO_INIT;
        
        nal = ptl_hndl2nal(&ni_handle);
        if (nal == NULL)
                return PTL_NI_INVALID;

        /* We don't support different uids yet */
        *uid = 0;
        return PTL_OK;
}

int PtlFailNid (ptl_handle_ni_t interface, ptl_nid_t nid, unsigned int threshold) 
{
        nal_t     *nal;

        if (!ptl_init)
                return PTL_NO_INIT;
        
        nal = ptl_hndl2nal(&interface);
        if (nal == NULL)
                return PTL_NI_INVALID;

        return nal->nal_fail_nid(nal, nid, threshold);
}

int PtlNIStatus(ptl_handle_ni_t interface_in, ptl_sr_index_t register_in,
                ptl_sr_value_t *status_out)
{
        nal_t     *nal;

        if (!ptl_init)
                return PTL_NO_INIT;
        
        nal = ptl_hndl2nal(&interface_in);
        if (nal == NULL)
                return PTL_NI_INVALID;

        return nal->nal_ni_status(nal, register_in, status_out);
}

int PtlNIDist(ptl_handle_ni_t interface_in, ptl_process_id_t process_in,
              unsigned long *distance_out)
{
        nal_t     *nal;

        if (!ptl_init)
                return PTL_NO_INIT;
        
        nal = ptl_hndl2nal(&interface_in);
        if (nal == NULL)
                return PTL_NI_INVALID;

        return nal->nal_ni_dist(nal, &process_in, distance_out);
}

int PtlMEAttach(ptl_handle_ni_t interface_in, ptl_pt_index_t index_in,
                ptl_process_id_t match_id_in, ptl_match_bits_t match_bits_in,
                ptl_match_bits_t ignore_bits_in, ptl_unlink_t unlink_in,
                ptl_ins_pos_t pos_in, ptl_handle_me_t *handle_out)
{
        nal_t     *nal;

        if (!ptl_init)
                return PTL_NO_INIT;
        
        nal = ptl_hndl2nal(&interface_in);
        if (nal == NULL)
                return PTL_NI_INVALID;

        return nal->nal_me_attach(nal, index_in, match_id_in, 
                                  match_bits_in, ignore_bits_in,
                                  unlink_in, pos_in, handle_out);
}

int PtlMEInsert(ptl_handle_me_t current_in, ptl_process_id_t match_id_in,
                ptl_match_bits_t match_bits_in, ptl_match_bits_t ignore_bits_in,
                ptl_unlink_t unlink_in, ptl_ins_pos_t position_in,
                ptl_handle_me_t * handle_out)
{
        nal_t     *nal;

        if (!ptl_init)
                return PTL_NO_INIT;
        
        nal = ptl_hndl2nal(&current_in);
        if (nal == NULL)
                return PTL_ME_INVALID;

        return nal->nal_me_insert(nal, &current_in, match_id_in,
                                  match_bits_in, ignore_bits_in,
                                  unlink_in, position_in, handle_out);
}

int PtlMEUnlink(ptl_handle_me_t current_in)
{
        nal_t     *nal;

        if (!ptl_init)
                return PTL_NO_INIT;
        
        nal = ptl_hndl2nal(&current_in);
        if (nal == NULL)
                return PTL_ME_INVALID;

        return nal->nal_me_unlink(nal, &current_in);
}

int PtlMDAttach(ptl_handle_me_t me_in, ptl_md_t md_in,
                ptl_unlink_t unlink_in, ptl_handle_md_t * handle_out)
{
        nal_t     *nal;

        if (!ptl_init)
                return PTL_NO_INIT;
        
        nal = ptl_hndl2nal(&me_in);
        if (nal == NULL)
                return PTL_ME_INVALID;

        if (!PtlHandleIsEqual(md_in.eq_handle, PTL_EQ_NONE) &&
            ptl_hndl2nal(&md_in.eq_handle) != nal)
                return PTL_MD_ILLEGAL;

        return (nal->nal_md_attach)(nal, &me_in, &md_in, 
                                    unlink_in, handle_out);
}

int PtlMDBind(ptl_handle_ni_t ni_in, ptl_md_t md_in,
              ptl_unlink_t unlink_in, ptl_handle_md_t *handle_out)
{
        nal_t     *nal;

        if (!ptl_init)
                return PTL_NO_INIT;
        
        nal = ptl_hndl2nal(&ni_in);
        if (nal == NULL)
                return PTL_NI_INVALID;

        if (!PtlHandleIsEqual(md_in.eq_handle, PTL_EQ_NONE) &&
            ptl_hndl2nal(&md_in.eq_handle) != nal)
                return PTL_MD_ILLEGAL;

        return (nal->nal_md_bind)(nal, &md_in, unlink_in, handle_out);
}

int PtlMDUpdate(ptl_handle_md_t md_in, ptl_md_t *old_inout,
                ptl_md_t *new_inout, ptl_handle_eq_t testq_in)
{
        nal_t    *nal;
        
        if (!ptl_init)
                return PTL_NO_INIT;
        
        nal = ptl_hndl2nal(&md_in);
        if (nal == NULL)
                return PTL_MD_INVALID;

        if (!PtlHandleIsEqual(testq_in, PTL_EQ_NONE) &&
            ptl_hndl2nal(&testq_in) != nal)
                return PTL_EQ_INVALID;

        return (nal->nal_md_update)(nal, &md_in, 
                                    old_inout, new_inout, &testq_in);
}

int PtlMDUnlink(ptl_handle_md_t md_in)
{
        nal_t    *nal;
        
        if (!ptl_init)
                return PTL_NO_INIT;
        
        nal = ptl_hndl2nal(&md_in);
        if (nal == NULL)
                return PTL_MD_INVALID;
        
        return (nal->nal_md_unlink)(nal, &md_in);
}

int PtlEQAlloc(ptl_handle_ni_t interface, ptl_size_t count,
               ptl_eq_handler_t callback,
               ptl_handle_eq_t *handle_out)
{
        nal_t    *nal;
        
        if (!ptl_init)
                return PTL_NO_INIT;
        
        nal = ptl_hndl2nal(&interface);
        if (nal == NULL)
                return PTL_NI_INVALID;

        return (nal->nal_eq_alloc)(nal, count, callback, handle_out);
}

int PtlEQFree(ptl_handle_eq_t eventq)
{
        nal_t       *nal;

        if (!ptl_init)
                return PTL_NO_INIT;
        
        nal = ptl_hndl2nal(&eventq);
        if (nal == NULL)
                return PTL_EQ_INVALID;

        return (nal->nal_eq_free)(nal, &eventq);
}

int PtlEQGet(ptl_handle_eq_t eventq, ptl_event_t *ev)
{
        int which;
        
        return (PtlEQPoll (&eventq, 1, 0, ev, &which));
}

int PtlEQWait(ptl_handle_eq_t eventq_in, ptl_event_t *event_out)
{
        int which;
        
        return (PtlEQPoll (&eventq_in, 1, PTL_TIME_FOREVER, 
                           event_out, &which));
}

int PtlEQPoll(ptl_handle_eq_t *eventqs_in, int neq_in, int timeout,
              ptl_event_t *event_out, int *which_out)
{
        int           i;
        nal_t        *nal;

        if (!ptl_init)
                return PTL_NO_INIT;

        if (neq_in < 1)
                return PTL_EQ_INVALID;

        nal = ptl_hndl2nal(&eventqs_in[0]);
        if (nal == NULL)
                return PTL_EQ_INVALID;

        for (i = 1; i < neq_in; i++)
                if (ptl_hndl2nal(&eventqs_in[i]) != nal)
                        return PTL_EQ_INVALID;

        return (nal->nal_eq_poll)(nal, eventqs_in, neq_in, timeout,
                                  event_out, which_out);
}


int PtlACEntry(ptl_handle_ni_t ni_in, ptl_ac_index_t index_in,
               ptl_process_id_t match_id_in, ptl_pt_index_t portal_in)
{
        nal_t    *nal;

        if (!ptl_init)
                return PTL_NO_INIT;
        
        nal = ptl_hndl2nal(&ni_in);
        if (nal == NULL)
                return PTL_NI_INVALID;
        
        return (nal->nal_ace_entry)(nal, index_in, match_id_in, portal_in);
}

int PtlPut(ptl_handle_md_t md_in, ptl_ack_req_t ack_req_in,
           ptl_process_id_t target_in, ptl_pt_index_t portal_in,
           ptl_ac_index_t ac_in, ptl_match_bits_t match_bits_in,
           ptl_size_t offset_in, ptl_hdr_data_t hdr_data_in)
{
        nal_t    *nal;

        if (!ptl_init)
                return PTL_NO_INIT;
        
        nal = ptl_hndl2nal(&md_in);
        if (nal == NULL)
                return PTL_MD_INVALID;

        return (nal->nal_put)(nal, &md_in, ack_req_in,
                              &target_in, portal_in, ac_in,
                              match_bits_in, offset_in, hdr_data_in);
}

int PtlGet(ptl_handle_md_t md_in, ptl_process_id_t target_in,
           ptl_pt_index_t portal_in, ptl_ac_index_t ac_in,
           ptl_match_bits_t match_bits_in, ptl_size_t offset_in)
{
        nal_t  *nal;

        if (!ptl_init)
                return PTL_NO_INIT;

        nal = ptl_hndl2nal(&md_in);
        if (nal == NULL)
                return PTL_MD_INVALID;

        return (nal->nal_get)(nal, &md_in, 
                              &target_in, portal_in, ac_in,
                              match_bits_in, offset_in);
}

