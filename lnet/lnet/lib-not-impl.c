/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lib/lib-not-impl.c
 *
 * boiler plate functions that can be used to write the 
 * library side routines
 */

# define DEBUG_SUBSYSTEM S_PORTALS

#include <portals/lib-p30.h>
#include <portals/arg-blocks.h>


int do_PtlACEntry(nal_cb_t * nal, void *private, void *v_args, void *v_ret)
{
        /*
         * Incoming:
         *      ptl_handle_ni_t ni_in
         *      ptl_ac_index_t index_in
         *      ptl_process_id_t match_id_in
         *      ptl_pt_index_t portal_in

         *
         * Outgoing:

         */

        PtlACEntry_in *args = v_args;
        PtlACEntry_out *ret = v_ret;

        if (!args)
                return ret->rc = PTL_SEGV;

        return ret->rc = PTL_NOT_IMPLEMENTED;
}
