/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lib/lib-pid.c
 * Process identification routines
 */

/* This should be removed.  The NAL should have the PID information */
#define DEBUG_SUBSYSTEM S_PORTALS

#if defined (__KERNEL__)
#       include <linux/kernel.h>
extern int getpid(void);
#else
#       include <stdio.h>
#       include <unistd.h>
#endif
#include <portals/lib-p30.h>
#include <portals/arg-blocks.h>

int do_PtlGetId(nal_cb_t * nal, void *private, void *v_args, void *v_ret)
{
        /*
         * Incoming:
         *      ptl_handle_ni_t handle_in
         *
         * Outgoing:
         *      ptl_process_id_t        * id_out
         *      ptl_id_t                * gsize_out
         */

        PtlGetId_out *ret = v_ret;
        lib_ni_t *ni = &nal->ni;

        ret->id_out.nid = ni->nid;
        ret->id_out.pid = ni->pid;

        return ret->rc = PTL_OK;
}
