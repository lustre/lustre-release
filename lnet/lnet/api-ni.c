/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * api/api-ni.c
 * Network Interface code
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

#include <portals/api-support.h>

#define MAX_NIS 8
static nal_t *ptl_interfaces[MAX_NIS];
int ptl_num_interfaces = 0;

nal_t *ptl_hndl2nal(ptl_handle_any_t *handle)
{
        unsigned int idx = handle->nal_idx;

        /* XXX we really rely on the caller NOT racing with interface
         * setup/teardown.  That ensures her NI handle can't get
         * invalidated out from under her (or worse, swapped for a
         * completely different interface!) */
        
        if (idx < MAX_NIS)
                return ptl_interfaces[idx];

        return NULL;
}

int ptl_ni_init(void)
{
        int i;

        for (i = 0; i < MAX_NIS; i++)
                ptl_interfaces[i] = NULL;

        return PTL_OK;
}

void ptl_ni_fini(void)
{
        int i;

        for (i = 0; i < MAX_NIS; i++) {
                nal_t *nal = ptl_interfaces[i];
                if (!nal)
                        continue;

                if (nal->shutdown)
                        nal->shutdown(nal, i);
        }
}

#ifdef __KERNEL__
DECLARE_MUTEX(ptl_ni_init_mutex);

static void ptl_ni_init_mutex_enter (void) 
{
        down (&ptl_ni_init_mutex);
}

static void ptl_ni_init_mutex_exit (void)
{
        up (&ptl_ni_init_mutex);
}

#else
static void ptl_ni_init_mutex_enter (void)
{
}

static void ptl_ni_init_mutex_exit (void) 
{
}

#endif

int PtlNIInit(ptl_interface_t interface, ptl_pt_index_t ptl_size,
              ptl_ac_index_t acl_size, ptl_pid_t requested_pid,
              ptl_handle_ni_t * handle)
{
        nal_t *nal;
        int i;

        if (!ptl_init)
                return PTL_NOINIT;

        ptl_ni_init_mutex_enter ();

        nal = interface(ptl_num_interfaces, ptl_size, acl_size, requested_pid);

        if (!nal) {
                ptl_ni_init_mutex_exit ();
                return PTL_NAL_FAILED;
        }

        for (i = 0; i < ptl_num_interfaces; i++) {
                if (ptl_interfaces[i] == nal) {
                        nal->refct++;
                        handle->nal_idx = i;
                        fprintf(stderr, "Returning existing NAL (%d)\n", i);
                        ptl_ni_init_mutex_exit ();
                        return PTL_OK;
                }
        }
        nal->refct = 1;

        handle->nal_idx = ptl_num_interfaces;
        if (ptl_num_interfaces >= MAX_NIS) {
                if (nal->shutdown)
                        nal->shutdown (nal, ptl_num_interfaces);
                ptl_ni_init_mutex_exit ();
                return PTL_NOSPACE;
        }

        ptl_interfaces[ptl_num_interfaces++] = nal;

        ptl_eq_ni_init(nal);
        ptl_me_ni_init(nal);

        ptl_ni_init_mutex_exit ();
        return PTL_OK;
}


int PtlNIFini(ptl_handle_ni_t ni)
{
        nal_t *nal;
        int rc;

        if (!ptl_init)
                return PTL_NOINIT;

        ptl_ni_init_mutex_enter ();

        nal = ptl_hndl2nal (&ni);
        if (nal == NULL) {
                ptl_ni_init_mutex_exit ();
                return PTL_INV_HANDLE;
        }

        nal->refct--;
        if (nal->refct > 0) {
                ptl_ni_init_mutex_exit ();
                return PTL_OK;
        }

        ptl_me_ni_fini(nal);
        ptl_eq_ni_fini(nal);

        rc = PTL_OK;
        if (nal->shutdown)
                rc = nal->shutdown(nal, ni.nal_idx);

        ptl_interfaces[ni.nal_idx] = NULL;
        ptl_num_interfaces--;

        ptl_ni_init_mutex_exit ();
        return rc;
}

int PtlNIHandle(ptl_handle_any_t handle_in, ptl_handle_ni_t * ni_out)
{
        *ni_out = handle_in;

        return PTL_OK;
}
