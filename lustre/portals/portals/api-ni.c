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

int ptl_init;

/* Put some magic in the NI handle so uninitialised/zeroed handles are easy
 * to spot */
#define NI_HANDLE_MAGIC  0xebc0de00
#define NI_HANDLE_MASK   0x000000ff

static struct nal_t *ptl_nal_table[NAL_MAX_NR];

#ifdef __KERNEL__
DECLARE_MUTEX(ptl_mutex);

static void ptl_mutex_enter (void) 
{
        down (&ptl_mutex);
}

static void ptl_mutex_exit (void)
{
        up (&ptl_mutex);
}
#else
static void ptl_mutex_enter (void)
{
}

static void ptl_mutex_exit (void) 
{
}
#endif

nal_t *ptl_hndl2nal(ptl_handle_any_t *handle)
{
        unsigned int idx = handle->nal_idx;

        /* XXX we really rely on the caller NOT racing with interface
         * setup/teardown.  That ensures her NI handle can't get
         * invalidated out from under her (or worse, swapped for a
         * completely different interface!) */

        if (((idx ^ NI_HANDLE_MAGIC) & ~NI_HANDLE_MASK) != 0)
                return NULL;

        idx &= NI_HANDLE_MASK;
        
        if (idx >= NAL_MAX_NR ||
            ptl_nal_table[idx] == NULL ||
            ptl_nal_table[idx]->nal_refct == 0)
                return NULL;

        return ptl_nal_table[idx];
}

int ptl_register_nal (ptl_interface_t interface, nal_t *nal)
{
        int    rc;
        
        ptl_mutex_enter();
        
        if (interface < 0 || interface >= NAL_MAX_NR)
                rc = PTL_IFACE_INVALID;
        else if (ptl_nal_table[interface] != NULL)
                rc = PTL_IFACE_DUP;
        else {
                rc = PTL_OK;
                ptl_nal_table[interface] = nal;
                LASSERT(nal->nal_refct == 0);
        }

        ptl_mutex_exit();
        return (rc);
}

void ptl_unregister_nal (ptl_interface_t interface)
{
        LASSERT(interface >= 0 && interface < NAL_MAX_NR);
        LASSERT(ptl_nal_table[interface] != NULL);
        LASSERT(ptl_nal_table[interface]->nal_refct == 0);
        
        ptl_mutex_enter();
        
        ptl_nal_table[interface] = NULL;

        ptl_mutex_exit();
}

int ptl_ni_init(void)
{
        /* If this assertion fails, we need more bits in NI_HANDLE_MASK and
         * to shift NI_HANDLE_MAGIC left appropriately */
        LASSERT (NAL_MAX_NR <= (NI_HANDLE_MASK + 1));
        
        ptl_mutex_enter();

        if (!ptl_init) {
                /* NULL pointers, clear flags */
                memset(ptl_nal_table, 0, sizeof(ptl_nal_table));
#ifndef __KERNEL__
                /* Kernel NALs register themselves when their module loads,
                 * and unregister themselves when their module is unloaded.
                 * Userspace NALs, are plugged in explicitly here... */
                {
                        extern nal_t procapi_nal;

                        /* XXX pretend it's socknal to keep liblustre happy... */
                        ptl_nal_table[SOCKNAL] = &procapi_nal;
                        LASSERT (procapi_nal.nal_refct == 0);
                }
#endif
                ptl_init = 1;
        }

        ptl_mutex_exit();
        
        return PTL_OK;
}

void ptl_ni_fini(void)
{
        nal_t  *nal;
        int     i;

        ptl_mutex_enter();

        if (ptl_init) {
                for (i = 0; i < NAL_MAX_NR; i++) {

                        nal = ptl_nal_table[i];
                        if (nal == NULL)
                                continue;
                        
                        if (nal->nal_refct != 0) {
                                CWARN("NAL %d has outstanding refcount %d\n",
                                      i, nal->nal_refct);
                                nal->shutdown(nal);
                        }
                        
                        ptl_nal_table[i] = NULL;
                }

                ptl_init = 0;
        }
        
        ptl_mutex_exit();
}

int PtlNIInit(ptl_interface_t interface, ptl_pid_t requested_pid,
              ptl_ni_limits_t *desired_limits, ptl_ni_limits_t *actual_limits,
              ptl_handle_ni_t *handle)
{
        nal_t *nal;
        int    i;
        int    rc;

        if (!ptl_init)
                return PTL_NO_INIT;

        ptl_mutex_enter ();

        if (interface == PTL_IFACE_DEFAULT) {
                for (i = 0; i < NAL_MAX_NR; i++)
                        if (ptl_nal_table[i] != NULL) {
                                interface = i;
                                break;
                        }
                /* NB if no interfaces are registered, 'interface' will
                 * fail the valid test below */
        }
        
        if (interface < 0 || 
            interface >= NAL_MAX_NR ||
            ptl_nal_table[interface] == NULL) {
                GOTO(out, rc = PTL_IFACE_INVALID);
        }

        nal = ptl_nal_table[interface];

        CDEBUG(D_OTHER, "Starting up NAL (%d) refs %d\n", interface, nal->nal_refct);
        rc = nal->startup(nal, requested_pid, desired_limits, actual_limits);

        if (rc != PTL_OK) {
                CERROR("Error %d starting up NAL %d, refs %d\n", rc,
                       interface, nal->nal_refct);
                GOTO(out, rc);
        }
        
        if (nal->nal_refct != 0) {
                /* Caller gets to know if this was the first ref or not */
                rc = PTL_IFACE_DUP;
        }
        
        nal->nal_refct++;
        handle->nal_idx = (NI_HANDLE_MAGIC & ~NI_HANDLE_MASK) | interface;

 out:
        ptl_mutex_exit ();
        return rc;
}

int PtlNIFini(ptl_handle_ni_t ni)
{
        nal_t *nal;
        int    idx;

        if (!ptl_init)
                return PTL_NO_INIT;

        ptl_mutex_enter ();

        nal = ptl_hndl2nal (&ni);
        if (nal == NULL) {
                ptl_mutex_exit ();
                return PTL_HANDLE_INVALID;
        }

        idx = ni.nal_idx & NI_HANDLE_MASK;

        LASSERT(nal->nal_refct > 0);

        nal->nal_refct--;

        /* nal_refct == 0 tells nal->shutdown to really shut down */
        nal->shutdown(nal);

        ptl_mutex_exit ();
        return PTL_OK;
}

int PtlNIHandle(ptl_handle_any_t handle_in, ptl_handle_ni_t * ni_out)
{
        *ni_out = handle_in;

        return PTL_OK;
}
