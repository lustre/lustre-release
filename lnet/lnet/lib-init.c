/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lib/lib-init.c
 * Start up the internal library and clear all structures
 * Called by the NAL when it initializes.  Safe to call multiple times.
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org
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
#include <portals/lib-p30.h>

#ifdef __KERNEL__
# include <libcfs/kp30.h>
#else
# include <string.h>
# include <sys/time.h>
#endif

#ifndef PTL_USE_LIB_FREELIST

int
kportal_descriptor_setup (lib_nal_t *nal,
                          ptl_ni_limits_t *requested_limits,
                          ptl_ni_limits_t *actual_limits)
{
        /* Ignore requested limits! */
        actual_limits->max_mes = INT_MAX;
        actual_limits->max_mds = INT_MAX;
        actual_limits->max_eqs = INT_MAX;

        return PTL_OK;
}

void
kportal_descriptor_cleanup (lib_nal_t *nal)
{
}
#else

int
lib_freelist_init (lib_nal_t *nal, lib_freelist_t *fl, int n, int size)
{
        char *space;

        LASSERT (n > 0);

        size += offsetof (lib_freeobj_t, fo_contents);

        PORTAL_ALLOC(space, n * size);
        if (space == NULL)
                return (PTL_NO_SPACE);

        CFS_INIT_LIST_HEAD (&fl->fl_list);
        fl->fl_objs = space;
        fl->fl_nobjs = n;
        fl->fl_objsize = size;

        do
        {
                memset (space, 0, size);
                list_add ((struct list_head *)space, &fl->fl_list);
                space += size;
        } while (--n != 0);

        return (PTL_OK);
}

void
lib_freelist_fini (lib_nal_t *nal, lib_freelist_t *fl)
{
        struct list_head *el;
        int               count;

        if (fl->fl_nobjs == 0)
                return;

        count = 0;
        for (el = fl->fl_list.next; el != &fl->fl_list; el = el->next)
                count++;

        LASSERT (count == fl->fl_nobjs);

        PORTAL_FREE(fl->fl_objs, fl->fl_nobjs * fl->fl_objsize);
        memset (fl, 0, sizeof (fl));
}

int
kportal_descriptor_setup (lib_nal_t *nal,
                          ptl_ni_limits_t *requested_limits,
                          ptl_ni_limits_t *actual_limits)
{
        /* NB on failure caller must still call kportal_descriptor_cleanup */
        /*               ******                                            */
        lib_ni_t  *ni = &nal->libnal_ni;
        int        rc;

        memset (&ni->ni_free_mes,  0, sizeof (ni->ni_free_mes));
        memset (&ni->ni_free_msgs, 0, sizeof (ni->ni_free_msgs));
        memset (&ni->ni_free_mds,  0, sizeof (ni->ni_free_mds));
        memset (&ni->ni_free_eqs,  0, sizeof (ni->ni_free_eqs));

        /* Ignore requested limits! */
        actual_limits->max_mes = MAX_MES;
        actual_limits->max_mds = MAX_MDS;
        actual_limits->max_eqs = MAX_EQS;
        /* Hahahah what a load of bollocks.  There's nowhere to
         * specify the max # messages in-flight */

        rc = lib_freelist_init (nal, &ni->ni_free_mes,
                                MAX_MES, sizeof (lib_me_t));
        if (rc != PTL_OK)
                return (rc);

        rc = lib_freelist_init (nal, &ni->ni_free_msgs,
                                MAX_MSGS, sizeof (lib_msg_t));
        if (rc != PTL_OK)
                return (rc);

        rc = lib_freelist_init (nal, &ni->ni_free_mds,
                                MAX_MDS, sizeof (lib_md_t));
        if (rc != PTL_OK)
                return (rc);

        rc = lib_freelist_init (nal, &ni->ni_free_eqs,
                                MAX_EQS, sizeof (lib_eq_t));
        return (rc);
}

void
kportal_descriptor_cleanup (lib_nal_t *nal)
{
        lib_ni_t   *ni = &nal->libnal_ni;
        
        lib_freelist_fini (nal, &ni->ni_free_mes);
        lib_freelist_fini (nal, &ni->ni_free_msgs);
        lib_freelist_fini (nal, &ni->ni_free_mds);
        lib_freelist_fini (nal, &ni->ni_free_eqs);
}

#endif

__u64
lib_create_interface_cookie (lib_nal_t *nal)
{
        /* NB the interface cookie in wire handles guards against delayed
         * replies and ACKs appearing valid in a new instance of the same
         * interface.  Initialisation time, even if it's only implemented
         * to millisecond resolution is probably easily good enough. */
        struct timeval tv;
        __u64          cookie;
#ifndef __KERNEL__
        int            rc = gettimeofday (&tv, NULL);
        LASSERT (rc == 0);
#else
	do_gettimeofday(&tv);
#endif
        cookie = tv.tv_sec;
        cookie *= 1000000;
        cookie += tv.tv_usec;
        return (cookie);
}

int
lib_setup_handle_hash (lib_nal_t *nal) 
{
        lib_ni_t *ni = &nal->libnal_ni;
        int       i;
        
        /* Arbitrary choice of hash table size */
#ifdef __KERNEL__
        ni->ni_lh_hash_size = PAGE_SIZE / sizeof (struct list_head);
#else
        ni->ni_lh_hash_size = (MAX_MES + MAX_MDS + MAX_EQS)/4;
#endif
        PORTAL_ALLOC(ni->ni_lh_hash_table,
                     ni->ni_lh_hash_size * sizeof (struct list_head));
        if (ni->ni_lh_hash_table == NULL)
                return (PTL_NO_SPACE);
        
        for (i = 0; i < ni->ni_lh_hash_size; i++)
                CFS_INIT_LIST_HEAD (&ni->ni_lh_hash_table[i]);

        ni->ni_next_object_cookie = PTL_COOKIE_TYPES;
        
        return (PTL_OK);
}

void
lib_cleanup_handle_hash (lib_nal_t *nal)
{
        lib_ni_t *ni = &nal->libnal_ni;

        if (ni->ni_lh_hash_table == NULL)
                return;
        
        PORTAL_FREE(ni->ni_lh_hash_table,
                    ni->ni_lh_hash_size * sizeof (struct list_head));
}

lib_handle_t *
lib_lookup_cookie (lib_nal_t *nal, __u64 cookie, int type) 
{
        /* ALWAYS called with statelock held */
        lib_ni_t            *ni = &nal->libnal_ni;
        struct list_head    *list;
        struct list_head    *el;
        unsigned int         hash;

        if ((cookie & (PTL_COOKIE_TYPES - 1)) != type)
                return (NULL);
        
        hash = ((unsigned int)cookie) % ni->ni_lh_hash_size;
        list = &ni->ni_lh_hash_table[hash];
        
        list_for_each (el, list) {
                lib_handle_t *lh = list_entry (el, lib_handle_t, lh_hash_chain);
                
                if (lh->lh_cookie == cookie)
                        return (lh);
        }
        
        return (NULL);
}

void
lib_initialise_handle (lib_nal_t *nal, lib_handle_t *lh, int type) 
{
        /* ALWAYS called with statelock held */
        lib_ni_t       *ni = &nal->libnal_ni;
        unsigned int    hash;

        LASSERT (type >= 0 && type < PTL_COOKIE_TYPES);
        lh->lh_cookie = ni->ni_next_object_cookie | type;
        ni->ni_next_object_cookie += PTL_COOKIE_TYPES;
        
        hash = ((unsigned int)lh->lh_cookie) % ni->ni_lh_hash_size;
        list_add (&lh->lh_hash_chain, &ni->ni_lh_hash_table[hash]);
}

void
lib_invalidate_handle (lib_nal_t *nal, lib_handle_t *lh)
{
        list_del (&lh->lh_hash_chain);
}

int
lib_init(lib_nal_t *libnal, nal_t *apinal, 
         ptl_process_id_t process_id,
         ptl_ni_limits_t *requested_limits,
         ptl_ni_limits_t *actual_limits)
{
        int       rc = PTL_OK;
        lib_ni_t *ni = &libnal->libnal_ni;
        int       ptl_size;
        int       i;
        ENTRY;

        /* NB serialised in PtlNIInit() */

        lib_assert_wire_constants ();

        /* Setup the API nal with the lib API handling functions */
        apinal->nal_get_id    = lib_api_get_id;
        apinal->nal_ni_status = lib_api_ni_status;
        apinal->nal_ni_dist   = lib_api_ni_dist;
        apinal->nal_fail_nid  = lib_api_fail_nid;
        apinal->nal_me_attach = lib_api_me_attach;
        apinal->nal_me_insert = lib_api_me_insert;
        apinal->nal_me_unlink = lib_api_me_unlink;
        apinal->nal_md_attach = lib_api_md_attach;
        apinal->nal_md_bind   = lib_api_md_bind;
        apinal->nal_md_unlink = lib_api_md_unlink;
        apinal->nal_md_update = lib_api_md_update;
        apinal->nal_eq_alloc  = lib_api_eq_alloc;
        apinal->nal_eq_free   = lib_api_eq_free;
        apinal->nal_eq_poll   = lib_api_eq_poll;
        apinal->nal_put       = lib_api_put;
        apinal->nal_get       = lib_api_get;

        apinal->nal_data      = libnal;
        ni->ni_api            = apinal;

        rc = kportal_descriptor_setup (libnal, requested_limits, 
                                       &ni->ni_actual_limits);
        if (rc != PTL_OK)
                goto out;

        memset(&ni->ni_counters, 0, sizeof(lib_counters_t));

        CFS_INIT_LIST_HEAD (&ni->ni_active_msgs);
        CFS_INIT_LIST_HEAD (&ni->ni_active_mds);
        CFS_INIT_LIST_HEAD (&ni->ni_active_eqs);
        CFS_INIT_LIST_HEAD (&ni->ni_test_peers);

#ifdef __KERNEL__
        spin_lock_init (&ni->ni_lock);
        cfs_waitq_init (&ni->ni_waitq);
#else
        pthread_mutex_init(&ni->ni_mutex, NULL);
        pthread_cond_init(&ni->ni_cond, NULL);
#endif

        ni->ni_interface_cookie = lib_create_interface_cookie (libnal);
        ni->ni_next_object_cookie = 0;
        rc = lib_setup_handle_hash (libnal);
        if (rc != PTL_OK)
                goto out;
        
        ni->ni_pid = process_id;

        if (requested_limits != NULL)
                ptl_size = requested_limits->max_pt_index + 1;
        else
                ptl_size = 64;

        ni->ni_portals.size = ptl_size;
        PORTAL_ALLOC(ni->ni_portals.tbl,
                     ptl_size * sizeof(struct list_head));
        if (ni->ni_portals.tbl == NULL) {
                rc = PTL_NO_SPACE;
                goto out;
        }

        for (i = 0; i < ptl_size; i++)
                CFS_INIT_LIST_HEAD(&(ni->ni_portals.tbl[i]));

        /* max_{mes,mds,eqs} set in kportal_descriptor_setup */

        /* We don't have an access control table! */
        ni->ni_actual_limits.max_ac_index = -1;

        ni->ni_actual_limits.max_pt_index = ptl_size - 1;
        ni->ni_actual_limits.max_md_iovecs = PTL_MD_MAX_IOV;
        ni->ni_actual_limits.max_me_list = INT_MAX;

        /* We don't support PtlGetPut! */
        ni->ni_actual_limits.max_getput_md = 0;

        if (actual_limits != NULL)
                *actual_limits = ni->ni_actual_limits;

 out:
        if (rc != PTL_OK) {
                lib_cleanup_handle_hash (libnal);
                kportal_descriptor_cleanup (libnal);
        }

        RETURN (rc);
}

int
lib_fini(lib_nal_t *nal)
{
        lib_ni_t *ni = &nal->libnal_ni;
        int       idx;

        /* NB no state_lock() since this is the last reference.  The NAL
         * should have shut down already, so it should be safe to unlink
         * and free all descriptors, even those that appear committed to a
         * network op (eg MD with non-zero pending count)
         */

        for (idx = 0; idx < ni->ni_portals.size; idx++)
                while (!list_empty (&ni->ni_portals.tbl[idx])) {
                        lib_me_t *me = list_entry (ni->ni_portals.tbl[idx].next,
                                                   lib_me_t, me_list);

                        CERROR ("Active me %p on exit\n", me);
                        list_del (&me->me_list);
                        lib_me_free (nal, me);
                }

        while (!list_empty (&ni->ni_active_mds)) {
                lib_md_t *md = list_entry (ni->ni_active_mds.next,
                                           lib_md_t, md_list);

                CERROR ("Active md %p on exit\n", md);
                list_del (&md->md_list);
                lib_md_free (nal, md);
        }

        while (!list_empty (&ni->ni_active_eqs)) {
                lib_eq_t *eq = list_entry (ni->ni_active_eqs.next,
                                           lib_eq_t, eq_list);

                CERROR ("Active eq %p on exit\n", eq);
                list_del (&eq->eq_list);
                lib_eq_free (nal, eq);
        }

        while (!list_empty (&ni->ni_active_msgs)) {
                lib_msg_t *msg = list_entry (ni->ni_active_msgs.next,
                                             lib_msg_t, msg_list);

                CERROR ("Active msg %p on exit\n", msg);
                list_del (&msg->msg_list);
                lib_msg_free (nal, msg);
        }

        PORTAL_FREE(ni->ni_portals.tbl,  
                    ni->ni_portals.size * sizeof(struct list_head));

        lib_cleanup_handle_hash (nal);
        kportal_descriptor_cleanup (nal);

#ifndef __KERNEL__
        pthread_mutex_destroy(&ni->ni_mutex);
        pthread_cond_destroy(&ni->ni_cond);
#endif

        return (PTL_OK);
}
