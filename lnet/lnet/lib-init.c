/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lib/lib-init.c
 * Start up the internal library and clear all structures
 * Called by the NAL when it initializes.  Safe to call multiple times.
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
#include <portals/lib-p30.h>

#ifdef __KERNEL__
# include <linux/string.h>      /* for memset() */
# include <linux/kp30.h>
# ifdef KERNEL_ADDR_CACHE
#  include <compute/OS/addrCache/cache.h>
# endif
#else
# include <string.h>
# include <sys/time.h>
#endif

#ifdef PTL_USE_SLAB_CACHE
static int ptl_slab_users;

kmem_cache_t *ptl_md_slab;
kmem_cache_t *ptl_msg_slab;
kmem_cache_t *ptl_me_slab;
kmem_cache_t *ptl_eq_slab;

atomic_t md_in_use_count;
atomic_t msg_in_use_count;
atomic_t me_in_use_count;
atomic_t eq_in_use_count;

/* NB zeroing in ctor and on freeing ensures items that
 * kmem_cache_validate() OK, but haven't been initialised
 * as an MD/ME/EQ can't have valid handles
 */
static void
ptl_md_slab_ctor (void *obj, kmem_cache_t *slab, unsigned long flags)
{
        memset (obj, 0, sizeof (lib_md_t));
}

static void
ptl_me_slab_ctor (void *obj, kmem_cache_t *slab, unsigned long flags)
{
        memset (obj, 0, sizeof (lib_me_t));
}

static void
ptl_eq_slab_ctor (void *obj, kmem_cache_t *slab, unsigned long flags)
{
        memset (obj, 0, sizeof (lib_eq_t));
}

int
kportal_descriptor_setup (nal_cb_t *nal)
{
        /* NB on failure caller must still call kportal_descriptor_cleanup */
        /*               ******                                            */

        /* We'll have 1 set of slabs for ALL the nals :) */

        if (ptl_slab_users++)
                return 0;

        ptl_md_slab = kmem_cache_create("portals_MD",
                                        sizeof(lib_md_t), 0,
                                        SLAB_HWCACHE_ALIGN,
                                        ptl_md_slab_ctor, NULL);
        if (!ptl_md_slab) {
                CERROR("couldn't allocate ptl_md_t slab");
                RETURN (PTL_NOSPACE);
        }

        /* NB no ctor for msgs; they don't need handle verification */
        ptl_msg_slab = kmem_cache_create("portals_MSG",
                                         sizeof(lib_msg_t), 0,
                                         SLAB_HWCACHE_ALIGN,
                                         NULL, NULL);
        if (!ptl_msg_slab) {
                CERROR("couldn't allocate ptl_msg_t slab");
                RETURN (PTL_NOSPACE);
        }

        ptl_me_slab = kmem_cache_create("portals_ME",
                                        sizeof(lib_me_t), 0,
                                        SLAB_HWCACHE_ALIGN,
                                        ptl_me_slab_ctor, NULL);
        if (!ptl_me_slab) {
                CERROR("couldn't allocate ptl_me_t slab");
                RETURN (PTL_NOSPACE);
        }

        ptl_eq_slab = kmem_cache_create("portals_EQ",
                                        sizeof(lib_eq_t), 0,
                                        SLAB_HWCACHE_ALIGN,
                                        ptl_eq_slab_ctor, NULL);
        if (!ptl_eq_slab) {
                CERROR("couldn't allocate ptl_eq_t slab");
                RETURN (PTL_NOSPACE);
        }

        RETURN(PTL_OK);
}

void
kportal_descriptor_cleanup (nal_cb_t *nal)
{
        if (--ptl_slab_users != 0)
                return;

        LASSERT (atomic_read (&md_in_use_count) == 0);
        LASSERT (atomic_read (&me_in_use_count) == 0);
        LASSERT (atomic_read (&eq_in_use_count) == 0);
        LASSERT (atomic_read (&msg_in_use_count) == 0);

        if (ptl_md_slab != NULL)
                kmem_cache_destroy(ptl_md_slab);
        if (ptl_msg_slab != NULL)
                kmem_cache_destroy(ptl_msg_slab);
        if (ptl_me_slab != NULL)
                kmem_cache_destroy(ptl_me_slab);
        if (ptl_eq_slab != NULL)
                kmem_cache_destroy(ptl_eq_slab);
}
#else

int
lib_freelist_init (nal_cb_t *nal, lib_freelist_t *fl, int n, int size)
{
        char *space;

        LASSERT (n > 0);

        size += offsetof (lib_freeobj_t, fo_contents);

        space = nal->cb_malloc (nal, n * size);
        if (space == NULL)
                return (PTL_NOSPACE);

        INIT_LIST_HEAD (&fl->fl_list);
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
lib_freelist_fini (nal_cb_t *nal, lib_freelist_t *fl)
{
        struct list_head *el;
        int               count;

        if (fl->fl_nobjs == 0)
                return;

        count = 0;
        for (el = fl->fl_list.next; el != &fl->fl_list; el = el->next)
                count++;

        LASSERT (count == fl->fl_nobjs);

        nal->cb_free (nal, fl->fl_objs, fl->fl_nobjs * fl->fl_objsize);
        memset (fl, 0, sizeof (fl));
}

int
kportal_descriptor_setup (nal_cb_t *nal)
{
        /* NB on failure caller must still call kportal_descriptor_cleanup */
        /*               ******                                            */
        int rc;

        memset (&nal->ni.ni_free_mes,  0, sizeof (nal->ni.ni_free_mes));
        memset (&nal->ni.ni_free_msgs, 0, sizeof (nal->ni.ni_free_msgs));
        memset (&nal->ni.ni_free_mds,  0, sizeof (nal->ni.ni_free_mds));
        memset (&nal->ni.ni_free_eqs,  0, sizeof (nal->ni.ni_free_eqs));

        rc = lib_freelist_init (nal, &nal->ni.ni_free_mes,
                                MAX_MES, sizeof (lib_me_t));
        if (rc != PTL_OK)
                return (rc);

        rc = lib_freelist_init (nal, &nal->ni.ni_free_msgs,
                                MAX_MSGS, sizeof (lib_msg_t));
        if (rc != PTL_OK)
                return (rc);

        rc = lib_freelist_init (nal, &nal->ni.ni_free_mds,
                                MAX_MDS, sizeof (lib_md_t));
        if (rc != PTL_OK)
                return (rc);

        rc = lib_freelist_init (nal, &nal->ni.ni_free_eqs,
                                MAX_EQS, sizeof (lib_eq_t));
        return (rc);
}

void
kportal_descriptor_cleanup (nal_cb_t *nal)
{
        lib_freelist_fini (nal, &nal->ni.ni_free_mes);
        lib_freelist_fini (nal, &nal->ni.ni_free_msgs);
        lib_freelist_fini (nal, &nal->ni.ni_free_mds);
        lib_freelist_fini (nal, &nal->ni.ni_free_eqs);
}

#endif

__u64
lib_create_interface_cookie (nal_cb_t *nal)
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
lib_setup_handle_hash (nal_cb_t *nal) 
{
        lib_ni_t *ni = &nal->ni;
        int       i;
        
        /* Arbitrary choice of hash table size */
#ifdef __KERNEL__
        ni->ni_lh_hash_size = PAGE_SIZE / sizeof (struct list_head);
#else
        ni->ni_lh_hash_size = (MAX_MES + MAX_MDS + MAX_EQS)/4;
#endif
        ni->ni_lh_hash_table = 
                (struct list_head *)nal->cb_malloc (nal, ni->ni_lh_hash_size
                                                    * sizeof (struct list_head));
        if (ni->ni_lh_hash_table == NULL)
                return (PTL_NOSPACE);
        
        for (i = 0; i < ni->ni_lh_hash_size; i++)
                INIT_LIST_HEAD (&ni->ni_lh_hash_table[i]);

        ni->ni_next_object_cookie = PTL_COOKIE_TYPES;
        
        return (PTL_OK);
}

void
lib_cleanup_handle_hash (nal_cb_t *nal)
{
        lib_ni_t *ni = &nal->ni;

        if (ni->ni_lh_hash_table == NULL)
                return;
        
        nal->cb_free (nal, ni->ni_lh_hash_table,
                      ni->ni_lh_hash_size * sizeof (struct list_head));
}

lib_handle_t *
lib_lookup_cookie (nal_cb_t *nal, __u64 cookie, int type) 
{
        /* ALWAYS called with statelock held */
        lib_ni_t            *ni = &nal->ni;
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
lib_initialise_handle (nal_cb_t *nal, lib_handle_t *lh, int type) 
{
        /* ALWAYS called with statelock held */
        lib_ni_t       *ni = &nal->ni;
        unsigned int    hash;

        LASSERT (type >= 0 && type < PTL_COOKIE_TYPES);
        lh->lh_cookie = ni->ni_next_object_cookie | type;
        ni->ni_next_object_cookie += PTL_COOKIE_TYPES;
        
        hash = ((unsigned int)lh->lh_cookie) % ni->ni_lh_hash_size;
        list_add (&lh->lh_hash_chain, &ni->ni_lh_hash_table[hash]);
}

void
lib_invalidate_handle (nal_cb_t *nal, lib_handle_t *lh)
{
        list_del (&lh->lh_hash_chain);
}

int
lib_init(nal_cb_t * nal, ptl_nid_t nid, ptl_pid_t pid, int gsize,
         ptl_pt_index_t ptl_size, ptl_ac_index_t acl_size)
{
        int       rc = PTL_OK;
        lib_ni_t *ni = &nal->ni;
        int i;
        ENTRY;

        /* NB serialised in PtlNIInit() */

        if (ni->refcnt != 0) {                       /* already initialised */
                ni->refcnt++;
                goto out;
        }

        /*
         * Allocate the portal table for this interface
         * and all per-interface objects.
         */
        memset(&ni->counters, 0, sizeof(lib_counters_t));

        rc = kportal_descriptor_setup (nal);
        if (rc != PTL_OK)
                goto out;

        INIT_LIST_HEAD (&ni->ni_active_msgs);
        INIT_LIST_HEAD (&ni->ni_active_mds);
        INIT_LIST_HEAD (&ni->ni_active_eqs);

        INIT_LIST_HEAD (&ni->ni_test_peers);

        ni->ni_interface_cookie = lib_create_interface_cookie (nal);
        ni->ni_next_object_cookie = 0;
        rc = lib_setup_handle_hash (nal);
        if (rc != PTL_OK)
                goto out;
        
        ni->nid = nid;
        ni->pid = pid;

        ni->num_nodes = gsize;
        ni->tbl.size = ptl_size;

        ni->tbl.tbl = nal->cb_malloc(nal, sizeof(struct list_head) * ptl_size);
        if (ni->tbl.tbl == NULL) {
                rc = PTL_NOSPACE;
                goto out;
        }

        for (i = 0; i < ptl_size; i++)
                INIT_LIST_HEAD(&(ni->tbl.tbl[i]));

        ni->debug = PTL_DEBUG_NONE;
        ni->up = 1;
        ni->refcnt++;

 out:
        if (rc != PTL_OK) {
                lib_cleanup_handle_hash (nal);
                kportal_descriptor_cleanup (nal);
        }

        RETURN (rc);
}

int
lib_fini(nal_cb_t * nal)
{
        lib_ni_t *ni = &nal->ni;
        int       idx;

        ni->refcnt--;

        if (ni->refcnt != 0)
                goto out;

        /* NB no stat_lock() since this is the last reference.  The NAL
         * should have shut down already, so it should be safe to unlink
         * and free all descriptors, even those that appear committed to a
         * network op (eg MD with non-zero pending count)
         */

        for (idx = 0; idx < ni->tbl.size; idx++)
                while (!list_empty (&ni->tbl.tbl[idx])) {
                        lib_me_t *me = list_entry (ni->tbl.tbl[idx].next,
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

        nal->cb_free(nal, ni->tbl.tbl, sizeof(struct list_head) * ni->tbl.size);
        ni->up = 0;

        lib_cleanup_handle_hash (nal);
        kportal_descriptor_cleanup (nal);

 out:
        return (PTL_OK);
}
