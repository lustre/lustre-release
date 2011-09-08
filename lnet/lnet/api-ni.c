/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_LNET
#include <lnet/lib-lnet.h>

#ifdef __KERNEL__
#define D_LNI D_CONSOLE
#else
#define D_LNI D_CONFIG
#endif

lnet_t      the_lnet;                           /* THE state of the network */

#ifdef __KERNEL__

static char *ip2nets = "";
CFS_MODULE_PARM(ip2nets, "s", charp, 0444,
                "LNET network <- IP table");

static char *networks = "";
CFS_MODULE_PARM(networks, "s", charp, 0444,
                "local networks");

static char *routes = "";
CFS_MODULE_PARM(routes, "s", charp, 0444,
                "routes to non-local networks");

char *
lnet_get_routes(void)
{
        return routes;
}

char *
lnet_get_networks(void)
{
        char   *nets;
        int     rc;

        if (*networks != 0 && *ip2nets != 0) {
                LCONSOLE_ERROR_MSG(0x101, "Please specify EITHER 'networks' or "
                                   "'ip2nets' but not both at once\n");
                return NULL;
        }

        if (*ip2nets != 0) {
                rc = lnet_parse_ip2nets(&nets, ip2nets);
                return (rc == 0) ? nets : NULL;
        }

        if (*networks != 0)
                return networks;

        return "tcp";
}

void
lnet_init_locks(void)
{
        cfs_spin_lock_init (&the_lnet.ln_lock);
        cfs_waitq_init (&the_lnet.ln_waitq);
        cfs_init_mutex(&the_lnet.ln_lnd_mutex);
        cfs_init_mutex(&the_lnet.ln_api_mutex);
}

void
lnet_fini_locks(void)
{
}

#else

char *
lnet_get_routes(void)
{
        char *str = getenv("LNET_ROUTES");

        return (str == NULL) ? "" : str;
}

char *
lnet_get_networks (void)
{
        static char       default_networks[256];
        char             *networks = getenv ("LNET_NETWORKS");
        char             *ip2nets  = getenv ("LNET_IP2NETS");
        char             *str;
        char             *sep;
        int               len;
        int               nob;
        int               rc;
        cfs_list_t       *tmp;

#ifdef NOT_YET
        if (networks != NULL && ip2nets != NULL) {
                LCONSOLE_ERROR_MSG(0x103, "Please set EITHER 'LNET_NETWORKS' or"
                                   " 'LNET_IP2NETS' but not both at once\n");
                return NULL;
        }

        if (ip2nets != NULL) {
                rc = lnet_parse_ip2nets(&networks, ip2nets);
                return (rc == 0) ? networks : NULL;
        }
#else
        SET_BUT_UNUSED(ip2nets);
        SET_BUT_UNUSED(rc);
#endif
        if (networks != NULL)
                return networks;

        /* In userland, the default 'networks=' is the list of known net types */

        len = sizeof(default_networks);
        str = default_networks;
        *str = 0;
        sep = "";

        cfs_list_for_each (tmp, &the_lnet.ln_lnds) {
                lnd_t *lnd = cfs_list_entry(tmp, lnd_t, lnd_list);

                nob = snprintf(str, len, "%s%s", sep,
                               libcfs_lnd2str(lnd->lnd_type));
                len -= nob;
                if (len < 0) {
                        /* overflowed the string; leave it where it was */
                        *str = 0;
                        break;
                }

                str += nob;
                sep = ",";
        }

        return default_networks;
}

# ifndef HAVE_LIBPTHREAD

void lnet_init_locks(void)
{
        the_lnet.ln_lock = 0;
        the_lnet.ln_lnd_mutex = 0;
        the_lnet.ln_api_mutex = 0;
}

void lnet_fini_locks(void)
{
        LASSERT (the_lnet.ln_api_mutex == 0);
        LASSERT (the_lnet.ln_lnd_mutex == 0);
        LASSERT (the_lnet.ln_lock == 0);
}

# else

void lnet_init_locks(void)
{
        pthread_cond_init(&the_lnet.ln_cond, NULL);
        pthread_mutex_init(&the_lnet.ln_lock, NULL);
        pthread_mutex_init(&the_lnet.ln_lnd_mutex, NULL);
        pthread_mutex_init(&the_lnet.ln_api_mutex, NULL);
}

void lnet_fini_locks(void)
{
        pthread_mutex_destroy(&the_lnet.ln_api_mutex);
        pthread_mutex_destroy(&the_lnet.ln_lnd_mutex);
        pthread_mutex_destroy(&the_lnet.ln_lock);
        pthread_cond_destroy(&the_lnet.ln_cond);
}

# endif
#endif

void lnet_assert_wire_constants (void)
{
        /* Wire protocol assertions generated by 'wirecheck'
         * running on Linux robert.bartonsoftware.com 2.6.8-1.521
         * #1 Mon Aug 16 09:01:18 EDT 2004 i686 athlon i386 GNU/Linux
         * with gcc version 3.3.3 20040412 (Red Hat Linux 3.3.3-7) */

        /* Constants... */
        CLASSERT (LNET_PROTO_TCP_MAGIC == 0xeebc0ded);
        CLASSERT (LNET_PROTO_TCP_VERSION_MAJOR == 1);
        CLASSERT (LNET_PROTO_TCP_VERSION_MINOR == 0);
        CLASSERT (LNET_MSG_ACK == 0);
        CLASSERT (LNET_MSG_PUT == 1);
        CLASSERT (LNET_MSG_GET == 2);
        CLASSERT (LNET_MSG_REPLY == 3);
        CLASSERT (LNET_MSG_HELLO == 4);

        /* Checks for struct ptl_handle_wire_t */
        CLASSERT ((int)sizeof(lnet_handle_wire_t) == 16);
        CLASSERT ((int)offsetof(lnet_handle_wire_t, wh_interface_cookie) == 0);
        CLASSERT ((int)sizeof(((lnet_handle_wire_t *)0)->wh_interface_cookie) == 8);
        CLASSERT ((int)offsetof(lnet_handle_wire_t, wh_object_cookie) == 8);
        CLASSERT ((int)sizeof(((lnet_handle_wire_t *)0)->wh_object_cookie) == 8);

        /* Checks for struct lnet_magicversion_t */
        CLASSERT ((int)sizeof(lnet_magicversion_t) == 8);
        CLASSERT ((int)offsetof(lnet_magicversion_t, magic) == 0);
        CLASSERT ((int)sizeof(((lnet_magicversion_t *)0)->magic) == 4);
        CLASSERT ((int)offsetof(lnet_magicversion_t, version_major) == 4);
        CLASSERT ((int)sizeof(((lnet_magicversion_t *)0)->version_major) == 2);
        CLASSERT ((int)offsetof(lnet_magicversion_t, version_minor) == 6);
        CLASSERT ((int)sizeof(((lnet_magicversion_t *)0)->version_minor) == 2);

        /* Checks for struct lnet_hdr_t */
        CLASSERT ((int)sizeof(lnet_hdr_t) == 72);
        CLASSERT ((int)offsetof(lnet_hdr_t, dest_nid) == 0);
        CLASSERT ((int)sizeof(((lnet_hdr_t *)0)->dest_nid) == 8);
        CLASSERT ((int)offsetof(lnet_hdr_t, src_nid) == 8);
        CLASSERT ((int)sizeof(((lnet_hdr_t *)0)->src_nid) == 8);
        CLASSERT ((int)offsetof(lnet_hdr_t, dest_pid) == 16);
        CLASSERT ((int)sizeof(((lnet_hdr_t *)0)->dest_pid) == 4);
        CLASSERT ((int)offsetof(lnet_hdr_t, src_pid) == 20);
        CLASSERT ((int)sizeof(((lnet_hdr_t *)0)->src_pid) == 4);
        CLASSERT ((int)offsetof(lnet_hdr_t, type) == 24);
        CLASSERT ((int)sizeof(((lnet_hdr_t *)0)->type) == 4);
        CLASSERT ((int)offsetof(lnet_hdr_t, payload_length) == 28);
        CLASSERT ((int)sizeof(((lnet_hdr_t *)0)->payload_length) == 4);
        CLASSERT ((int)offsetof(lnet_hdr_t, msg) == 32);
        CLASSERT ((int)sizeof(((lnet_hdr_t *)0)->msg) == 40);

        /* Ack */
        CLASSERT ((int)offsetof(lnet_hdr_t, msg.ack.dst_wmd) == 32);
        CLASSERT ((int)sizeof(((lnet_hdr_t *)0)->msg.ack.dst_wmd) == 16);
        CLASSERT ((int)offsetof(lnet_hdr_t, msg.ack.match_bits) == 48);
        CLASSERT ((int)sizeof(((lnet_hdr_t *)0)->msg.ack.match_bits) == 8);
        CLASSERT ((int)offsetof(lnet_hdr_t, msg.ack.mlength) == 56);
        CLASSERT ((int)sizeof(((lnet_hdr_t *)0)->msg.ack.mlength) == 4);

        /* Put */
        CLASSERT ((int)offsetof(lnet_hdr_t, msg.put.ack_wmd) == 32);
        CLASSERT ((int)sizeof(((lnet_hdr_t *)0)->msg.put.ack_wmd) == 16);
        CLASSERT ((int)offsetof(lnet_hdr_t, msg.put.match_bits) == 48);
        CLASSERT ((int)sizeof(((lnet_hdr_t *)0)->msg.put.match_bits) == 8);
        CLASSERT ((int)offsetof(lnet_hdr_t, msg.put.hdr_data) == 56);
        CLASSERT ((int)sizeof(((lnet_hdr_t *)0)->msg.put.hdr_data) == 8);
        CLASSERT ((int)offsetof(lnet_hdr_t, msg.put.ptl_index) == 64);
        CLASSERT ((int)sizeof(((lnet_hdr_t *)0)->msg.put.ptl_index) == 4);
        CLASSERT ((int)offsetof(lnet_hdr_t, msg.put.offset) == 68);
        CLASSERT ((int)sizeof(((lnet_hdr_t *)0)->msg.put.offset) == 4);

        /* Get */
        CLASSERT ((int)offsetof(lnet_hdr_t, msg.get.return_wmd) == 32);
        CLASSERT ((int)sizeof(((lnet_hdr_t *)0)->msg.get.return_wmd) == 16);
        CLASSERT ((int)offsetof(lnet_hdr_t, msg.get.match_bits) == 48);
        CLASSERT ((int)sizeof(((lnet_hdr_t *)0)->msg.get.match_bits) == 8);
        CLASSERT ((int)offsetof(lnet_hdr_t, msg.get.ptl_index) == 56);
        CLASSERT ((int)sizeof(((lnet_hdr_t *)0)->msg.get.ptl_index) == 4);
        CLASSERT ((int)offsetof(lnet_hdr_t, msg.get.src_offset) == 60);
        CLASSERT ((int)sizeof(((lnet_hdr_t *)0)->msg.get.src_offset) == 4);
        CLASSERT ((int)offsetof(lnet_hdr_t, msg.get.sink_length) == 64);
        CLASSERT ((int)sizeof(((lnet_hdr_t *)0)->msg.get.sink_length) == 4);

        /* Reply */
        CLASSERT ((int)offsetof(lnet_hdr_t, msg.reply.dst_wmd) == 32);
        CLASSERT ((int)sizeof(((lnet_hdr_t *)0)->msg.reply.dst_wmd) == 16);

        /* Hello */
        CLASSERT ((int)offsetof(lnet_hdr_t, msg.hello.incarnation) == 32);
        CLASSERT ((int)sizeof(((lnet_hdr_t *)0)->msg.hello.incarnation) == 8);
        CLASSERT ((int)offsetof(lnet_hdr_t, msg.hello.type) == 40);
        CLASSERT ((int)sizeof(((lnet_hdr_t *)0)->msg.hello.type) == 4);
}

lnd_t *
lnet_find_lnd_by_type (int type)
{
        lnd_t              *lnd;
        cfs_list_t         *tmp;

        /* holding lnd mutex */
        cfs_list_for_each (tmp, &the_lnet.ln_lnds) {
                lnd = cfs_list_entry(tmp, lnd_t, lnd_list);

                if ((int)lnd->lnd_type == type)
                        return lnd;
        }

        return NULL;
}

void
lnet_register_lnd (lnd_t *lnd)
{
        LNET_MUTEX_DOWN(&the_lnet.ln_lnd_mutex);

        LASSERT (the_lnet.ln_init);
        LASSERT (libcfs_isknown_lnd(lnd->lnd_type));
        LASSERT (lnet_find_lnd_by_type(lnd->lnd_type) == NULL);

        cfs_list_add_tail (&lnd->lnd_list, &the_lnet.ln_lnds);
        lnd->lnd_refcount = 0;

        CDEBUG(D_NET, "%s LND registered\n", libcfs_lnd2str(lnd->lnd_type));

        LNET_MUTEX_UP(&the_lnet.ln_lnd_mutex);
}

void
lnet_unregister_lnd (lnd_t *lnd)
{
        LNET_MUTEX_DOWN(&the_lnet.ln_lnd_mutex);

        LASSERT (the_lnet.ln_init);
        LASSERT (lnet_find_lnd_by_type(lnd->lnd_type) == lnd);
        LASSERT (lnd->lnd_refcount == 0);

        cfs_list_del (&lnd->lnd_list);
        CDEBUG(D_NET, "%s LND unregistered\n", libcfs_lnd2str(lnd->lnd_type));

        LNET_MUTEX_UP(&the_lnet.ln_lnd_mutex);
}

#ifndef LNET_USE_LIB_FREELIST

int
lnet_descriptor_setup (void)
{
        return 0;
}

void
lnet_descriptor_cleanup (void)
{
}

#else

int
lnet_freelist_init (lnet_freelist_t *fl, int n, int size)
{
        char *space;

        LASSERT (n > 0);

        size += offsetof (lnet_freeobj_t, fo_contents);

        LIBCFS_ALLOC(space, n * size);
        if (space == NULL)
                return (-ENOMEM);

        CFS_INIT_LIST_HEAD (&fl->fl_list);
        fl->fl_objs = space;
        fl->fl_nobjs = n;
        fl->fl_objsize = size;

        do
        {
                memset (space, 0, size);
                cfs_list_add ((cfs_list_t *)space, &fl->fl_list);
                space += size;
        } while (--n != 0);

        return (0);
}

void
lnet_freelist_fini (lnet_freelist_t *fl)
{
        cfs_list_t       *el;
        int               count;

        if (fl->fl_nobjs == 0)
                return;

        count = 0;
        for (el = fl->fl_list.next; el != &fl->fl_list; el = el->next)
                count++;

        LASSERT (count == fl->fl_nobjs);

        LIBCFS_FREE(fl->fl_objs, fl->fl_nobjs * fl->fl_objsize);
        memset (fl, 0, sizeof (*fl));
}

int
lnet_descriptor_setup (void)
{
        /* NB on failure caller must still call lnet_descriptor_cleanup */
        /*               ******                                         */
        int        rc;

        memset (&the_lnet.ln_free_mes,  0, sizeof (the_lnet.ln_free_mes));
        memset (&the_lnet.ln_free_msgs, 0, sizeof (the_lnet.ln_free_msgs));
        memset (&the_lnet.ln_free_mds,  0, sizeof (the_lnet.ln_free_mds));
        memset (&the_lnet.ln_free_eqs,  0, sizeof (the_lnet.ln_free_eqs));

        rc = lnet_freelist_init(&the_lnet.ln_free_mes,
                                MAX_MES, sizeof (lnet_me_t));
        if (rc != 0)
                return (rc);

        rc = lnet_freelist_init(&the_lnet.ln_free_msgs,
                                MAX_MSGS, sizeof (lnet_msg_t));
        if (rc != 0)
                return (rc);

        rc = lnet_freelist_init(&the_lnet.ln_free_mds,
                                MAX_MDS, sizeof (lnet_libmd_t));
        if (rc != 0)
                return (rc);

        rc = lnet_freelist_init(&the_lnet.ln_free_eqs,
                                MAX_EQS, sizeof (lnet_eq_t));
        return (rc);
}

void
lnet_descriptor_cleanup (void)
{
        lnet_freelist_fini (&the_lnet.ln_free_mes);
        lnet_freelist_fini (&the_lnet.ln_free_msgs);
        lnet_freelist_fini (&the_lnet.ln_free_mds);
        lnet_freelist_fini (&the_lnet.ln_free_eqs);
}

#endif

__u64
lnet_create_interface_cookie (void)
{
        /* NB the interface cookie in wire handles guards against delayed
         * replies and ACKs appearing valid after reboot. Initialisation time,
         * even if it's only implemented to millisecond resolution is probably
         * easily good enough. */
        struct timeval tv;
        __u64          cookie;
#ifndef __KERNEL__
        int            rc = gettimeofday (&tv, NULL);
        LASSERT (rc == 0);
#else
        cfs_gettimeofday(&tv);
#endif
        cookie = tv.tv_sec;
        cookie *= 1000000;
        cookie += tv.tv_usec;
        return cookie;
}

int
lnet_setup_handle_hash (void)
{
        int       i;

        /* Arbitrary choice of hash table size */
#ifdef __KERNEL__
        the_lnet.ln_lh_hash_size =
                (2 * CFS_PAGE_SIZE) / sizeof (cfs_list_t);
#else
        the_lnet.ln_lh_hash_size = (MAX_MES + MAX_MDS + MAX_EQS)/4;
#endif
        LIBCFS_ALLOC(the_lnet.ln_lh_hash_table,
                     the_lnet.ln_lh_hash_size * sizeof (cfs_list_t));
        if (the_lnet.ln_lh_hash_table == NULL)
                return (-ENOMEM);

        for (i = 0; i < the_lnet.ln_lh_hash_size; i++)
                CFS_INIT_LIST_HEAD (&the_lnet.ln_lh_hash_table[i]);

        the_lnet.ln_next_object_cookie = LNET_COOKIE_TYPES;

        return (0);
}

void
lnet_cleanup_handle_hash (void)
{
        if (the_lnet.ln_lh_hash_table == NULL)
                return;

        LIBCFS_FREE(the_lnet.ln_lh_hash_table,
                    the_lnet.ln_lh_hash_size * sizeof (cfs_list_t));
}

lnet_libhandle_t *
lnet_lookup_cookie (__u64 cookie, int type)
{
        /* ALWAYS called with LNET_LOCK held */
        cfs_list_t          *list;
        cfs_list_t          *el;
        unsigned int         hash;

        if ((cookie & (LNET_COOKIE_TYPES - 1)) != type)
                return (NULL);

        hash = ((unsigned int)(cookie >> LNET_COOKIE_TYPE_BITS)) % the_lnet.ln_lh_hash_size;
        list = &the_lnet.ln_lh_hash_table[hash];

        cfs_list_for_each (el, list) {
                lnet_libhandle_t *lh = cfs_list_entry (el, lnet_libhandle_t,
                                                      lh_hash_chain);

                if (lh->lh_cookie == cookie)
                        return (lh);
        }

        return (NULL);
}

void
lnet_initialise_handle (lnet_libhandle_t *lh, int type)
{
        /* ALWAYS called with LNET_LOCK held */
        unsigned int    hash;

        LASSERT (type >= 0 && type < LNET_COOKIE_TYPES);
        lh->lh_cookie = the_lnet.ln_next_object_cookie | type;
        the_lnet.ln_next_object_cookie += LNET_COOKIE_TYPES;

        hash = ((unsigned int)(lh->lh_cookie >> LNET_COOKIE_TYPE_BITS)) % the_lnet.ln_lh_hash_size;
        cfs_list_add (&lh->lh_hash_chain, &the_lnet.ln_lh_hash_table[hash]);
}

void
lnet_invalidate_handle (lnet_libhandle_t *lh)
{
        /* ALWAYS called with LNET_LOCK held */
        cfs_list_del (&lh->lh_hash_chain);
}

cfs_list_t *
lnet_portal_mhash_alloc(void)
{
        cfs_list_t       *mhash;
        int               i;

        LIBCFS_ALLOC(mhash, sizeof(cfs_list_t) * LNET_PORTAL_HASH_SIZE);
        if (mhash == NULL)
                return NULL;

        for (i = 0; i < LNET_PORTAL_HASH_SIZE; i++)
                CFS_INIT_LIST_HEAD(&mhash[i]);

        return mhash;
}

void
lnet_portal_mhash_free(cfs_list_t *mhash)
{
        int     i;

        for (i = 0; i < LNET_PORTAL_HASH_SIZE; i++) {
                while (!cfs_list_empty(&mhash[i])) {
                        lnet_me_t *me = cfs_list_entry(mhash[i].next,
                                                       lnet_me_t, me_list);
                        CERROR ("Active ME %p on exit portal mhash\n", me);
                        cfs_list_del(&me->me_list);
                        lnet_me_free(me);
                }
        }
        LIBCFS_FREE(mhash, sizeof(cfs_list_t) * LNET_PORTAL_HASH_SIZE);
}

int
lnet_init_finalizers(void)
{
#ifdef __KERNEL__
        int    i;

        the_lnet.ln_nfinalizers = (int) cfs_num_online_cpus();

        LIBCFS_ALLOC(the_lnet.ln_finalizers,
                     the_lnet.ln_nfinalizers *
                     sizeof(*the_lnet.ln_finalizers));
        if (the_lnet.ln_finalizers == NULL) {
                CERROR("Can't allocate ln_finalizers\n");
                return -ENOMEM;
        }

        for (i = 0; i < the_lnet.ln_nfinalizers; i++)
                the_lnet.ln_finalizers[i] = NULL;
#else
        the_lnet.ln_finalizing = 0;
#endif

        CFS_INIT_LIST_HEAD(&the_lnet.ln_finalizeq);
        return 0;
}

void
lnet_fini_finalizers(void)
{
#ifdef __KERNEL__
        int    i;

        for (i = 0; i < the_lnet.ln_nfinalizers; i++)
                LASSERT (the_lnet.ln_finalizers[i] == NULL);

        LIBCFS_FREE(the_lnet.ln_finalizers,
                    the_lnet.ln_nfinalizers *
                    sizeof(*the_lnet.ln_finalizers));
#else
        LASSERT (!the_lnet.ln_finalizing);
#endif
        LASSERT (cfs_list_empty(&the_lnet.ln_finalizeq));
}

#ifndef __KERNEL__
/**
 * Reserved API - do not use.
 * Temporary workaround to allow uOSS and test programs force server
 * mode in userspace. See comments near ln_server_mode_flag in
 * lnet/lib-types.h */

void
lnet_server_mode() {
        the_lnet.ln_server_mode_flag = 1;
}
#endif

int
lnet_prepare(lnet_pid_t requested_pid)
{
        /* Prepare to bring up the network */
        int               rc = 0;
        int               i;

        LASSERT (the_lnet.ln_refcount == 0);

        the_lnet.ln_routing = 0;

#ifdef __KERNEL__
        LASSERT ((requested_pid & LNET_PID_USERFLAG) == 0);
        the_lnet.ln_pid = requested_pid;
#else
        if (the_lnet.ln_server_mode_flag) {/* server case (uOSS) */
                LASSERT ((requested_pid & LNET_PID_USERFLAG) == 0);

                if (cfs_curproc_uid())/* Only root can run user-space server */
                        return -EPERM;
                the_lnet.ln_pid = requested_pid;

        } else {/* client case (liblustre) */

                /* My PID must be unique on this node and flag I'm userspace */
                the_lnet.ln_pid = getpid() | LNET_PID_USERFLAG;
        }
#endif

        rc = lnet_descriptor_setup();
        if (rc != 0)
                goto failed0;

        memset(&the_lnet.ln_counters, 0,
               sizeof(the_lnet.ln_counters));

        CFS_INIT_LIST_HEAD (&the_lnet.ln_active_msgs);
        CFS_INIT_LIST_HEAD (&the_lnet.ln_active_mds);
        CFS_INIT_LIST_HEAD (&the_lnet.ln_active_eqs);
        CFS_INIT_LIST_HEAD (&the_lnet.ln_test_peers);
        CFS_INIT_LIST_HEAD (&the_lnet.ln_nis);
        CFS_INIT_LIST_HEAD (&the_lnet.ln_zombie_nis);
        CFS_INIT_LIST_HEAD (&the_lnet.ln_remote_nets);
        CFS_INIT_LIST_HEAD (&the_lnet.ln_routers);

        the_lnet.ln_interface_cookie = lnet_create_interface_cookie();

        lnet_init_rtrpools();

        rc = lnet_setup_handle_hash ();
        if (rc != 0)
                goto failed0;

        rc = lnet_create_peer_table();
        if (rc != 0)
                goto failed1;

        rc = lnet_init_finalizers();
        if (rc != 0)
                goto failed2;

        the_lnet.ln_nportals = MAX_PORTALS;
        LIBCFS_ALLOC(the_lnet.ln_portals,
                     the_lnet.ln_nportals *
                     sizeof(*the_lnet.ln_portals));
        if (the_lnet.ln_portals == NULL) {
                rc = -ENOMEM;
                goto failed3;
        }

        for (i = 0; i < the_lnet.ln_nportals; i++) {
                CFS_INIT_LIST_HEAD(&(the_lnet.ln_portals[i].ptl_mlist));
                CFS_INIT_LIST_HEAD(&(the_lnet.ln_portals[i].ptl_msgq));
                the_lnet.ln_portals[i].ptl_options = 0;
        }

        return 0;

 failed3:
        lnet_fini_finalizers();
 failed2:
        lnet_destroy_peer_table();
 failed1:
        lnet_cleanup_handle_hash();
 failed0:
        lnet_descriptor_cleanup();
        return rc;
}

int
lnet_unprepare (void)
{
        int       idx;

        /* NB no LNET_LOCK since this is the last reference.  All LND instances
         * have shut down already, so it is safe to unlink and free all
         * descriptors, even those that appear committed to a network op (eg MD
         * with non-zero pending count) */

        lnet_fail_nid(LNET_NID_ANY, 0);

        LASSERT (cfs_list_empty(&the_lnet.ln_test_peers));
        LASSERT (the_lnet.ln_refcount == 0);
        LASSERT (cfs_list_empty(&the_lnet.ln_nis));
        LASSERT (cfs_list_empty(&the_lnet.ln_zombie_nis));
        LASSERT (the_lnet.ln_nzombie_nis == 0);

        for (idx = 0; idx < the_lnet.ln_nportals; idx++) {
                lnet_portal_t *ptl = &the_lnet.ln_portals[idx];

                LASSERT (cfs_list_empty(&ptl->ptl_msgq));

                while (!cfs_list_empty(&ptl->ptl_mlist)) {
                        lnet_me_t *me = cfs_list_entry(ptl->ptl_mlist.next,
                                                       lnet_me_t, me_list);
                        CERROR ("Active ME %p on exit\n", me);
                        cfs_list_del (&me->me_list);
                        lnet_me_free (me);
                }

                if (ptl->ptl_mhash != NULL) {
                        LASSERT (lnet_portal_is_unique(ptl));
                        lnet_portal_mhash_free(ptl->ptl_mhash);
                }
        }

        while (!cfs_list_empty (&the_lnet.ln_active_mds)) {
                lnet_libmd_t *md = cfs_list_entry (the_lnet.ln_active_mds.next,
                                                   lnet_libmd_t, md_list);

                CERROR ("Active MD %p on exit\n", md);
                cfs_list_del_init (&md->md_list);
                lnet_md_free (md);
        }

        while (!cfs_list_empty (&the_lnet.ln_active_eqs)) {
                lnet_eq_t *eq = cfs_list_entry (the_lnet.ln_active_eqs.next,
                                                lnet_eq_t, eq_list);

                CERROR ("Active EQ %p on exit\n", eq);
                cfs_list_del (&eq->eq_list);
                lnet_eq_free (eq);
        }

        while (!cfs_list_empty (&the_lnet.ln_active_msgs)) {
                lnet_msg_t *msg = cfs_list_entry (the_lnet.ln_active_msgs.next,
                                                  lnet_msg_t, msg_activelist);

                CERROR ("Active msg %p on exit\n", msg);
                LASSERT (msg->msg_onactivelist);
                msg->msg_onactivelist = 0;
                cfs_list_del (&msg->msg_activelist);
                lnet_msg_free (msg);
        }

        LIBCFS_FREE(the_lnet.ln_portals,  
                    the_lnet.ln_nportals * sizeof(*the_lnet.ln_portals));

        lnet_free_rtrpools();
        lnet_fini_finalizers();
        lnet_destroy_peer_table();
        lnet_cleanup_handle_hash();
        lnet_descriptor_cleanup();

        return (0);
}

lnet_ni_t  *
lnet_net2ni_locked (__u32 net)
{
        cfs_list_t       *tmp;
        lnet_ni_t        *ni;

        cfs_list_for_each (tmp, &the_lnet.ln_nis) {
                ni = cfs_list_entry(tmp, lnet_ni_t, ni_list);

                if (LNET_NIDNET(ni->ni_nid) == net) {
                        lnet_ni_addref_locked(ni);
                        return ni;
                }
        }

        return NULL;
}

int
lnet_islocalnet (__u32 net)
{
        lnet_ni_t        *ni;

        LNET_LOCK();
        ni = lnet_net2ni_locked(net);
        if (ni != NULL)
                lnet_ni_decref_locked(ni);
        LNET_UNLOCK();

        return ni != NULL;
}

lnet_ni_t  *
lnet_nid2ni_locked (lnet_nid_t nid)
{
        cfs_list_t       *tmp;
        lnet_ni_t        *ni;

        cfs_list_for_each (tmp, &the_lnet.ln_nis) {
                ni = cfs_list_entry(tmp, lnet_ni_t, ni_list);

                if (ni->ni_nid == nid) {
                        lnet_ni_addref_locked(ni);
                        return ni;
                }
        }

        return NULL;
}

int
lnet_islocalnid (lnet_nid_t nid)
{
        lnet_ni_t     *ni;

        LNET_LOCK();
        ni = lnet_nid2ni_locked(nid);
        if (ni != NULL)
                lnet_ni_decref_locked(ni);
        LNET_UNLOCK();

        return ni != NULL;
}

int
lnet_count_acceptor_nis (void)
{
        /* Return the # of NIs that need the acceptor. */
        int            count = 0;
#if defined(__KERNEL__) || defined(HAVE_LIBPTHREAD)
        cfs_list_t    *tmp;
        lnet_ni_t     *ni;

        LNET_LOCK();
        cfs_list_for_each (tmp, &the_lnet.ln_nis) {
                ni = cfs_list_entry(tmp, lnet_ni_t, ni_list);

                if (ni->ni_lnd->lnd_accept != NULL)
                        count++;
        }

        LNET_UNLOCK();

#endif /* defined(__KERNEL__) || defined(HAVE_LIBPTHREAD) */
        return count;
}

void
lnet_shutdown_lndnis (void)
{
        int                i;
        int                islo;
        lnet_ni_t         *ni;

        /* NB called holding the global mutex */

        /* All quiet on the API front */
        LASSERT (!the_lnet.ln_shutdown);
        LASSERT (the_lnet.ln_refcount == 0);
        LASSERT (cfs_list_empty(&the_lnet.ln_zombie_nis));
        LASSERT (the_lnet.ln_nzombie_nis == 0);
        LASSERT (cfs_list_empty(&the_lnet.ln_remote_nets));

        LNET_LOCK();
        the_lnet.ln_shutdown = 1;               /* flag shutdown */

        /* Unlink NIs from the global table */
        while (!cfs_list_empty(&the_lnet.ln_nis)) {
                ni = cfs_list_entry(the_lnet.ln_nis.next,
                                    lnet_ni_t, ni_list);
                cfs_list_del (&ni->ni_list);

                the_lnet.ln_nzombie_nis++;
                lnet_ni_decref_locked(ni); /* drop ln_nis' ref */
        }

        /* Drop the cached eqwait NI. */
        if (the_lnet.ln_eqwaitni != NULL) {
                lnet_ni_decref_locked(the_lnet.ln_eqwaitni);
                the_lnet.ln_eqwaitni = NULL;
        }

        /* Drop the cached loopback NI. */
        if (the_lnet.ln_loni != NULL) {
                lnet_ni_decref_locked(the_lnet.ln_loni);
                the_lnet.ln_loni = NULL;
        }

        LNET_UNLOCK();

        /* Clear lazy portals and drop delayed messages which hold refs
         * on their lnet_msg_t::msg_rxpeer */
        for (i = 0; i < the_lnet.ln_nportals; i++)
                LNetClearLazyPortal(i);

        /* Clear the peer table and wait for all peers to go (they hold refs on
         * their NIs) */
        lnet_clear_peer_table();

        LNET_LOCK();
        /* Now wait for the NI's I just nuked to show up on ln_zombie_nis
         * and shut them down in guaranteed thread context */
        i = 2;
        while (the_lnet.ln_nzombie_nis != 0) {

                while (cfs_list_empty(&the_lnet.ln_zombie_nis)) {
                        LNET_UNLOCK();
                        ++i;
                        if ((i & (-i)) == i)
                                CDEBUG(D_WARNING,"Waiting for %d zombie NIs\n",
                                       the_lnet.ln_nzombie_nis);
                        cfs_pause(cfs_time_seconds(1));
                        LNET_LOCK();
                }

                ni = cfs_list_entry(the_lnet.ln_zombie_nis.next,
                                    lnet_ni_t, ni_list);
                cfs_list_del(&ni->ni_list);
                ni->ni_lnd->lnd_refcount--;

                LNET_UNLOCK();

                islo = ni->ni_lnd->lnd_type == LOLND;

                LASSERT (!cfs_in_interrupt ());
                (ni->ni_lnd->lnd_shutdown)(ni);

                /* can't deref lnd anymore now; it might have unregistered
                 * itself...  */

                if (!islo)
                        CDEBUG(D_LNI, "Removed LNI %s\n",
                               libcfs_nid2str(ni->ni_nid));

                LIBCFS_FREE(ni, sizeof(*ni));

                LNET_LOCK();
                the_lnet.ln_nzombie_nis--;
        }

        the_lnet.ln_shutdown = 0;
        LNET_UNLOCK();

        if (the_lnet.ln_network_tokens != NULL) {
                LIBCFS_FREE(the_lnet.ln_network_tokens,
                            the_lnet.ln_network_tokens_nob);
                the_lnet.ln_network_tokens = NULL;
        }
}

int
lnet_startup_lndnis (void)
{
        lnd_t             *lnd;
        lnet_ni_t         *ni;
        cfs_list_t         nilist;
        int                rc = 0;
        int                lnd_type;
        int                nicount = 0;
        char              *nets = lnet_get_networks();

        CFS_INIT_LIST_HEAD(&nilist);

        if (nets == NULL)
                goto failed;

        rc = lnet_parse_networks(&nilist, nets);
        if (rc != 0)
                goto failed;

        while (!cfs_list_empty(&nilist)) {
                ni = cfs_list_entry(nilist.next, lnet_ni_t, ni_list);
                lnd_type = LNET_NETTYP(LNET_NIDNET(ni->ni_nid));

                LASSERT (libcfs_isknown_lnd(lnd_type));

                if (lnd_type == CIBLND    ||
                    lnd_type == OPENIBLND ||
                    lnd_type == IIBLND    ||
                    lnd_type == VIBLND) {
                        CERROR("LND %s obsoleted\n",
                               libcfs_lnd2str(lnd_type));
                        goto failed;
                }

                LNET_MUTEX_DOWN(&the_lnet.ln_lnd_mutex);
                lnd = lnet_find_lnd_by_type(lnd_type);

#ifdef __KERNEL__
                if (lnd == NULL) {
                        LNET_MUTEX_UP(&the_lnet.ln_lnd_mutex);
                        rc = cfs_request_module("%s",
                                                libcfs_lnd2modname(lnd_type));
                        LNET_MUTEX_DOWN(&the_lnet.ln_lnd_mutex);

                        lnd = lnet_find_lnd_by_type(lnd_type);
                        if (lnd == NULL) {
                                LNET_MUTEX_UP(&the_lnet.ln_lnd_mutex);
                                CERROR("Can't load LND %s, module %s, rc=%d\n",
                                       libcfs_lnd2str(lnd_type),
                                       libcfs_lnd2modname(lnd_type), rc);
#ifndef HAVE_MODULE_LOADING_SUPPORT
                                LCONSOLE_ERROR_MSG(0x104, "Your kernel must be "
                                         "compiled with kernel module "
                                         "loading support.");
#endif
                                goto failed;
                        }
                }
#else
                if (lnd == NULL) {
                        LNET_MUTEX_UP(&the_lnet.ln_lnd_mutex);
                        CERROR("LND %s not supported\n",
                               libcfs_lnd2str(lnd_type));
                        goto failed;
                }
#endif

                ni->ni_refcount = 1;

                LNET_LOCK();
                lnd->lnd_refcount++;
                LNET_UNLOCK();

                ni->ni_lnd = lnd;

                rc = (lnd->lnd_startup)(ni);

                LNET_MUTEX_UP(&the_lnet.ln_lnd_mutex);

                if (rc != 0) {
                        LCONSOLE_ERROR_MSG(0x105, "Error %d starting up LNI %s"
                                           "\n",
                                           rc, libcfs_lnd2str(lnd->lnd_type));
                        LNET_LOCK();
                        lnd->lnd_refcount--;
                        LNET_UNLOCK();
                        goto failed;
                }

                LASSERT (ni->ni_peertimeout <= 0 || lnd->lnd_query != NULL);

                cfs_list_del(&ni->ni_list);

                LNET_LOCK();
                cfs_list_add_tail(&ni->ni_list, &the_lnet.ln_nis);
                LNET_UNLOCK();

                if (lnd->lnd_type == LOLND) {
                        lnet_ni_addref(ni);
                        LASSERT (the_lnet.ln_loni == NULL);
                        the_lnet.ln_loni = ni;
                        continue;
                }

#ifndef __KERNEL__
                if (lnd->lnd_wait != NULL) {
                        if (the_lnet.ln_eqwaitni == NULL) {
                                lnet_ni_addref(ni);
                                the_lnet.ln_eqwaitni = ni;
                        }
                } else {
# ifndef HAVE_LIBPTHREAD
                        LCONSOLE_ERROR_MSG(0x106, "LND %s not supported in a "
                                           "single-threaded runtime\n",
                                           libcfs_lnd2str(lnd_type));
                        goto failed;
# endif
                }
#endif
                if (ni->ni_peertxcredits == 0 ||
                    ni->ni_maxtxcredits == 0) {
                        LCONSOLE_ERROR_MSG(0x107, "LNI %s has no %scredits\n",
                                           libcfs_lnd2str(lnd->lnd_type),
                                           ni->ni_peertxcredits == 0 ?
                                           "" : "per-peer ");
                        goto failed;
                }

                ni->ni_txcredits = ni->ni_mintxcredits = ni->ni_maxtxcredits;

                CDEBUG(D_LNI, "Added LNI %s [%d/%d/%d/%d]\n",
                       libcfs_nid2str(ni->ni_nid),
                       ni->ni_peertxcredits, ni->ni_txcredits,
                       ni->ni_peerrtrcredits, ni->ni_peertimeout);

                nicount++;
        }

        if (the_lnet.ln_eqwaitni != NULL && nicount > 1) {
                lnd_type = the_lnet.ln_eqwaitni->ni_lnd->lnd_type;
                LCONSOLE_ERROR_MSG(0x109, "LND %s can only run single-network"
                                   "\n",
                                   libcfs_lnd2str(lnd_type));
                goto failed;
        }

        return 0;

 failed:
        lnet_shutdown_lndnis();

        while (!cfs_list_empty(&nilist)) {
                ni = cfs_list_entry(nilist.next, lnet_ni_t, ni_list);
                cfs_list_del(&ni->ni_list);
                LIBCFS_FREE(ni, sizeof(*ni));
        }

        return -ENETDOWN;
}

/**
 * Initialize LNet library.
 *
 * Only userspace program needs to call this function - it's automatically
 * called in the kernel at module loading time. Caller has to call LNetFini()
 * after a call to LNetInit(), if and only if the latter returned 0. It must
 * be called exactly once.
 *
 * \return 0 on success, and -ve on failures.
 */
int
LNetInit(void)
{
        lnet_assert_wire_constants ();
        LASSERT (!the_lnet.ln_init);

        memset(&the_lnet, 0, sizeof(the_lnet));

        lnet_init_locks();
        the_lnet.ln_refcount = 0;
        the_lnet.ln_init = 1;
        LNetInvalidateHandle(&the_lnet.ln_rc_eqh);
        CFS_INIT_LIST_HEAD(&the_lnet.ln_lnds);
        CFS_INIT_LIST_HEAD(&the_lnet.ln_zombie_rcd);

#ifdef __KERNEL__
        /* All LNDs apart from the LOLND are in separate modules.  They
         * register themselves when their module loads, and unregister
         * themselves when their module is unloaded. */
#else
        /* Register LNDs
         * NB the order here determines default 'networks=' order */
# ifdef CRAY_XT3
        LNET_REGISTER_ULND(the_ptllnd);
# endif
# ifdef HAVE_LIBPTHREAD
        LNET_REGISTER_ULND(the_tcplnd);
# endif
#endif
        lnet_register_lnd(&the_lolnd);
        return 0;
}

/**
 * Finalize LNet library.
 *
 * Only userspace program needs to call this function. It can be called
 * at most once.
 *
 * \pre LNetInit() called with success.
 * \pre All LNet users called LNetNIFini() for matching LNetNIInit() calls.
 */
void
LNetFini(void)
{
        LASSERT (the_lnet.ln_init);
        LASSERT (the_lnet.ln_refcount == 0);

        while (!cfs_list_empty(&the_lnet.ln_lnds))
                lnet_unregister_lnd(cfs_list_entry(the_lnet.ln_lnds.next,
                                                   lnd_t, lnd_list));
        lnet_fini_locks();

        the_lnet.ln_init = 0;
}

/**
 * Set LNet PID and start LNet interfaces, routing, and forwarding.
 *
 * Userspace program should call this after a successful call to LNetInit().
 * Users must call this function at least once before any other functions.
 * For each successful call there must be a corresponding call to
 * LNetNIFini(). For subsequent calls to LNetNIInit(), \a requested_pid is
 * ignored.
 *
 * The PID used by LNet may be different from the one requested.
 * See LNetGetId().
 *
 * \param requested_pid PID requested by the caller.
 *
 * \return 0 on success, and non-zero error code on failures.
 */
int
LNetNIInit(lnet_pid_t requested_pid)
{
        int         im_a_router = 0;
        int         rc;

        LNET_MUTEX_DOWN(&the_lnet.ln_api_mutex);

        LASSERT (the_lnet.ln_init);
        CDEBUG(D_OTHER, "refs %d\n", the_lnet.ln_refcount);

        if (the_lnet.ln_refcount > 0) {
                rc = the_lnet.ln_refcount++;
                goto out;
        }

        lnet_get_tunables();

        if (requested_pid == LNET_PID_ANY) {
                /* Don't instantiate LNET just for me */
                rc = -ENETDOWN;
                goto failed0;
        }

        rc = lnet_prepare(requested_pid);
        if (rc != 0)
                goto failed0;

        rc = lnet_startup_lndnis();
        if (rc != 0)
                goto failed1;

        rc = lnet_parse_routes(lnet_get_routes(), &im_a_router);
        if (rc != 0)
                goto failed2;

        rc = lnet_check_routes();
        if (rc != 0)
                goto failed2;

        rc = lnet_alloc_rtrpools(im_a_router);
        if (rc != 0)
                goto failed2;

        rc = lnet_acceptor_start();
        if (rc != 0)
                goto failed2;

        the_lnet.ln_refcount = 1;
        /* Now I may use my own API functions... */

        /* NB router checker needs the_lnet.ln_ping_info in
         * lnet_router_checker -> lnet_update_ni_status */
        rc = lnet_ping_target_init();
        if (rc != 0)
                goto failed3;

        rc = lnet_router_checker_start();
        if (rc != 0)
                goto failed4;

        lnet_proc_init();
        goto out;

 failed4:
        lnet_ping_target_fini();
 failed3:
        the_lnet.ln_refcount = 0;
        lnet_acceptor_stop();
 failed2:
        lnet_destroy_routes();
        lnet_shutdown_lndnis();
 failed1:
        lnet_unprepare();
 failed0:
        LASSERT (rc < 0);
 out:
        LNET_MUTEX_UP(&the_lnet.ln_api_mutex);
        return rc;
}

/**
 * Stop LNet interfaces, routing, and forwarding.
 *
 * Users must call this function once for each successful call to LNetNIInit().
 * Once the LNetNIFini() operation has been started, the results of pending
 * API operations are undefined.
 *
 * \return always 0 for current implementation.
 */
int
LNetNIFini()
{
        LNET_MUTEX_DOWN(&the_lnet.ln_api_mutex);

        LASSERT (the_lnet.ln_init);
        LASSERT (the_lnet.ln_refcount > 0);

        if (the_lnet.ln_refcount != 1) {
                the_lnet.ln_refcount--;
        } else {
                LASSERT (!the_lnet.ln_niinit_self);

                lnet_proc_fini();
                lnet_router_checker_stop();
                lnet_ping_target_fini();

                /* Teardown fns that use my own API functions BEFORE here */
                the_lnet.ln_refcount = 0;

                lnet_acceptor_stop();
                lnet_destroy_routes();
                lnet_shutdown_lndnis();
                lnet_unprepare();
        }

        LNET_MUTEX_UP(&the_lnet.ln_api_mutex);
        return 0;
}

/**
 * This is an ugly hack to export IOC_LIBCFS_DEBUG_PEER and
 * IOC_LIBCFS_PORTALS_COMPATIBILITY commands to users, by tweaking the LNet
 * internal ioctl handler.
 *
 * IOC_LIBCFS_PORTALS_COMPATIBILITY is now deprecated, don't use it.
 *
 * \param cmd IOC_LIBCFS_DEBUG_PEER to print debugging data about a peer.
 * The data will be printed to system console. Don't use it excessively.
 * \param arg A pointer to lnet_process_id_t, process ID of the peer.
 *
 * \return Always return 0 when called by users directly (i.e., not via ioctl).
 */
int
LNetCtl(unsigned int cmd, void *arg)
{
        struct libcfs_ioctl_data *data = arg;
        lnet_process_id_t         id = {0};
        lnet_ni_t                *ni;
        int                       rc;

        LASSERT (the_lnet.ln_init);
        LASSERT (the_lnet.ln_refcount > 0);

        switch (cmd) {
        case IOC_LIBCFS_GET_NI:
                rc = LNetGetId(data->ioc_count, &id);
                data->ioc_nid = id.nid;
                return rc;

        case IOC_LIBCFS_FAIL_NID:
                return lnet_fail_nid(data->ioc_nid, data->ioc_count);

        case IOC_LIBCFS_ADD_ROUTE:
                rc = lnet_add_route(data->ioc_net, data->ioc_count,
                                    data->ioc_nid);
                return (rc != 0) ? rc : lnet_check_routes();

        case IOC_LIBCFS_DEL_ROUTE:
                return lnet_del_route(data->ioc_net, data->ioc_nid);

        case IOC_LIBCFS_GET_ROUTE:
                return lnet_get_route(data->ioc_count,
                                      &data->ioc_net, &data->ioc_count,
                                      &data->ioc_nid, &data->ioc_flags);
        case IOC_LIBCFS_NOTIFY_ROUTER:
                return lnet_notify(NULL, data->ioc_nid, data->ioc_flags,
                                   cfs_time_current() -
                                   cfs_time_seconds(cfs_time_current_sec() -
                                                    (time_t)data->ioc_u64[0]));

        case IOC_LIBCFS_PORTALS_COMPATIBILITY:
                /* This can be removed once lustre stops calling it */
                return 0;

        case IOC_LIBCFS_LNET_DIST:
                rc = LNetDist(data->ioc_nid, &data->ioc_nid, &data->ioc_u32[1]);
                if (rc < 0 && rc != -EHOSTUNREACH)
                        return rc;

                data->ioc_u32[0] = rc;
                return 0;

        case IOC_LIBCFS_TESTPROTOCOMPAT:
                LNET_LOCK();
                the_lnet.ln_testprotocompat = data->ioc_flags;
                LNET_UNLOCK();
                return 0;

        case IOC_LIBCFS_PING:
                id.nid = data->ioc_nid;
                id.pid = data->ioc_u32[0];
                rc = lnet_ping(id, data->ioc_u32[1], /* timeout */
                               (lnet_process_id_t *)data->ioc_pbuf1,
                               data->ioc_plen1/sizeof(lnet_process_id_t));
                if (rc < 0)
                        return rc;
                data->ioc_count = rc;
                return 0;

        case IOC_LIBCFS_DEBUG_PEER: {
                /* CAVEAT EMPTOR: this one designed for calling directly; not
                 * via an ioctl */
                id = *((lnet_process_id_t *) arg);

                lnet_debug_peer(id.nid);

                ni = lnet_net2ni(LNET_NIDNET(id.nid));
                if (ni == NULL) {
                        CDEBUG(D_WARNING, "No NI for %s\n", libcfs_id2str(id));
                } else {
                        if (ni->ni_lnd->lnd_ctl == NULL) {
                                CDEBUG(D_WARNING, "No ctl for %s\n",
                                       libcfs_id2str(id));
                        } else {
                                (void)ni->ni_lnd->lnd_ctl(ni, cmd, arg);
                        }

                        lnet_ni_decref(ni);
                }
                return 0;
        }

        default:
                ni = lnet_net2ni(data->ioc_net);
                if (ni == NULL)
                        return -EINVAL;

                if (ni->ni_lnd->lnd_ctl == NULL)
                        rc = -EINVAL;
                else
                        rc = ni->ni_lnd->lnd_ctl(ni, cmd, arg);

                lnet_ni_decref(ni);
                return rc;
        }
        /* not reached */
}

/**
 * Retrieve the lnet_process_id_t ID of LNet interface at \a index. Note that
 * all interfaces share a same PID, as requested by LNetNIInit().
 *
 * \param index Index of the interface to look up.
 * \param id On successful return, this location will hold the
 * lnet_process_id_t ID of the interface.
 *
 * \retval 0 If an interface exists at \a index.
 * \retval -ENOENT If no interface has been found.
 */
int
LNetGetId(unsigned int index, lnet_process_id_t *id)
{
        lnet_ni_t        *ni;
        cfs_list_t       *tmp;
        int               rc = -ENOENT;

        LASSERT (the_lnet.ln_init);
        LASSERT (the_lnet.ln_refcount > 0);

        LNET_LOCK();

        cfs_list_for_each(tmp, &the_lnet.ln_nis) {
                if (index-- != 0)
                        continue;

                ni = cfs_list_entry(tmp, lnet_ni_t, ni_list);

                id->nid = ni->ni_nid;
                id->pid = the_lnet.ln_pid;
                rc = 0;
                break;
        }

        LNET_UNLOCK();

        return rc;
}

/**
 * Print a string representation of handle \a h into buffer \a str of
 * \a len bytes.
 */
void
LNetSnprintHandle(char *str, int len, lnet_handle_any_t h)
{
        snprintf(str, len, LPX64, h.cookie);
}

static int
lnet_create_ping_info(void)
{
        int               i;
        int               n;
        int               rc;
        unsigned int      infosz;
        lnet_ni_t        *ni;
        lnet_process_id_t id;
        lnet_ping_info_t *pinfo;

        for (n = 0; ; n++) {
                rc = LNetGetId(n, &id);
                if (rc == -ENOENT)
                        break;

                LASSERT (rc == 0);
        }

        infosz = offsetof(lnet_ping_info_t, pi_ni[n]);
        LIBCFS_ALLOC(pinfo, infosz);
        if (pinfo == NULL) {
                CERROR("Can't allocate ping info[%d]\n", n);
                return -ENOMEM;
        }

        pinfo->pi_nnis    = n;
        pinfo->pi_pid     = the_lnet.ln_pid;
        pinfo->pi_magic   = LNET_PROTO_PING_MAGIC;
        pinfo->pi_version = LNET_PROTO_PING_VERSION;

        for (i = 0; i < n; i++) {
                lnet_ni_status_t *ns = &pinfo->pi_ni[i];

                rc = LNetGetId(i, &id);
                LASSERT (rc == 0);

                ns->ns_nid    = id.nid;
                ns->ns_status = LNET_NI_STATUS_UP;

                LNET_LOCK();

                ni = lnet_nid2ni_locked(id.nid);
                LASSERT (ni != NULL);
                LASSERT (ni->ni_status == NULL);
                ni->ni_status = ns;
                lnet_ni_decref_locked(ni);

                LNET_UNLOCK();
        }

        the_lnet.ln_ping_info = pinfo;
        return 0;
}

static void
lnet_destroy_ping_info(void)
{
        lnet_ni_t *ni;

        LNET_LOCK();

        cfs_list_for_each_entry (ni, &the_lnet.ln_nis, ni_list) {
                ni->ni_status = NULL;
        }

        LNET_UNLOCK();

        LIBCFS_FREE(the_lnet.ln_ping_info,
                    offsetof(lnet_ping_info_t,
                             pi_ni[the_lnet.ln_ping_info->pi_nnis]));
        the_lnet.ln_ping_info = NULL;
        return;
}

int
lnet_ping_target_init(void)
{
        lnet_md_t         md = {0};
        lnet_handle_me_t  meh;
        lnet_process_id_t id;
        int               rc;
        int               rc2;
        int               infosz;

        rc = lnet_create_ping_info();
        if (rc != 0)
                return rc;

        /* We can have a tiny EQ since we only need to see the unlink event on
         * teardown, which by definition is the last one! */
        rc = LNetEQAlloc(2, LNET_EQ_HANDLER_NONE, &the_lnet.ln_ping_target_eq);
        if (rc != 0) {
                CERROR("Can't allocate ping EQ: %d\n", rc);
                goto failed_0;
        }

        memset(&id, 0, sizeof(lnet_process_id_t));
        id.nid = LNET_NID_ANY;
        id.pid = LNET_PID_ANY;

        rc = LNetMEAttach(LNET_RESERVED_PORTAL, id,
                          LNET_PROTO_PING_MATCHBITS, 0,
                          LNET_UNLINK, LNET_INS_AFTER,
                          &meh);
        if (rc != 0) {
                CERROR("Can't create ping ME: %d\n", rc);
                goto failed_1;
        }

        /* initialize md content */
        infosz = offsetof(lnet_ping_info_t,
                          pi_ni[the_lnet.ln_ping_info->pi_nnis]);
        md.start     = the_lnet.ln_ping_info;
        md.length    = infosz;
        md.threshold = LNET_MD_THRESH_INF;
        md.max_size  = 0;
        md.options   = LNET_MD_OP_GET | LNET_MD_TRUNCATE |
                       LNET_MD_MANAGE_REMOTE;
        md.user_ptr  = NULL;
        md.eq_handle = the_lnet.ln_ping_target_eq;

        rc = LNetMDAttach(meh, md,
                          LNET_RETAIN,
                          &the_lnet.ln_ping_target_md);
        if (rc != 0) {
                CERROR("Can't attach ping MD: %d\n", rc);
                goto failed_2;
        }

        return 0;

 failed_2:
        rc2 = LNetMEUnlink(meh);
        LASSERT (rc2 == 0);
 failed_1:
        rc2 = LNetEQFree(the_lnet.ln_ping_target_eq);
        LASSERT (rc2 == 0);
 failed_0:
        lnet_destroy_ping_info();
        return rc;
}

void
lnet_ping_target_fini(void)
{
        lnet_event_t    event;
        int             rc;
        int             which;
        int             timeout_ms = 1000;
        cfs_sigset_t    blocked = cfs_block_allsigs();

        LNetMDUnlink(the_lnet.ln_ping_target_md);
        /* NB md could be busy; this just starts the unlink */

        for (;;) {
                rc = LNetEQPoll(&the_lnet.ln_ping_target_eq, 1,
                                timeout_ms, &event, &which);

                /* I expect overflow... */
                LASSERT (rc >= 0 || rc == -EOVERFLOW);

                if (rc == 0) {
                        /* timed out: provide a diagnostic */
                        CWARN("Still waiting for ping MD to unlink\n");
                        timeout_ms *= 2;
                        continue;
                }

                /* Got a valid event */
                if (event.unlinked)
                        break;
        }

        rc = LNetEQFree(the_lnet.ln_ping_target_eq);
        LASSERT (rc == 0);
        lnet_destroy_ping_info();
        cfs_restore_sigs(blocked);
}

int
lnet_ping (lnet_process_id_t id, int timeout_ms, lnet_process_id_t *ids, int n_ids)
{
        lnet_handle_eq_t     eqh;
        lnet_handle_md_t     mdh;
        lnet_event_t         event;
        lnet_md_t            md = {0};
        int                  which;
        int                  unlinked = 0;
        int                  replied = 0;
        const int            a_long_time = 60000; /* mS */
        int                  infosz = offsetof(lnet_ping_info_t, pi_ni[n_ids]);
        lnet_ping_info_t    *info;
        lnet_process_id_t    tmpid;
        int                  i;
        int                  nob;
        int                  rc;
        int                  rc2;
        cfs_sigset_t         blocked;

        if (n_ids <= 0 ||
            id.nid == LNET_NID_ANY ||
            timeout_ms > 500000 ||              /* arbitrary limit! */
            n_ids > 20)                         /* arbitrary limit! */
                return -EINVAL;

        if (id.pid == LNET_PID_ANY)
                id.pid = LUSTRE_SRV_LNET_PID;

        LIBCFS_ALLOC(info, infosz);
        if (info == NULL)
                return -ENOMEM;

        /* NB 2 events max (including any unlink event) */
        rc = LNetEQAlloc(2, LNET_EQ_HANDLER_NONE, &eqh);
        if (rc != 0) {
                CERROR("Can't allocate EQ: %d\n", rc);
                goto out_0;
        }

        /* initialize md content */
        md.start     = info;
        md.length    = infosz;
        md.threshold = 2; /*GET/REPLY*/
        md.max_size  = 0;
        md.options   = LNET_MD_TRUNCATE;
        md.user_ptr  = NULL;
        md.eq_handle = eqh;

        rc = LNetMDBind(md, LNET_UNLINK, &mdh);
        if (rc != 0) {
                CERROR("Can't bind MD: %d\n", rc);
                goto out_1;
        }

        rc = LNetGet(LNET_NID_ANY, mdh, id,
                     LNET_RESERVED_PORTAL,
                     LNET_PROTO_PING_MATCHBITS, 0);

        if (rc != 0) {
                /* Don't CERROR; this could be deliberate! */

                rc2 = LNetMDUnlink(mdh);
                LASSERT (rc2 == 0);

                /* NB must wait for the UNLINK event below... */
                unlinked = 1;
                timeout_ms = a_long_time;
        }

        do {
                /* MUST block for unlink to complete */
                if (unlinked)
                        blocked = cfs_block_allsigs();

                rc2 = LNetEQPoll(&eqh, 1, timeout_ms, &event, &which);

                if (unlinked)
                        cfs_restore_sigs(blocked);

                CDEBUG(D_NET, "poll %d(%d %d)%s\n", rc2,
                       (rc2 <= 0) ? -1 : event.type,
                       (rc2 <= 0) ? -1 : event.status,
                       (rc2 > 0 && event.unlinked) ? " unlinked" : "");

                LASSERT (rc2 != -EOVERFLOW);     /* can't miss anything */

                if (rc2 <= 0 || event.status != 0) {
                        /* timeout or error */
                        if (!replied && rc == 0)
                                rc = (rc2 < 0) ? rc2 :
                                     (rc2 == 0) ? -ETIMEDOUT :
                                     event.status;

                        if (!unlinked) {
                                /* Ensure completion in finite time... */
                                LNetMDUnlink(mdh);
                                /* No assertion (racing with network) */
                                unlinked = 1;
                                timeout_ms = a_long_time;
                        } else if (rc2 == 0) {
                                /* timed out waiting for unlink */
                                CWARN("ping %s: late network completion\n",
                                      libcfs_id2str(id));
                        }
                } else if (event.type == LNET_EVENT_REPLY) {
                        replied = 1;
                        rc = event.mlength;
                }

        } while (rc2 <= 0 || !event.unlinked);

        if (!replied) {
                if (rc >= 0)
                        CWARN("%s: Unexpected rc >= 0 but no reply!\n",
                              libcfs_id2str(id));
                rc = -EIO;
                goto out_1;
        }

        nob = rc;
        LASSERT (nob >= 0 && nob <= infosz);

        rc = -EPROTO;                           /* if I can't parse... */

        if (nob < 8) {
                /* can't check magic/version */
                CERROR("%s: ping info too short %d\n",
                       libcfs_id2str(id), nob);
                goto out_1;
        }

        if (info->pi_magic == __swab32(LNET_PROTO_PING_MAGIC)) {
                lnet_swap_pinginfo(info);
        } else if (info->pi_magic != LNET_PROTO_PING_MAGIC) {
                CERROR("%s: Unexpected magic %08x\n", 
                       libcfs_id2str(id), info->pi_magic);
                goto out_1;
        }

        if (info->pi_version != LNET_PROTO_PING_VERSION) {
                CERROR("%s: Unexpected version 0x%x\n",
                       libcfs_id2str(id), info->pi_version);
                goto out_1;
        }

        if (nob < offsetof(lnet_ping_info_t, pi_ni[0])) {
                CERROR("%s: Short reply %d(%d min)\n", libcfs_id2str(id),
                       nob, (int)offsetof(lnet_ping_info_t, pi_ni[0]));
                goto out_1;
        }

        if (info->pi_nnis < n_ids)
                n_ids = info->pi_nnis;

        if (nob < offsetof(lnet_ping_info_t, pi_ni[n_ids])) {
                CERROR("%s: Short reply %d(%d expected)\n", libcfs_id2str(id),
                       nob, (int)offsetof(lnet_ping_info_t, pi_ni[n_ids]));
                goto out_1;
        }

        rc = -EFAULT;                           /* If I SEGV... */

        for (i = 0; i < n_ids; i++) {
                tmpid.pid = info->pi_pid;
                tmpid.nid = info->pi_ni[i].ns_nid;
#ifdef __KERNEL__
                if (cfs_copy_to_user(&ids[i], &tmpid, sizeof(tmpid)))
                        goto out_1;
#else
                ids[i] = tmpid;
#endif
        }
        rc = info->pi_nnis;

 out_1:
        rc2 = LNetEQFree(eqh);
        if (rc2 != 0)
                CERROR("rc2 %d\n", rc2);
        LASSERT (rc2 == 0);

 out_0:
        LIBCFS_FREE(info, infosz);
        return rc;
}
