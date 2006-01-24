/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2005 Cluster File Systems, Inc. All rights reserved.
 *   Author: PJ Kirner <pjkirner@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   This file is confidential source code owned by Cluster File Systems.
 *   No viewing, modification, compilation, redistribution, or any other
 *   form of use is permitted except through a signed license agreement.
 *
 *   If you have not signed such an agreement, then you have no rights to
 *   this file.  Please destroy it immediately and contact CFS.
 *
 */

#include "ptllnd.h"


/*
 * TBD List
 * - Add code to prevent peers with diffrent credits from connection
 * - peer->peer_outstanding_credits LASSERT is incorrect if peer is allowed
 *   to have a  diffrent number of credits configured
 
 */

lnd_t               kptllnd_lnd = {
        .lnd_type       = PTLLND,
        .lnd_startup    = kptllnd_startup,
        .lnd_shutdown   = kptllnd_shutdown,
        .lnd_ctl        = kptllnd_ctl,
        .lnd_send       = kptllnd_send,
        .lnd_recv       = kptllnd_recv,
        .lnd_eager_recv = kptllnd_eager_recv,
};

kptl_data_t             kptllnd_data;
kptl_stats_t            kptllnd_stats;

void kptllnd_shutdown (lnet_ni_t *ni);

void ptllnd_assert_wire_constants (void)
{
        /* TBD - auto generated */
}

__u32
kptllnd_cksum (void *ptr, int nob)
{
        char  *c  = ptr;
        __u32  sum = 0;

        while (nob-- > 0)
                sum = ((sum << 1) | (sum >> 31)) + *c++;

        /* ensure I don't return 0 (== no checksum) */
        return (sum == 0) ? 1 : sum;
}

void
kptllnd_init_msg(kptl_msg_t *msg, int type, int body_nob)
{
        msg->ptlm_type = type;
        msg->ptlm_nob  = offsetof(kptl_msg_t, ptlm_u) + body_nob;
}

void
kptllnd_msg_pack(
        kptl_msg_t *msg,
        int credits,
        lnet_nid_t dstnid,
        __u64 dststamp,
        __u64 seq,
        kptl_data_t *kptllnd_data)
{
        msg->ptlm_magic    = PTLLND_MSG_MAGIC;
        msg->ptlm_version  = PTLLND_MSG_VERSION;
        /* msg->ptlm_type  Filled in kptllnd_init_msg()  */
        msg->ptlm_credits  = credits;
        /* msg->ptlm_nob   Filled in kptllnd_init_msg()  */
        msg->ptlm_cksum    = 0;
        msg->ptlm_srcnid   = kptllnd_data->kptl_ni->ni_nid;
        msg->ptlm_srcstamp = kptllnd_data->kptl_incarnation;
        msg->ptlm_dstnid   = dstnid;
        msg->ptlm_dststamp = dststamp;
        msg->ptlm_seq      = seq;

        if (*kptllnd_tunables.kptl_cksum) {
                /* NB ptlm_cksum zero while computing cksum */
                msg->ptlm_cksum = kptllnd_cksum(msg, msg->ptlm_nob);
        }
}

int
kptllnd_msg_unpack(kptl_msg_t *msg, int nob,kptl_data_t *kptllnd_data)
{
        const int hdr_size = offsetof(kptl_msg_t, ptlm_u);
        __u32     msg_cksum;
        int       flip;
        int       msg_nob;

        /* 6 bytes are enough to have received magic + version */
        if (nob < 6) {
                CERROR("Very Short message: %d\n", nob);
                return -EPROTO;
        }

        /*
         * Determine if we need to flip
         */
        if (msg->ptlm_magic == PTLLND_MSG_MAGIC) {
                flip = 0;
        } else if (msg->ptlm_magic == __swab32(PTLLND_MSG_MAGIC)) {
                flip = 1;
        } else {
                CERROR("Bad magic: %08x\n", msg->ptlm_magic);
                return -EPROTO;
        }

        if (msg->ptlm_version !=
            (flip ? __swab16(PTLLND_MSG_VERSION) : PTLLND_MSG_VERSION)) {
                CERROR("Bad version: got %d expected %d\n",
                        msg->ptlm_version,PTLLND_MSG_VERSION);
                return -EPROTO;
        }

        if (nob < hdr_size) {
                CERROR("Short header: got %d, wanted at least %d\n",
                        nob, hdr_size);
                return -EPROTO;
        }

        msg_nob = flip ? __swab32(msg->ptlm_nob) : msg->ptlm_nob;
        if (nob != msg_nob) {
                CERROR("Short message: got %d, wanted %d\n", nob, msg_nob);
                return -EPROTO;
        }

        /* checksum must be computed with
         * 1) ptlm_cksum zero and
         * 2) BEFORE anything gets modified/flipped
         */
        msg_cksum = flip ? __swab32(msg->ptlm_cksum) : msg->ptlm_cksum;
        msg->ptlm_cksum = 0;
        if (msg_cksum != 0){
                STAT_UPDATE(kps_incoming_checksums_calculated);
                if( msg_cksum != kptllnd_cksum(msg, msg_nob) ) {
                        STAT_UPDATE(kps_incoming_checksums_invalid);
                        CERROR("Bad checksum\n");
                        return -EPROTO;
                }
        }

        /* Restore the checksum */
        msg->ptlm_cksum = msg_cksum;

        if(flip){
                 /* leave magic unflipped as a clue to peer endianness */
                __swab16s(&msg->ptlm_version);
                /* These two are 1 byte long so we don't swap them
                   But check this assumtion*/
                CLASSERT (sizeof(msg->ptlm_type) == 1);
                CLASSERT (sizeof(msg->ptlm_credits) == 1);
                msg->ptlm_nob = msg_nob;
                __swab64s(&msg->ptlm_srcnid);
                __swab64s(&msg->ptlm_srcstamp);
                __swab64s(&msg->ptlm_dstnid);
                __swab64s(&msg->ptlm_dststamp);
                __swab64s(&msg->ptlm_seq);

                switch(msg->ptlm_type)
                {
                        case PTLLND_MSG_TYPE_PUT:
                        case PTLLND_MSG_TYPE_GET:
                                __swab64s(&msg->ptlm_u.req.kptlrm_matchbits);
                                break;
                        case PTLLND_MSG_TYPE_IMMEDIATE:
                        case PTLLND_MSG_TYPE_NOOP:
                                /* Do nothing */
                                break;
                        case PTLLND_MSG_TYPE_HELLO:
                                __swab64s(&msg->ptlm_u.hello.kptlhm_matchbits);
                                __swab32s(&msg->ptlm_u.hello.kptlhm_max_msg_size);
                                break;
                        default:
                                CERROR("Bad message type: %d\n", msg->ptlm_type);
                                return -EPROTO;
                }
        }

        /*
         * Src nid can not be ANY
         */
        if (msg->ptlm_srcnid == LNET_NID_ANY) {
                CERROR("Bad src nid: %s\n", libcfs_nid2str(msg->ptlm_srcnid));
                return -EPROTO;
        }

        return 0;
}



int
kptllnd_ctl(lnet_ni_t *ni, unsigned int cmd, void *arg)
{
        struct libcfs_ioctl_data *data = arg;
        int          rc = -EINVAL;
        kptl_data_t *kptllnd_data = ni->ni_data;

        CDEBUG(D_NET, ">>> kptllnd_ctl cmd=%u arg=%p\n",cmd,arg);

        /*
         * Validate that the context block is actually
         * pointing to this interface
         */
        LASSERT (ni == kptllnd_data->kptl_ni);

        switch(cmd) {
        case IOC_LIBCFS_DEL_PEER: {
                rc = kptllnd_peer_del (kptllnd_data, data->ioc_nid);
                break;
        }
        /*
         * Not Supported - This is Legacy stuff
        case IOC_LIBCFS_GET_PEER:
        case IOC_LIBCFS_ADD_PEER:
        case IOC_LIBCFS_GET_CONN:
        case IOC_LIBCFS_CLOSE_CONNECTION:
        case IOC_LIBCFS_REGISTER_MYNID:
        */
        default:
                CERROR("Unsupported IOCTL command %d\n",cmd);
                rc=-EINVAL;
                break;
        }
        CDEBUG(D_NET, "<<< kptllnd_ctl rc=%d\n",rc);
        return rc;
}

void
kptllnd_posted_object_setup(
        kptl_posted_object_t* posted_obj,
        kptl_data_t *kptllnd_data,
        int type)
{
        /*
         * Setup back pointer to LND instance data
         */
        posted_obj->po_kptllnd_data = kptllnd_data;

        /*
         * Setup descriptor type
         */
        posted_obj->po_flags.pof_type = type;
}

int
kptllnd_startup (lnet_ni_t *ni)
{
        int             rc;
        int             i;
        struct timeval  tv;
        kptl_data_t    *kptllnd_data;
        ptl_err_t       ptl_rc;


        CDEBUG(D_NET, ">>>\n");

        LASSERT (ni->ni_lnd == &kptllnd_lnd);

        LIBCFS_ALLOC (kptllnd_data,sizeof(*kptllnd_data));
        if (kptllnd_data == NULL){
                CERROR ("Failed to allocate memory for PTLLND context\n");
                return -ENOMEM;
        }

        /*
         * zero pointers, flags etc
         * put everything into a known state.
         */
        memset (kptllnd_data, 0, sizeof (*kptllnd_data));
        kptllnd_data->kptl_eqh = PTL_INVALID_HANDLE;
        kptllnd_data->kptl_nih = PTL_INVALID_HANDLE;

        /*
         * Uptick the module reference count
         */
        PORTAL_MODULE_USE;

        /*
         * Setup pointers between the ni and context data block
         */
        kptllnd_data->kptl_ni = ni;
        ni->ni_data = kptllnd_data;

        /*
         * Setup Credits
         */
        ni->ni_maxtxcredits = *kptllnd_tunables.kptl_credits;
        ni->ni_peertxcredits = *kptllnd_tunables.kptl_peercredits;


        /*
         * Initialize the Network interface instance
         * We use the default because we don't have any
         * way to choose a better interface.
         * Requested and actual limits are ignored.
         */
        ptl_rc = PtlNIInit(
#ifdef _USING_LUSTRE_PORTALS_
                PTL_IFACE_DEFAULT,
#else /* _USING_CRAY_PORTALS_ */
                CRAY_KERN_NAL,
#endif
                PTLLND_PID, NULL, NULL,
                &kptllnd_data->kptl_nih);

        /*
         * Note: PTL_IFACE_DUP simply means that the requested
         * interface was already inited and that we're sharing it.
         * Which is ok.
         */
        if (ptl_rc != PTL_OK && ptl_rc != PTL_IFACE_DUP){
                CERROR ("PtlNIInit: error %d\n", ptl_rc);
                rc = -EINVAL;
                goto failed;
        }

        ptl_rc = PtlEQAlloc(
                kptllnd_data->kptl_nih,
                8,                      /* We use callback - no need for max */
                kptllnd_eq_callback,    /* handler callback */
                &kptllnd_data->kptl_eqh);   /* output handle */
        if(ptl_rc != PTL_OK) {
                CERROR("PtlEQAlloc failed %d\n",ptl_rc);
                rc = -ENOMEM;
                goto failed;
        }

        /*
         * Fetch the lower NID
         */
        ptl_rc != PtlGetId(kptllnd_data->kptl_nih, &kptllnd_data->kptl_portals_id);
        if (ptl_rc != PTL_OK) {
                CERROR ("PtlGetID: error %d\n", ptl_rc);
                rc = -EINVAL;
                goto failed;
        }

        if (kptllnd_data->kptl_portals_id.pid != PTLLND_PID) {
                /* The kernel ptllnd must have the expected PID */
                CERROR("Unexpected PID: %u (%u expected)\n",
                       kptllnd_data->kptl_portals_id.pid, PTLLND_PID);
                rc = -EINVAL;
                goto failed;
        }
        
        CDEBUG(D_NET, "lnet nid=" LPX64 " (passed in)\n",ni->ni_nid);

        /*
         * Create the new NID.  Based on the LND network type
         * and the lower ni's address data.
         */
        ni->ni_nid = ptl2lnetnid(kptllnd_data, kptllnd_data->kptl_portals_id.nid);

        CDEBUG(D_NET, "ptl  nid=" FMT_NID "\n",kptllnd_data->kptl_portals_id.nid);
        CDEBUG(D_NET, "ptl  pid= %d\n", kptllnd_data->kptl_portals_id.pid);
        CDEBUG(D_NET, "lnet nid=" LPX64 " (passed back)\n",ni->ni_nid);

        /*
         * Initialized the incarnation
         */
        do_gettimeofday(&tv);
        kptllnd_data->kptl_incarnation = (((__u64)tv.tv_sec) * 1000000) + tv.tv_usec;
        CDEBUG(D_NET, "Incarnation=" LPX64 "\n",kptllnd_data->kptl_incarnation);

        /*
         * Setup the sched locks/lists/waitq
         */
        spin_lock_init (&kptllnd_data->kptl_sched_lock);
        init_waitqueue_head (&kptllnd_data->kptl_sched_waitq);
        INIT_LIST_HEAD (&kptllnd_data->kptl_sched_txq);
        INIT_LIST_HEAD (&kptllnd_data->kptl_sched_rxq);
        INIT_LIST_HEAD (&kptllnd_data->kptl_sched_rxbq);

        /*
         * Setup the tx locks/lists/waitq
         */
        spin_lock_init (&kptllnd_data->kptl_tx_lock);
        INIT_LIST_HEAD (&kptllnd_data->kptl_idle_txs);

        /*
         * Allocate and setup the peer hash table
         */
        CDEBUG(D_NET, "Allocate Peer Hash Table\n");
        rwlock_init(&kptllnd_data->kptl_peer_rw_lock);
        kptllnd_data->kptl_peer_hash_size = *kptllnd_tunables.kptl_peer_hash_table_size;
        INIT_LIST_HEAD(&kptllnd_data->kptl_canceled_peers);
        LIBCFS_ALLOC (kptllnd_data->kptl_peers,
                      sizeof (struct list_head) * kptllnd_data->kptl_peer_hash_size);
        if (kptllnd_data->kptl_peers == NULL) {
                CERROR("Failed to allocate space for peer hash table size=%d\n",
                        kptllnd_data->kptl_peer_hash_size);
                rc = -ENOMEM;
                goto failed;
        }
        for (i = 0; i < kptllnd_data->kptl_peer_hash_size; i++)
                INIT_LIST_HEAD(&kptllnd_data->kptl_peers[i]);

        /* lists/ptrs/locks initialised */
        kptllnd_data->kptl_init = PTLLND_INIT_DATA;

        /*****************************************************/

        /*
         * Start the scheduler threads for handling incoming
         * requests.  No need to advance the state because
         * this will be automatically cleaned up now that PTLNAT_INIT_DATA
         * state has been entered
         */
        CDEBUG(D_NET, "starting %d scheduler threads\n",PTLLND_N_SCHED);
        for (i = 0; i < PTLLND_N_SCHED; i++) {
                rc = kptllnd_thread_start (
                        kptllnd_scheduler,
                        i+1,
                        kptllnd_data);
                if (rc != 0) {
                        CERROR("Can't spawn scheduler[%d]: %d\n", i+1, rc);
                        goto failed;
                }
        }
        
        rc = kptllnd_thread_start (
                kptllnd_watchdog,
                0,
                kptllnd_data);
        if (rc != 0) {
                CERROR("Can't spawn watchdog[0]: %d\n", rc);
                goto failed;
        }

        /*
         * Allocate space for the tx descriptors
         * (Note we don't need to advance the init state
         * because we'll use the pointer being NULL as a sentry
         * to know that we have to clean this up
         */
        CDEBUG(D_NET, "Allocate TX Descriptor array\n");
        LIBCFS_ALLOC (kptllnd_data->kptl_tx_descs,
                      (*kptllnd_tunables.kptl_ntx) * sizeof(kptl_tx_t));
        if (kptllnd_data->kptl_tx_descs == NULL){
                CERROR ("Can't allocate space for TX Descriptor array count=%d\n",
                        (*kptllnd_tunables.kptl_ntx));
                rc = -ENOMEM;
                goto failed;
        }

        /*
         * Now setup the tx descriptors
         */
        rc = kptllnd_setup_tx_descs(kptllnd_data);
        if (rc != 0) {
                CERROR ("Can\'t setup tx descs: %d\n", rc);
                goto failed;
        }

        /* flag TX descs initialised */
        kptllnd_data->kptl_init = PTLLND_INIT_TXD;

        /*****************************************************/


        kptllnd_rx_buffer_pool_init(&kptllnd_data->kptl_rx_buffer_pool);

        /* flag rx descs initialised */
        kptllnd_data->kptl_init = PTLLND_INIT_RXD;

        /*****************************************************/


        kptllnd_data->kptl_rx_cache = cfs_mem_cache_create (
                "ptllnd_rx",
                sizeof(kptl_rx_t) + *kptllnd_tunables.kptl_max_msg_size,
                0, /* offset */
                0); /* flags */
        if( kptllnd_data->kptl_rx_cache == NULL ){
                CERROR("Can't create slab for RX descriptrs\n");
                goto failed;
        }

        rc = kptllnd_rx_buffer_pool_reserve(
                        &kptllnd_data->kptl_rx_buffer_pool,
                        kptllnd_data,
                        *kptllnd_tunables.kptl_concurrent_peers);
        if( rc != 0) {
                CERROR("Can't reserve RX Buffer pool: %d\n",rc);
                goto failed;
        }

        /* flag everything initialised */
        kptllnd_data->kptl_init = PTLLND_INIT_ALL;


        /*****************************************************/

        CDEBUG(D_NET, "<<< kptllnd_startup SUCCESS\n");
        return 0;

 failed:
        CDEBUG(D_NET, "kptllnd_startup failed rc=%d\n",rc);
        kptllnd_shutdown (ni);
        CDEBUG(D_NET, "<<< kptllnd_startup rc=%d\n",rc);
        return rc;
}

void
kptllnd_shutdown (lnet_ni_t *ni)
{
        int             i;
        kptl_data_t    *kptllnd_data = ni->ni_data;

        CDEBUG(D_NET, ">>> kptllnd_shutdown\n");

        /*
         * Validate that the context block is actually
         * pointing to this interface
         */
        LASSERT (ni == kptllnd_data->kptl_ni);

        CDEBUG(D_MALLOC, "before LND cleanup: kmem %d\n",
               atomic_read (&libcfs_kmemory));

        /*
         * Now depending on where we are in the initialization
         * cleanup the context block
         */
        switch (kptllnd_data->kptl_init) {

        case PTLLND_INIT_ALL:
        case PTLLND_INIT_RXD:
                CDEBUG(D_NET, "PTLLND_INIT_RXD\n");

                kptllnd_rx_buffer_pool_fini(
                        &kptllnd_data->kptl_rx_buffer_pool);

                LASSERT(list_empty(&kptllnd_data->kptl_sched_rxq));
                LASSERT(list_empty(&kptllnd_data->kptl_sched_rxbq));

                /* fall through */
        case PTLLND_INIT_TXD:
                CDEBUG(D_NET, "PTLLND_INIT_TXD\n");

                /*
                 * If there were peers started up then
                 * clean them up.
                 */
                if( atomic_read(&kptllnd_data->kptl_npeers) != 0) {
                        CDEBUG(D_NET, "Deleting %d peers\n",atomic_read(&kptllnd_data->kptl_npeers));

                        /* nuke all peers */
                        kptllnd_peer_del(kptllnd_data, LNET_NID_ANY);

                        i = 2;
                        while (atomic_read (&kptllnd_data->kptl_npeers) != 0) {

                                i++;
                                CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* power of 2? */
                                       "Waiting for %d peers to terminate\n",
                                       atomic_read (&kptllnd_data->kptl_npeers));
                                CDEBUG(D_NET, "Waiting for %d peers to terminate\n",
                                        atomic_read (&kptllnd_data->kptl_npeers));
                                cfs_pause(cfs_time_seconds(1));
                        }
                }

                LASSERT(list_empty(&kptllnd_data->kptl_canceled_peers));
                CDEBUG(D_NET, "All peers deleted\n");

                /*
                 * Set the shutdown flag
                 */
                kptllnd_data->kptl_shutdown = 1;

                /*
                 * First thing we do is shutdown the scheduler threads
                 * It makes cleanup easier to not have to worry about races
                 * with N other threads.
                 *
                 * Also this is safe no matter the kptl_init state
                 * because it is a nop because kptl_nthreads==0
                 * if we are not in the right state.
                 */
                if(atomic_read (&kptllnd_data->kptl_nthreads) != 0){
                        CDEBUG(D_NET, "Stopping %d threads\n",atomic_read(&kptllnd_data->kptl_nthreads));
                        /*
                         * Wake up all the schedulers
                         */
                        wake_up_all (&kptllnd_data->kptl_sched_waitq);

                        i = 2;
                        while (atomic_read (&kptllnd_data->kptl_nthreads) != 0) {
                                i++;
                                CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET, /* power of 2? */
                                       "Waiting for %d threads to terminate\n",
                                       atomic_read (&kptllnd_data->kptl_nthreads));
                                CDEBUG(D_NET, "Waiting for %d threads to terminate\n",
                                        atomic_read (&kptllnd_data->kptl_nthreads));
                                cfs_pause(cfs_time_seconds(1));
                        }

                }
                CDEBUG(D_NET, "All Threads stopped\n");


                LASSERT(list_empty(&kptllnd_data->kptl_sched_txq));

                kptllnd_cleanup_tx_descs(kptllnd_data);

                /* fall through */
        case PTLLND_INIT_DATA:

                CDEBUG(D_NET, "PTLLND_INIT_DATA\n");

                LASSERT (atomic_read(&kptllnd_data->kptl_npeers) == 0);
                LASSERT (kptllnd_data->kptl_peers != NULL);
                for (i = 0; i < kptllnd_data->kptl_peer_hash_size; i++) {
                        LASSERT (list_empty (&kptllnd_data->kptl_peers[i]));
                }
                /*
                 * Nothing here now, but libcfs might soon require
                 * us to explicitly destroy wait queues and semaphores
                 * that would be done here
                 */

                /* fall through */

        case PTLLND_INIT_NOTHING:
                CDEBUG(D_NET, "PTLLND_INIT_NOTHING\n");
                break;
        }

        /*
         * There are a number of things that can be done
         * outside the state machine, because the construction
         * (or lack thereof) can be determined directly from
         * the pointer or handle itself.
         * Clean these things up here
         */

        /*
         * Cleanup the portals EQ
         */
        if(!PtlHandleIsEqual(kptllnd_data->kptl_eqh,PTL_INVALID_HANDLE))
                PtlEQFree(kptllnd_data->kptl_eqh);

        /*
         * release the portals ni handle
         */
        if(!PtlHandleIsEqual(kptllnd_data->kptl_nih,PTL_INVALID_HANDLE))
                PtlNIFini(kptllnd_data->kptl_nih);

        /*
         *  Free the tx descriptors
         */
        if (kptllnd_data->kptl_tx_descs != NULL)
                LIBCFS_FREE(kptllnd_data->kptl_tx_descs,
                        (*kptllnd_tunables.kptl_ntx) * sizeof(kptl_tx_t));

        /*
         * Cleanup the RX descriptor slab
         */
        if (kptllnd_data->kptl_rx_cache != NULL)
                cfs_mem_cache_destroy( kptllnd_data->kptl_rx_cache);

        /*
         * Cleanup the peer hash table
         */
        if (kptllnd_data->kptl_peers != NULL){
                LIBCFS_FREE (kptllnd_data->kptl_peers,
                             sizeof (struct list_head) *
                             kptllnd_data->kptl_peer_hash_size);
        }

        /*
         * And free the context block
         */
        LIBCFS_FREE(kptllnd_data,sizeof(*kptllnd_data));

        CDEBUG(D_MALLOC, "after LND cleanup: kmem %d\n",
               atomic_read (&libcfs_kmemory));

        PORTAL_MODULE_UNUSE;
        CDEBUG(D_NET, "<<<\n");
}

int __init
kptllnd_module_init (void)
{
        int    rc;

        CDEBUG(D_NET, ">>> %s %s\n",__DATE__,__TIME__);

        /*
         * Display the module parameters
         */
        CDEBUG(D_INFO,"ntx = %d\n",*kptllnd_tunables.kptl_ntx);
        CDEBUG(D_INFO,"concurrent_peers = %d\n",*kptllnd_tunables.kptl_concurrent_peers);
        CDEBUG(D_INFO,"cksum = %d\n",*kptllnd_tunables.kptl_cksum);
        CDEBUG(D_INFO,"portal = %d\n",*kptllnd_tunables.kptl_portal);
        CDEBUG(D_INFO,"timeout = %d (seconds)\n",*kptllnd_tunables.kptl_timeout);
        CDEBUG(D_INFO,"rxb_npages = %d\n",*kptllnd_tunables.kptl_rxb_npages);
        CDEBUG(D_INFO,"credits = %d\n",*kptllnd_tunables.kptl_credits);
        CDEBUG(D_INFO,"peercredits = %d\n",*kptllnd_tunables.kptl_peercredits);
        CDEBUG(D_INFO,"max_msg_size = %d\n",*kptllnd_tunables.kptl_max_msg_size);

        ptllnd_assert_wire_constants();

        /*
         * Check for valid parameters.
         */
        if (*kptllnd_tunables.kptl_credits > *kptllnd_tunables.kptl_ntx) {
                CERROR ("Can't set credits(%d) > ntx(%d)\n",
                        *kptllnd_tunables.kptl_credits,
                        *kptllnd_tunables.kptl_ntx);
                return -EINVAL;
        }

        rc = kptllnd_tunables_init();
        if (rc != 0)
                return rc;

        kptllnd_proc_init();
        lnet_register_lnd(&kptllnd_lnd);

        CDEBUG(D_NET, "<<<\n");
        return 0;
}

void __exit
kptllnd_module_fini (void)
{

        CDEBUG(D_NET, ">>> %s %s\n",__DATE__,__TIME__);
        lnet_unregister_lnd(&kptllnd_lnd);
        kptllnd_proc_fini();
        kptllnd_tunables_fini();
        // kpttllnd_get_stats();
        CDEBUG(D_NET, "<<<\n");
}

#define DO_TYPE(x) case x: return #x;

const char *get_ev_type_string(int type)
{
        switch(type)
        {
                DO_TYPE(PTL_EVENT_GET_START);
                DO_TYPE(PTL_EVENT_GET_END);
                DO_TYPE(PTL_EVENT_PUT_START);
                DO_TYPE(PTL_EVENT_PUT_END);
                DO_TYPE(PTL_EVENT_REPLY_START);
                DO_TYPE(PTL_EVENT_REPLY_END);
                DO_TYPE(PTL_EVENT_ACK);
                DO_TYPE(PTL_EVENT_SEND_START);
                DO_TYPE(PTL_EVENT_SEND_END);
                DO_TYPE(PTL_EVENT_UNLINK);
        default:
                return "";
        }
}

const char *get_msg_type_string(int type)
{
        switch(type)
        {
                DO_TYPE(PTLLND_MSG_TYPE_INVALID);
                DO_TYPE(PTLLND_MSG_TYPE_PUT);
                DO_TYPE(PTLLND_MSG_TYPE_GET);
                DO_TYPE(PTLLND_MSG_TYPE_IMMEDIATE);
                DO_TYPE(PTLLND_MSG_TYPE_HELLO);
                DO_TYPE(PTLLND_MSG_TYPE_NOOP);
        default:
                return "";
        }
}

#define LOGSTAT(x) CDEBUG(D_NET, "%30.30s %d\n",#x,kptllnd_stats.x);

kptl_stats_t* kpttllnd_get_stats(void)
{
        LOGSTAT(kps_incoming_checksums_calculated);
        LOGSTAT(kps_incoming_checksums_invalid);
        LOGSTAT(kps_cleaning_caneled_peers);
        LOGSTAT(kps_checking_buckets);
        LOGSTAT(kps_too_many_peers);
        LOGSTAT(kps_peers_created);
        LOGSTAT(kps_sending_credits_back_noop_msg);
        LOGSTAT(kps_no_credits);
        LOGSTAT(kps_saving_last_credit);
        LOGSTAT(kps_rx_allocated);
        LOGSTAT(kps_rx_released);
        LOGSTAT(kps_rx_allocation_failed);
        LOGSTAT(kps_tx_allocated);
        LOGSTAT(kps_tx_released);
        LOGSTAT(kps_tx_allocation_failed);
        LOGSTAT(kps_recv_delayed);
        LOGSTAT(kps_send_routing);
        LOGSTAT(kps_send_target_is_router);
        LOGSTAT(kps_send_put);
        LOGSTAT(kps_send_get);
        LOGSTAT(kps_send_immd);
        LOGSTAT(kps_send_reply);
        LOGSTAT(kps_rx_event);
        LOGSTAT(kps_rx_unlink_event);
        LOGSTAT(kps_tx_event);
        LOGSTAT(kps_tx_unlink_event);
        LOGSTAT(kps_posted_tx_msg_mds);
        LOGSTAT(kps_posted_tx_bulk_mds);
        
        return &kptllnd_stats;
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Kernel Portals LND v1.00");
MODULE_LICENSE("GPL");

module_init(kptllnd_module_init);
module_exit(kptllnd_module_fini);
