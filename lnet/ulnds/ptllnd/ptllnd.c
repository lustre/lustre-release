/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2005 Cluster File Systems, Inc. All rights reserved.
 *   Author: Eric Barton <eeb@bartonsoftware.com>
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

lnd_t               the_ptllnd = {
        .lnd_type       = PTLLND,
        .lnd_startup    = ptllnd_startup,
        .lnd_shutdown   = ptllnd_shutdown,
        .lnd_send       = ptllnd_send,
        .lnd_recv       = ptllnd_recv,
        .lnd_eager_recv = ptllnd_eager_recv,
        .lnd_notify     = ptllnd_notify,
        .lnd_wait       = ptllnd_wait,
};

static int ptllnd_ni_count = 0;

int
ptllnd_parse_int_tunable(int *value, char *name, int dflt)
{
        char    *env = getenv(name);
        char    *end;

        if (env == NULL) {
                *value = dflt;
                return 0;
        }

        *value = strtoull(env, &end, 0);
        if (*end == 0)
                return 0;

        CERROR("Can't parse tunable %s=%s\n", name, env);
        return -EINVAL;
}

int
ptllnd_get_tunables(lnet_ni_t *ni)
{
        ptllnd_ni_t *plni = ni->ni_data;
        int          max_immediate;
        int          msgs_per_buffer;
        int          rc;
        int          temp;

        rc = ptllnd_parse_int_tunable(&plni->plni_portal,
                                      "PTLLND_PORTAL", PTLLND_PORTAL);
        if (rc != 0)
                return rc;

        rc = ptllnd_parse_int_tunable(&temp,
                                      "PTLLND_PID", PTLLND_PID);
        if (rc != 0)
                return rc;
        plni->plni_ptllnd_pid = (ptl_pid_t)temp;

        rc = ptllnd_parse_int_tunable(&plni->plni_peer_credits,
                                      "PTLLND_PEERCREDITS", PTLLND_PEERCREDITS);
        if (rc != 0)
                return rc;

        rc = ptllnd_parse_int_tunable(&max_immediate,
                                      "PTLLND_MAX_MSG_SIZE",
                                      PTLLND_MAX_MSG_SIZE);
        if (rc != 0)
                return rc;

        rc = ptllnd_parse_int_tunable(&msgs_per_buffer,
                                      "PTLLND_MSGS_PER_BUFFER",
                                      PTLLND_MSGS_PER_BUFFER);
        if (rc != 0)
                return rc;

        rc = ptllnd_parse_int_tunable(&plni->plni_msgs_spare,
                                      "PTLLND_MSGS_SPARE",
                                      PTLLND_MSGS_SPARE);
        if (rc != 0)
                return rc;

        rc = ptllnd_parse_int_tunable(&plni->plni_peer_hash_size,
                                      "PTLLND_PEER_HASH_SIZE",
                                      PTLLND_PEER_HASH_SIZE);
        if (rc != 0)
                return rc;


        rc = ptllnd_parse_int_tunable(&plni->plni_eq_size,
                                      "PTLLND_EQ_SIZE", PTLLND_EQ_SIZE);
        if (rc != 0)
                return rc;

        plni->plni_max_msg_size = max_immediate;
        if (plni->plni_max_msg_size < sizeof(kptl_msg_t))
                plni->plni_max_msg_size = sizeof(kptl_msg_t);

        plni->plni_buffer_size = plni->plni_max_msg_size * msgs_per_buffer;

        CDEBUG(D_NET, "portal          = %d\n",plni->plni_portal);
        CDEBUG(D_NET, "ptllnd_pid      = %d\n",plni->plni_ptllnd_pid);
        CDEBUG(D_NET, "max_immediate   = %d\n",max_immediate);
        CDEBUG(D_NET, "msgs_per_buffer = %d\n",msgs_per_buffer);
        CDEBUG(D_NET, "msgs_spare      = %d\n",plni->plni_msgs_spare);
        CDEBUG(D_NET, "peer_hash_size  = %d\n",plni->plni_peer_hash_size);
        CDEBUG(D_NET, "eq_size         = %d\n",plni->plni_eq_size);
        CDEBUG(D_NET, "max_msg_size    = %d\n",plni->plni_max_msg_size);
        CDEBUG(D_NET, "buffer_size     = %d\n",plni->plni_buffer_size);

        return 0;
}

ptllnd_buffer_t *
ptllnd_create_buffer (lnet_ni_t *ni)
{
        ptllnd_ni_t     *plni = ni->ni_data;
        ptllnd_buffer_t *buf;

        LIBCFS_ALLOC(buf, sizeof(*buf));
        if (buf == NULL) {
                CERROR("Can't allocate buffer descriptor\n");
                return NULL;
        }

        buf->plb_ni = ni;
        buf->plb_posted = 0;
        CFS_INIT_LIST_HEAD(&buf->plb_list);

        LIBCFS_ALLOC(buf->plb_buffer, plni->plni_buffer_size);
        if (buf->plb_buffer == NULL) {
                CERROR("Can't allocate buffer size %d\n",
                       plni->plni_buffer_size);
                LIBCFS_FREE(buf, sizeof(*buf));
                return NULL;
        }

        list_add(&buf->plb_list, &plni->plni_buffers);
        plni->plni_nbuffers++;

        return buf;
}

void
ptllnd_destroy_buffer (ptllnd_buffer_t *buf)
{
        ptllnd_ni_t     *plni = buf->plb_ni->ni_data;

        LASSERT (!buf->plb_posted);

        plni->plni_nbuffers--;
        list_del(&buf->plb_list);
        LIBCFS_FREE(buf->plb_buffer, plni->plni_buffer_size);
        LIBCFS_FREE(buf, sizeof(*buf));
}

int
ptllnd_grow_buffers (lnet_ni_t *ni)
{
        ptllnd_ni_t     *plni = ni->ni_data;
        ptllnd_buffer_t *buf;
        int              nmsgs;
        int              nbufs;
        int              rc;

        CDEBUG(D_NET, "nposted_buffers = %d (before)\n",plni->plni_nposted_buffers);
        CDEBUG(D_NET, "nbuffers = %d (before)\n",plni->plni_nbuffers);

        nmsgs = plni->plni_npeers * plni->plni_peer_credits +
                plni->plni_msgs_spare;

        nbufs = (nmsgs * plni->plni_max_msg_size + plni->plni_buffer_size - 1) /
                plni->plni_buffer_size;

        while (nbufs > plni->plni_nbuffers) {
                buf = ptllnd_create_buffer(ni);

                if (buf == NULL)
                        return -ENOMEM;

                rc = ptllnd_post_buffer(buf);
                if (rc != 0){
                        /* TODO - this path seems to orpahn the buffer
                         * in a state where its not posted and will never be
                         * However it does not leak the buffer as it's
                         * already been put onto the global buffer list
                         * and will be cleaned up
                         */
                        return rc;
                }
        }

        CDEBUG(D_NET, "nposted_buffers = %d (after)\n",plni->plni_nposted_buffers);
        CDEBUG(D_NET, "nbuffers = %d (after)\n",plni->plni_nbuffers);
        return 0;
}

void
ptllnd_destroy_buffers (lnet_ni_t *ni)
{
        ptllnd_ni_t       *plni = ni->ni_data;
        ptllnd_buffer_t   *buf;
        struct list_head  *tmp;
        struct list_head  *nxt;

        CDEBUG(D_NET, "nposted_buffers = %d (before)\n",plni->plni_nposted_buffers);
        CDEBUG(D_NET, "nbuffers = %d (before)\n",plni->plni_nbuffers);

        list_for_each_safe(tmp, nxt, &plni->plni_buffers) {
                buf = list_entry(tmp, ptllnd_buffer_t, plb_list);

                //CDEBUG(D_NET, "buf=%p posted=%d\n",buf,buf->plb_posted);

                LASSERT (plni->plni_nbuffers > 0);
                if (buf->plb_posted) {
                        LASSERT (plni->plni_nposted_buffers > 0);

#ifdef LUSTRE_PORTALS_UNLINK_SEMANTICS
                        (void) PtlMDUnlink(buf->plb_md);
                        while (buf->plb_posted)
                                ptllnd_wait(ni, -1);
#else
                        while (buf->plb_posted) {
                                rc = PtlMDUnlink(buf->plb_md);
                                if (rc == PTL_OK) {
                                        buf->plb_posted = 0;
                                        plni->plni_nposted_buffers--;
                                        break;
                                }
                                LASSERT (rc == PTL_MD_IN_USE);
                                ptllnd_wait(ni, -1);
                        }
#endif
                }
                ptllnd_destroy_buffer(buf);
        }

        CDEBUG(D_NET, "nposted_buffers = %d (after)\n",plni->plni_nposted_buffers);
        CDEBUG(D_NET, "nbuffers = %d (after)\n",plni->plni_nbuffers);

        LASSERT (plni->plni_nposted_buffers == 0);
        LASSERT (plni->plni_nbuffers == 0);
}

int
ptllnd_create_peer_hash (lnet_ni_t *ni)
{
        ptllnd_ni_t *plni = ni->ni_data;
        int          i;

        plni->plni_npeers = 0;

        LIBCFS_ALLOC(plni->plni_peer_hash,
                     plni->plni_peer_hash_size * sizeof(*plni->plni_peer_hash));
        if (plni->plni_peer_hash == NULL) {
                CERROR("Can't allocate ptllnd peer hash (size %d)\n",
                       plni->plni_peer_hash_size);
                return -ENOMEM;
        }

        for (i = 0; i < plni->plni_peer_hash_size; i++)
                CFS_INIT_LIST_HEAD(&plni->plni_peer_hash[i]);

        return 0;
}

void
ptllnd_destroy_peer_hash (lnet_ni_t *ni)
{
        ptllnd_ni_t    *plni = ni->ni_data;
        int             i;

        LASSERT( plni->plni_npeers == 0);

        for (i = 0; i < plni->plni_peer_hash_size; i++)
                LASSERT (list_empty(&plni->plni_peer_hash[i]));

        LIBCFS_FREE(plni->plni_peer_hash,
                    plni->plni_peer_hash_size * sizeof(*plni->plni_peer_hash));
}

void
ptllnd_close_peers (lnet_ni_t *ni)
{
        ptllnd_ni_t    *plni = ni->ni_data;
        ptllnd_peer_t  *plp;
        int             i;

        CDEBUG(D_NET, ">>> npeers=%d\n",plni->plni_npeers);

        for (i = 0; i < plni->plni_peer_hash_size; i++)
                while (!list_empty(&plni->plni_peer_hash[i])) {
                        plp = list_entry(plni->plni_peer_hash[i].next,
                                         ptllnd_peer_t, plp_list);

                        ptllnd_close_peer(plp);
                }

        CDEBUG(D_NET, "<<< npeers=%d\n",plni->plni_npeers);
}

__u64
ptllnd_get_timestamp(void)
{
        struct timeval  tv;
        int             rc = gettimeofday(&tv, NULL);

        LASSERT (rc == 0);
        return ((__u64)tv.tv_sec) * 1000000 + tv.tv_usec;
}

void
ptllnd_shutdown (lnet_ni_t *ni)
{
        ptllnd_ni_t *plni = ni->ni_data;
        int          rc;

        CDEBUG(D_NET, ">>>\n");

        LASSERT (ptllnd_ni_count == 1);

        ptllnd_destroy_buffers(ni);
        ptllnd_close_peers(ni);
        ptllnd_abort_txs(ni);

        while (plni->plni_npeers > 0)
                ptllnd_wait(ni, -1);

        LASSERT (plni->plni_ntxs == 0);
        LASSERT (plni->plni_nrxs == 0);

        rc = PtlEQFree(plni->plni_eqh);
        LASSERT (rc == PTL_OK);

        rc = PtlNIFini(plni->plni_nih);
        LASSERT (rc == PTL_OK);

        ptllnd_destroy_peer_hash(ni);
        LIBCFS_FREE(plni, sizeof(*plni));
        ptllnd_ni_count--;

        CDEBUG(D_NET, "<<<\n");
}

int
ptllnd_startup (lnet_ni_t *ni)
{
        ptllnd_ni_t *plni;
        int          rc;

        CDEBUG(D_NET, ">>> ni=%p\n",ni);

	/* could get limits from portals I guess... */
	ni->ni_maxtxcredits =
	ni->ni_peertxcredits = 1000;

        if (ptllnd_ni_count != 0) {
                CERROR("Can't have > 1 instance of ptllnd\n");
                return -EPERM;
        }

        ptllnd_ni_count++;

        LIBCFS_ALLOC(plni, sizeof(*plni));
        if (plni == NULL) {
                CERROR("Can't allocate ptllnd state\n");
                rc = -ENOMEM;
                goto failed0;
        }

        ni->ni_data = plni;
        
        /*
         * For redundant routing to work the router on the
         * return (which could be diffrent than the router
         * on the forward path needs to know the originating
         * PID of the Catamount client.
         * To make this work properly we just force
         * the lnet pid to the pid of this process.
         */
        the_lnet.ln_pid = getpid();
        CDEBUG(D_NET, "Forcing LNET pid to %d\n",the_lnet.ln_pid);

        plni->plni_stamp = ptllnd_get_timestamp();
        plni->plni_nrxs = 0;
        plni->plni_ntxs = 0;
        CFS_INIT_LIST_HEAD(&plni->plni_active_txs);
        CFS_INIT_LIST_HEAD(&plni->plni_zombie_txs);

        /*
         *  Initilize buffer related data structures
         */
        CFS_INIT_LIST_HEAD(&plni->plni_buffers);
        plni->plni_nbuffers = 0;
        plni->plni_nposted_buffers = 0;

        rc = ptllnd_get_tunables(ni);
        if (rc != 0)
                goto failed1;

        rc = ptllnd_create_peer_hash(ni);
        if (rc != 0)
                goto failed1;

        /* NB I most probably won't get the PID I requested here.  It doesn't
         * matter because I don't need a fixed PID (only connection acceptors
         * need a "well known" PID). */

        rc = PtlNIInit(PTL_IFACE_DEFAULT, plni->plni_ptllnd_pid,
                       NULL, NULL, &plni->plni_nih);
        if (rc != PTL_OK && rc != PTL_IFACE_DUP) {
                CERROR("PtlNIInit failed: %d\n", rc);
                rc = -ENODEV;
                goto failed2;
        }

        rc = PtlEQAlloc(plni->plni_nih, plni->plni_eq_size,
                        PTL_EQ_HANDLER_NONE, &plni->plni_eqh);
        if (rc != PTL_OK) {
                CERROR("PtlEQAlloc failed: %d\n", rc);
                rc = -ENODEV;
                goto failed3;
        }

        /*
         * Fetch the Portals NID
         */
        if(rc != PtlGetId(plni->plni_nih,&plni->plni_portals_id)){
                CERROR ("PtlGetID failed : %d\n", rc);
                rc = -EINVAL;
                goto failed4;
        }

        CDEBUG(D_NET, "lnet nid=" LPX64 " (passed in)\n",ni->ni_nid);

        /*
         * Create the new NID.  Based on the LND network type
         * and the lower ni's address data.
         */
        ni->ni_nid = ptllnd_ptl2lnetnid(ni, plni->plni_portals_id.nid);

        CDEBUG(D_NET, "ptl  pid=" FMT_PID "\n",plni->plni_portals_id.pid);
        CDEBUG(D_NET, "ptl  nid=" FMT_NID "\n",plni->plni_portals_id.nid);
        CDEBUG(D_NET, "lnet nid=" LPX64 " (passed back)\n",ni->ni_nid);

        rc = ptllnd_grow_buffers(ni);
        if (rc != 0)
                goto failed4;

        CDEBUG(D_NET, "<<<\n");
	return 0;

 failed4:
        ptllnd_destroy_buffers(ni);
        PtlEQFree(plni->plni_eqh);
 failed3:
        PtlNIFini(plni->plni_nih);
 failed2:
        ptllnd_destroy_peer_hash(ni);
 failed1:
        LIBCFS_FREE(plni, sizeof(*plni));
 failed0:
        ptllnd_ni_count--;
        CDEBUG(D_NET, "<<< rc=%d\n",rc);
        return rc;
}

const char *ptllnd_evtype2str(int type)
{
#define DO_TYPE(x) case x: return #x;
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
#undef DO_TYPE
}

const char *ptllnd_msgtype2str(int type)
{
#define DO_TYPE(x) case x: return #x;
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
#undef DO_TYPE
}
