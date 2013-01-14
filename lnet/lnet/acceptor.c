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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_LNET
#include <lnet/lib-lnet.h>

#ifdef __KERNEL__
static char *accept = "secure";
CFS_MODULE_PARM(accept, "s", charp, 0444,
                "Accept connections (secure|all|none)");

static int accept_port = 988;
CFS_MODULE_PARM(accept_port, "i", int, 0444,
                "Acceptor's port (same on all nodes)");

static int accept_backlog = 127;
CFS_MODULE_PARM(accept_backlog, "i", int, 0444,
                "Acceptor's listen backlog");

static int accept_timeout = 5;
CFS_MODULE_PARM(accept_timeout, "i", int, 0644,
		"Acceptor's timeout (seconds)");

struct {
	int               pta_shutdown;
	cfs_socket_t     *pta_sock;
	struct semaphore  pta_signal;
} lnet_acceptor_state;

int
lnet_acceptor_timeout(void)
{
        return accept_timeout;
}
EXPORT_SYMBOL(lnet_acceptor_timeout);

int
lnet_acceptor_port(void)
{
        return accept_port;
}
EXPORT_SYMBOL(lnet_acceptor_port);

void
lnet_connect_console_error (int rc, lnet_nid_t peer_nid, 
                           __u32 peer_ip, int peer_port)
{
        switch (rc) {
        /* "normal" errors */
        case -ECONNREFUSED:
                CNETERR("Connection to %s at host %u.%u.%u.%u on port %d was "
                        "refused: check that Lustre is running on that node.\n",
                        libcfs_nid2str(peer_nid),
                        HIPQUAD(peer_ip), peer_port);
                break;
        case -EHOSTUNREACH:
        case -ENETUNREACH:
                CNETERR("Connection to %s at host %u.%u.%u.%u "
                        "was unreachable: the network or that node may "
                        "be down, or Lustre may be misconfigured.\n",
                        libcfs_nid2str(peer_nid), HIPQUAD(peer_ip));
                break;
        case -ETIMEDOUT:
                CNETERR("Connection to %s at host %u.%u.%u.%u on "
                        "port %d took too long: that node may be hung "
                        "or experiencing high load.\n",
                        libcfs_nid2str(peer_nid),
                        HIPQUAD(peer_ip), peer_port);
                break;
        case -ECONNRESET:
                LCONSOLE_ERROR_MSG(0x11b, "Connection to %s at host %u.%u.%u.%u"
                                   " on port %d was reset: "
                                   "is it running a compatible version of "
                                   "Lustre and is %s one of its NIDs?\n",
                                   libcfs_nid2str(peer_nid),
                                   HIPQUAD(peer_ip), peer_port,
                                   libcfs_nid2str(peer_nid));
                break;
        case -EPROTO:
                LCONSOLE_ERROR_MSG(0x11c, "Protocol error connecting to %s at "
                                   "host %u.%u.%u.%u on port %d: is it running "
                                   "a compatible version of Lustre?\n",
                                   libcfs_nid2str(peer_nid),
                                   HIPQUAD(peer_ip), peer_port);
                break;
        case -EADDRINUSE:
                LCONSOLE_ERROR_MSG(0x11d, "No privileged ports available to "
                                   "connect to %s at host %u.%u.%u.%u on port "
                                   "%d\n", libcfs_nid2str(peer_nid),
                                   HIPQUAD(peer_ip), peer_port);
                break;
        default:
                LCONSOLE_ERROR_MSG(0x11e, "Unexpected error %d connecting to %s"
                                   " at host %u.%u.%u.%u on port %d\n", rc,
                                   libcfs_nid2str(peer_nid),
                                   HIPQUAD(peer_ip), peer_port);
                break;
        }
}
EXPORT_SYMBOL(lnet_connect_console_error);

int
lnet_connect(cfs_socket_t **sockp, lnet_nid_t peer_nid,
            __u32 local_ip, __u32 peer_ip, int peer_port)
{
        lnet_acceptor_connreq_t cr;
        cfs_socket_t           *sock;
        int                     rc;
        int                     port;
        int                     fatal;

        CLASSERT (sizeof(cr) <= 16);            /* not too big to be on the stack */

        for (port = LNET_ACCEPTOR_MAX_RESERVED_PORT; 
             port >= LNET_ACCEPTOR_MIN_RESERVED_PORT; 
             --port) {
                /* Iterate through reserved ports. */

                rc = libcfs_sock_connect(&sock, &fatal, 
                                         local_ip, port, 
                                         peer_ip, peer_port);
                if (rc != 0) {
                        if (fatal)
                                goto failed;
                        continue;
                }

                CLASSERT (LNET_PROTO_ACCEPTOR_VERSION == 1);

                if (the_lnet.ln_ptlcompat != 2) {
                        /* When portals compatibility is "strong", simply
                         * connect (i.e. send no acceptor connection request).
                         * Othewise send an acceptor connection request. I can
                         * have no portals peers so everyone else should
                         * understand my protocol. */
                        cr.acr_magic   = LNET_PROTO_ACCEPTOR_MAGIC;
                        cr.acr_version = LNET_PROTO_ACCEPTOR_VERSION;
                        cr.acr_nid     = peer_nid;

                        if (the_lnet.ln_testprotocompat != 0) {
                                /* single-shot proto check */
                                LNET_LOCK();
                                if ((the_lnet.ln_testprotocompat & 4) != 0) {
                                        cr.acr_version++;
                                        the_lnet.ln_testprotocompat &= ~4;
                                }
                                if ((the_lnet.ln_testprotocompat & 8) != 0) {
                                        cr.acr_magic = LNET_PROTO_MAGIC;
                                        the_lnet.ln_testprotocompat &= ~8;
                                }
                                LNET_UNLOCK();
                        }

                        rc = libcfs_sock_write(sock, &cr, sizeof(cr),
                                               accept_timeout);
                        if (rc != 0)
                                goto failed_sock;
                }
                
                *sockp = sock;
                return 0;
        }

        rc = -EADDRINUSE;
        goto failed;
        
 failed_sock:
        libcfs_sock_release(sock);
 failed:
        lnet_connect_console_error(rc, peer_nid, peer_ip, peer_port);
        return rc;
}
EXPORT_SYMBOL(lnet_connect);

static inline int
lnet_accept_magic(__u32 magic, __u32 constant)
{
        return (magic == constant ||
                magic == __swab32(constant));
}

int
lnet_accept(lnet_ni_t *blind_ni, cfs_socket_t *sock, __u32 magic)
{
        lnet_acceptor_connreq_t cr;
        __u32                   peer_ip;
        int                     peer_port;
        int                     rc;
        int                     flip;
        lnet_ni_t              *ni;
        char                   *str;

        /* CAVEAT EMPTOR: I may be called by an LND in any thread's context if
         * I passed the new socket "blindly" to the single NI that needed an
         * acceptor.  If so, blind_ni != NULL... */

        LASSERT (sizeof(cr) <= 16);             /* not too big for the stack */
        
        rc = libcfs_sock_getaddr(sock, 1, &peer_ip, &peer_port);
        LASSERT (rc == 0);                      /* we succeeded before */

        if (!lnet_accept_magic(magic, LNET_PROTO_ACCEPTOR_MAGIC)) {

                if (lnet_accept_magic(magic, LNET_PROTO_MAGIC)) {
                        /* future version compatibility!
                         * When LNET unifies protocols over all LNDs, the first
                         * thing sent will be a version query.  I send back
                         * LNET_PROTO_ACCEPTOR_MAGIC to tell her I'm "old" */

                        memset (&cr, 0, sizeof(cr));
                        cr.acr_magic = LNET_PROTO_ACCEPTOR_MAGIC;
                        cr.acr_version = LNET_PROTO_ACCEPTOR_VERSION;
                        rc = libcfs_sock_write(sock, &cr, sizeof(cr),
                                               accept_timeout);

                        if (rc != 0)
                                CERROR("Error sending magic+version in response"
                                       "to LNET magic from %u.%u.%u.%u: %d\n",
                                       HIPQUAD(peer_ip), rc);
                        return -EPROTO;
                }

                if (magic == le32_to_cpu(LNET_PROTO_TCP_MAGIC))
                        str = "'old' socknal/tcpnal";
                else if (lnet_accept_magic(magic, LNET_PROTO_RA_MAGIC))
                        str = "'old' ranal";
                else if (lnet_accept_magic(magic, LNET_PROTO_OPENIB_MAGIC))
                        str = "'old' openibnal";
                else
                        str = "unrecognised";
            
                LCONSOLE_ERROR_MSG(0x11f, "Refusing connection from %u.%u.%u.%u"
                                   " magic %08x: %s acceptor protocol\n",
                                   HIPQUAD(peer_ip), magic, str);
                return -EPROTO;
        }

        flip = (magic != LNET_PROTO_ACCEPTOR_MAGIC);

        rc = libcfs_sock_read(sock, &cr.acr_version, 
                              sizeof(cr.acr_version),
                              accept_timeout);
        if (rc != 0) {
                CERROR("Error %d reading connection request version from "
                       "%u.%u.%u.%u\n", rc, HIPQUAD(peer_ip));
                return -EIO;
        }

        if (flip)
                __swab32s(&cr.acr_version);
        
        if (cr.acr_version != LNET_PROTO_ACCEPTOR_VERSION) {
                /* future version compatibility!
                 * An acceptor-specific protocol rev will first send a version
                 * query.  I send back my current version to tell her I'm
                 * "old". */
                int peer_version = cr.acr_version;

                memset (&cr, 0, sizeof(cr));
                cr.acr_magic = LNET_PROTO_ACCEPTOR_MAGIC;
                cr.acr_version = LNET_PROTO_ACCEPTOR_VERSION;

                rc = libcfs_sock_write(sock, &cr, sizeof(cr),
                                       accept_timeout);

                if (rc != 0)
                        CERROR("Error sending magic+version in response"
                               "to version %d from %u.%u.%u.%u: %d\n",
                               peer_version, HIPQUAD(peer_ip), rc);
                return -EPROTO;
        }

        rc = libcfs_sock_read(sock, &cr.acr_nid,
                              sizeof(cr) -
                              offsetof(lnet_acceptor_connreq_t, acr_nid),
                              accept_timeout);
        if (rc != 0) {
                CERROR("Error %d reading connection request from "
                       "%u.%u.%u.%u\n", rc, HIPQUAD(peer_ip));
                return -EIO;
        }

        if (flip)
                __swab64s(&cr.acr_nid);

        ni = lnet_net2ni(LNET_NIDNET(cr.acr_nid));
        if (ni == NULL ||               /* no matching net */
            ni->ni_nid != cr.acr_nid) { /* right NET, wrong NID! */
                if (ni != NULL)
                        lnet_ni_decref(ni);
                LCONSOLE_ERROR_MSG(0x120, "Refusing connection from %u.%u.%u.%u"
                                   " for %s: No matching NI\n",
                                   HIPQUAD(peer_ip), libcfs_nid2str(cr.acr_nid));
                return -EPERM;
        }

        if (ni->ni_lnd->lnd_accept == NULL) {
                /* This catches a request for the loopback LND */
                lnet_ni_decref(ni);
                LCONSOLE_ERROR_MSG(0x121, "Refusing connection from %u.%u.%u.%u"
                                  " for %s: NI doesn not accept IP connections\n",
                                  HIPQUAD(peer_ip), libcfs_nid2str(cr.acr_nid));
                return -EPERM;
        }

        CDEBUG(D_NET, "Accept %s from %u.%u.%u.%u%s\n",
               libcfs_nid2str(cr.acr_nid), HIPQUAD(peer_ip),
               blind_ni == NULL ? "" : " (blind)");

        if (blind_ni == NULL) {
                /* called by the acceptor: call into the requested NI... */
                rc = ni->ni_lnd->lnd_accept(ni, sock);
        } else {
                /* portals_compatible set and the (only) NI called me to verify
                 * and skip the connection request... */
                LASSERT (the_lnet.ln_ptlcompat != 0);
                LASSERT (ni == blind_ni);
                rc = 0;
        }

        lnet_ni_decref(ni);
        return rc;
}
EXPORT_SYMBOL(lnet_accept);
        
int
lnet_acceptor(void *arg)
{
	char           name[16];
	cfs_socket_t  *newsock;
	int            rc;
        int            n_acceptor_nis;
	__u32          magic;
	__u32          peer_ip;
	int            peer_port;
        lnet_ni_t     *blind_ni = NULL;
        int            secure = (int)((unsigned long)arg);

	LASSERT (lnet_acceptor_state.pta_sock == NULL);

        if (the_lnet.ln_ptlcompat != 0) {
                /* When portals_compatibility is enabled, peers may connect
                 * without sending an acceptor connection request.  There is no
                 * ambiguity about which network the peer wants to connect to
                 * since there can only be 1 network, so I pass connections
                 * "blindly" to it. */
                n_acceptor_nis = lnet_count_acceptor_nis(&blind_ni);
                LASSERT (n_acceptor_nis == 1);
                LASSERT (blind_ni != NULL);
        }

	snprintf(name, sizeof(name), "acceptor_%03d", accept_port);
	cfs_daemonize(name);
	cfs_block_allsigs();

	rc = libcfs_sock_listen(&lnet_acceptor_state.pta_sock,
				0, accept_port, accept_backlog);
	if (rc != 0) {
                if (rc == -EADDRINUSE)
                        LCONSOLE_ERROR_MSG(0x122, "Can't start acceptor on port"
                                           " %d: port already in use\n",
                                           accept_port);
                else
                        LCONSOLE_ERROR_MSG(0x123, "Can't start acceptor on port "
                                           "%d: unexpected error %d\n",
                                           accept_port, rc);

		lnet_acceptor_state.pta_sock = NULL;
        } else {
                LCONSOLE(0, "Accept %s, port %d%s\n", 
                         accept, accept_port,
                         blind_ni == NULL ? "" : " (proto compatible)");
        }
        
	/* set init status and unblock parent */
	lnet_acceptor_state.pta_shutdown = rc;
	mutex_up(&lnet_acceptor_state.pta_signal);
	
	if (rc != 0)
		return rc;

	while (!lnet_acceptor_state.pta_shutdown) {
		
		rc = libcfs_sock_accept(&newsock, lnet_acceptor_state.pta_sock);
		if (rc != 0) {
			if (rc != -EAGAIN) {
				CWARN("Accept error %d: pausing...\n", rc);
				cfs_pause(cfs_time_seconds(1));
			}
			continue;
		}

		rc = libcfs_sock_getaddr(newsock, 1, &peer_ip, &peer_port);
		if (rc != 0) {
			CERROR("Can't determine new connection's address\n");
			goto failed;
		}

                if (secure && peer_port > LNET_ACCEPTOR_MAX_RESERVED_PORT) {
                        CERROR("Refusing connection from %u.%u.%u.%u: "
                               "insecure port %d\n",
                               HIPQUAD(peer_ip), peer_port);
                        goto failed;
                }

                if (blind_ni != NULL) {
                        rc = blind_ni->ni_lnd->lnd_accept(blind_ni, newsock);
                        if (rc != 0) {
                                CERROR("NI %s refused 'blind' connection from "
                                       "%u.%u.%u.%u\n", 
                                       libcfs_nid2str(blind_ni->ni_nid), 
                                       HIPQUAD(peer_ip));
                                goto failed;
                        }
                        continue;
                }
                
		rc = libcfs_sock_read(newsock, &magic, sizeof(magic),
				      accept_timeout);
		if (rc != 0) {
                        CERROR("Error %d reading connection request from "
                               "%u.%u.%u.%u\n", rc, HIPQUAD(peer_ip));
			goto failed;
		}

                rc = lnet_accept(NULL, newsock, magic);
                if (rc != 0)
                        goto failed;
                
                continue;
                
	failed:
		libcfs_sock_release(newsock);
	}
	
	libcfs_sock_release(lnet_acceptor_state.pta_sock);
        lnet_acceptor_state.pta_sock = NULL;

        if (blind_ni != NULL)
                lnet_ni_decref(blind_ni);

        LCONSOLE(0,"Acceptor stopping\n");
	
	/* unblock lnet_acceptor_stop() */
	mutex_up(&lnet_acceptor_state.pta_signal);
	return 0;
}

int
lnet_acceptor_start(void)
{
	long   pid;
        long   secure;

	LASSERT (lnet_acceptor_state.pta_sock == NULL);
	init_mutex_locked(&lnet_acceptor_state.pta_signal);

        if (!strcmp(accept, "secure")) {
                secure = 1;
        } else if (!strcmp(accept, "all")) {
                secure = 0;
        } else if (!strcmp(accept, "none")) {
                return 0;
        } else {
                LCONSOLE_ERROR_MSG(0x124, "Can't parse 'accept=\"%s\"'\n",
                                   accept);
                return -EINVAL;
        }
	
	if (lnet_count_acceptor_nis(NULL) == 0)  /* not required */
		return 0;
	
	pid = cfs_kernel_thread(lnet_acceptor, (void *)secure, 0);
	if (pid < 0) {
		CERROR("Can't start acceptor thread: %ld\n", pid);
		return -ESRCH;
	}

	mutex_down(&lnet_acceptor_state.pta_signal); /* wait for acceptor to startup */

	if (!lnet_acceptor_state.pta_shutdown) {
                /* started OK */
                LASSERT (lnet_acceptor_state.pta_sock != NULL);
		return 0;
        }

        LASSERT (lnet_acceptor_state.pta_sock == NULL);
	return -ENETDOWN;
}

void
lnet_acceptor_stop(void)
{
	if (lnet_acceptor_state.pta_sock == NULL) /* not running */
		return;
	
	lnet_acceptor_state.pta_shutdown = 1;
	libcfs_sock_abort_accept(lnet_acceptor_state.pta_sock);

	/* block until acceptor signals exit */
	mutex_down(&lnet_acceptor_state.pta_signal);
}

#else /* __KERNEL__ */
#ifdef HAVE_LIBPTHREAD

static char *accept_type;
static int accept_port = 988;
static int accept_backlog;
static int accept_timeout;

struct {
        int                   pta_shutdown;
        int                   pta_sock;
        struct cfs_completion pta_completion;
} lnet_acceptor_state;

int
lnet_acceptor_port(void)
{
        return accept_port;
}

int
lnet_parse_int_tunable(int *value, char *name, int dflt)
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
lnet_parse_string_tunable(char **value, char *name, char *dflt)
{
        char    *env = getenv(name);

        if (env == NULL)
                *value = dflt;             
        else
                *value = env;

        return 0;
}

int
lnet_acceptor_get_tunables()
{
        int rc;
        rc = lnet_parse_string_tunable(&accept_type, "LNET_ACCEPT", "secure");

        if (rc != 0)
                return rc;

        rc = lnet_parse_int_tunable(&accept_port, "LNET_ACCEPT_PORT", 988);

        if (rc != 0)
                return rc;
        
        rc = lnet_parse_int_tunable(&accept_backlog, "LNET_ACCEPT_BACKLOG", 127);

        if (rc != 0)
                return rc;

        rc = lnet_parse_int_tunable(&accept_timeout, "LNET_ACCEPT_TIMEOUT", 5);

        if (rc != 0)
                return rc;

        CDEBUG(D_NET, "accept_type     = %s\n", accept_type);
        CDEBUG(D_NET, "accept_port     = %d\n", accept_port);
        CDEBUG(D_NET, "accept_backlog  = %d\n", accept_backlog);
        CDEBUG(D_NET, "accept_timeout  = %d\n", accept_timeout);
        return 0;
}

static inline int
lnet_accept_magic(__u32 magic, __u32 constant)
{
        return (magic == constant ||
                magic == __swab32(constant));
}

/* user-land lnet_accept() isn't used by any LND's directly. So, we don't
 * do it visible outside acceptor.c and we can change its prototype
 * freely */
static int
lnet_accept(int sock, __u32 magic, __u32 peer_ip, int peer_port)
{
        int rc, flip;
        lnet_acceptor_connreq_t cr;
        lnet_ni_t *ni;
        
        if (!lnet_accept_magic(magic, LNET_PROTO_ACCEPTOR_MAGIC)) {
                LCONSOLE_ERROR("Refusing connection from %u.%u.%u.%u magic %08x: "
                               "unsupported acceptor protocol\n",
                               HIPQUAD(peer_ip), magic);
                return -EPROTO;
        }

        flip = (magic != LNET_PROTO_ACCEPTOR_MAGIC);
        
        rc = libcfs_sock_read(sock, &cr.acr_version, 
                              sizeof(cr.acr_version),
                              accept_timeout);
        if (rc != 0) {
                CERROR("Error %d reading connection request version from "
                       "%u.%u.%u.%u\n", rc, HIPQUAD(peer_ip));
                return -EIO;
        }

        if (flip)
                __swab32s(&cr.acr_version);

        if (cr.acr_version != LNET_PROTO_ACCEPTOR_VERSION)
                return -EPROTO;
                
        rc = libcfs_sock_read(sock, &cr.acr_nid,
                              sizeof(cr) -
                              offsetof(lnet_acceptor_connreq_t, acr_nid),
                              accept_timeout);
        if (rc != 0) {
                CERROR("Error %d reading connection request from "
                       "%u.%u.%u.%u\n", rc, HIPQUAD(peer_ip));
                return -EIO;
        }

        if (flip)
                __swab64s(&cr.acr_nid);

        ni = lnet_net2ni(LNET_NIDNET(cr.acr_nid));
                       
        if (ni == NULL ||                    /* no matching net */
             ni->ni_nid != cr.acr_nid) {     /* right NET, wrong NID! */
                if (ni != NULL)
                        lnet_ni_decref(ni);
                LCONSOLE_ERROR("Refusing connection from %u.%u.%u.%u for %s: "
                               " No matching NI\n",
                               HIPQUAD(peer_ip), libcfs_nid2str(cr.acr_nid));
                return -EPERM;
        }

        if (ni->ni_lnd->lnd_accept == NULL) {
                lnet_ni_decref(ni);
                LCONSOLE_ERROR("Refusing connection from %u.%u.%u.%u for %s: "
                               " NI doesn not accept IP connections\n",
                               HIPQUAD(peer_ip), libcfs_nid2str(cr.acr_nid));
                return -EPERM;
        }
        
        CDEBUG(D_NET, "Accept %s from %u.%u.%u.%u\n",
               libcfs_nid2str(cr.acr_nid), HIPQUAD(peer_ip));

        rc = ni->ni_lnd->lnd_accept(ni, sock);
        
        lnet_ni_decref(ni);
        return rc;
}

int
lnet_acceptor(void *arg)
{
        char           name[16];
        int            secure = (int)((unsigned long)arg);
        int            rc;
        int            newsock;
        __u32          peer_ip;
        int            peer_port;
        __u32          magic;

        snprintf(name, sizeof(name), "acceptor_%03d", accept_port);
        cfs_daemonize(name);
        cfs_block_allsigs();

        rc = libcfs_sock_listen(&lnet_acceptor_state.pta_sock,
                                0, accept_port, accept_backlog);
        if (rc != 0) {
                if (rc == -EADDRINUSE)
                        LCONSOLE_ERROR("Can't start acceptor on port %d: "
                                       "port already in use\n",
                                       accept_port);
                else
                        LCONSOLE_ERROR("Can't start acceptor on port %d: "
                                       "unexpected error %d\n",
                                       accept_port, rc);

        } else {
                LCONSOLE(0, "Accept %s, port %d\n", accept_type, accept_port);
        }
        
        /* set init status and unblock parent */
        lnet_acceptor_state.pta_shutdown = rc;
        cfs_complete(&lnet_acceptor_state.pta_completion);

        if (rc != 0)
                return rc;

        while (!lnet_acceptor_state.pta_shutdown) {

                rc = libcfs_sock_accept(&newsock, lnet_acceptor_state.pta_sock,
                                        &peer_ip, &peer_port);
                if (rc != 0)
                        continue;

                /* maybe we're waken up with libcfs_sock_abort_accept() */
                if (lnet_acceptor_state.pta_shutdown) {
                        close(newsock);
                        break;
                }

                if (secure && peer_port > LNET_ACCEPTOR_MAX_RESERVED_PORT) {
                        CERROR("Refusing connection from %u.%u.%u.%u: "
                               "insecure port %d\n",
                               HIPQUAD(peer_ip), peer_port);
                        goto failed;
                }

                rc = libcfs_sock_read(newsock, &magic, sizeof(magic),
                                      accept_timeout);
                if (rc != 0) {
                        CERROR("Error %d reading connection request from "
                               "%u.%u.%u.%u\n", rc, HIPQUAD(peer_ip));
                        goto failed;
                }

                rc = lnet_accept(newsock, magic, peer_ip, peer_port);
                if (rc != 0)
                        goto failed;
                
                continue;
                
          failed:
                close(newsock);
        }
        
        close(lnet_acceptor_state.pta_sock);
        CDEBUG(D_NET, "Acceptor stopping\n");

        /* unblock lnet_acceptor_stop() */
        cfs_complete(&lnet_acceptor_state.pta_completion);        

        return 0;
}

static int skip_waiting_for_completion;

int
lnet_acceptor_start(void)
{
        long   secure;
        int rc;

        rc = lnet_acceptor_get_tunables();
        if (rc != 0)
                return rc;

        /* Do nothing if we're liblustre clients */
        if ((the_lnet.ln_pid & LNET_PID_USERFLAG) != 0)
                return 0;
                        
        cfs_init_completion(&lnet_acceptor_state.pta_completion);

        if (!strcmp(accept_type, "secure")) {
                secure = 1;
        } else if (!strcmp(accept_type, "all")) {
                secure = 0;
        } else if (!strcmp(accept_type, "none")) {
                skip_waiting_for_completion = 1;
                return 0;
        } else {
                LCONSOLE_ERROR ("Can't parse 'accept_type=\"%s\"'\n", accept_type);
                cfs_fini_completion(&lnet_acceptor_state.pta_completion);
                return -EINVAL;
        }

        if (lnet_count_acceptor_nis(NULL) == 0) { /* not required */
                skip_waiting_for_completion = 1;
                return 0;
        }

        rc = cfs_create_thread(lnet_acceptor, (void *)secure);
        if (rc != 0) {
                CERROR("Can't start acceptor thread: %d\n", rc);
                cfs_fini_completion(&lnet_acceptor_state.pta_completion);
                return rc;
        }

        /* wait for acceptor to startup */
        cfs_wait_for_completion(&lnet_acceptor_state.pta_completion);

        if (!lnet_acceptor_state.pta_shutdown)
                return 0;
        
        cfs_fini_completion(&lnet_acceptor_state.pta_completion);
        return -ENETDOWN;
}

void
lnet_acceptor_stop(void)
{
        /* Do nothing if we're liblustre clients */
        if ((the_lnet.ln_pid & LNET_PID_USERFLAG) != 0)
                return;

        if (!skip_waiting_for_completion) {
                lnet_acceptor_state.pta_shutdown = 1;
                libcfs_sock_abort_accept(accept_port);
                
                /* block until acceptor signals exit */
                cfs_wait_for_completion(&lnet_acceptor_state.pta_completion);
        }
        
        cfs_fini_completion(&lnet_acceptor_state.pta_completion);
}
#else
int
lnet_acceptor_start(void)
{
	return 0;
}

void
lnet_acceptor_stop(void)
{
}
#endif /* !HAVE_LIBPTHREAD */
#endif /* !__KERNEL__ */
