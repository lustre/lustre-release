/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2005 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
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
 *
 */

#define DEBUG_SUBSYSTEM S_PORTALS
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

static int accept_proto_version = PTL_PROTO_ACCEPTOR_VERSION;
CFS_MODULE_PARM(accept_proto_version, "i", int, 0444,
                "Acceptor protocol version (outgoing connection requests)");

struct {
	int               pta_shutdown;
	struct socket    *pta_sock;
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
                LCONSOLE_ERROR("Connection to %s at host %u.%u.%u.%u "
                               "on port %d was refused: "
                               "check that Lustre is running on that node.\n",
                               libcfs_nid2str(peer_nid),
                               HIPQUAD(peer_ip), peer_port);
                break;
        case -EHOSTUNREACH:
        case -ENETUNREACH:
                LCONSOLE_ERROR("Connection to %s at host %u.%u.%u.%u "
                               "was unreachable: the network or that node may "
                               "be down, or Lustre may be misconfigured.\n",
                               libcfs_nid2str(peer_nid), HIPQUAD(peer_ip));
                break;
        case -ETIMEDOUT:
                LCONSOLE_ERROR("Connection to %s at host %u.%u.%u.%u on "
                               "port %d took too long: that node may be hung "
                               "or experiencing high load.\n",
                               libcfs_nid2str(peer_nid),
                               HIPQUAD(peer_ip), peer_port);
                break;
        case -ECONNRESET:
                LCONSOLE_ERROR("Connection to %s at host %u.%u.%u.%u on "
                               "port %d was reset: "
                               "is it running a compatible version of Lustre "
                               "and is %s one of its NIDs?\n",
                               libcfs_nid2str(peer_nid),
                               HIPQUAD(peer_ip), peer_port,
                               libcfs_nid2str(peer_nid));
                break;
        case -EPROTO:
                LCONSOLE_ERROR("Protocol error connecting to %s at host "
                               "%u.%u.%u.%u on port %d: "
                               "is it running a compatible version of Lustre?\n",
                               libcfs_nid2str(peer_nid),
                               HIPQUAD(peer_ip), peer_port);
                break;
        case -EADDRINUSE:
                LCONSOLE_ERROR("No privileged ports available to connect to "
                               "%s at host %u.%u.%u.%u on port %d\n",
                               libcfs_nid2str(peer_nid),
                               HIPQUAD(peer_ip), peer_port);
                break;
        default:
                LCONSOLE_ERROR("Unexpected error %d connecting to %s at "
                               "host %u.%u.%u.%u on port %d\n", rc,
                               libcfs_nid2str(peer_nid),
                               HIPQUAD(peer_ip), peer_port);
                break;
        }
}
EXPORT_SYMBOL(lnet_connect_console_error);

int
lnet_connect(struct socket **sockp, lnet_nid_t peer_nid,
            __u32 local_ip, __u32 peer_ip, int peer_port)
{
        lnet_acceptor_connreq_t  cr;
        struct socket          *sock;
        int                     rc;
        int                     port;
        int                     fatal;

        CLASSERT (sizeof(cr) <= 16);            /* not too big to be on the stack */

        for (port = PTL_ACCEPTOR_MAX_RESERVED_PORT; 
             port >= PTL_ACCEPTOR_MIN_RESERVED_PORT; 
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

                /* Ensure writing connection requests don't block.  PAGE_SIZE
                 * isn't excessive and easily big enough for all the NALs */
                rc = libcfs_sock_setbuf(sock, PAGE_SIZE, PAGE_SIZE);
                if (rc != 0) {
                        CERROR("Error %d setting buffer sizes\n", rc);
                        goto failed_sock;
                }

                CLASSERT (PTL_PROTO_ACCEPTOR_VERSION == 1);

                if (accept_proto_version == PTL_PROTO_ACCEPTOR_VERSION) {

                        LASSERT (lnet_apini.apini_ptlcompat < 2); /* no portals peers */
                                
                        cr.acr_magic   = PTL_PROTO_ACCEPTOR_MAGIC;
                        cr.acr_version = PTL_PROTO_ACCEPTOR_VERSION;
                        cr.acr_nid     = peer_nid;

                        rc = libcfs_sock_write(sock, &cr, sizeof(cr), 0);
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
lnet_accept(ptl_ni_t *blind_ni, struct socket *sock, __u32 magic)
{
        lnet_acceptor_connreq_t  cr;
        __u32                   peer_ip;
        int                     peer_port;
        int                     rc;
        int                     flip;
        ptl_ni_t               *ni;
        char                   *str;

        /* CAVEAT EMPTOR: I may be called by a NAL in any thread's context if I
         * passed the new socket "blindly" to the single NI that needed an
         * acceptor.  If so, blind_ni != NULL... */

        LASSERT (sizeof(cr) <= 16);             /* not too big for the stack */
        
        rc = libcfs_sock_getaddr(sock, 1, &peer_ip, &peer_port);
        LASSERT (rc == 0);                      /* we succeeded before */

        if (!lnet_accept_magic(magic, PTL_PROTO_ACCEPTOR_MAGIC)) {

                if (magic == le32_to_cpu(PTL_PROTO_TCP_MAGIC))
                        str = "'old' socknal/tcpnal";
                else if (lnet_accept_magic(magic, PTL_PROTO_RA_MAGIC))
                        str = "'old' ranal";
                else if (lnet_accept_magic(magic, PTL_PROTO_OPENIB_MAGIC))
                        str = "'old' openibnal";
                else
                        str = "unrecognised";
            
                LCONSOLE_ERROR("Refusing connection from %u.%u.%u.%u magic %08x: "
                               " %s acceptor protocol\n",
                               HIPQUAD(peer_ip), magic, str);
                return -EPROTO;
        }

        flip = magic != PTL_PROTO_ACCEPTOR_MAGIC;

        /* FTTB, we only have 1 acceptor protocol version.  When this changes,
         * we'll have to read the version number first before we know how much
         * more to read... */
        rc = libcfs_sock_read(sock, &cr.acr_version, 
                              sizeof(cr) - 
                              offsetof(lnet_acceptor_connreq_t, acr_version),
                              accept_timeout);
        if (rc != 0) {
                CERROR("Error %d reading connection request from "
                       "%u.%u.%u.%u\n", rc, HIPQUAD(peer_ip));
                return -EIO;
        }

        if (flip) {
                __swab32s(&cr.acr_version);
                __swab64s(&cr.acr_nid);
        }
        
        if (cr.acr_version != PTL_PROTO_ACCEPTOR_VERSION) {
                LCONSOLE_ERROR("Refusing connection from %u.%u.%u.%u: "
                               " unrecognised protocol version %d\n",
                               HIPQUAD(peer_ip), cr.acr_version);
                return -EPROTO;
        }

        ni = lnet_net2ni(PTL_NIDNET(cr.acr_nid));
        if (ni == NULL ||             /* no matching net */
            ni->ni_nid != cr.acr_nid) /* right NET, but wrong NID! */ {
                if (ni != NULL)
                        ptl_ni_decref(ni);
                LCONSOLE_ERROR("Refusing connection from %u.%u.%u.%u for %s: "
                               " No matching NI\n",
                               HIPQUAD(peer_ip), libcfs_nid2str(cr.acr_nid));
                return -EPERM;
        }

        if (ni->ni_nal->nal_accept == NULL) {
                ptl_ni_decref(ni);
                LCONSOLE_ERROR("Refusing connection from %u.%u.%u.%u for %s: "
                               " NI doesn not accept IP connections\n",
                               HIPQUAD(peer_ip), libcfs_nid2str(cr.acr_nid));
                return -EPERM;
        }
                
        CDEBUG(D_NET, "Accept %s from %u.%u.%u.%u%s\n",
               libcfs_nid2str(cr.acr_nid), HIPQUAD(peer_ip),
               blind_ni == NULL ? "" : " (blind)");

        if (blind_ni == NULL) {
                rc = ni->ni_nal->nal_accept(ni, sock);
                if (rc != 0)
                        CERROR("NI %s refused connection from %u.%u.%u.%u\n",
                               libcfs_nid2str(ni->ni_nid), HIPQUAD(peer_ip));
        } else {
                /* blind_ni is the only NI that needs me and it was given the
                 * chance to handle this connection request itself in case it
                 * was sent by an "old" socknal.  But this connection request
                 * uses the new acceptor protocol and I'm just being called to
                 * verify and skip it */
                LASSERT (ni == blind_ni);
                rc = 0;
        }

        ptl_ni_decref(ni);
        return rc;
}
EXPORT_SYMBOL(lnet_accept);
        
int
lnet_acceptor(void *arg)
{
	char           name[16];
	struct socket *newsock;
	int            rc;
        int            n_acceptor_nis;
	__u32          magic;
	__u32          peer_ip;
	int            peer_port;
        ptl_ni_t      *blind_ni;
        int            secure = (int)((unsigned long)arg);

	LASSERT (lnet_acceptor_state.pta_sock == NULL);

        /* If there is only a single NI that needs me, I'll pass her
         * connections "blind".  Otherwise I'll have to read the bytestream to
         * see which NI the connection is for.  NB I don't get to run at all if
         * there are 0 acceptor_nis... */
        n_acceptor_nis = ptl_count_acceptor_nis(&blind_ni);
        LASSERT (n_acceptor_nis > 0);
        if (n_acceptor_nis > 1) {
                ptl_ni_decref(blind_ni);
                blind_ni = NULL;
        }

	snprintf(name, sizeof(name), "acceptor_%03d", accept_port);
	libcfs_daemonize(name);
	libcfs_blockallsigs();

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

	while (lnet_acceptor_state.pta_shutdown == 0) {
		
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

                if (secure && peer_port > PTL_ACCEPTOR_MAX_RESERVED_PORT) {
                        CERROR("Refusing connection from %u.%u.%u.%u: "
                               "insecure port %d\n",
                               HIPQUAD(peer_ip), peer_port);
                        goto failed;
                }

                /* Ensure writing connection requests don't block.  PAGE_SIZE
                 * isn't excessive and easily big enough for all the NALs */
                rc = libcfs_sock_setbuf(newsock, PAGE_SIZE, PAGE_SIZE);
                if (rc != 0) {
                        CERROR("Refusing connection from %u.%u.%u.%u: "
                               "error %d setting buffer sizes\n", 
                               HIPQUAD(peer_ip), rc);
                        goto failed;
                }

                if (blind_ni != NULL) {
                        rc = blind_ni->ni_nal->nal_accept(blind_ni, newsock);
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
                ptl_ni_decref(blind_ni);

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

        /* If we're talking to any portals (pre-LNET) nodes we force the old
         * acceptor protocol on outgoing connections */
        if (lnet_apini.apini_ptlcompat > 1)
                accept_proto_version = 0;
        
	LASSERT (lnet_acceptor_state.pta_sock == NULL);
	init_mutex_locked(&lnet_acceptor_state.pta_signal);

        if (!strcmp(accept, "secure")) {
                secure = 1;
        } else if (!strcmp(accept, "all")) {
                secure = 0;
        } else if (!strcmp(accept, "none")) {
                return 0;
        } else {
                LCONSOLE_ERROR ("Can't parse 'accept=\"%s\"'\n",
                                accept);
                return -EINVAL;
        }
	
	if (ptl_count_acceptor_nis(NULL) == 0)  /* not required */
		return 0;
	
	pid = cfs_kernel_thread(lnet_acceptor, (void *)secure, 0);
	if (pid < 0) {
		CERROR("Can't start acceptor thread: %ld\n", pid);
		return -ESRCH;
	}

	mutex_down(&lnet_acceptor_state.pta_signal); /* wait for acceptor to startup */

	if (lnet_acceptor_state.pta_shutdown == 0) {
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

int
lnet_acceptor_start(void)
{
	return 0;
}

void
lnet_acceptor_stop(void)
{
}

#endif /* !__KERNEL__ */
