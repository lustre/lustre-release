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
#include <portals/lib-p30.h>

#define MIN_RESERVED_PORT    512
#define MAX_RESERVED_PORT    1023

#ifdef __KERNEL__
static int acceptor_port = 988;
CFS_MODULE_PARM(acceptor_port, "i", int, 0444,
                "Acceptor's port (same on all nodes)");

static int acceptor_backlog = 127;
CFS_MODULE_PARM(acceptor_backlog, "i", int, 0444,
                "Acceptor's listen backlog "
                "(set to 0 to refuse incoming connections)");

static int acceptor_timeout = 5;
CFS_MODULE_PARM(acceptor_timeout, "i", int, 0644,
		"Acceptor's timeout (seconds)");

static int accept_secure_only = 1;
CFS_MODULE_PARM(accept_secure_only, "i", int, 0644,
                "Accept connection requests only from secure ports?");

static int acceptor_proto_version = PTL_PROTO_ACCEPTOR_VERSION;
CFS_MODULE_PARM(acceptor_proto_version, "i", int, 0444,
                "Acceptor protocol version (outgoing connection requests)");

struct {
	int               pta_shutdown;
	struct socket    *pta_sock;
	struct semaphore  pta_signal;
} ptl_acceptor_state;

int
ptl_acceptor_timeout(void)
{
        return acceptor_timeout;
}
EXPORT_SYMBOL(ptl_acceptor_timeout);

int
ptl_acceptor_port(void)
{
        return acceptor_port;
}
EXPORT_SYMBOL(ptl_acceptor_port);

void
ptl_connect_console_error (int rc, ptl_nid_t peer_nid, 
                           __u32 peer_ip, int peer_port)
{
        switch (rc) {
        /* "normal" errors */
        case -ECONNREFUSED:
                LCONSOLE_ERROR("Connection to %s at host %u.%u.%u.%u "
                               "on port %d was refused; "
                               "check that Lustre is running on that node.\n",
                               libcfs_nid2str(peer_nid),
                               HIPQUAD(peer_ip), peer_port);
                break;
        case -EHOSTUNREACH:
        case -ENETUNREACH:
                LCONSOLE_ERROR("Connection to %s at host %u.%u.%u.%u "
                               "was unreachable; the network or that node may "
                               "be down, or Lustre may be misconfigured.\n",
                               libcfs_nid2str(peer_nid), HIPQUAD(peer_ip));
                break;
        case -ETIMEDOUT:
                LCONSOLE_ERROR("Connection to %s at host %u.%u.%u.%u on "
                               "port %d took too long; that node may be hung "
                               "or experiencing high load.\n",
                               libcfs_nid2str(peer_nid),
                               HIPQUAD(peer_ip), peer_port);
                break;
        case -ECONNRESET:
                LCONSOLE_ERROR("Connection to %s at host %u.%u.%u.%u on "
                               "port %d was reset; "
                               "Is it running a compatible version of Lustre?\n",
                               libcfs_nid2str(peer_nid),
                               HIPQUAD(peer_ip), peer_port);
                break;
        case -EPROTO:
                LCONSOLE_ERROR("Protocol error connecting to %s at host "
                               "%u.%u.%u.%u on port %d: "
                               "Is it running a compatible version of Lustre?\n",
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
EXPORT_SYMBOL(ptl_connect_console_error);

ptl_err_t
ptl_connect(struct socket **sockp, ptl_nid_t peer_nid,
            __u32 local_ip, __u32 peer_ip, int peer_port)
{
        ptl_acceptor_connreq_t  cr;
        struct socket          *sock;
        int                     rc;
        int                     port;
        int                     fatal;

        CLASSERT (sizeof(cr) <= 16);            /* not too big to be on the stack */

        for (port = MAX_RESERVED_PORT; port >= MIN_RESERVED_PORT; --port) {
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

                if (acceptor_proto_version == PTL_PROTO_ACCEPTOR_VERSION) {
                                
                        cr.acr_magic   = PTL_PROTO_ACCEPTOR_MAGIC;
                        cr.acr_version = PTL_PROTO_ACCEPTOR_VERSION;
                        cr.acr_nid     = peer_nid;

                        rc = libcfs_sock_write(sock, &cr, sizeof(cr), 0);
                        if (rc != 0)
                                goto failed_sock;
                }
                
                *sockp = sock;
                return PTL_OK;
        }

        rc = -EADDRINUSE;
        goto failed;
        
 failed_sock:
        libcfs_sock_release(sock);
 failed:
        ptl_connect_console_error(rc, peer_nid, peer_ip, peer_port);
        return PTL_FAIL;
}
EXPORT_SYMBOL(ptl_connect);

static inline int
ptl_accept_magic(__u32 magic, __u32 constant)
{
        return (magic == constant ||
                magic == __swab32(constant));
}

ptl_err_t
ptl_accept(struct socket *sock, __u32 magic, int choose_ni)
{
        ptl_acceptor_connreq_t  cr;
        __u32                   peer_ip;
        int                     peer_port;
        int                     rc;
        int                     flip;
        ptl_ni_t               *ni;

        /* CAVEAT EMPTOR: I may be called by a NAL in any thread's context if I
         * passed the new socket "blindly" to the single NI that needed an
         * acceptor.  If so, 'choose_ni' is FALSE... */

        LASSERT (sizeof(cr) <= 16);             /* not too big for the stack */
        
        rc = libcfs_sock_getaddr(sock, 1, &peer_ip, &peer_port);
        LASSERT (rc == 0);                      /* we succeeded before */

        if (ptl_accept_magic(magic, PTL_PROTO_TCP_MAGIC)) {
                CERROR("Refusing connection from %u.%u.%u.%u: "
                       " 'old' socknal/tcpnal acceptor protocol\n",
                       HIPQUAD(peer_ip));
                return PTL_FAIL;
        }
        
        if (ptl_accept_magic(magic, PTL_PROTO_RA_MAGIC)) {
                CERROR("Refusing connection from %u.%u.%u.%u: "
                       " 'old' ranal acceptor protocol\n",
                       HIPQUAD(peer_ip));
                return PTL_FAIL;
        }
        
        if (ptl_accept_magic(magic, PTL_PROTO_OPENIB_MAGIC)) {
                CERROR("Refusing connection from %u.%u.%u.%u: "
                       " 'old' openibnal acceptor protocol\n",
                       HIPQUAD(peer_ip));
                return PTL_FAIL;
        }
            
        if (!ptl_accept_magic(magic, PTL_PROTO_ACCEPTOR_MAGIC)) {
                CERROR("Refusing connection from %u.%u.%u.%u: "
                       " unrecognised magic %08x\n",
                       HIPQUAD(peer_ip), magic);
                return PTL_FAIL;
        }

        flip = magic != PTL_PROTO_ACCEPTOR_MAGIC;

        /* FTTB, we only have 1 acceptor protocol version.  When this changes,
         * we'll have to read the version number first before we know how much
         * more to read... */
        rc = libcfs_sock_read(sock, &cr.acr_version, 
                              sizeof(cr) - 
                              offsetof(ptl_acceptor_connreq_t, acr_version),
                              acceptor_timeout);
        if (rc != 0) {
                CERROR("Error %d reading connection request from "
                       "%u.%u.%u.%u\n", rc, HIPQUAD(peer_ip));
                return PTL_FAIL;
        }

        if (flip) {
                __swab32s(&cr.acr_version);
                __swab64s(&cr.acr_nid);
        }
        
        if (cr.acr_version != PTL_PROTO_ACCEPTOR_VERSION) {
                CERROR("Refusing connection from %u.%u.%u.%u: "
                       " unrecognised protocol version %d\n",
                       HIPQUAD(peer_ip), cr.acr_version);
                return PTL_FAIL;
        }

        if (!choose_ni) {
                /* I got called just to skip the connection request */
                return PTL_OK;
        }

        ni = ptl_net2ni(PTL_NIDNET(cr.acr_nid));
        if (ni == NULL ||             /* no matching net */
            ni->ni_nid != cr.acr_nid) /* right NET, but wrong NID! */ {
                if (ni != NULL)
                        ptl_ni_decref(ni);
                CERROR("Refusing connection from %u.%u.%u.%u for %s: "
                       " No matching NI\n",
                       HIPQUAD(peer_ip), libcfs_nid2str(cr.acr_nid));
                return PTL_FAIL;
        }

        if (ni->ni_nal->nal_accept == NULL) {
                ptl_ni_decref(ni);
                CERROR("Refusing connection from %u.%u.%u.%u for %s: "
                       " NI doesn not accept IP connections\n",
                       HIPQUAD(peer_ip), libcfs_nid2str(cr.acr_nid));
                return PTL_FAIL;
        }
                
        rc = ni->ni_nal->nal_accept(ni, sock);
        if (rc != PTL_OK)
                CERROR("NI %s refused connection from %u.%u.%u.%u\n",
                       libcfs_nid2str(ni->ni_nid), HIPQUAD(peer_ip));

        ptl_ni_decref(ni);
        return rc;
}
EXPORT_SYMBOL(ptl_accept);
        
int
ptl_acceptor(void *arg)
{
	char           name[16];
	struct socket *newsock;
	int            rc;
	__u32          magic;
	__u32          peer_ip;
	int            peer_port;
        ptl_ni_t      *blind_ni;

        /* If there is only a single NI that needs me, I'll pass her
         * connections "blind".  Otherwise I'll have to read the bytestream to
         * see which NI the connection is for. */
        rc = ptl_count_acceptor_nis(&blind_ni);
        LASSERT (rc > 0);
        if (rc > 1) {
                ptl_ni_decref(blind_ni);
                blind_ni = NULL;
        }
        
	LASSERT (ptl_acceptor_state.pta_sock == NULL);

	snprintf(name, sizeof(name), "acceptor_%03d", acceptor_port);
	kportal_daemonize(name);
	kportal_blockallsigs();

	LASSERT (acceptor_backlog > 0);
	rc = libcfs_sock_listen(&ptl_acceptor_state.pta_sock,
				0, acceptor_port, acceptor_backlog);
	if (rc != 0) {
                if (rc == -EADDRINUSE)
                        LCONSOLE_ERROR("Can't start acceptor on port %d: "
                                       "port already in use\n",
                                       acceptor_port);
                else
                        LCONSOLE_ERROR("Can't start acceptor on port %d: "
                                       "unexpected error %d\n",
                                       acceptor_port, rc);

		ptl_acceptor_state.pta_sock = NULL;
        }
        
	/* set init status and unblock parent */
	ptl_acceptor_state.pta_shutdown = rc;
	mutex_up(&ptl_acceptor_state.pta_signal);
	
	if (rc != 0)
		return rc;
	
	while (ptl_acceptor_state.pta_shutdown == 0) {
		
		rc = libcfs_sock_accept(&newsock, ptl_acceptor_state.pta_sock);
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

                if (accept_secure_only &&
                    peer_port > MAX_RESERVED_PORT) {
                        CERROR("Refusing connection from %u.%u.%u.%u: "
                               "insecure port %d\n", HIPQUAD(peer_ip), peer_port);
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
                        if (rc != PTL_OK) {
                                CERROR("NI %s refused 'blind' connection from "
                                       "%u.%u.%u.%u\n", 
                                       libcfs_nid2str(blind_ni->ni_nid), 
                                       HIPQUAD(peer_ip));
                                goto failed;
                        }
                        continue;
                }
                
		rc = libcfs_sock_read(newsock, &magic, sizeof(magic),
				      acceptor_timeout);
		if (rc != 0) {
                        CERROR("Error %d reading connection request from "
                               "%u.%u.%u.%u\n", rc, HIPQUAD(peer_ip));
			goto failed;
		}

                rc = ptl_accept(newsock, magic, 1);
                if (rc != PTL_OK)
                        goto failed;
                
                continue;
                
	failed:
		libcfs_sock_release(newsock);
	}
	
	libcfs_sock_release(ptl_acceptor_state.pta_sock);
        if (blind_ni != NULL)
                ptl_ni_decref(blind_ni);
	
	/* unblock ptl_acceptor_stop() */
	mutex_up(&ptl_acceptor_state.pta_signal);
	return 0;
}

ptl_err_t
ptl_acceptor_start(void)
{
	long   pid;

	LASSERT (ptl_acceptor_state.pta_sock == NULL);
	init_mutex_locked(&ptl_acceptor_state.pta_signal);
	
	if (acceptor_backlog <= 0 ||            /* disabled */
            ptl_count_acceptor_nis(NULL) == 0)  /* not required */
		return PTL_OK;
	
	pid = cfs_kernel_thread (ptl_acceptor, NULL, 0);
	if (pid < 0) {
		CERROR ("Can't start acceptor: %ld\n", pid);
		return PTL_FAIL;
	}

	mutex_down(&ptl_acceptor_state.pta_signal); /* wait for acceptor to startup */

	if (ptl_acceptor_state.pta_shutdown == 0) {
                /* started OK */
                LASSERT (ptl_acceptor_state.pta_sock != NULL);
		return PTL_OK;
        }

	CERROR ("Can't start acceptor: %d\n", ptl_acceptor_state.pta_shutdown);
        LASSERT (ptl_acceptor_state.pta_sock == NULL);
	return PTL_FAIL;
}

void
ptl_acceptor_stop(void)
{
	if (ptl_acceptor_state.pta_sock == NULL) /* not running */
		return;
	
	ptl_acceptor_state.pta_shutdown = 1;
	libcfs_sock_abort_accept(ptl_acceptor_state.pta_sock);

	/* block until acceptor signals exit */
	mutex_down(&ptl_acceptor_state.pta_signal);
}

#else /* __KERNEL__ */

ptl_err_t
ptl_acceptor_start(void)
{
	return PTL_OK;
}

void
ptl_acceptor_stop(void)
{
}

#endif /* !__KERNEL__ */
