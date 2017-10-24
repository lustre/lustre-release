/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 2013, 2015, Intel Corporation.
 *
 *   This file is part of Lustre, https://wiki.hpdd.intel.com/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Portals; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <time.h>
#include <linux/types.h>

#include <libcfs/util/string.h>
#include <libcfs/util/ioctl.h>
#include <libcfs/libcfs_debug.h>
#include <lnet/lnetctl.h>
#include <lnet/socklnd.h>
#include <lnet/lnet.h>

unsigned int libcfs_debug;
unsigned int libcfs_printk = D_CANTMASK;

static bool  g_net_interactive;
static bool  g_net_set;
static __u32 g_net;

#define IOC_BUF_SIZE	8192
static char local_buf[IOC_BUF_SIZE];
static char *ioc_buf = local_buf;

/* Convert a string boolean to an int; "enable" -> 1 */
int
lnet_parse_bool (int *b, char *str)
{
        if (!strcasecmp (str, "no") ||
            !strcasecmp (str, "n") ||
            !strcasecmp (str, "off") ||
            !strcasecmp (str, "down") ||
            !strcasecmp (str, "disable"))
        {
                *b = 0;
                return (0);
        }

        if (!strcasecmp (str, "yes") ||
            !strcasecmp (str, "y") ||
            !strcasecmp (str, "on") ||
            !strcasecmp (str, "up") ||
            !strcasecmp (str, "enable"))
        {
                *b = 1;
                return (0);
        }

        return (-1);
}

int
lnet_parse_port (int *port, char *str)
{
        char      *end;

        *port = strtol (str, &end, 0);

        if (*end == 0 &&                        /* parsed whole string */
            *port > 0 && *port < 65536)         /* minimal sanity check */
                return (0);

        return (-1);
}

#ifdef HAVE_GETHOSTBYNAME
static struct hostent *
ptl_gethostbyname(char * hname) {
        struct hostent *he;
        he = gethostbyname(hname);
        if (!he) {
                switch(h_errno) {
                case HOST_NOT_FOUND:
                case NO_ADDRESS:
                        fprintf(stderr, "Unable to resolve hostname: %s\n",
                                hname);
                        break;
                default:
                        fprintf(stderr, "gethostbyname error for %s: %s\n",
                                hname, strerror(h_errno));
                        break;
                }
                return NULL;
        }
        return he;
}
#endif

int
lnet_parse_ipquad (__u32 *ipaddrp, char *str)
{
        int             a;
        int             b;
        int             c;
        int             d;

        if (sscanf (str, "%d.%d.%d.%d", &a, &b, &c, &d) == 4 &&
            (a & ~0xff) == 0 && (b & ~0xff) == 0 &&
            (c & ~0xff) == 0 && (d & ~0xff) == 0)
        {
                *ipaddrp = (a<<24)|(b<<16)|(c<<8)|d;
                return (0);
        }

        return (-1);
}

int
lnet_parse_ipaddr (__u32 *ipaddrp, char *str)
{
#ifdef HAVE_GETHOSTBYNAME
        struct hostent *he;
#endif

        if (!strcmp (str, "_all_")) {
                *ipaddrp = 0;
                return (0);
        }

        if (lnet_parse_ipquad(ipaddrp, str) == 0)
                return (0);

#ifdef HAVE_GETHOSTBYNAME
        if ((('a' <= str[0] && str[0] <= 'z') ||
             ('A' <= str[0] && str[0] <= 'Z')) &&
             (he = ptl_gethostbyname (str)) != NULL) {
                __u32 addr = *(__u32 *)he->h_addr;

                *ipaddrp = ntohl(addr);         /* HOST byte order */
                return (0);
        }
#endif

        return (-1);
}

char *
ptl_ipaddr_2_str(__u32 ipaddr, char *str, size_t strsize, int lookup)
{
#ifdef HAVE_GETHOSTBYNAME
        __u32           net_ip;
        struct hostent *he;

        if (lookup) {
                net_ip = htonl (ipaddr);
                he = gethostbyaddr (&net_ip, sizeof (net_ip), AF_INET);
                if (he != NULL) {
			strlcpy(str, he->h_name, strsize);
                        return (str);
                }
        }
#endif

        sprintf (str, "%d.%d.%d.%d",
                 (ipaddr >> 24) & 0xff, (ipaddr >> 16) & 0xff,
                 (ipaddr >> 8) & 0xff, ipaddr & 0xff);
        return (str);
}

int
lnet_parse_time (time_t *t, char *str)
{
        char          *end;
        int            n;
        struct tm      tm;

        *t = strtol (str, &end, 0);
        if (*end == 0) /* parsed whole string */
                return (0);

        memset (&tm, 0, sizeof (tm));
        n = sscanf (str, "%d-%d-%d-%d:%d:%d",
                    &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                    &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
        if (n != 6)
                return (-1);

        tm.tm_mon--;                    /* convert to 0 == Jan */
        tm.tm_year -= 1900;             /* y2k quirk */
        tm.tm_isdst = -1;               /* dunno if it's daylight savings... */

        *t = mktime (&tm);
        if (*t == (time_t)-1)
                return (-1);

        return (0);
}

int
lnet_parse_nid(char *nid_str, struct lnet_process_id *id_ptr)
{
        id_ptr->pid = LNET_PID_ANY;
        id_ptr->nid = libcfs_str2nid(nid_str);
        if (id_ptr->nid == LNET_NID_ANY) {
                fprintf (stderr, "Can't parse nid \"%s\"\n", nid_str);
                return -1;
        }

        return 0;
}

static int g_net_is_set(char *cmd)
{
	if (g_net_set)
		return 1;

	if (cmd != NULL) {
		char *net;

		if (g_net_interactive)
			net = "network";
		else
			net = "--net";

		fprintf(stderr,
			"You must run '%s <network>' command before '%s'\n",
			cmd, net);
		return 0;
	}

	return 0;
}

static int g_net_is_compatible(char *cmd, ...)
{
	va_list ap;
	int nal;

	if (!g_net_is_set(cmd))
		return 0;

	va_start(ap, cmd);

	do {
		nal = va_arg(ap, int);
                if (nal == LNET_NETTYP(g_net)) {
                        va_end (ap);
                        return 1;
                }
        } while (nal != 0);

        va_end (ap);

        if (cmd != NULL)
                fprintf (stderr,
                         "Command %s not compatible with %s NAL\n",
                         cmd,
                         libcfs_lnd2str(LNET_NETTYP(g_net)));

        return 0;
}

int ptl_initialize(int argc, char **argv)
{
	if (argc > 1)
		g_net_interactive = true;

	register_ioc_dev(LNET_DEV_ID, LNET_DEV_PATH);

        return 0;
}


int jt_ptl_network(int argc, char **argv)
{
	struct libcfs_ioctl_data data;
	__u32 net = LNET_NIDNET(LNET_NID_ANY);
	int rc;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <net>|up|down\n", argv[0]);
		return -1;
	}

	if (!strcmp(argv[1], "unconfigure") || !strcmp(argv[1], "down")) {
		LIBCFS_IOC_INIT(data);
		rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_UNCONFIGURE, &data);

		if (rc == 0) {
			printf("LNET ready to unload\n");
			return 0;
		}

		if (errno == ENODEV) {
			printf("LNET is currently not loaded.");
			return 0;
		}

		if (errno == EBUSY)
			fprintf(stderr, "LNET busy\n");
		else
			fprintf(stderr, "LNET unconfigure error %d: %s\n",
				errno, strerror(errno));
		return -1;
	} else if (!strcmp(argv[1], "configure") || !strcmp(argv[1], "up")) {
		LIBCFS_IOC_INIT(data);
		rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_CONFIGURE, &data);

		if (rc == 0) {
			printf("LNET configured\n");
			return 0;
		}

		fprintf(stderr, "LNET configure error %d: %s\n",
			errno, strerror(errno));
		return -1;
	}

	net = libcfs_str2net(argv[1]);
	if (net == LNET_NIDNET(LNET_NID_ANY)) {
		fprintf(stderr, "Can't parse net %s\n", argv[1]);
		return -1;
	}

	g_net_set = true;
	g_net = net;
	return 0;
}

int
jt_ptl_list_nids(int argc, char **argv)
{
        struct libcfs_ioctl_data data;
        int                      all = 0, return_nid = 0;
        int                      count;
        int                      rc;

        all = (argc == 2) && (strcmp(argv[1], "all") == 0);
        /* Hack to pass back value */
        return_nid = (argc == 2) && (argv[1][0] == 1);

        if ((argc > 2) && !(all || return_nid)) {
                fprintf(stderr, "usage: %s [all]\n", argv[0]);
                return 0;
        }

        for (count = 0;; count++) {
                LIBCFS_IOC_INIT (data);
                data.ioc_count = count;
                rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_GET_NI, &data);

                if (rc < 0) {
                        if ((count > 0) && (errno == ENOENT))
                                /* We found them all */
                                break;
                        fprintf(stderr,"IOC_LIBCFS_GET_NI error %d: %s\n",
                                errno, strerror(errno));
                        return -1;
                }

                if (all || (LNET_NETTYP(LNET_NIDNET(data.ioc_nid)) != LOLND)) {
                        printf("%s\n", libcfs_nid2str(data.ioc_nid));
                        if (return_nid) {
                                *(__u64 *)(argv[1]) = data.ioc_nid;
                                return_nid--;
                        }
                }
        }

        return 0;
}

int
jt_ptl_which_nid (int argc, char **argv)
{
        struct libcfs_ioctl_data data;
        int          best_dist = 0;
        int          best_order = 0;
        lnet_nid_t   best_nid = LNET_NID_ANY;
        int          dist;
        int          order;
        lnet_nid_t   nid;
        char        *nidstr;
        int          rc;
        int          i;

        if (argc < 2) {
                fprintf(stderr, "usage: %s NID [NID...]\n", argv[0]);
                return 0;
        }

        for (i = 1; i < argc; i++) {
                nidstr = argv[i];
                nid = libcfs_str2nid(nidstr);
                if (nid == LNET_NID_ANY) {
                        fprintf(stderr, "Can't parse NID %s\n", nidstr);
                        return -1;
                }

                LIBCFS_IOC_INIT(data);
                data.ioc_nid = nid;

                rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_LNET_DIST, &data);
                if (rc != 0) {
                        fprintf(stderr, "Can't get distance to %s: %s\n",
                                nidstr, strerror(errno));
                        return -1;
                }

                dist = data.ioc_u32[0];
                order = data.ioc_u32[1];

                if (dist < 0) {
                        if (dist == -EHOSTUNREACH)
                                continue;

                        fprintf(stderr, "Unexpected distance to %s: %d\n",
                                nidstr, dist);
                        return -1;
                }

                if (best_nid == LNET_NID_ANY ||
                    dist < best_dist ||
                    (dist == best_dist && order < best_order)) {
                        best_dist = dist;
                        best_order = order;
                        best_nid = nid;
                }
        }

        if (best_nid == LNET_NID_ANY) {
                fprintf(stderr, "No reachable NID\n");
                return -1;
        }

        printf("%s\n", libcfs_nid2str(best_nid));
        return 0;
}

int
jt_ptl_print_interfaces (int argc, char **argv)
{
        struct libcfs_ioctl_data data;
	char                     buffer[3][HOST_NAME_MAX + 1];
        int                      index;
        int                      rc;

        if (!g_net_is_compatible (argv[0], SOCKLND, 0))
                return -1;

        for (index = 0;;index++) {
                LIBCFS_IOC_INIT(data);
                data.ioc_net   = g_net;
                data.ioc_count = index;

                rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_GET_INTERFACE, &data);
                if (rc != 0)
                        break;

                printf ("%s: (%s/%s) npeer %d nroute %d\n",
			ptl_ipaddr_2_str(data.ioc_u32[0], buffer[2],
					 sizeof(buffer[2]), 1),
			ptl_ipaddr_2_str(data.ioc_u32[0], buffer[0],
					 sizeof(buffer[0]), 0),
			ptl_ipaddr_2_str(data.ioc_u32[1], buffer[1],
					 sizeof(buffer[1]), 0),
                        data.ioc_u32[2], data.ioc_u32[3]);
        }

        if (index == 0) {
                if (errno == ENOENT) {
                        printf ("<no interfaces>\n");
                } else {
                        fprintf(stderr, "Error getting interfaces: %s: "
                                "check dmesg.\n",
                                strerror(errno));
                }
        }

        return 0;
}

int
jt_ptl_add_interface (int argc, char **argv)
{
        struct libcfs_ioctl_data data;
        __u32                    ipaddr;
        int                      rc;
        __u32                    netmask = 0xffffff00;
        int                      i;
        int                      count;
        char                    *end;

        if (argc < 2 || argc > 3) {
                fprintf (stderr, "usage: %s ipaddr [netmask]\n", argv[0]);
                return 0;
        }

        if (!g_net_is_compatible(argv[0], SOCKLND, 0))
                return -1;

        if (lnet_parse_ipaddr(&ipaddr, argv[1]) != 0) {
                fprintf (stderr, "Can't parse ip: %s\n", argv[1]);
                return -1;
        }

        if (argc > 2 ) {
                count = strtol(argv[2], &end, 0);
                if (count > 0 && count < 32 && *end == 0) {
                        netmask = 0;
                        for (i = count; i > 0; i--)
                                netmask = netmask|(1<<(32-i));
                } else if (lnet_parse_ipquad(&netmask, argv[2]) != 0) {
                        fprintf (stderr, "Can't parse netmask: %s\n", argv[2]);
                        return -1;
                }
        }

        LIBCFS_IOC_INIT(data);
        data.ioc_net    = g_net;
        data.ioc_u32[0] = ipaddr;
        data.ioc_u32[1] = netmask;

        rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_ADD_INTERFACE, &data);
        if (rc != 0) {
                fprintf (stderr, "failed to add interface: %s\n",
                         strerror (errno));
                return -1;
        }

        return 0;
}

int
jt_ptl_del_interface (int argc, char **argv)
{
        struct libcfs_ioctl_data data;
        int                      rc;
        __u32                    ipaddr = 0;

        if (argc > 2) {
                fprintf (stderr, "usage: %s [ipaddr]\n", argv[0]);
                return 0;
        }

        if (!g_net_is_compatible(argv[0], SOCKLND, 0))
                return -1;

        if (argc == 2 &&
            lnet_parse_ipaddr(&ipaddr, argv[1]) != 0) {
                fprintf (stderr, "Can't parse ip: %s\n", argv[1]);
                return -1;
        }

        LIBCFS_IOC_INIT(data);
        data.ioc_net    = g_net;
        data.ioc_u32[0] = ipaddr;

        rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_DEL_INTERFACE, &data);
        if (rc != 0) {
                fprintf (stderr, "failed to delete interface: %s\n",
                         strerror (errno));
                return -1;
        }

        return 0;
}

int
jt_ptl_print_peers (int argc, char **argv)
{
	struct libcfs_ioctl_data data;
	struct lnet_process_id        id;
	char                     buffer[2][HOST_NAME_MAX + 1];
	int                      index;
	int                      rc;

	if (!g_net_is_compatible(argv[0], SOCKLND, O2IBLND, GNILND,
				 PTL4LND, 0))
		return -1;

        for (index = 0;;index++) {
                LIBCFS_IOC_INIT(data);
                data.ioc_net     = g_net;
                data.ioc_count   = index;

                rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_GET_PEER, &data);
                if (rc != 0)
                        break;

                if (g_net_is_compatible(NULL, SOCKLND, 0)) {
                        id.nid = data.ioc_nid;
                        id.pid = data.ioc_u32[4];
                        printf ("%-20s [%d]%s->%s:%d #%d\n",
				libcfs_id2str(id),
                                data.ioc_count, /* persistence */
				/* my ip */
				ptl_ipaddr_2_str(data.ioc_u32[2], buffer[0],
						 sizeof(buffer[0]), 1),
				/* peer ip */
				ptl_ipaddr_2_str(data.ioc_u32[0], buffer[1],
						 sizeof(buffer[1]), 1),
                                data.ioc_u32[1], /* peer port */
                                data.ioc_u32[3]); /* conn_count */
		} else if (g_net_is_compatible(NULL, GNILND, 0)) {
			int disconn = data.ioc_flags >> 16;
			char *state;

			if (disconn)
				state = "D";
			else
				state = data.ioc_flags & 0xffff ? "C" : "U";

			printf("%-20s (%d) %s [%d] %ju sq %d/%d tx %d/%d/%d\n",
			       libcfs_nid2str(data.ioc_nid), /* peer nid */
			       data.ioc_net, /* gemini device id */
			       state, /* peer is Connecting, Up, or Down */
			       data.ioc_count,   /* peer refcount */
			       (uintmax_t)data.ioc_u64[0], /* peerstamp */
			       data.ioc_u32[2], data.ioc_u32[3], /* tx and rx seq */
			       /* fmaq, nfma, nrdma */
			       data.ioc_u32[0], data.ioc_u32[1], data.ioc_u32[4]);
                } else {
                        printf ("%-20s [%d]\n",
                                libcfs_nid2str(data.ioc_nid), data.ioc_count);
                }
        }

        if (index == 0) {
                if (errno == ENOENT) {
                        printf ("<no peers>\n");
                } else {
                        fprintf(stderr, "Error getting peer list: %s: "
                                "check dmesg.\n",
                                strerror(errno));
                }
        }
        return 0;
}

int jt_ptl_add_peer(int argc, char **argv)
{
	struct libcfs_ioctl_data data;
	lnet_nid_t nid;
	__u32 ip = 0;
	int port = 0;
	int rc;

	if (!g_net_is_compatible(argv[0], SOCKLND, GNILND, 0))
		return -1;

	if (argc != 4) {
		fprintf(stderr, "usage(tcp,gni): %s nid ipaddr port\n",
			argv[0]);
		return 0;
	}

        nid = libcfs_str2nid(argv[1]);
        if (nid == LNET_NID_ANY) {
                fprintf (stderr, "Can't parse NID: %s\n", argv[1]);
                return -1;
        }

        if (lnet_parse_ipaddr (&ip, argv[2]) != 0) {
                fprintf (stderr, "Can't parse ip addr: %s\n", argv[2]);
                return -1;
        }

        if (lnet_parse_port (&port, argv[3]) != 0) {
                fprintf (stderr, "Can't parse port: %s\n", argv[3]);
                return -1;
        }

        LIBCFS_IOC_INIT(data);
        data.ioc_net    = g_net;
        data.ioc_nid    = nid;
        data.ioc_u32[0] = ip;
        data.ioc_u32[1] = port;

        rc = l_ioctl (LNET_DEV_ID, IOC_LIBCFS_ADD_PEER, &data);
        if (rc != 0) {
                fprintf (stderr, "failed to add peer: %s\n",
                         strerror (errno));
                return -1;
        }

        return 0;
}

int
jt_ptl_del_peer (int argc, char **argv)
{
	struct libcfs_ioctl_data data;
	lnet_nid_t               nid = LNET_NID_ANY;
	lnet_pid_t               pid = LNET_PID_ANY;
	__u32                    ip = 0;
	int                      rc;

	if (!g_net_is_compatible(argv[0], SOCKLND, O2IBLND, GNILND,
				 PTL4LND, 0))
		return -1;

        if (g_net_is_compatible(NULL, SOCKLND, 0)) {
                if (argc > 3) {
                        fprintf (stderr, "usage: %s [nid] [ipaddr]\n",
                                 argv[0]);
                        return 0;
                }
        } else if (argc > 2) {
                fprintf (stderr, "usage: %s [nid]\n", argv[0]);
                return 0;
        }

        if (argc > 1 &&
            !libcfs_str2anynid(&nid, argv[1])) {
                fprintf (stderr, "Can't parse nid: %s\n", argv[1]);
                return -1;
        }

        if (g_net_is_compatible(NULL, SOCKLND, 0)) {
                if (argc > 2 &&
                    lnet_parse_ipaddr (&ip, argv[2]) != 0) {
                        fprintf (stderr, "Can't parse ip addr: %s\n",
                                 argv[2]);
                        return -1;
                }
        }

        LIBCFS_IOC_INIT(data);
        data.ioc_net    = g_net;
        data.ioc_nid    = nid;
        data.ioc_u32[0] = ip;
        data.ioc_u32[1] = pid;

        rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_DEL_PEER, &data);
        if (rc != 0) {
                fprintf (stderr, "failed to remove peer: %s\n",
                         strerror (errno));
                return -1;
        }

        return 0;
}

int
jt_ptl_print_connections (int argc, char **argv)
{
        struct libcfs_ioctl_data data;
	struct lnet_process_id        id;
	char                     buffer[2][HOST_NAME_MAX + 1];
        int                      index;
        int                      rc;

	if (!g_net_is_compatible(argv[0], SOCKLND, O2IBLND, GNILND, 0))
                return -1;

        for (index = 0; ; index++) {
                LIBCFS_IOC_INIT(data);
                data.ioc_net     = g_net;
                data.ioc_count   = index;

                rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_GET_CONN, &data);
                if (rc != 0)
                        break;

		if (g_net_is_compatible(NULL, SOCKLND, 0)) {
			id.nid = data.ioc_nid;
			id.pid = data.ioc_u32[6];
			printf("%-20s %s[%d]%s->%s:%d %d/%d %s\n",
			       libcfs_id2str(id),
			       (data.ioc_u32[3] == SOCKLND_CONN_ANY) ? "A" :
			       (data.ioc_u32[3] == SOCKLND_CONN_CONTROL) ? "C" :
			       (data.ioc_u32[3] == SOCKLND_CONN_BULK_IN) ? "I" :
			 (data.ioc_u32[3] == SOCKLND_CONN_BULK_OUT) ? "O" : "?",
			       data.ioc_u32[4], /* scheduler */
			       /* local IP addr */
			       ptl_ipaddr_2_str(data.ioc_u32[2], buffer[0],
						sizeof(buffer[0]), 1),
			       /* remote IP addr */
			       ptl_ipaddr_2_str(data.ioc_u32[0], buffer[1],
						sizeof(buffer[1]), 1),
			       data.ioc_u32[1],         /* remote port */
			       data.ioc_count, /* tx buffer size */
			       data.ioc_u32[5], /* rx buffer size */
			       data.ioc_flags ? "nagle" : "nonagle");
		} else if (g_net_is_compatible(NULL, O2IBLND, 0)) {
			printf("%s mtu %d\n",
			       libcfs_nid2str(data.ioc_nid),
			       data.ioc_u32[0]); /* path MTU */
		} else if (g_net_is_compatible(NULL, GNILND, 0)) {
			printf("%-20s [%d]\n",
			       libcfs_nid2str(data.ioc_nid),
			       data.ioc_u32[0] /* device id */);
		} else {
			printf("%s\n", libcfs_nid2str(data.ioc_nid));
		}
	}

        if (index == 0) {
                if (errno == ENOENT) {
                        printf ("<no connections>\n");
                } else {
                        fprintf(stderr, "Error getting connection list: %s: "
                                "check dmesg.\n",
                                strerror(errno));
                }
        }
        return 0;
}

int jt_ptl_disconnect(int argc, char **argv)
{
        struct libcfs_ioctl_data data;
        lnet_nid_t               nid = LNET_NID_ANY;
        __u32                    ipaddr = 0;
        int                      rc;

        if (argc > 3) {
                fprintf(stderr, "usage: %s [nid] [ipaddr]\n", argv[0]);
                return 0;
        }

	if (!g_net_is_compatible(NULL, SOCKLND, O2IBLND, GNILND, 0))
                return 0;

        if (argc >= 2 &&
            !libcfs_str2anynid(&nid, argv[1])) {
                fprintf (stderr, "Can't parse nid %s\n", argv[1]);
                return -1;
        }

        if (g_net_is_compatible (NULL, SOCKLND, 0) &&
            argc >= 3 &&
            lnet_parse_ipaddr (&ipaddr, argv[2]) != 0) {
                fprintf (stderr, "Can't parse ip addr %s\n", argv[2]);
                return -1;
        }

        LIBCFS_IOC_INIT(data);
        data.ioc_net     = g_net;
        data.ioc_nid     = nid;
        data.ioc_u32[0]  = ipaddr;

        rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_CLOSE_CONNECTION, &data);
        if (rc != 0) {
                fprintf(stderr, "failed to remove connection: %s\n",
                        strerror(errno));
                return -1;
        }

        return 0;
}

int jt_ptl_push_connection (int argc, char **argv)
{
        struct libcfs_ioctl_data data;
        int                      rc;
        lnet_nid_t               nid = LNET_NID_ANY;

        if (argc > 2) {
                fprintf(stderr, "usage: %s [nid]\n", argv[0]);
                return 0;
        }

	if (!g_net_is_compatible (argv[0], SOCKLND, GNILND, 0))
                return -1;

        if (argc > 1 &&
            !libcfs_str2anynid(&nid, argv[1])) {
                fprintf(stderr, "Can't parse nid: %s\n", argv[1]);
                return -1;
        }

        LIBCFS_IOC_INIT(data);
        data.ioc_net     = g_net;
        data.ioc_nid     = nid;

        rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_PUSH_CONNECTION, &data);
        if (rc != 0) {
                fprintf(stderr, "failed to push connection: %s\n",
                        strerror(errno));
                return -1;
        }

        return 0;
}

int jt_ptl_ping(int argc, char **argv)
{
        int                      rc;
        int                      timeout;
	struct lnet_process_id id;
	struct lnet_process_id ids[16];
        int                      maxids = sizeof(ids)/sizeof(ids[0]);
        struct libcfs_ioctl_data data;
        char                    *sep;
        int                      i;

        if (argc < 2) {
                fprintf(stderr, "usage: %s id [timeout (secs)]\n", argv[0]);
                return 0;
        }

        sep = strchr(argv[1], '-');
        if (sep == NULL) {
                rc = lnet_parse_nid(argv[1], &id);
                if (rc != 0)
                        return -1;
        } else {
                char   *end;

                if (argv[1][0] == 'u' ||
                    argv[1][0] == 'U')
                        id.pid = strtoul(&argv[1][1], &end, 0) | LNET_PID_USERFLAG;
                else
                        id.pid = strtoul(argv[1], &end, 0);

                if (end != sep) { /* assuming '-' is part of hostname */
                        rc = lnet_parse_nid(argv[1], &id);
                        if (rc != 0)
                                return -1;
                } else {
                        id.nid = libcfs_str2nid(sep + 1);

                        if (id.nid == LNET_NID_ANY) {
                                fprintf(stderr,
                                        "Can't parse process id \"%s\"\n",
                                        argv[1]);
                                return -1;
                        }
                }
        }

	if (argc > 2) {
		timeout = 1000 * atol(argv[2]);
		if (timeout > 120 * 1000) {
			fprintf(stderr, "Timeout %s is to large\n",
				argv[2]);
			return -1;
		}
	} else
                timeout = 1000;                 /* default 1 second timeout */

        LIBCFS_IOC_INIT (data);
        data.ioc_nid     = id.nid;
        data.ioc_u32[0]  = id.pid;
        data.ioc_u32[1]  = timeout;
        data.ioc_plen1   = sizeof(ids);
        data.ioc_pbuf1   = (char *)ids;

        rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_PING, &data);
        if (rc != 0) {
                fprintf(stderr, "failed to ping %s: %s\n",
                        id.pid == LNET_PID_ANY ?
                        libcfs_nid2str(id.nid) : libcfs_id2str(id),
                        strerror(errno));
                return -1;
        }

        for (i = 0; i < data.ioc_count && i < maxids; i++)
                printf("%s\n", libcfs_id2str(ids[i]));

        if (data.ioc_count > maxids)
                printf("%d out of %d ids listed\n", maxids, data.ioc_count);

        return 0;
}

int jt_ptl_mynid(int argc, char **argv)
{
        struct libcfs_ioctl_data data;
        lnet_nid_t               nid;
        int rc;

        if (argc != 2) {
                fprintf(stderr, "usage: %s NID\n", argv[0]);
                return 0;
        }

        nid = libcfs_str2nid(argv[1]);
        if (nid == LNET_NID_ANY) {
                fprintf(stderr, "Can't parse NID '%s'\n", argv[1]);
                return -1;
        }

        LIBCFS_IOC_INIT(data);
        data.ioc_net = LNET_NIDNET(nid);
        data.ioc_nid = nid;

        rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_REGISTER_MYNID, &data);
        if (rc < 0)
                fprintf(stderr, "setting my NID failed: %s\n",
                       strerror(errno));
        else
                printf("registered my nid %s\n", libcfs_nid2str(nid));

        return 0;
}

int
jt_ptl_fail_nid (int argc, char **argv)
{
        int                      rc;
        lnet_nid_t               nid;
	int			 threshold;
        struct libcfs_ioctl_data data;

        if (argc < 2 || argc > 3)
        {
                fprintf (stderr, "usage: %s nid|\"*\" [count (0 == mend)]\n", argv[0]);
                return (0);
        }

        if (!libcfs_str2anynid(&nid, argv[1]))
        {
                fprintf (stderr, "Can't parse nid \"%s\"\n", argv[1]);
                return (-1);
        }

        if (argc < 3) {
                threshold = LNET_MD_THRESH_INF;
	} else if (sscanf(argv[2], "%i", &threshold) != 1) {
                fprintf (stderr, "Can't parse count \"%s\"\n", argv[2]);
                return (-1);
        }

        LIBCFS_IOC_INIT (data);
        data.ioc_nid = nid;
        data.ioc_count = threshold;

        rc = l_ioctl (LNET_DEV_ID, IOC_LIBCFS_FAIL_NID, &data);
        if (rc < 0)
                fprintf (stderr, "IOC_LIBCFS_FAIL_NID failed: %s\n",
                         strerror (errno));
        else
                printf ("%s %s\n", threshold == 0 ? "Unfailing" : "Failing", argv[1]);

        return (0);
}

int
jt_ptl_add_route (int argc, char **argv)
{
	struct lnet_ioctl_config_data data;
	lnet_nid_t               gateway_nid;
	__u32			 hops = LNET_UNDEFINED_HOPS;
	unsigned int		 priority = 0;
	char                    *end;
	int                      rc;

	if (argc < 2 || argc > 4) {
		fprintf(stderr, "usage: %s gateway [hopcount [priority]]\n",
			argv[0]);
		return -1;
	}

	if (g_net_is_set(argv[0]) == 0)
		return -1;

	gateway_nid = libcfs_str2nid(argv[1]);
	if (gateway_nid == LNET_NID_ANY) {
		fprintf(stderr, "Can't parse gateway NID \"%s\"\n", argv[1]);
		return -1;
	}

	if (argc > 2) {
		hops = strtol(argv[2], &end, 0);
		if (hops == 0 || hops >= 256 ||
		    (end != NULL && *end != 0)) {
			fprintf(stderr, "Can't parse hopcount \"%s\"\n",
				argv[2]);
			return -1;
		}
		if (argc == 4) {
			priority = strtoul(argv[3], &end, 0);
			if (end != NULL && *end != 0) {
				fprintf(stderr,
					"Can't parse priority \"%s\"\n",
					argv[3]);
				return -1;
			}
		}
	}

	LIBCFS_IOC_INIT_V2(data, cfg_hdr);
	data.cfg_net = g_net;
	data.cfg_config_u.cfg_route.rtr_hop = hops;
	data.cfg_nid = gateway_nid;
	data.cfg_config_u.cfg_route.rtr_priority = priority;

	rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_ADD_ROUTE, &data);
	if (rc != 0) {
		fprintf(stderr, "IOC_LIBCFS_ADD_ROUTE failed: %s\n",
			strerror(errno));
		return -1;
	}

	return 0;
}

int
jt_ptl_del_route (int argc, char **argv)
{
	struct lnet_ioctl_config_data data;
	lnet_nid_t               nid;
	int                      rc;

	if (argc != 2) {
		fprintf(stderr, "usage: %s gatewayNID\n", argv[0]);
		return 0;
	}

	if (libcfs_str2anynid(&nid, argv[1]) == 0) {
		fprintf(stderr, "Can't parse gateway NID "
			"\"%s\"\n", argv[1]);
		return -1;
	}

	LIBCFS_IOC_INIT_V2(data, cfg_hdr);
	data.cfg_net = g_net_set ? g_net : LNET_NIDNET(LNET_NID_ANY);
	data.cfg_nid = nid;

	rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_DEL_ROUTE, &data);
	if (rc != 0) {
		fprintf(stderr, "IOC_LIBCFS_DEL_ROUTE (%s) failed: %s\n",
			libcfs_nid2str(nid), strerror(errno));
		return -1;
	}

	return 0;
}

int
jt_ptl_notify_router (int argc, char **argv)
{
        struct libcfs_ioctl_data data;
        int                      enable;
        lnet_nid_t               nid;
        int                      rc;
        struct timeval           now;
        time_t                   when;

        if (argc < 3)
        {
                fprintf (stderr, "usage: %s targetNID <up/down> [<time>]\n", 
                         argv[0]);
                return (0);
        }

        nid = libcfs_str2nid(argv[1]);
        if (nid == LNET_NID_ANY) {
                fprintf (stderr, "Can't parse target NID \"%s\"\n", argv[1]);
                return (-1);
        }

        if (lnet_parse_bool (&enable, argv[2]) != 0) {
                fprintf (stderr, "Can't parse boolean %s\n", argv[2]);
                return (-1);
        }

        gettimeofday(&now, NULL);

        if (argc < 4) {
                when = now.tv_sec;
        } else if (lnet_parse_time (&when, argv[3]) != 0) {
                fprintf(stderr, "Can't parse time %s\n"
                        "Please specify either 'YYYY-MM-DD-HH:MM:SS'\n"
                        "or an absolute unix time in seconds\n", argv[3]);
                return (-1);
        } else if (when > now.tv_sec) {
                fprintf (stderr, "%s specifies a time in the future\n",
                         argv[3]);
                return (-1);
        }

        LIBCFS_IOC_INIT(data);
        data.ioc_nid = nid;
        data.ioc_flags = enable;
        /* Yeuch; 'cept I need a __u64 on 64 bit machines... */
        data.ioc_u64[0] = (__u64)when;

        rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_NOTIFY_ROUTER, &data);
        if (rc != 0) {
                fprintf (stderr, "IOC_LIBCFS_NOTIFY_ROUTER (%s) failed: %s\n",
                         libcfs_nid2str(nid), strerror (errno));
                return (-1);
        }

        return (0);
}

int
jt_ptl_print_routes (int argc, char **argv)
{
	struct lnet_ioctl_config_data  data;
	int                       rc;
	int                       index;
	__u32                     net;
	lnet_nid_t                nid;
	unsigned int              hops;
	int                       alive;
	unsigned int		  pri;

	for (index = 0; ; index++) {
		LIBCFS_IOC_INIT_V2(data, cfg_hdr);
		data.cfg_count = index;

		rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_GET_ROUTE, &data);
		if (rc != 0)
			break;

		net     = data.cfg_net;
		hops    = data.cfg_config_u.cfg_route.rtr_hop;
		nid     = data.cfg_nid;
		alive   = data.cfg_config_u.cfg_route.rtr_flags;
		pri     = data.cfg_config_u.cfg_route.rtr_priority;

		printf("net %18s hops %u gw %32s %s pri %u\n",
		       libcfs_net2str(net), hops,
		       libcfs_nid2str(nid), alive ? "up" : "down", pri);
	}

	if (errno != ENOENT)
		fprintf(stderr, "Error getting routes: %s: check dmesg.\n",
			strerror(errno));

	return 0;
}

static int
fault_attr_nid_parse(char *str, lnet_nid_t *nid_p)
{
	lnet_nid_t nid;
	__u32	   net;
	int	   rc = 0;

	/* NB: can't support range ipaddress except * and *@net */
	if (strlen(str) > 2 && str[0] == '*' && str[1] == '@') {
		net = libcfs_str2net(str + 2);
		if (net == LNET_NIDNET(LNET_NID_ANY))
			goto failed;

		nid = LNET_MKNID(net, LNET_NIDADDR(LNET_NID_ANY));
	} else {
		rc = libcfs_str2anynid(&nid, str);
		if (!rc)
			goto failed;
	}

	*nid_p = nid;
	return 0;
failed:
	fprintf(stderr, "Invalid NID : %s\n", str);
	return -1;
}

static int
fault_attr_msg_parse(char *msg_str, __u32 *mask_p)
{
	if (!strcasecmp(msg_str, "put")) {
		*mask_p |= LNET_PUT_BIT;
		return 0;

	} else if (!strcasecmp(msg_str, "ack")) {
		*mask_p |= LNET_ACK_BIT;
		return 0;

	} else if (!strcasecmp(msg_str, "get")) {
		*mask_p |= LNET_GET_BIT;
		return 0;

	} else if (!strcasecmp(msg_str, "reply")) {
		*mask_p |= LNET_REPLY_BIT;
		return 0;
	}

	fprintf(stderr, "unknown message type %s\n", msg_str);
	return -1;
}

static int
fault_attr_ptl_parse(char *ptl_str, __u64 *mask_p)
{
	unsigned long rc = strtoul(optarg, NULL, 0);

	if (rc >= 64) {
		fprintf(stderr, "invalid portal: %lu\n", rc);
		return -1;
	}

	*mask_p |= (1ULL << rc);
	return 0;
}

static int
fault_simul_rule_add(__u32 opc, char *name, int argc, char **argv)
{
	struct libcfs_ioctl_data  data = { { 0 } };
	struct lnet_fault_attr    attr;
	char			 *optstr;
	int			  rc;

	static const struct option opts[] = {
	{ .name = "source",   .has_arg = required_argument, .val = 's' },
	{ .name = "dest",     .has_arg = required_argument, .val = 'd' },
	{ .name = "rate",     .has_arg = required_argument, .val = 'r' },
	{ .name = "interval", .has_arg = required_argument, .val = 'i' },
	{ .name = "latency",  .has_arg = required_argument, .val = 'l' },
	{ .name = "portal",   .has_arg = required_argument, .val = 'p' },
	{ .name = "message",  .has_arg = required_argument, .val = 'm' },
	{ .name = NULL } };

	if (argc == 1) {
		fprintf(stderr, "Failed, please provide source, destination "
				"and rate of rule\n");
		return -1;
	}

	optstr = opc == LNET_CTL_DROP_ADD ? "s:d:r:i:p:m:" : "s:d:r:l:p:m:";
	memset(&attr, 0, sizeof(attr));
	while (1) {
		char c = getopt_long(argc, argv, optstr, opts, NULL);

		if (c == -1)
			break;

		switch (c) {
		case 's': /* source NID/NET */
			rc = fault_attr_nid_parse(optarg, &attr.fa_src);
			if (rc != 0)
				goto getopt_failed;
			break;

		case 'd': /* dest NID/NET */
			rc = fault_attr_nid_parse(optarg, &attr.fa_dst);
			if (rc != 0)
				goto getopt_failed;
			break;

		case 'r': /* drop rate */
			if (opc == LNET_CTL_DROP_ADD)
				attr.u.drop.da_rate = strtoul(optarg, NULL, 0);
			else
				attr.u.delay.la_rate = strtoul(optarg, NULL, 0);
			break;

		case 'i': /* time interval (# seconds) for message drop */
			if (opc == LNET_CTL_DROP_ADD)
				attr.u.drop.da_interval = strtoul(optarg,
								  NULL, 0);
			else
				attr.u.delay.la_interval = strtoul(optarg,
								   NULL, 0);
			break;

		case 'l': /* seconds to wait before activating rule */
			attr.u.delay.la_latency = strtoul(optarg, NULL, 0);
			break;

		case 'p': /* portal to filter */
			rc = fault_attr_ptl_parse(optarg, &attr.fa_ptl_mask);
			if (rc != 0)
				goto getopt_failed;
			break;

		case 'm': /* message types to filter */
			rc = fault_attr_msg_parse(optarg, &attr.fa_msg_mask);
			if (rc != 0)
				goto getopt_failed;
			break;

		default:
			fprintf(stderr, "error: %s: option '%s' "
				"unrecognized\n", argv[0], argv[optind - 1]);
			goto getopt_failed;
		}
	}
	optind = 1;

	if (opc == LNET_CTL_DROP_ADD) {
		/* NB: drop rate and interval are exclusive to each other */
		if (!((attr.u.drop.da_rate == 0) ^
		      (attr.u.drop.da_interval == 0))) {
			fprintf(stderr,
				"please provide either drop rate or interval "
				"but not both at the same time.\n");
			return -1;
		}
	} else if (opc == LNET_CTL_DELAY_ADD) {
		if (!((attr.u.delay.la_rate == 0) ^
		      (attr.u.delay.la_interval == 0))) {
			fprintf(stderr,
				"please provide either delay rate or interval "
				"but not both at the same time.\n");
			return -1;
		}

		if (attr.u.delay.la_latency == 0) {
			fprintf(stderr, "latency cannot be zero\n");
			return -1;
		}
	}

	if (attr.fa_src == 0 || attr.fa_dst == 0) {
		fprintf(stderr, "Please provide both source and destination "
				"of %s rule\n", name);
		return -1;
	}

	data.ioc_flags = opc;
	data.ioc_inllen1 = sizeof(attr);
	data.ioc_inlbuf1 = (char *)&attr;
	if (libcfs_ioctl_pack(&data, &ioc_buf, IOC_BUF_SIZE) != 0) {
		fprintf(stderr, "libcfs_ioctl_pack failed\n");
		return -1;
	}

	rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_LNET_FAULT, ioc_buf);
	if (rc != 0) {
		fprintf(stderr, "add %s rule %s->%s failed: %s\n",
			name, libcfs_nid2str(attr.fa_src),
			libcfs_nid2str(attr.fa_dst), strerror(errno));
		return -1;
	}

	printf("Added %s rule %s->%s (1/%d)\n",
	       name, libcfs_nid2str(attr.fa_src), libcfs_nid2str(attr.fa_dst),
	       opc == LNET_CTL_DROP_ADD ?
	       attr.u.drop.da_rate : attr.u.delay.la_rate);
	return 0;

getopt_failed:
	optind = 1;
	return -1;
}

int
jt_ptl_drop_add(int argc, char **argv)
{
	return fault_simul_rule_add(LNET_CTL_DROP_ADD, "drop", argc, argv);
}

int
jt_ptl_delay_add(int argc, char **argv)
{
	return fault_simul_rule_add(LNET_CTL_DELAY_ADD, "delay", argc, argv);
}

static int
fault_simul_rule_del(__u32 opc, char *name, int argc, char **argv)
{
	struct libcfs_ioctl_data data = { { 0 } };
	struct lnet_fault_attr   attr;
	bool			 all = false;
	int			 rc;

	static const struct option opts[] = {
		{ .name = "source", .has_arg = required_argument, .val = 's' },
		{ .name = "dest",   .has_arg = required_argument, .val = 'd' },
		{ .name = "all",    .has_arg = no_argument,	  .val = 'a' },
		{ .name = NULL } };

	if (argc == 1) {
		fprintf(stderr, "Failed, please provide source and "
				"destination of rule\n");
		return -1;
	}

	memset(&attr, 0, sizeof(attr));
	while (1) {
		char c = getopt_long(argc, argv, "s:d:a", opts, NULL);

		if (c == -1 || all)
			break;

		switch (c) {
		case 's':
			rc = fault_attr_nid_parse(optarg, &attr.fa_src);
			if (rc != 0)
				goto getopt_failed;
			break;
		case 'd':
			rc = fault_attr_nid_parse(optarg, &attr.fa_dst);
			if (rc != 0)
				goto getopt_failed;
			break;
		case 'a':
			attr.fa_src = attr.fa_dst = 0;
			all = true;
			break;
		default:
			fprintf(stderr, "error: %s: option '%s' "
				"unrecognized\n", argv[0], argv[optind - 1]);
			goto getopt_failed;
		}
	}
	optind = 1;

	data.ioc_flags = opc;
	data.ioc_inllen1 = sizeof(attr);
	data.ioc_inlbuf1 = (char *)&attr;
	if (libcfs_ioctl_pack(&data, &ioc_buf, IOC_BUF_SIZE) != 0) {
		fprintf(stderr, "libcfs_ioctl_pack failed\n");
		return -1;
	}

	rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_LNET_FAULT, ioc_buf);
	if (rc != 0) {
		fprintf(stderr, "remove %s rule %s->%s failed: %s\n", name,
			all ? "all" : libcfs_nid2str(attr.fa_src),
			all ? "all" : libcfs_nid2str(attr.fa_dst),
			strerror(errno));
		return -1;
	}

	libcfs_ioctl_unpack(&data, ioc_buf);
	printf("Removed %d %s rules\n", data.ioc_count, name);
	return 0;

getopt_failed:
	optind = 1;
	return -1;
}

int
jt_ptl_drop_del(int argc, char **argv)
{
	return fault_simul_rule_del(LNET_CTL_DROP_DEL, "drop", argc, argv);
}

int
jt_ptl_delay_del(int argc, char **argv)
{
	return fault_simul_rule_del(LNET_CTL_DELAY_DEL, "delay", argc, argv);
}

static int
fault_simul_rule_reset(__u32 opc, char *name, int argc, char **argv)
{
	struct libcfs_ioctl_data   data = { { 0 } };
	int			   rc;

	LIBCFS_IOC_INIT(data);
	data.ioc_flags = opc;

	rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_LNET_FAULT, &data);
	if (rc != 0) {
		fprintf(stderr, "failed to reset %s stats: %s\n",
			name, strerror(errno));
		return -1;
	}
	return 0;
}

int
jt_ptl_drop_reset(int argc, char **argv)
{
	return fault_simul_rule_reset(LNET_CTL_DROP_RESET, "drop", argc, argv);
}

int
jt_ptl_delay_reset(int argc, char **argv)
{
	return fault_simul_rule_reset(LNET_CTL_DELAY_RESET, "delay",
				      argc, argv);
}

static int
fault_simul_rule_list(__u32 opc, char *name, int argc, char **argv)
{
	struct libcfs_ioctl_data data = { { 0 } };
	struct lnet_fault_attr   attr;
	struct lnet_fault_stat   stat;
	int			 pos;

	printf("LNet %s rules:\n", name);
	for (pos = 0;; pos++) {
		int		rc;

		memset(&attr, 0, sizeof(attr));
		memset(&stat, 0, sizeof(stat));

		data.ioc_count = pos;
		data.ioc_flags = opc;
		data.ioc_inllen1 = sizeof(attr);
		data.ioc_inlbuf1 = (char *)&attr;
		data.ioc_inllen2 = sizeof(stat);
		data.ioc_inlbuf2 = (char *)&stat;
		if (libcfs_ioctl_pack(&data, &ioc_buf, IOC_BUF_SIZE) != 0) {
			fprintf(stderr, "libcfs_ioctl_pack failed\n");
			return -1;
		}

		rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_LNET_FAULT, ioc_buf);
		if (rc != 0)
			break;

		libcfs_ioctl_unpack(&data, ioc_buf);

		if (opc == LNET_CTL_DROP_LIST) {
			printf("%s->%s (1/%d | %d) ptl %#jx, msg %x, "
			       "%ju/%ju, PUT %ju, ACK %ju, GET "
			       "%ju, REP %ju\n",
			       libcfs_nid2str(attr.fa_src),
			       libcfs_nid2str(attr.fa_dst),
			       attr.u.drop.da_rate, attr.u.drop.da_interval,
			       (uintmax_t)attr.fa_ptl_mask, attr.fa_msg_mask,
			       (uintmax_t)stat.u.drop.ds_dropped,
			       (uintmax_t)stat.fs_count,
			       (uintmax_t)stat.fs_put,
			       (uintmax_t)stat.fs_ack,
			       (uintmax_t)stat.fs_get,
			       (uintmax_t)stat.fs_reply);

		} else if (opc == LNET_CTL_DELAY_LIST) {
			printf("%s->%s (1/%d | %d, latency %d) ptl %#jx"
			       ", msg %x, %ju/%ju, PUT %ju"
			       ", ACK %ju, GET %ju, REP %ju\n",
			       libcfs_nid2str(attr.fa_src),
			       libcfs_nid2str(attr.fa_dst),
			       attr.u.delay.la_rate, attr.u.delay.la_interval,
			       attr.u.delay.la_latency,
			       (uintmax_t)attr.fa_ptl_mask, attr.fa_msg_mask,
			       (uintmax_t)stat.u.delay.ls_delayed,
			       (uintmax_t)stat.fs_count,
			       (uintmax_t)stat.fs_put,
			       (uintmax_t)stat.fs_ack,
			       (uintmax_t)stat.fs_get,
			       (uintmax_t)stat.fs_reply);
		}
	}
	printf("found total %d\n", pos);

	return 0;
}

int
jt_ptl_drop_list(int argc, char **argv)
{
	return fault_simul_rule_list(LNET_CTL_DROP_LIST, "drop", argc, argv);
}

int
jt_ptl_delay_list(int argc, char **argv)
{
	return fault_simul_rule_list(LNET_CTL_DELAY_LIST, "delay", argc, argv);
}

double
get_cycles_per_usec ()
{
        FILE      *f = fopen ("/proc/cpuinfo", "r");
        double     mhz;
        char      line[64];

        if (f != NULL) {
                while (fgets (line, sizeof (line), f) != NULL)
                        if (sscanf (line, "cpu MHz : %lf", &mhz) == 1) {
                                fclose (f);
                                return (mhz);
                        }
                fclose (f);
        }

        fprintf (stderr, "Can't read/parse /proc/cpuinfo\n");
        return (1000.0);
}

int jt_ptl_testprotocompat(int argc, char **argv)
{
        struct libcfs_ioctl_data  data;
        int                       rc;
        int                       flags;
        char                     *end;

        if (argc < 2)  {
                fprintf(stderr, "usage: %s <number>\n", argv[0]);
                return 0;
        }

        flags = strtol(argv[1], &end, 0);
        if (flags < 0 || *end != 0) {
                fprintf(stderr, "Can't parse flags '%s'\n", argv[1]);
                return -1;
        }

        LIBCFS_IOC_INIT(data);
        data.ioc_flags = flags;
        rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_TESTPROTOCOMPAT, &data);

        if (rc != 0) {
                fprintf(stderr, "test proto compat %x failed: %s\n",
                        flags, strerror(errno));
                return -1;
        }

        printf("test proto compat %x OK\n", flags);
        return 0;
}


