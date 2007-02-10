/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *   This file is part of Portals, http://www.sf.net/projects/lustre/
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

#include <stdio.h>
#include <sys/types.h>
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#include <sys/socket.h>
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifndef _IOWR
#include "ioctl.h"
#endif
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif

#include <libcfs/portals_utils.h>
#include <lnet/api-support.h>
#include <lnet/lnetctl.h>
#include <lnet/socklnd.h>
#include "parser.h"

unsigned int libcfs_debug;
unsigned int libcfs_printk;

static int   g_net_set;
static __u32 g_net;

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
ptl_ipaddr_2_str (__u32 ipaddr, char *str, int lookup)
{
#ifdef HAVE_GETHOSTBYNAME
        __u32           net_ip;
        struct hostent *he;

        if (lookup) {
                net_ip = htonl (ipaddr);
                he = gethostbyaddr (&net_ip, sizeof (net_ip), AF_INET);
                if (he != NULL) {
                        strcpy(str, he->h_name);
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

int g_net_is_set (char *cmd) 
{
        if (g_net_set)
                return 1;
        
        if (cmd != NULL)
                fprintf(stderr, 
                        "You must run the 'network' command before '%s'.\n",
                        cmd);
        return 0;
}

int g_net_is_compatible (char *cmd, ...)
{
        va_list       ap;
        int           nal;

        if (!g_net_is_set(cmd))
                return 0;

        va_start(ap, cmd);

        do {
                nal = va_arg (ap, int);
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
        register_ioc_dev(LNET_DEV_ID, LNET_DEV_PATH,
                         LNET_DEV_MAJOR, LNET_DEV_MINOR);
        return 0;
}


int jt_ptl_network(int argc, char **argv)
{
        struct libcfs_ioctl_data data;
        __u32                    net = LNET_NIDNET(LNET_NID_ANY);
        int                      rc;

        if (argc < 2) {
                fprintf(stderr, "usage: %s <net>|up|down\n", argv[0]);
                return 0;
        }

        if (!strcmp(argv[1], "unconfigure") ||
            !strcmp(argv[1], "down")) {
                LIBCFS_IOC_INIT(data);
                rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_UNCONFIGURE, &data);

                if (rc == 0) {
                        printf ("LNET ready to unload\n");
                        return 0;
                }

                if (errno == EBUSY)
                        fprintf(stderr, "LNET busy\n");
                else
                        fprintf(stderr, "LNET unconfigure error %d: %s\n",
                                errno, strerror(errno));
                return -1;
        }

        if (!strcmp(argv[1], "configure") ||
            !strcmp(argv[1], "up")) {
                LIBCFS_IOC_INIT(data);
                rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_CONFIGURE, &data);

                if (rc == 0) {
                        printf ("LNET configured\n");
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

        g_net_set = 1;
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
        char                     buffer[3][64];
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
                        ptl_ipaddr_2_str(data.ioc_u32[0], buffer[2], 1),
                        ptl_ipaddr_2_str(data.ioc_u32[0], buffer[0], 0),
                        ptl_ipaddr_2_str(data.ioc_u32[1], buffer[1], 0),
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
        lnet_process_id_t        id;
        char                     buffer[2][64];
        int                      index;
        int                      rc;

        if (!g_net_is_compatible (argv[0], SOCKLND, RALND, PTLLND,
                                  OPENIBLND, CIBLND, IIBLND, VIBLND, O2IBLND, 0))
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
                                ptl_ipaddr_2_str (data.ioc_u32[2], buffer[0], 1), /* my ip */
                                ptl_ipaddr_2_str (data.ioc_u32[0], buffer[1], 1), /* peer ip */
                                data.ioc_u32[1], /* peer port */
                                data.ioc_u32[3]); /* conn_count */
                } else if (g_net_is_compatible(NULL, PTLLND, 0)) {
                        id.nid = data.ioc_nid;
                        id.pid = data.ioc_u32[4];
                        printf ("%-20s s %d%s [%d] "LPD64".%06d"
                                " m "LPD64"/"LPD64" q %d/%d c %d/%d\n",
                                libcfs_id2str(id),
                                data.ioc_net,   /* state */
                                data.ioc_flags ? "" : " ~!h", /* sent_hello */
                                data.ioc_count, /* refcount */
                                data.ioc_u64[0]/1000000, /* incarnation secs */
                                (int)(data.ioc_u64[0]%1000000), /* incarnation usecs */
                                (((__u64)data.ioc_u32[1])<<32) |
                                ((__u64)data.ioc_u32[0]), /* next_matchbits */
                                (((__u64)data.ioc_u32[3])<<32) |
                                ((__u64)data.ioc_u32[2]), /* last_matchbits_seen */
                                data.ioc_u32[5] >> 16, /* nsendq */
                                data.ioc_u32[5] & 0xffff, /* nactiveq */
                                data.ioc_u32[6] >> 16, /* credits */
                                data.ioc_u32[6] & 0xffff); /* outstanding_credits */
                } else if (g_net_is_compatible(NULL, RALND, OPENIBLND, CIBLND, VIBLND, 0)) {
                        printf ("%-20s [%d]@%s:%d\n",
                                libcfs_nid2str(data.ioc_nid), /* peer nid */
                                data.ioc_count,   /* peer persistence */
                                ptl_ipaddr_2_str (data.ioc_u32[0], buffer[1], 1), /* peer ip */
                                data.ioc_u32[1]); /* peer port */
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

int 
jt_ptl_add_peer (int argc, char **argv)
{
        struct libcfs_ioctl_data data;
        lnet_nid_t               nid;
        __u32                    ip = 0;
        int                      port = 0;
        int                      rc;

        if (!g_net_is_compatible (argv[0], SOCKLND, RALND, 
                                  OPENIBLND, CIBLND, IIBLND, VIBLND, 0))
                return -1;

        if (g_net_is_compatible(NULL, SOCKLND, OPENIBLND, CIBLND, RALND, 0)) {
                if (argc != 4) {
                        fprintf (stderr, "usage(tcp,openib,cib,ra): %s nid ipaddr port\n", 
                                 argv[0]);
                        return 0;
                }
        } else if (g_net_is_compatible(NULL, VIBLND, 0)) {
                if (argc != 3) {
                        fprintf (stderr, "usage(vib): %s nid ipaddr\n", 
                                 argv[0]);
                        return 0;
                }
        } else if (argc != 2) {
                fprintf (stderr, "usage(iib): %s nid\n", argv[0]);
                return 0;
        }

        nid = libcfs_str2nid(argv[1]);
        if (nid == LNET_NID_ANY) {
                fprintf (stderr, "Can't parse NID: %s\n", argv[1]);
                return -1;
        }

        if (g_net_is_compatible (NULL, SOCKLND, OPENIBLND, CIBLND, VIBLND, RALND, 0) &&
            lnet_parse_ipaddr (&ip, argv[2]) != 0) {
                fprintf (stderr, "Can't parse ip addr: %s\n", argv[2]);
                return -1;
        }

        if (g_net_is_compatible (NULL, SOCKLND, OPENIBLND, CIBLND, RALND, 0) &&
            lnet_parse_port (&port, argv[3]) != 0) {
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
        char                    *end;
        int                      rc;

        if (!g_net_is_compatible (argv[0], SOCKLND, RALND, MXLND, PTLLND,
                                  OPENIBLND, CIBLND, IIBLND, VIBLND, O2IBLND, 0))
                return -1;

        if (g_net_is_compatible(NULL, SOCKLND, 0)) {
                if (argc > 3) {
                        fprintf (stderr, "usage: %s [nid] [ipaddr]\n",
                                 argv[0]);
                        return 0;
                }
        } else if (g_net_is_compatible(NULL, PTLLND, 0)) {
                if (argc > 3) {
                        fprintf (stderr, "usage: %s [nid] [pid]\n",
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
        } else if (g_net_is_compatible(NULL, PTLLND, 0)) {
                if (argc > 2) {
                        pid = strtol(argv[2], &end, 0);
                        if (end == argv[2] || *end == 0) {
                                fprintf(stderr, "Can't parse pid %s\n",
                                        argv[2]);
                                return -1;
                        }
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
        lnet_process_id_t        id;
        char                     buffer[2][64];
        int                      index;
        int                      rc;

        if (!g_net_is_compatible (argv[0], SOCKLND, RALND, 
                                  OPENIBLND, CIBLND, IIBLND, VIBLND, O2IBLND, 0))
                return -1;

        for (index = 0; ; index++) {
                LIBCFS_IOC_INIT(data);
                data.ioc_net     = g_net;
                data.ioc_count   = index;

                rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_GET_CONN, &data);
                if (rc != 0)
                        break;

                if (g_net_is_compatible (NULL, SOCKLND, 0)) {
                        id.nid = data.ioc_nid;
                        id.pid = data.ioc_u32[6];
                        printf ("%-20s %s[%d]%s->%s:%d %d/%d %s\n",
                                libcfs_id2str(id),
                                (data.ioc_u32[3] == SOCKLND_CONN_ANY) ? "A" :
                                (data.ioc_u32[3] == SOCKLND_CONN_CONTROL) ? "C" :
                                (data.ioc_u32[3] == SOCKLND_CONN_BULK_IN) ? "I" :
                                (data.ioc_u32[3] == SOCKLND_CONN_BULK_OUT) ? "O" : "?",
                                data.ioc_u32[4], /* scheduler */
                                ptl_ipaddr_2_str (data.ioc_u32[2], buffer[0], 1), /* local IP addr */
                                ptl_ipaddr_2_str (data.ioc_u32[0], buffer[1], 1), /* remote IP addr */
                                data.ioc_u32[1],         /* remote port */
                                data.ioc_count, /* tx buffer size */
                                data.ioc_u32[5], /* rx buffer size */
                                data.ioc_flags ? "nagle" : "nonagle");
                } else if (g_net_is_compatible (NULL, RALND, 0)) {
                        printf ("%-20s [%d]\n",
                                libcfs_nid2str(data.ioc_nid),
                                data.ioc_u32[0] /* device id */);
                } else {
                        printf ("%s\n", libcfs_nid2str(data.ioc_nid));
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

        if (!g_net_is_compatible (NULL, SOCKLND, RALND, MXLND,
                                  OPENIBLND, CIBLND, IIBLND, VIBLND, O2IBLND, 0))
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

        if (!g_net_is_compatible (argv[0], SOCKLND, 0))
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

int 
jt_ptl_print_active_txs (int argc, char **argv)
{
        struct libcfs_ioctl_data data;
        int                      index;
        int                      rc;

        if (!g_net_is_compatible (argv[0], QSWLND, 0))
                return -1;

        for (index = 0;;index++) {
                LIBCFS_IOC_INIT(data);
                data.ioc_net   = g_net;
                data.ioc_count = index;

                rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_GET_TXDESC, &data);
                if (rc != 0)
                        break;

                printf ("type %u payload %6d to %s via %s by pid %6d: "
                        "%s, %s, state %d\n",
                        data.ioc_u32[0],
                        data.ioc_count,
                        libcfs_nid2str(data.ioc_nid),
                        libcfs_nid2str(data.ioc_u64[0]),
                        data.ioc_u32[1],
                        (data.ioc_flags & 1) ? "delayed" : "immediate",
                        (data.ioc_flags & 2) ? "nblk"    : "normal",
                        data.ioc_flags >> 2);
        }

        if (index == 0) {
                if (errno == ENOENT) {
                        printf ("<no active descs>\n");
                } else {
                        fprintf(stderr, "Error getting active transmits list: "
                                "%s: check dmesg.\n",
                                strerror(errno));
                }
        }
        return 0;
}

int jt_ptl_ping_test(int argc, char **argv)
{
        int       rc;
        lnet_nid_t nid;
        long      count   = 1;
        long      size    = 4;
        long      timeout = 1;
        struct libcfs_ioctl_data data;

        if (argc < 2) {
                fprintf(stderr, "usage: %s nid [count] [size] [timeout (secs)]\n", argv[0]);
                return 0;
        }

        nid = libcfs_str2nid(argv[1]);
        if (nid == LNET_NID_ANY) {
                fprintf (stderr, "Can't parse nid \"%s\"\n", argv[1]);
                return (-1);
        }
        
        if (argc > 2)
        {
                count = atol(argv[2]);

                if (count < 0 || count > 20000) 
                {
                        fprintf(stderr, "are you insane?  %ld is a crazy count.\n", count);
                        return -1;
                }
        }
        
        if (argc > 3)
                size= atol(argv[3]);

        if (argc > 4)
                timeout = atol (argv[4]);
        
        LIBCFS_IOC_INIT (data);
        data.ioc_count   = count;
        data.ioc_nid     = nid;
        data.ioc_u32[0]  = size;
        data.ioc_u32[1]  = timeout;
        
        rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_PING_TEST, &data);
        if (rc) {
                fprintf(stderr, "failed to start pinger: %s\n",
                        strerror(errno));
                return -1;
        }
        return 0;
}

int jt_ptl_ping(int argc, char **argv)
{
        int                      rc;
        int                      timeout;
        lnet_process_id_t        id;
        lnet_process_id_t        ids[16];
        int                      maxids = sizeof(ids)/sizeof(ids[0]);
        struct libcfs_ioctl_data data;
        int                      i;

        if (argc < 2) {
                fprintf(stderr, "usage: %s nid [timeout (secs)] [pid]\n", argv[0]);
                return 0;
        }

        id.nid = libcfs_str2nid(argv[1]);
        if (id.nid == LNET_NID_ANY) {
                fprintf (stderr, "Can't parse nid \"%s\"\n", argv[1]);
                return -1;
        }

        if (argc > 2)
                timeout = 1000 * atol(argv[2]);
        else
                timeout = 1000;                 /* default 1 second timeout */

        if (argc > 3)
                id.pid = atol(argv[3]);
        else
                id.pid = LNET_PID_ANY;

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
        unsigned int             threshold;
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
        } else if (sscanf (argv[2], "%i", &threshold) != 1) {
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
        struct libcfs_ioctl_data data;
        lnet_nid_t               gateway_nid;
        unsigned int             hops = 1;
        char                    *end;
        int                      rc;
        
        if (argc < 2 || argc > 3)
        {
                fprintf (stderr, "usage: %s gateway [hopcount]\n", argv[0]);
                return (0);
        }

        if (!g_net_is_set(argv[0]))
                return (-1);

        gateway_nid = libcfs_str2nid(argv[1]);
        if (gateway_nid == LNET_NID_ANY) {
                fprintf (stderr, "Can't parse gateway NID \"%s\"\n", argv[1]);
                return (-1);
        }

        if (argc == 3) {
                hops = strtoul(argv[2], &end, 0);
                if (hops >= 256 || *end != 0) {
                        fprintf (stderr, "Can't parse hopcount \"%s\"\n", argv[2]);
                        return -1;
                }
        }
        
        LIBCFS_IOC_INIT(data);
        data.ioc_net = g_net;
        data.ioc_count = hops;
        data.ioc_nid = gateway_nid;

        rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_ADD_ROUTE, &data);
        if (rc != 0) {
                fprintf (stderr, "IOC_LIBCFS_ADD_ROUTE failed: %s\n", strerror (errno));
                return (-1);
        }
        
        return (0);
}

int
jt_ptl_del_route (int argc, char **argv)
{
        struct libcfs_ioctl_data data;
        lnet_nid_t               nid;
        int                      rc;
        
        if (argc != 2) {
                fprintf (stderr, "usage: %s gatewayNID\n", argv[0]);
                return (0);
        }

        if (!libcfs_str2anynid(&nid, argv[1])) {
                fprintf (stderr, "Can't parse gateway NID "
                         "\"%s\"\n", argv[1]);
                return -1;
        }

        LIBCFS_IOC_INIT(data);
        data.ioc_net = g_net_set ? g_net : LNET_NIDNET(LNET_NID_ANY);
        data.ioc_nid = nid;

        rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_DEL_ROUTE, &data);
        if (rc != 0) {
                fprintf (stderr, "IOC_LIBCFS_DEL_ROUTE (%s) failed: %s\n", 
                         libcfs_nid2str(nid), strerror (errno));
                return (-1);
        }
        
        return (0);
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
        struct libcfs_ioctl_data  data;
        int                       rc;
        int                       index;
        __u32                     net;
        lnet_nid_t                nid;
        unsigned int              hops;
        int                       alive;

        for (index = 0;;index++)
        {
                LIBCFS_IOC_INIT(data);
                data.ioc_count = index;
                
                rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_GET_ROUTE, &data);
                if (rc != 0)
                        break;

                net     = data.ioc_net;
                hops    = data.ioc_count;
                nid     = data.ioc_nid;
                alive   = data.ioc_flags;

                printf ("net %18s hops %u gw %32s %s\n", 
                        libcfs_net2str(net), hops,
                        libcfs_nid2str(nid), alive ? "up" : "down");
        }

        if (errno != ENOENT)
                fprintf(stderr, "Error getting routes: %s: check dmesg.\n",
                        strerror(errno));

        return (0);
}

static int
lwt_control(int enable, int clear)
{
        struct libcfs_ioctl_data data;
        int                      rc;

        LIBCFS_IOC_INIT(data);
        data.ioc_flags = (enable ? 1 : 0) | (clear ? 2 : 0);

        rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_LWT_CONTROL, &data);
        if (rc == 0)
                return (0);

        fprintf(stderr, "IOC_LIBCFS_LWT_CONTROL failed: %s\n",
                strerror(errno));
        return (-1);
}

static int
lwt_snapshot(cycles_t *now, int *ncpu, int *totalsize, 
             lwt_event_t *events, int size)
{
        struct libcfs_ioctl_data data;
        int                      rc;

        LIBCFS_IOC_INIT(data);
        data.ioc_pbuf1 = (char *)events;
        data.ioc_plen1 = size;

        rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_LWT_SNAPSHOT, &data);
        if (rc != 0) {
                fprintf(stderr, "IOC_LIBCFS_LWT_SNAPSHOT failed: %s\n",
                        strerror(errno));
                return (-1);
        }

        /* crappy overloads */
        if (data.ioc_u32[2] != sizeof(lwt_event_t) ||
            data.ioc_u32[3] != offsetof(lwt_event_t, lwte_where)) {
                fprintf(stderr,"kernel/user LWT event mismatch %d(%d),%d(%d)\n",
                        (int)data.ioc_u32[2], (int)sizeof(lwt_event_t),
                        (int)data.ioc_u32[3],
                        (int)offsetof(lwt_event_t, lwte_where));
                return (-1);
        }

        if (now != NULL)
                *now = data.ioc_u64[0];

        LASSERT (data.ioc_u32[0] != 0);
        if (ncpu != NULL)
                *ncpu = data.ioc_u32[0];

        LASSERT (data.ioc_u32[1] != 0);
        if (totalsize != NULL)
                *totalsize = data.ioc_u32[1];

        return (0);
}

static char *
lwt_get_string(char *kstr)
{
        char                     *ustr;
        struct libcfs_ioctl_data  data;
        int                       size;
        int                       rc;

        /* FIXME: this could maintain a symbol table since we expect to be
         * looking up the same strings all the time... */

        LIBCFS_IOC_INIT(data);
        data.ioc_pbuf1 = kstr;
        data.ioc_plen1 = 1;        /* non-zero just to fool portal_ioctl_is_invalid() */
        data.ioc_pbuf2 = NULL;
        data.ioc_plen2 = 0;

        rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_LWT_LOOKUP_STRING, &data);
        if (rc != 0) {
                fprintf(stderr, "IOC_LIBCFS_LWT_LOOKUP_STRING failed: %s\n",
                        strerror(errno));
                return (NULL);
        }

        size = data.ioc_count;
        ustr = (char *)malloc(size);
        if (ustr == NULL) {
                fprintf(stderr, "Can't allocate string storage of size %d\n",
                        size);
                return (NULL);
        }

        LIBCFS_IOC_INIT(data);
        data.ioc_pbuf1 = kstr;
        data.ioc_plen1 = 1;        /* non-zero just to fool portal_ioctl_is_invalid() */
        data.ioc_pbuf2 = ustr;
        data.ioc_plen2 = size;

        rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_LWT_LOOKUP_STRING, &data);
        if (rc != 0) {
                fprintf(stderr, "IOC_LIBCFS_LWT_LOOKUP_STRING failed: %s\n",
                        strerror(errno));
                return (NULL);
        }

        LASSERT(strlen(ustr) == size - 1);
        return (ustr);
}

static void
lwt_put_string(char *ustr)
{
        free(ustr);
}

static int
lwt_print(FILE *f, cycles_t t0, cycles_t tlast, double mhz, int cpu, lwt_event_t *e)
{
#ifndef __WORDSIZE
# error "__WORDSIZE not defined"
#elif __WORDSIZE == 32
# define XFMT "%#010lx"
#elif __WORDSIZE== 64
# define XFMT "%#018lx"
#else
# error "Unexpected __WORDSIZE"
#endif
        char           *where = lwt_get_string(e->lwte_where);

        if (where == NULL)
                return (-1);

        fprintf(f, XFMT" "XFMT" "XFMT" "XFMT": "XFMT" %2d %10.6f %10.2f %s\n",
                e->lwte_p1, e->lwte_p2, e->lwte_p3, e->lwte_p4,
                (long)e->lwte_task, cpu, (e->lwte_when - t0) / (mhz * 1000000.0),
                (t0 == e->lwte_when) ? 0.0 : (e->lwte_when - tlast) / mhz,
                where);

        lwt_put_string(where);

        return (0);
#undef XFMT
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

int
jt_ptl_lwt(int argc, char **argv)
{
        const int       lwt_max_cpus = 32;
        int             ncpus;
        int             totalspace;
        int             nevents_per_cpu;
        lwt_event_t    *events;
        lwt_event_t    *cpu_event[lwt_max_cpus + 1];
        lwt_event_t    *next_event[lwt_max_cpus];
        lwt_event_t    *first_event[lwt_max_cpus];
        int             cpu;
        lwt_event_t    *e;
        int             rc;
        int             i;
        double          mhz;
        cycles_t        t0;
        cycles_t        tlast;
        cycles_t        tnow;
        struct timeval  tvnow;
        int             printed_date = 0;
        int             nlines = 0;
        FILE           *f = stdout;

        if (argc < 2 ||
            (strcmp(argv[1], "start") &&
             strcmp(argv[1], "stop"))) {
                fprintf(stderr, 
                        "usage:  %s start\n"
                        "        %s stop [fname]\n", argv[0], argv[0]);
                return (-1);
        }
        
        if (!strcmp(argv[1], "start")) {
                /* disable */
                if (lwt_control(0, 0) != 0)
                        return (-1);

                /* clear */
                if (lwt_control(0, 1) != 0)
                        return (-1);

                /* enable */
                if (lwt_control(1, 0) != 0)
                        return (-1);

                return (0);
        }
                
        if (lwt_snapshot(NULL, &ncpus, &totalspace, NULL, 0) != 0)
                return (-1);

        if (ncpus > lwt_max_cpus) {
                fprintf(stderr, "Too many cpus: %d (%d)\n", 
                        ncpus, lwt_max_cpus);
                return (-1);
        }

        events = (lwt_event_t *)malloc(totalspace);
        if (events == NULL) {
                fprintf(stderr, "Can't allocate %d\n", totalspace);
                return (-1);
        }

        if (lwt_control(0, 0) != 0) {           /* disable */
                free(events);
                return (-1);
        }

        if (lwt_snapshot(&tnow, NULL, NULL, events, totalspace)) {
                free(events);
                return (-1);
        }

        /* we want this time to be sampled at snapshot time */
        gettimeofday(&tvnow, NULL);

        if (argc > 2) {
                f = fopen (argv[2], "w");
                if (f == NULL) {
                        fprintf(stderr, "Can't open %s for writing: %s\n", argv[2], strerror (errno));
                        free(events);
                        return (-1);
                }
        }

        mhz = get_cycles_per_usec();
        
        /* carve events into per-cpu slices */
        nevents_per_cpu = totalspace / (ncpus * sizeof(lwt_event_t));
        for (cpu = 0; cpu <= ncpus; cpu++)
                cpu_event[cpu] = &events[cpu * nevents_per_cpu];

        /* find the earliest event on each cpu */
        for (cpu = 0; cpu < ncpus; cpu++) {
                first_event[cpu] = NULL;

                for (e = cpu_event[cpu]; e < cpu_event[cpu + 1]; e++) {

                        if (e->lwte_where == NULL) /* not an event */
                                continue;

                        if (first_event[cpu] == NULL ||
                            first_event[cpu]->lwte_when > e->lwte_when)
                                first_event[cpu] = e;
                }

                next_event[cpu] = first_event[cpu];
        }

        t0 = tlast = 0;
        for (cpu = 0; cpu < ncpus; cpu++) {
                e = first_event[cpu];
                if (e == NULL)                  /* no events this cpu */
                        continue;
                
                if (e == cpu_event[cpu])
                        e = cpu_event[cpu + 1] - 1;
                else 
                        e = e - 1;
                
                /* If there's an event immediately before the first one, this
                 * cpu wrapped its event buffer */
                if (e->lwte_where == NULL)
                        continue;
         
                /* We should only start outputting events from the most recent
                 * first event in any wrapped cpu.  Events before this time on
                 * other cpus won't have any events from this CPU to interleave
                 * with. */
                if (t0 < first_event[cpu]->lwte_when)
                        t0 = first_event[cpu]->lwte_when;
        }

        for (;;) {
                /* find which cpu has the next event */
                cpu = -1;
                for (i = 0; i < ncpus; i++) {

                        if (next_event[i] == NULL) /* this cpu exhausted */
                                continue;

                        if (cpu < 0 ||
                            next_event[i]->lwte_when < next_event[cpu]->lwte_when)
                                cpu = i;
                }

                if (cpu < 0)                    /* all cpus exhausted */
                        break;

                if (t0 == 0) {
                        /* no wrapped cpus and this is he first ever event */
                        t0 = next_event[cpu]->lwte_when;
                }
                
                if (t0 <= next_event[cpu]->lwte_when) {
                        /* on or after the first event */
                        if (!printed_date) {
                                cycles_t du = (tnow - t0) / mhz;
                                time_t   then = tvnow.tv_sec - du/1000000;
                                
                                if (du % 1000000 > tvnow.tv_usec)
                                        then--;

                                fprintf(f, "%s", ctime(&then));
                                printed_date = 1;
                        }
                        
                        rc = lwt_print(f, t0, tlast, mhz, cpu, next_event[cpu]);
                        if (rc != 0)
                                break;

                        if (++nlines % 10000 == 0 && f != stdout) {
                                /* show some activity... */
                                printf(".");
                                fflush (stdout);
                        }
                }

                tlast = next_event[cpu]->lwte_when;
                
                next_event[cpu]++;
                if (next_event[cpu] == cpu_event[cpu + 1])
                        next_event[cpu] = cpu_event[cpu];

                if (next_event[cpu]->lwte_where == NULL ||
                    next_event[cpu] == first_event[cpu])
                        next_event[cpu] = NULL;
        }

        if (f != stdout) {
                printf("\n");
                fclose(f);
        }

        free(events);
        return (0);
}

int jt_ptl_memhog(int argc, char **argv)
{
        static int                gfp = 0;        /* sticky! */

        struct libcfs_ioctl_data  data;
        int                       rc;
        int                       count;
        char                     *end;
        
        if (argc < 2)  {
                fprintf(stderr, "usage: %s <npages> [<GFP flags>]\n", argv[0]);
                return 0;
        }

        count = strtol(argv[1], &end, 0);
        if (count < 0 || *end != 0) {
                fprintf(stderr, "Can't parse page count '%s'\n", argv[1]);
                return -1;
        }

        if (argc >= 3) {
                rc = strtol(argv[2], &end, 0);
                if (*end != 0) {
                        fprintf(stderr, "Can't parse gfp flags '%s'\n", argv[2]);
                        return -1;
                }
                gfp = rc;
        }
        
        LIBCFS_IOC_INIT(data);
        data.ioc_count = count;
        data.ioc_flags = gfp;
        rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_MEMHOG, &data);

        if (rc != 0) {
                fprintf(stderr, "memhog %d failed: %s\n", count, strerror(errno));
                return -1;
        }
        
        printf("memhog %d OK\n", count);
        return 0;
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


