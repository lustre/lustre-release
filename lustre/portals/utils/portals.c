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
#include "ioctl.h"
#include <sys/ioctl.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#include <endian.h>
#if CRAY_PORTALS
#ifdef REDSTORM
#define __QK__
#endif
#include <portals/ipmap.h>
#endif

#ifdef __CYGWIN__

#include <netinet/in.h>

#endif /* __CYGWIN__ */
 
#include <portals/api-support.h>
#include <portals/ptlctl.h>
#include <portals/list.h>
#include <portals/lib-types.h>
#include <portals/socknal.h>
#include "parser.h"

unsigned int portal_debug;
unsigned int portal_printk;

static unsigned int g_nal = 0;

typedef struct
{
        char *name;
        int   num;
} name2num_t;

static name2num_t nalnames[] = {
        {"any",         0},
#if !CRAY_PORTALS
        {"tcp",		SOCKNAL},
        {"elan",	QSWNAL},
        {"gm",	        GMNAL},
        {"openib",      OPENIBNAL},
        {"iib",         IIBNAL},
        {"lo",          LONAL},
        {"ra",          RANAL},
#else
        {"cray_kern_nal", CRAY_KERN_NAL},
        {"cray_user_nal", CRAY_USER_NAL},
        {"cray_qk_nal",   CRAY_QK_NAL},
#endif
        {NULL,		-1}
};

static cfg_record_cb_t g_record_cb;

/* Convert a string boolean to an int; "enable" -> 1 */
int ptl_parse_bool (int *b, char *str) {
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

/* Convert human readable size string to and int; "1k" -> 1000 */
int ptl_parse_size (int *sizep, char *str) {
        int size;
        char mod[32];

        switch (sscanf (str, "%d%1[gGmMkK]", &size, mod)) {
        default:
                return (-1);

        case 1:
                *sizep = size;
                return (0);

        case 2:
                switch (*mod) {
                case 'g':
                case 'G':
                        *sizep = size << 30;
                        return (0);

                case 'm':
                case 'M':
                        *sizep = size << 20;
                        return (0);

                case 'k':
                case 'K':
                        *sizep = size << 10;
                        return (0);

                default:
                        *sizep = size;
                        return (0);
                }
        }
}

int 
ptl_set_cfg_record_cb(cfg_record_cb_t cb)
{
        g_record_cb = cb;
        return 0;
}

int 
pcfg_ioctl(struct portals_cfg *pcfg) 
{
        int rc;

        if (pcfg->pcfg_nal ==0)
                pcfg->pcfg_nal    = g_nal;

        if (g_record_cb) {
                rc = g_record_cb(PORTALS_CFG_TYPE, sizeof(*pcfg), pcfg);
        } else {
                struct portal_ioctl_data data;
                PORTAL_IOC_INIT (data);
                data.ioc_pbuf1   = (char*)pcfg;
                data.ioc_plen1   = sizeof(*pcfg);
                /* XXX liblustre hack XXX */
                data.ioc_nal_cmd = pcfg->pcfg_command;
                data.ioc_nid = pcfg->pcfg_nid;

                rc = l_ioctl (PORTALS_DEV_ID, IOC_PORTAL_NAL_CMD, &data);
        }

        return (rc);
}



static name2num_t *
name2num_lookup_name (name2num_t *table, char *str)
{
        while (table->name != NULL)
                if (!strcmp (str, table->name))
                        return (table);
                else
                        table++;
        return (NULL);
}

static name2num_t *
name2num_lookup_num (name2num_t *table, int num)
{
        while (table->name != NULL)
                if (num == table->num)
                        return (table);
                else
                        table++;
        return (NULL);
}

int
ptl_name2nal (char *str)
{
        name2num_t *e = name2num_lookup_name (nalnames, str);

        return ((e == NULL) ? -1 : e->num);
}

static char *
nal2name (int nal)
{
        name2num_t *e = name2num_lookup_num (nalnames, nal);

        return ((e == NULL) ? "???" : e->name);
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
                        fprintf(stderr, "gethostbyname error: %s\n",
                                strerror(errno));
                        break;
                }
                return NULL;
        }
        return he;
}
#endif

int
ptl_parse_port (int *port, char *str)
{
        char      *end;
        
        *port = strtol (str, &end, 0);

        if (*end == 0 &&                        /* parsed whole string */
            *port > 0 && *port < 65536)         /* minimal sanity check */
                return (0);
        
        return (-1);
}

int
ptl_parse_time (time_t *t, char *str) 
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
ptl_parse_ipquad (__u32 *ipaddrp, char *str)
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
ptl_parse_ipaddr (__u32 *ipaddrp, char *str)
{
#ifdef HAVE_GETHOSTBYNAME
        struct hostent *he;
#endif

        if (!strcmp (str, "_all_")) 
        {
                *ipaddrp = 0;
                return (0);
        }

        if (ptl_parse_ipquad(ipaddrp, str) == 0)
                return (0);

#if HAVE_GETHOSTBYNAME        
        if ((('a' <= str[0] && str[0] <= 'z') ||
             ('A' <= str[0] && str[0] <= 'Z')) &&
             (he = ptl_gethostbyname (str)) != NULL)
        {
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
ptl_parse_nid (ptl_nid_t *nidp, char *str)
{
        __u32               ipaddr;
        char               *end;
        unsigned long long  ullval;
        
        if (!strcmp (str, "_all_")) {
                *nidp = PTL_NID_ANY;
                return (0);
        }

        if (ptl_parse_ipaddr (&ipaddr, str) == 0) {
#if !CRAY_PORTALS
                *nidp = (ptl_nid_t)ipaddr;
#else
                *nidp = (((ptl_nid_t)ipaddr & PNAL_HOSTID_MASK) << PNAL_VNODE_SHIFT);
#endif
                return (0);
        }

        ullval = strtoull(str, &end, 0);
        if (*end == 0) {
                /* parsed whole string */
                *nidp = (ptl_nid_t)ullval;
                return (0);
        }

        return (-1);
}

__u64 ptl_nid2u64(ptl_nid_t nid)
{
        switch (sizeof (nid)) {
        case 8:
                return (nid);
        case 4:
                return ((__u32)nid);
        default:
                fprintf(stderr, "Unexpected sizeof(ptl_nid_t) == %u\n", sizeof(nid));
                abort();
                /* notreached */
                return (-1);
        }
}

char *
ptl_nid2str (char *buffer, ptl_nid_t nid)
{
        __u64           nid64 = ptl_nid2u64(nid);
#ifdef HAVE_GETHOSTBYNAME
        struct hostent *he = 0;

        /* Don't try to resolve NIDs that are e.g. Elan host IDs.  Assume
         * TCP addresses in the 0.x.x.x subnet are not in use.  This can
         * happen on routers and slows things down a _lot_.  Bug 3442. */
        if (nid & 0xff000000) {
                __u32 addr = htonl((__u32)nid); /* back to NETWORK byte order */

                he = gethostbyaddr ((const char *)&addr, sizeof (addr), AF_INET);
        }

        if (he != NULL)
                sprintf(buffer, "%#x:%s", (int)(nid64 >> 32), he->h_name);
        else
#endif /* HAVE_GETHOSTBYNAME */
                sprintf(buffer, LPX64, nid64);

        return (buffer);
}

int g_nal_is_set () 
{
        if (g_nal == 0) {
                fprintf (stderr, "Error: you must run the 'network' command first.\n");
                return (0);
        }

        return (1);
}

int g_nal_is_compatible (char *cmd, ...)
{
        va_list       ap;
        int           nal;

        if (!g_nal_is_set ())
                return (0);

        va_start (ap, cmd);

        do {
                nal = va_arg (ap, int);
        } while (nal != 0 && nal != g_nal);
        
        va_end (ap);
        
        if (g_nal == nal)
                return (1);

        if (cmd != NULL) {
                /* Don't complain verbosely if we've not been passed a command
                 * name to complain about! */
                fprintf (stderr, "Command %s not compatible with nal %s\n",
                         cmd, nal2name (g_nal));
        }
        return (0);
}

int
sock_write (int cfd, void *buffer, int nob)
{
        while (nob > 0)
        {
                int rc = write (cfd, buffer, nob);

                if (rc < 0)
                {
                        if (errno == EINTR)
                                continue;
                        
                        return (rc);
                }

                if (rc == 0)
                {
                        fprintf (stderr, "Unexpected zero sock_write\n");
                        abort();
                }

                nob -= rc;
                buffer = (char *)buffer + nob;
        }
        
        return (0);
}

int
sock_read (int cfd, void *buffer, int nob)
{
        while (nob > 0)
        {
                int rc = read (cfd, buffer, nob);
                
                if (rc < 0)
                {
                        if (errno == EINTR)
                                continue;
                        
                        return (rc);
                }
                
                if (rc == 0)                    /* EOF */
                {
                        errno = ECONNABORTED;
                        return (-1);
                }
                
                nob -= rc;
                buffer = (char *)buffer + nob;
        }
        
        return (0);
}

int ptl_initialize(int argc, char **argv) 
{
        register_ioc_dev(PORTALS_DEV_ID, PORTALS_DEV_PATH);
        return 0;
}


int jt_ptl_network(int argc, char **argv)
{
        name2num_t *entry;
        int         nal;
        
        if (argc == 2 &&
            (nal = ptl_name2nal (argv[1])) >= 0) {
                g_nal = nal;
                return (0);
        }
                
        fprintf(stderr, "usage: %s \n", argv[0]);
        for (entry = nalnames; entry->name != NULL; entry++)
                fprintf (stderr, "%s%s", entry == nalnames ? "<" : "|", entry->name);
        fprintf(stderr, ">\n");
        return (-1);
}

int
jt_ptl_print_interfaces (int argc, char **argv)
{
        struct portals_cfg       pcfg;
        char                     buffer[3][64];
        int                      index;
        int                      rc;

        if (!g_nal_is_compatible (argv[0], SOCKNAL, 0))
                return -1;

        for (index = 0;;index++) {
                PCFG_INIT (pcfg, NAL_CMD_GET_INTERFACE);
                pcfg.pcfg_count = index;

                rc = pcfg_ioctl (&pcfg);
                if (rc != 0)
                        break;

                printf ("%s: (%s/%s) npeer %d nroute %d\n",
                        ptl_ipaddr_2_str(pcfg.pcfg_id, buffer[2], 1),
                        ptl_ipaddr_2_str(pcfg.pcfg_id, buffer[0], 0),
                        ptl_ipaddr_2_str(pcfg.pcfg_misc, buffer[1], 0),
                        pcfg.pcfg_fd, pcfg.pcfg_count);
        }

        if (index == 0)
                printf ("<no interfaces>\n");
        return 0;
}

int
jt_ptl_add_interface (int argc, char **argv)
{
        struct portals_cfg       pcfg;
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

        if (!g_nal_is_compatible(argv[0], SOCKNAL, 0))
                return -1;

        if (ptl_parse_ipaddr(&ipaddr, argv[1]) != 0) {
                fprintf (stderr, "Can't parse ip: %s\n", argv[1]);
                return -1;
        }

        if (argc > 2 ) {
                count = strtol(argv[2], &end, 0);
                if (count > 0 && count < 32 && *end == 0) {
                        netmask = 0;
                        for (i = count; i > 0; i--)
                                netmask = netmask|(1<<(32-i));
                } else if (ptl_parse_ipquad(&netmask, argv[2]) != 0) {
                        fprintf (stderr, "Can't parse netmask: %s\n", argv[2]);
                        return -1;
                }
        }

        PCFG_INIT(pcfg, NAL_CMD_ADD_INTERFACE);
        pcfg.pcfg_id     = ipaddr;
        pcfg.pcfg_misc   = netmask;

        rc = pcfg_ioctl (&pcfg);
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
        struct portals_cfg       pcfg;
        int                      rc;
        __u32                    ipaddr = 0;

        if (argc > 2) {
                fprintf (stderr, "usage: %s [ipaddr]\n", argv[0]);
                return 0;
        }

        if (!g_nal_is_compatible(argv[0], SOCKNAL, 0))
                return -1;

        if (argc == 2 &&
            ptl_parse_ipaddr(&ipaddr, argv[1]) != 0) {
                fprintf (stderr, "Can't parse ip: %s\n", argv[1]);
                return -1;
        }
        
        PCFG_INIT(pcfg, NAL_CMD_DEL_INTERFACE);
        pcfg.pcfg_id = ipaddr;

        rc = pcfg_ioctl (&pcfg);
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
        struct portals_cfg       pcfg;
        char                     buffer[2][64];
        int                      index;
        int                      rc;

        if (!g_nal_is_compatible (argv[0], SOCKNAL, OPENIBNAL, IIBNAL, RANAL, 0))
                return -1;

        for (index = 0;;index++) {
                PCFG_INIT (pcfg, NAL_CMD_GET_PEER);
                pcfg.pcfg_count   = index;

                rc = pcfg_ioctl (&pcfg);
                if (rc != 0)
                        break;

                if (g_nal_is_compatible(NULL, SOCKNAL, 0))
                        printf (LPX64"[%d]%s@%s:%d #%d\n",
                                pcfg.pcfg_nid, pcfg.pcfg_wait,
                                ptl_ipaddr_2_str (pcfg.pcfg_size, buffer[0], 1),
                                ptl_ipaddr_2_str (pcfg.pcfg_id, buffer[1], 1),
                                pcfg.pcfg_misc, pcfg.pcfg_count);
                else
                        printf (LPX64"[%d]\n",
                                pcfg.pcfg_nid, pcfg.pcfg_wait);
        }

        if (index == 0)
                printf ("<no peers>\n");
        return 0;
}

int 
jt_ptl_add_peer (int argc, char **argv)
{
        struct portals_cfg       pcfg;
        ptl_nid_t                nid;
        __u32                    ip = 0;
        int                      port = 0;
        int                      rc;

        if (!g_nal_is_compatible (argv[0], SOCKNAL, OPENIBNAL, IIBNAL, RANAL, 0))
                return -1;

        if (g_nal_is_compatible(NULL, SOCKNAL, RANAL, 0)) {
                if (argc != 4) {
                        fprintf (stderr, "usage(tcp): %s nid ipaddr port\n", 
                                 argv[0]);
                        return 0;
                }
        } else if (argc != 2) {
                fprintf (stderr, "usage(openib,iib): %s nid\n", argv[0]);
                return 0;
        }

        if (ptl_parse_nid (&nid, argv[1]) != 0 ||
                nid == PTL_NID_ANY) {
                fprintf (stderr, "Can't parse NID: %s\n", argv[1]);
                return -1;
        }

        if (g_nal_is_compatible (NULL, SOCKNAL, RANAL, 0)) {
                if (ptl_parse_ipaddr (&ip, argv[2]) != 0) {
                        fprintf (stderr, "Can't parse ip addr: %s\n", argv[2]);
                        return -1;
                }

                if (ptl_parse_port (&port, argv[3]) != 0) {
                        fprintf (stderr, "Can't parse port: %s\n", argv[3]);
                        return -1;
                }
        }

        PCFG_INIT(pcfg, NAL_CMD_ADD_PEER);
        pcfg.pcfg_nid     = nid;
        pcfg.pcfg_id      = ip;
        pcfg.pcfg_misc    = port;

        rc = pcfg_ioctl (&pcfg);
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
        struct portals_cfg       pcfg;
        ptl_nid_t                nid = PTL_NID_ANY;
        __u32                    ip = 0;
        int                      single_share = 0;
        int                      argidx;
        int                      rc;

        if (!g_nal_is_compatible (argv[0], SOCKNAL, OPENIBNAL, IIBNAL, RANAL, 0))
                return -1;

        if (g_nal_is_compatible(NULL, SOCKNAL, 0)) {
                if (argc > 4) {
                        fprintf (stderr, "usage: %s [nid] [ipaddr] [single_share]\n",
                                 argv[0]);
                        return 0;
                }
        } else if (argc > 3) {
                fprintf (stderr, "usage: %s [nid] [single_share]\n", argv[0]);
                return 0;
        }
                
        if (argc > 1 &&
            ptl_parse_nid (&nid, argv[1]) != 0) {
                fprintf (stderr, "Can't parse nid: %s\n", argv[1]);
                return -1;
        }

        argidx = 2;
        if (g_nal_is_compatible(NULL, SOCKNAL, 0)) {
                if (argc > argidx &&
                    ptl_parse_ipaddr (&ip, argv[argidx]) != 0) {
                        fprintf (stderr, "Can't parse ip addr: %s\n",
                                 argv[argidx]);
                        return -1;
                }
                argidx++;
        }
        
        if (argc > argidx) {
                if (!strcmp (argv[argidx], "single_share")) {
                        single_share = 1;
                } else {
                        fprintf (stderr, "Unrecognised arg %s'\n", argv[3]);
                        return -1;
                }
        }

        PCFG_INIT(pcfg, NAL_CMD_DEL_PEER);
        pcfg.pcfg_nid = nid;
        pcfg.pcfg_id = ip;
        pcfg.pcfg_flags = single_share;

        rc = pcfg_ioctl (&pcfg);
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
        struct portals_cfg       pcfg;
        char                     buffer[2][64];
        int                      index;
        int                      rc;

        if (!g_nal_is_compatible (argv[0], SOCKNAL, OPENIBNAL, IIBNAL, RANAL, 0))
                return -1;

        for (index = 0;;index++) {
                PCFG_INIT (pcfg,  NAL_CMD_GET_CONN);
                pcfg.pcfg_count   = index;
                
                rc = pcfg_ioctl (&pcfg);
                if (rc != 0)
                        break;

                if (g_nal_is_compatible (NULL, SOCKNAL, 0))
                        printf ("[%d]%s:"LPX64"@%s:%d:%s %d/%d %s\n",
                                pcfg.pcfg_gw_nal,       /* scheduler */
                                ptl_ipaddr_2_str (pcfg.pcfg_fd, buffer[0], 1), /* local IP addr */
                                pcfg.pcfg_nid, 
                                ptl_ipaddr_2_str (pcfg.pcfg_id, buffer[1], 1), /* remote IP addr */
                                pcfg.pcfg_misc,         /* remote port */
                                (pcfg.pcfg_flags == SOCKNAL_CONN_ANY) ? "A" :
                                (pcfg.pcfg_flags == SOCKNAL_CONN_CONTROL) ? "C" :
                                (pcfg.pcfg_flags == SOCKNAL_CONN_BULK_IN) ? "I" :
                                (pcfg.pcfg_flags == SOCKNAL_CONN_BULK_OUT) ? "O" : "?",
                                pcfg.pcfg_count,        /* tx buffer size */
                                pcfg.pcfg_size,         /* rx buffer size */
                                pcfg.pcfg_wait ? "nagle" : "nonagle");
                else
                        printf (LPX64"\n",
                                pcfg.pcfg_nid);
        }

        if (index == 0)
                printf ("<no connections>\n");
        return 0;
}

int jt_ptl_connect(int argc, char **argv)
{
#ifndef HAVE_CONNECT
        /* no connect() support */
        return -1;
#else /* HAVE_CONNECT */
        struct portals_cfg pcfg;
        struct sockaddr_in srvaddr;
        struct sockaddr_in locaddr;
        __u32 ipaddr;
        char *flag;
        int fd, rc;
        int type = SOCKNAL_CONN_ANY;
        int port, rport;
        int o;

        if (argc < 3) {
                fprintf(stderr, "usage: %s ip port [type]\n", argv[0]);
                return 0;
        }

        if (!g_nal_is_compatible (argv[0], SOCKNAL, 0))
                return -1;
        
        rc = ptl_parse_ipaddr (&ipaddr, argv[1]);
        if (rc != 0) {
                fprintf(stderr, "Can't parse hostname: %s\n", argv[1]);
                return -1;
        }

        if (ptl_parse_port (&port, argv[2]) != 0) {
                fprintf (stderr, "Can't parse port: %s\n", argv[2]);
                return -1;
        }

        if (argc > 3)
                for (flag = argv[3]; *flag != 0; flag++)
                        switch (*flag)
                        {
                        case 'I':
                                if (type != SOCKNAL_CONN_ANY) {
                                        fprintf(stderr, "Can't flag type twice\n");
                                        return -1;
                                }
                                type = SOCKNAL_CONN_BULK_IN;
                                break;

                        case 'O':
                                if (type != SOCKNAL_CONN_ANY) {
                                        fprintf(stderr, "Can't flag type twice\n");
                                        return -1;
                                }
                                type = SOCKNAL_CONN_BULK_OUT;
                                break;

                        case 'C':
                                if (type != SOCKNAL_CONN_ANY) {
                                        fprintf(stderr, "Can't flag type twice\n");
                                        return -1;
                                }
                                type = SOCKNAL_CONN_CONTROL;
                                break;
                                
                        default:
                                fprintf (stderr, "unrecognised flag '%c'\n",
                                         *flag);
                                return (-1);
                        }

        memset(&locaddr, 0, sizeof(locaddr)); 
        locaddr.sin_family = AF_INET; 
        locaddr.sin_addr.s_addr = INADDR_ANY;

        memset(&srvaddr, 0, sizeof(srvaddr));
        srvaddr.sin_family = AF_INET;
        srvaddr.sin_port = htons(port);
        srvaddr.sin_addr.s_addr = htonl(ipaddr);


        for (rport = IPPORT_RESERVED - 1; rport > IPPORT_RESERVED / 2; --rport) {
                fd = socket(PF_INET, SOCK_STREAM, 0); 
                if ( fd < 0 ) { 
                        fprintf(stderr, "socket() failed: %s\n", strerror(errno)); 
                        return -1; 
                }

                o = 1;
                rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, 
                                &o, sizeof(o));
                
                locaddr.sin_port = htons(rport);
                rc = bind(fd, (struct sockaddr *)&locaddr, sizeof(locaddr)); 
                if (rc == 0 || errno == EACCES) {
                        rc = connect(fd, (struct sockaddr *)&srvaddr, sizeof(srvaddr));
                        if (rc == 0) {
                                break;
                        } else if (errno != EADDRINUSE) {
                                fprintf(stderr, "Error connecting to host: %s\n", strerror(errno));
                                close(fd);
                                return -1;
                        }
                } else if (errno != EADDRINUSE) {
                        fprintf(stderr, "Error binding to port %d: %d: %s\n", port, errno, strerror(errno));
                        close(fd);
                        return -1;
                }
        }

        if (rport == IPPORT_RESERVED / 2) {
                fprintf(stderr,
                        "Warning: all privileged ports are in use.\n"); 
                return -1;
        }

        printf("Connected host: %s type: %s\n", 
               argv[1],
               (type == SOCKNAL_CONN_ANY) ? "A" :
               (type == SOCKNAL_CONN_CONTROL) ? "C" :
               (type == SOCKNAL_CONN_BULK_IN) ? "I" :
               (type == SOCKNAL_CONN_BULK_OUT) ? "O" : "?");

        PCFG_INIT(pcfg, NAL_CMD_REGISTER_PEER_FD);
        pcfg.pcfg_nal = g_nal;
        pcfg.pcfg_fd = fd;
        pcfg.pcfg_misc = type;
        
        rc = pcfg_ioctl(&pcfg);
        if (rc) {
                fprintf(stderr, "failed to register fd with portals: %s\n", 
                        strerror(errno));
                close (fd);
                return -1;
        }

        printf("Connection to %s registered with socknal\n", argv[1]);

        rc = close(fd);
        if (rc)
                fprintf(stderr, "close failed: %d\n", rc);

        return 0;
#endif /* HAVE_CONNECT */
}

int jt_ptl_disconnect(int argc, char **argv)
{
        struct portals_cfg       pcfg;
        ptl_nid_t                nid = PTL_NID_ANY;
        __u32                    ipaddr = 0;
        int                      rc;

        if (argc > 3) {
                fprintf(stderr, "usage: %s [nid] [ipaddr]\n", argv[0]);
                return 0;
        }

        if (!g_nal_is_compatible (NULL, SOCKNAL, OPENIBNAL, IIBNAL, RANAL, 0))
                return 0;

        if (argc >= 2 &&
            ptl_parse_nid (&nid, argv[1]) != 0) {
                fprintf (stderr, "Can't parse nid %s\n", argv[1]);
                return -1;
        }

        if (g_nal_is_compatible (NULL, SOCKNAL, 0) &&
            argc >= 3 &&
            ptl_parse_ipaddr (&ipaddr, argv[2]) != 0) {
                fprintf (stderr, "Can't parse ip addr %s\n", argv[2]);
                return -1;
        }

        PCFG_INIT(pcfg, NAL_CMD_CLOSE_CONNECTION);
        pcfg.pcfg_nid     = nid;
        pcfg.pcfg_id      = ipaddr;
        
        rc = pcfg_ioctl(&pcfg);
        if (rc) {
                fprintf(stderr, "failed to remove connection: %s\n",
                        strerror(errno));
                return -1;
        }

        return 0;
}

int jt_ptl_push_connection (int argc, char **argv)
{
        struct portals_cfg       pcfg;
        int                      rc;
        ptl_nid_t                nid = PTL_NID_ANY;
        __u32                    ipaddr = 0;

        if (argc > 3) {
                fprintf(stderr, "usage: %s [nid] [ip]\n", argv[0]);
                return 0;
        }

        if (!g_nal_is_compatible (argv[0], SOCKNAL, 0))
                return -1;
        
        if (argc > 1 &&
            ptl_parse_nid (&nid, argv[1]) != 0) {
                fprintf(stderr, "Can't parse nid: %s\n", argv[1]);
                return -1;
        }
                        
        if (argc > 2 &&
            ptl_parse_ipaddr (&ipaddr, argv[2]) != 0) {
                fprintf(stderr, "Can't parse ipaddr: %s\n", argv[2]);
        }

        PCFG_INIT(pcfg, NAL_CMD_PUSH_CONNECTION);
        pcfg.pcfg_nid     = nid;
        pcfg.pcfg_id      = ipaddr;
        
        rc = pcfg_ioctl(&pcfg);
        if (rc) {
                fprintf(stderr, "failed to push connection: %s\n",
                        strerror(errno));
                return -1;
        }

        return 0;
}

int 
jt_ptl_print_active_txs (int argc, char **argv)
{
        struct portals_cfg       pcfg;
        int                      index;
        int                      rc;

        if (!g_nal_is_compatible (argv[0], QSWNAL, 0))
                return -1;

        for (index = 0;;index++) {
                PCFG_INIT(pcfg, NAL_CMD_GET_TXDESC);
                pcfg.pcfg_count   = index;
        
                rc = pcfg_ioctl(&pcfg);
                if (rc != 0)
                        break;

                printf ("%p: %5s payload %6d bytes to "LPX64" via "LPX64" by pid %6d: %s, %s, state %d\n",
                        pcfg.pcfg_pbuf1,
                        pcfg.pcfg_count == PTL_MSG_ACK ? "ACK" :
                        pcfg.pcfg_count == PTL_MSG_PUT ? "PUT" :
                        pcfg.pcfg_count == PTL_MSG_GET ? "GET" :
                        pcfg.pcfg_count == PTL_MSG_REPLY ? "REPLY" : "<wierd message>",
                        pcfg.pcfg_size,
                        pcfg.pcfg_nid,
                        pcfg.pcfg_nid2,
                        pcfg.pcfg_misc,
                        (pcfg.pcfg_flags & 1) ? "delayed" : "immediate",
                        (pcfg.pcfg_flags & 2) ? "nblk"    : "normal",
                        pcfg.pcfg_flags >> 2);
        }

        if (index == 0)
                printf ("<no active descs>\n");
        return 0;
}

int jt_ptl_ping(int argc, char **argv)
{
        int       rc;
        ptl_nid_t nid;
        long      count   = 1;
        long      size    = 4;
        long      timeout = 1;
        struct portal_ioctl_data data;

        if (argc < 2) {
                fprintf(stderr, "usage: %s nid [count] [size] [timeout (secs)]\n", argv[0]);
                return 0;
        }

        if (!g_nal_is_set())
                return -1;

        if (ptl_parse_nid (&nid, argv[1]) != 0)
        {
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
        
        PORTAL_IOC_INIT (data);
        data.ioc_count   = count;
        data.ioc_size    = size;
        data.ioc_nid     = nid;
        data.ioc_nal     = g_nal;
        data.ioc_timeout = timeout;
        
        rc = l_ioctl(PORTALS_DEV_ID, IOC_PORTAL_PING, &data);
        if (rc) {
                fprintf(stderr, "failed to start pinger: %s\n",
                        strerror(errno));
                return -1;
        }
        return 0;
}

int jt_ptl_shownid(int argc, char **argv)
{
        struct portal_ioctl_data data;
        int                      rc;
        
        if (argc > 1) {
                fprintf(stderr, "usage: %s\n", argv[0]);
                return 0;
        }
        
        if (!g_nal_is_set())
                return -1;

        PORTAL_IOC_INIT (data);
        data.ioc_nal = g_nal;
        rc = l_ioctl(PORTALS_DEV_ID, IOC_PORTAL_GET_NID, &data);
        if (rc < 0)
                fprintf(stderr, "getting my NID failed: %s\n",
                        strerror (errno));
        else
                printf(LPX64"\n", data.ioc_nid);
        return 0;
}

int jt_ptl_mynid(int argc, char **argv)
{
        int rc;
        char hostname[1024];
        char *nidstr;
        struct portals_cfg pcfg;
        ptl_nid_t mynid;

        if (argc > 2) {
                fprintf(stderr, "usage: %s [NID]\n", argv[0]);
                fprintf(stderr, "NID defaults to the primary IP address of the machine.\n");
                return 0;
        }

        if (!g_nal_is_set())
                return -1;

        if (argc >= 2)
                nidstr = argv[1];
        else if (gethostname(hostname, sizeof(hostname)) != 0) {
                fprintf(stderr, "gethostname failed: %s\n",
                        strerror(errno));
                return -1;
        }
        else
                nidstr = hostname;

        rc = ptl_parse_nid (&mynid, nidstr);
        if (rc != 0) {
                fprintf (stderr, "Can't convert '%s' into a NID\n", nidstr);
                return -1;
        }
        
        PCFG_INIT(pcfg, NAL_CMD_REGISTER_MYNID);
        pcfg.pcfg_nid = mynid;

        rc = pcfg_ioctl(&pcfg);
        if (rc < 0)
                fprintf(stderr, "setting my NID failed: %s\n",
                       strerror(errno));
        else
                printf("registered my nid "LPX64" (%s)\n", 
                       ptl_nid2u64(mynid), hostname);
        return 0;
}

int
jt_ptl_fail_nid (int argc, char **argv)
{
        int                      rc;
        ptl_nid_t                nid;
        unsigned int             threshold;
        struct portal_ioctl_data data;

        if (argc < 2 || argc > 3)
        {
                fprintf (stderr, "usage: %s nid|\"_all_\" [count (0 == mend)]\n", argv[0]);
                return (0);
        }
        
        if (!g_nal_is_set())
                return (-1);

        if (!strcmp (argv[1], "_all_"))
                nid = PTL_NID_ANY;
        else if (ptl_parse_nid (&nid, argv[1]) != 0)
        {
                fprintf (stderr, "Can't parse nid \"%s\"\n", argv[1]);
                return (-1);
        }

        if (argc < 3)
                threshold = PTL_MD_THRESH_INF;
        else if (sscanf (argv[2], "%i", &threshold) != 1) {
                fprintf (stderr, "Can't parse count \"%s\"\n", argv[2]);
                return (-1);
        }
        
        PORTAL_IOC_INIT (data);
        data.ioc_nal = g_nal;
        data.ioc_nid = nid;
        data.ioc_count = threshold;
        
        rc = l_ioctl (PORTALS_DEV_ID, IOC_PORTAL_FAIL_NID, &data);
        if (rc < 0)
                fprintf (stderr, "IOC_PORTAL_FAIL_NID failed: %s\n",
                         strerror (errno));
        else
                printf ("%s %s\n", threshold == 0 ? "Unfailing" : "Failing", argv[1]);
        
        return (0);
}

int
jt_ptl_add_route (int argc, char **argv)
{
        struct portals_cfg       pcfg;
        ptl_nid_t                nid1;
        ptl_nid_t                nid2;
        ptl_nid_t                gateway_nid;
        int                      rc;
        
        if (argc < 3)
        {
                fprintf (stderr, "usage: %s gateway target [target]\n", argv[0]);
                return (0);
        }

        if (!g_nal_is_set())
                return (-1);

        if (ptl_parse_nid (&gateway_nid, argv[1]) != 0)
        {
                fprintf (stderr, "Can't parse gateway NID \"%s\"\n", argv[1]);
                return (-1);
        }

        if (ptl_parse_nid (&nid1, argv[2]) != 0)
        {
                fprintf (stderr, "Can't parse first target NID \"%s\"\n", argv[2]);
                return (-1);
        }

        if (argc < 4)
                nid2 = nid1;
        else if (ptl_parse_nid (&nid2, argv[3]) != 0)
        {
                fprintf (stderr, "Can't parse second target NID \"%s\"\n", argv[4]);
                return (-1);
        }

        PCFG_INIT(pcfg, NAL_CMD_ADD_ROUTE);
        pcfg.pcfg_nid = gateway_nid;
        pcfg.pcfg_nal = ROUTER;
        pcfg.pcfg_gw_nal = g_nal;
        pcfg.pcfg_nid2 = MIN (nid1, nid2);
        pcfg.pcfg_nid3 = MAX (nid1, nid2);

        rc = pcfg_ioctl(&pcfg);
        if (rc != 0) 
        {
                fprintf (stderr, "NAL_CMD_ADD_ROUTE failed: %s\n", strerror (errno));
                return (-1);
        }
        
        return (0);
}

int
jt_ptl_del_route (int argc, char **argv)
{
        struct portals_cfg       pcfg;
        ptl_nid_t                nid;
        ptl_nid_t                nid1 = PTL_NID_ANY;
        ptl_nid_t                nid2 = PTL_NID_ANY;
        int                      rc;
        
        if (argc < 2)
        {
                fprintf (stderr, "usage: %s targetNID\n", argv[0]);
                return (0);
        }

        if (!g_nal_is_set())
                return (-1);

        if (ptl_parse_nid (&nid, argv[1]) != 0)
        {
                fprintf (stderr, "Can't parse gateway NID \"%s\"\n", argv[1]);
                return (-1);
        }

        if (argc >= 3 &&
            ptl_parse_nid (&nid1, argv[2]) != 0)
        {
                fprintf (stderr, "Can't parse target NID \"%s\"\n", argv[2]);
                return (-1);
        }

        if (argc < 4) {
                nid2 = nid1;
        } else {
                if (ptl_parse_nid (&nid2, argv[3]) != 0) {
                        fprintf (stderr, "Can't parse target NID \"%s\"\n", argv[3]);
                        return (-1);
                }

                if (nid1 > nid2) {
                        ptl_nid_t tmp = nid1;
                        
                        nid1 = nid2;
                        nid2 = tmp;
                }
        }
        
        PCFG_INIT(pcfg, NAL_CMD_DEL_ROUTE);
        pcfg.pcfg_nal = ROUTER;
        pcfg.pcfg_gw_nal = g_nal;
        pcfg.pcfg_nid = nid;
        pcfg.pcfg_nid2 = nid1;
        pcfg.pcfg_nid3 = nid2;

        rc = pcfg_ioctl(&pcfg);
        if (rc != 0) 
        {
                fprintf (stderr, "NAL_CMD_DEL_ROUTE ("LPX64") failed: %s\n", 
                         ptl_nid2u64(nid), strerror (errno));
                return (-1);
        }
        
        return (0);
}

int
jt_ptl_notify_router (int argc, char **argv)
{
        struct portals_cfg       pcfg;
        int                      enable;
        ptl_nid_t                nid;
        int                      rc;
        struct timeval           now;
        time_t                   when;

        if (argc < 3)
        {
                fprintf (stderr, "usage: %s targetNID <up/down> [<time>]\n", 
                         argv[0]);
                return (0);
        }

        if (ptl_parse_nid (&nid, argv[1]) != 0)
        {
                fprintf (stderr, "Can't parse target NID \"%s\"\n", argv[1]);
                return (-1);
        }

        if (ptl_parse_bool (&enable, argv[2]) != 0) {
                fprintf (stderr, "Can't parse boolean %s\n", argv[2]);
                return (-1);
        }

        gettimeofday(&now, NULL);
        
        if (argc < 4) {
                when = now.tv_sec;
        } else if (ptl_parse_time (&when, argv[3]) != 0) {
                fprintf(stderr, "Can't parse time %s\n"
                        "Please specify either 'YYYY-MM-DD-HH:MM:SS'\n"
                        "or an absolute unix time in seconds\n", argv[3]);
                return (-1);
        } else if (when > now.tv_sec) {
                fprintf (stderr, "%s specifies a time in the future\n",
                         argv[3]);
                return (-1);
        }

        PCFG_INIT(pcfg, NAL_CMD_NOTIFY_ROUTER);
        pcfg.pcfg_nal = ROUTER;
        pcfg.pcfg_gw_nal = g_nal;
        pcfg.pcfg_nid = nid;
        pcfg.pcfg_flags = enable;
        /* Yeuch; 'cept I need a __u64 on 64 bit machines... */
        pcfg.pcfg_nid3 = (__u64)when;
        
        rc = pcfg_ioctl(&pcfg);
        if (rc != 0) 
        {
                fprintf (stderr, "NAL_CMD_NOTIFY_ROUTER ("LPX64") failed: %s\n",
                         ptl_nid2u64(nid), strerror (errno));
                return (-1);
        }
        
        return (0);
}

int
jt_ptl_print_routes (int argc, char **argv)
{
        char                      buffer[3][128];
        struct portals_cfg        pcfg;
        int                       rc;
        int                       index;
        int			  gateway_nal;
        ptl_nid_t		  gateway_nid;
        ptl_nid_t		  nid1;
        ptl_nid_t		  nid2;
        int                       alive;

        for (index = 0;;index++)
        {
                PCFG_INIT(pcfg, NAL_CMD_GET_ROUTE);
                pcfg.pcfg_nal = ROUTER;
                pcfg.pcfg_count = index;
                
                rc = pcfg_ioctl(&pcfg);
                if (rc != 0)
                        break;

                gateway_nal = pcfg.pcfg_gw_nal;
                gateway_nid = pcfg.pcfg_nid;
                nid1 = pcfg.pcfg_nid2;
                nid2 = pcfg.pcfg_nid3;
                alive = pcfg.pcfg_flags;

                printf ("%8s %18s : %s - %s, %s\n", 
                        nal2name (gateway_nal), 
                        ptl_nid2str (buffer[0], gateway_nid),
                        ptl_nid2str (buffer[1], nid1),
                        ptl_nid2str (buffer[2], nid2),
                        alive ? "up" : "down");
        }
        return (0);
}

static int
lwt_control(int enable, int clear)
{
        struct portal_ioctl_data data;
        int                      rc;

        PORTAL_IOC_INIT(data);
        data.ioc_flags = enable;
        data.ioc_misc = clear;

        rc = l_ioctl(PORTALS_DEV_ID, IOC_PORTAL_LWT_CONTROL, &data);
        if (rc == 0)
                return (0);

        fprintf(stderr, "IOC_PORTAL_LWT_CONTROL failed: %s\n",
                strerror(errno));
        return (-1);
}

static int
lwt_snapshot(cycles_t *now, int *ncpu, int *totalsize, 
             lwt_event_t *events, int size)
{
        struct portal_ioctl_data data;
        int                      rc;

        PORTAL_IOC_INIT(data);
        data.ioc_pbuf1 = (char *)events;
        data.ioc_plen1 = size;

        rc = l_ioctl(PORTALS_DEV_ID, IOC_PORTAL_LWT_SNAPSHOT, &data);
        if (rc != 0) {
                fprintf(stderr, "IOC_PORTAL_LWT_SNAPSHOT failed: %s\n",
                        strerror(errno));
                return (-1);
        }

        /* crappy overloads */
        if (data.ioc_nid2 != sizeof(lwt_event_t) ||
            data.ioc_nid3 != offsetof(lwt_event_t, lwte_where)) {
                fprintf(stderr,"kernel/user LWT event mismatch %d(%d),%d(%d)\n",
                        (int)data.ioc_nid2, sizeof(lwt_event_t),
                        (int)data.ioc_nid3,
                        (int)offsetof(lwt_event_t, lwte_where));
                return (-1);
        }

        LASSERT (data.ioc_count != 0);
        LASSERT (data.ioc_misc != 0);

        if (now != NULL)
                *now = data.ioc_nid;

        if (ncpu != NULL)
                *ncpu = data.ioc_count;

        if (totalsize != NULL)
                *totalsize = data.ioc_misc;

        return (0);
}

static char *
lwt_get_string(char *kstr)
{
        char                     *ustr;
        struct portal_ioctl_data  data;
        int                       size;
        int                       rc;

        /* FIXME: this could maintain a symbol table since we expect to be
         * looking up the same strings all the time... */

        PORTAL_IOC_INIT(data);
        data.ioc_pbuf1 = kstr;
        data.ioc_plen1 = 1;        /* non-zero just to fool portal_ioctl_is_invalid() */
        data.ioc_pbuf2 = NULL;
        data.ioc_plen2 = 0;

        rc = l_ioctl(PORTALS_DEV_ID, IOC_PORTAL_LWT_LOOKUP_STRING, &data);
        if (rc != 0) {
                fprintf(stderr, "IOC_PORTAL_LWT_LOOKUP_STRING failed: %s\n",
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

        PORTAL_IOC_INIT(data);
        data.ioc_pbuf1 = kstr;
        data.ioc_plen1 = 1;        /* non-zero just to fool portal_ioctl_is_invalid() */
        data.ioc_pbuf2 = ustr;
        data.ioc_plen2 = size;

        rc = l_ioctl(PORTALS_DEV_ID, IOC_PORTAL_LWT_LOOKUP_STRING, &data);
        if (rc != 0) {
                fprintf(stderr, "IOC_PORTAL_LWT_LOOKUP_STRING failed: %s\n",
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

        struct portal_ioctl_data  data;
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
        
        PORTAL_IOC_INIT(data);
        data.ioc_count = count;
        data.ioc_flags = gfp;
        rc = l_ioctl(PORTALS_DEV_ID, IOC_PORTAL_MEMHOG, &data);

        if (rc != 0) {
                fprintf(stderr, "memhog %d failed: %s\n", count, strerror(errno));
                return -1;
        }
        
        printf("memhog %d OK\n", count);
        return 0;
}

