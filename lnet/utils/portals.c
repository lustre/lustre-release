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
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#include <asm/byteorder.h>

#include <portals/api-support.h>
#include <portals/ptlctl.h>
#include <portals/list.h>
#include <portals/lib-types.h>
#include <portals/socknal.h>
#include "parser.h"

unsigned int portal_debug;
unsigned int portal_printk;
unsigned int portal_stack;
unsigned int portal_cerror;

static unsigned int g_nal = 0;

static int g_socket_txmem = 0;
static int g_socket_rxmem = 0;
static int g_socket_nonagle = 1;

typedef struct
{
        char *name;
        int   num;
} name2num_t;

static name2num_t nalnames[] = {
        {"any",         0},
        {"tcp",		SOCKNAL},
        {"toe",		TOENAL},
        {"elan",	QSWNAL},
        {"gm",	        GMNAL},
        {"ib",	        IBNAL},
        {"scimac",      SCIMACNAL},
        {NULL,		-1}
};

static cfg_record_cb_t g_record_cb;

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
ptl_parse_ipaddr (__u32 *ipaddrp, char *str)
{
        struct hostent *he;
        int             a;
        int             b;
        int             c;
        int             d;

        if (!strcmp (str, "_all_")) 
        {
                *ipaddrp = 0;
                return (0);
        }

        if (sscanf (str, "%d.%d.%d.%d", &a, &b, &c, &d) == 4 &&
            (a & ~0xff) == 0 && (b & ~0xff) == 0 &&
            (c & ~0xff) == 0 && (d & ~0xff) == 0)
        {
                *ipaddrp = (a<<24)|(b<<16)|(c<<8)|d;
                return (0);
        }
        
        if ((('a' <= str[0] && str[0] <= 'z') ||
             ('A' <= str[0] && str[0] <= 'Z')) &&
             (he = ptl_gethostbyname (str)) != NULL)
        {
                __u32 addr = *(__u32 *)he->h_addr;

                *ipaddrp = ntohl(addr);         /* HOST byte order */
                return (0);
        }

        return (-1);
}

char *
ptl_ipaddr_2_str (__u32 ipaddr, char *str)
{
        __u32           net_ip;
        struct hostent *he;
        
        net_ip = htonl (ipaddr);
        he = gethostbyaddr (&net_ip, sizeof (net_ip), AF_INET);
        if (he != NULL)
                return (he->h_name);
        
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
                *nidp = (ptl_nid_t)ipaddr;
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

char *
ptl_nid2str (char *buffer, ptl_nid_t nid)
{
        __u32           addr = htonl((__u32)nid); /* back to NETWORK byte order */
        struct hostent *he = gethostbyaddr ((const char *)&addr, sizeof (addr), AF_INET);

        if (he != NULL)
                strcpy (buffer, he->h_name);
        else
                sprintf (buffer, LPX64, nid);
        
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
jt_ptl_print_autoconnects (int argc, char **argv)
{
        struct portals_cfg        pcfg;
        char                     buffer[64];
        int                      index;
        int                      rc;

        if (!g_nal_is_compatible (argv[0], SOCKNAL, 0))
                return -1;

        for (index = 0;;index++) {
                PCFG_INIT (pcfg, NAL_CMD_GET_AUTOCONN);
                pcfg.pcfg_count   = index;

                rc = pcfg_ioctl (&pcfg);
                if (rc != 0)
                        break;

                printf (LPX64"@%s:%d #%d buffer %d "
                        "nonagle %s affinity %s eager %s share %d\n",
                        pcfg.pcfg_nid, ptl_ipaddr_2_str (pcfg.pcfg_id, buffer),
                        pcfg.pcfg_misc, pcfg.pcfg_count, pcfg.pcfg_size, 
                        (pcfg.pcfg_flags & 1) ? "on" : "off",
                        (pcfg.pcfg_flags & 2) ? "on" : "off",
                        (pcfg.pcfg_flags & 4) ? "on" : "off",
                        pcfg.pcfg_wait);
        }

        if (index == 0)
                printf ("<no autoconnect routes>\n");
        return 0;
}

int 
jt_ptl_add_autoconnect (int argc, char **argv)
{
        struct portals_cfg        pcfg;
        ptl_nid_t                nid;
        __u32                    ip;
        int                      port;
        int                      irq_affinity = 0;
        int                      share = 0;
        int                      eager = 0;
        int                      rc;

        if (argc < 4 || argc > 5) {
                fprintf (stderr, "usage: %s nid ipaddr port [ise]\n", argv[0]);
                return 0;
        }

        if (!g_nal_is_compatible (argv[0], SOCKNAL, 0))
                return -1;

        if (ptl_parse_nid (&nid, argv[1]) != 0 ||
                nid == PTL_NID_ANY) {
                fprintf (stderr, "Can't parse NID: %s\n", argv[1]);
                return -1;
        }

        if (ptl_parse_ipaddr (&ip, argv[2]) != 0) {
                fprintf (stderr, "Can't parse ip addr: %s\n", argv[2]);
                return -1;
        }

        if (ptl_parse_port (&port, argv[3]) != 0) {
                fprintf (stderr, "Can't parse port: %s\n", argv[3]);
                return -1;
        }

        if (argc > 4) {
                char *opts = argv[4];
                
                while (*opts != 0)
                        switch (*opts++) {
                        case 'i':
                                irq_affinity = 1;
                                break;
                        case 's':
                                share = 1;
                                break;
                        case 'e':
                                eager = 1;
                                break;
                        default:
                                fprintf (stderr, "Can't parse options: %s\n",
                                         argv[4]);
                                return -1;
                        }
        }

        PCFG_INIT(pcfg, NAL_CMD_ADD_AUTOCONN);
        pcfg.pcfg_nid     = nid;
        pcfg.pcfg_id      = ip;
        pcfg.pcfg_misc    = port;
        /* only passing one buffer size! */
        pcfg.pcfg_size    = MAX (g_socket_rxmem, g_socket_txmem);
        pcfg.pcfg_flags   = (g_socket_nonagle ? 0x01 : 0) |
                            (irq_affinity     ? 0x02 : 0) |
                            (share            ? 0x04 : 0) |
                            (eager            ? 0x08 : 0);

        rc = pcfg_ioctl (&pcfg);
        if (rc != 0) {
                fprintf (stderr, "failed to enable autoconnect: %s\n",
                         strerror (errno));
                return -1;
        }
        
        return 0;
}

int 
jt_ptl_del_autoconnect (int argc, char **argv)
{
        struct portals_cfg       pcfg;
        ptl_nid_t                nid = PTL_NID_ANY;
        __u32                    ip  = 0;
        int                      share = 0;
        int                      keep_conn = 0;
        int                      rc;

        if (argc > 4) {
                fprintf (stderr, "usage: %s [nid] [ipaddr] [sk]\n",
                         argv[0]);
                return 0;
        }

        if (!g_nal_is_compatible (argv[0], SOCKNAL, 0))
                return -1;

        if (argc > 1 &&
            ptl_parse_nid (&nid, argv[1]) != 0) {
                fprintf (stderr, "Can't parse nid: %s\n", argv[1]);
                return -1;
        }

        if (argc > 2 &&
            ptl_parse_ipaddr (&ip, argv[2]) != 0) {
                fprintf (stderr, "Can't parse ip addr: %s\n", argv[2]);
                return -1;
        }

        if (argc > 3) {
                char *opts = argv[3];
                
                while (*opts != 0)
                        switch (*opts++) {
                        case 's':
                                share = 1;
                                break;
                        case 'k':
                                keep_conn = 1;
                                break;
                        default:
                                fprintf (stderr, "Can't parse flags: %s\n", 
                                         argv[3]);
                                return -1;
                        }
        }

        PCFG_INIT(pcfg, NAL_CMD_DEL_AUTOCONN);
        pcfg.pcfg_nid     = nid;
        pcfg.pcfg_id      = ip;
        pcfg.pcfg_flags   = (share     ? 1 : 0) |
                           (keep_conn ? 2 : 0);

        rc = pcfg_ioctl (&pcfg);
        if (rc != 0) {
                fprintf (stderr, "failed to remove autoconnect route: %s\n",
                         strerror (errno));
                return -1;
        }
        
        return 0;
}

int 
jt_ptl_print_connections (int argc, char **argv)
{
        struct portals_cfg       pcfg;
        char                     buffer[64];
        int                      index;
        int                      rc;

        if (!g_nal_is_compatible (argv[0], SOCKNAL, 0))
                return -1;

        for (index = 0;;index++) {
                PCFG_INIT (pcfg,  NAL_CMD_GET_CONN);
                pcfg.pcfg_count   = index;
                
                rc = pcfg_ioctl (&pcfg);
                if (rc != 0)
                        break;

                printf (LPX64"@%s:%d:%s\n",
                        pcfg.pcfg_nid, 
                        ptl_ipaddr_2_str (pcfg.pcfg_id, buffer),
                        pcfg.pcfg_misc,
                        (pcfg.pcfg_flags == SOCKNAL_CONN_ANY) ? "A" :
                        (pcfg.pcfg_flags == SOCKNAL_CONN_CONTROL) ? "C" :
                        (pcfg.pcfg_flags == SOCKNAL_CONN_BULK_IN) ? "I" :
                        (pcfg.pcfg_flags == SOCKNAL_CONN_BULK_OUT) ? "O" : "?");
        }

        if (index == 0)
                printf ("<no connections>\n");
        return 0;
}

int jt_ptl_connect(int argc, char **argv)
{
        struct portals_cfg pcfg;
        struct sockaddr_in srvaddr;
        __u32 ipaddr;
        char *flag;
        int fd, rc;
        int nonagle = 0;
        int rxmem = 0;
        int txmem = 0;
        int bind_irq = 0;
        int type = SOCKNAL_CONN_ANY;
        int port;
        int o;
        int olen;

        if (argc < 3) {
                fprintf(stderr, "usage: %s ip port [xibctr]\n", argv[0]);
                return 0;
        }

        if (!g_nal_is_compatible (argv[0], SOCKNAL, TOENAL, 0))
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
                        case 'i':
                                bind_irq = 1;
                                break;
                                
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

        memset(&srvaddr, 0, sizeof(srvaddr));
        srvaddr.sin_family = AF_INET;
        srvaddr.sin_port = htons(port);
        srvaddr.sin_addr.s_addr = htonl(ipaddr);

        fd = socket(PF_INET, SOCK_STREAM, 0);
        if ( fd < 0 ) {
                fprintf(stderr, "socket() failed: %s\n", strerror(errno));
                return -1;
        }

        if (g_socket_nonagle)
        {
                o = 1;
                if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &o, sizeof (o)) != 0) { 
                        fprintf(stderr, "cannot disable nagle: %s\n", strerror(errno));
                        return (-1);
                }
        }

        if (g_socket_rxmem != 0) {
                o = g_socket_rxmem;
                if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &o, sizeof (o)) != 0) { 
                        fprintf(stderr, "cannot set receive buffer size: %s\n", strerror(errno));
                        return (-1);
                }
        }

        if (g_socket_txmem != 0) {
                o = g_socket_txmem;
                if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &o, sizeof (o)) != 0) { 
                        fprintf(stderr, "cannot set send buffer size: %s\n", strerror(errno));
                        return (-1);
                }
        }

        rc = connect(fd, (struct sockaddr *)&srvaddr, sizeof(srvaddr));
        if ( rc == -1 ) { 
                fprintf(stderr, "connect() failed: %s\n", strerror(errno));
                return -1;
        }

        olen = sizeof (txmem);
        if (getsockopt (fd, SOL_SOCKET, SO_SNDBUF, &txmem, &olen) != 0)
                fprintf (stderr, "Can't get send buffer size: %s\n", strerror (errno));
        olen = sizeof (rxmem);
        if (getsockopt (fd, SOL_SOCKET, SO_RCVBUF, &rxmem, &olen) != 0)
                fprintf (stderr, "Can't get receive buffer size: %s\n", strerror (errno));
        olen = sizeof (nonagle);
        if (getsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &nonagle, &olen) != 0)
                fprintf (stderr, "Can't get nagle: %s\n", strerror (errno));

        printf("Connected host: %s snd: %d rcv: %d nagle: %s type: %s\n", 
               argv[1], txmem, rxmem, nonagle ? "Disabled" : "Enabled",
               (type == SOCKNAL_CONN_ANY) ? "A" :
               (type == SOCKNAL_CONN_CONTROL) ? "C" :
               (type == SOCKNAL_CONN_BULK_IN) ? "I" :
               (type == SOCKNAL_CONN_BULK_OUT) ? "O" : "?");

        PCFG_INIT(pcfg, NAL_CMD_REGISTER_PEER_FD);
        pcfg.pcfg_nal = g_nal;
        pcfg.pcfg_fd = fd;
        pcfg.pcfg_flags = bind_irq;
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
}

int jt_ptl_disconnect(int argc, char **argv)
{
        struct portals_cfg        pcfg;
        ptl_nid_t                nid = PTL_NID_ANY;
        __u32                    ipaddr = 0;
        int                      rc;

        if (argc > 3) {
                fprintf(stderr, "usage: %s [nid] [ipaddr]\n", argv[0]);
                return 0;
        }

        if (!g_nal_is_compatible (NULL, SOCKNAL, TOENAL, 0))
                return 0;

        if (argc >= 2 &&
            ptl_parse_nid (&nid, argv[1]) != 0) {
                fprintf (stderr, "Can't parse nid %s\n", argv[1]);
                return -1;
        }

        if (argc >= 3 &&
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
        struct portals_cfg        pcfg;
        int                      rc;
        ptl_nid_t                nid = PTL_NID_ANY;
        __u32                    ipaddr = 0;

        if (argc > 3) {
                fprintf(stderr, "usage: %s [nid] [ip]\n", argv[0]);
                return 0;
        }

        if (!g_nal_is_compatible (argv[0], SOCKNAL, TOENAL, 0))
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
        struct portals_cfg        pcfg;
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
                printf("registered my nid "LPX64" (%s)\n", mynid, hostname);
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
jt_ptl_rxmem (int argc, char **argv)
{
        int   size;
        
        if (argc > 1)
        {
                if (Parser_size (&size, argv[1]) != 0 || size < 0)
                {
                        fprintf (stderr, "Can't parse size %s\n", argv[1]);
                        return (0);
                }

                g_socket_rxmem = size;
        }
        printf ("Socket rmem = %d\n", g_socket_rxmem);        
        return (0);
}

int
jt_ptl_txmem (int argc, char **argv)
{
        int   size;
        
        if (argc > 1)
        {
                if (Parser_size (&size, argv[1]) != 0 || size < 0)
                {
                        fprintf (stderr, "Can't parse size %s\n", argv[1]);
                        return (0);
                }
                g_socket_txmem = size;
        }
        printf ("Socket txmem = %d\n", g_socket_txmem);
        return (0);
}

int
jt_ptl_nagle (int argc, char **argv)
{
        int enable;

        if (argc > 1)
        {
                if (Parser_bool (&enable, argv[1]) != 0)
                {
                        fprintf (stderr, "Can't parse boolean %s\n", argv[1]);
                        return (-1);
                }
                g_socket_nonagle = !enable;
        }
        printf ("Nagle %s\n", g_socket_nonagle ? "disabled" : "enabled");
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
                fprintf (stderr, "NAL_CMD_DEL_ROUTE ("LPX64") failed: %s\n", nid, strerror (errno));
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

        if (Parser_bool (&enable, argv[2]) != 0) {
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
                         nid, strerror (errno));
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
        char            whenstr[32];
        char           *where = lwt_get_string(e->lwte_where);

        if (where == NULL)
                return (-1);

        sprintf(whenstr, LPD64, e->lwte_when - t0);

        fprintf(f, "%#010lx %#010lx %#010lx %#010lx: %#010lx %1d %10.6f %10.2f %s\n",
                e->lwte_p1, e->lwte_p2, e->lwte_p3, e->lwte_p4,
                (long)e->lwte_task, cpu, (e->lwte_when - t0) / (mhz * 1000000.0),
                (t0 == e->lwte_when) ? 0.0 : (e->lwte_when - tlast) / mhz,
                where);

        lwt_put_string(where);

        return (0);
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
        int             ncpus;
        int             totalspace;
        int             nevents_per_cpu;
        lwt_event_t    *events;
        lwt_event_t    *cpu_event[LWT_MAX_CPUS + 1];
        lwt_event_t    *next_event[LWT_MAX_CPUS];
        lwt_event_t    *first_event[LWT_MAX_CPUS];
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

        if (ncpus > LWT_MAX_CPUS) {
                fprintf(stderr, "Too many cpus: %d (%d)\n", 
                        ncpus, LWT_MAX_CPUS);
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
                }

                tlast = next_event[cpu]->lwte_when;
                
                next_event[cpu]++;
                if (next_event[cpu] == cpu_event[cpu + 1])
                        next_event[cpu] = cpu_event[cpu];

                if (next_event[cpu]->lwte_where == NULL ||
                    next_event[cpu] == first_event[cpu])
                        next_event[cpu] = NULL;
        }

        if (f != stdout)
                fclose(f);

        free(events);
        return (0);
}

int jt_ptl_memhog(int argc, char **argv)
{
        struct portal_ioctl_data  data;
        int                       rc;
        int                       count;
        char                     *end;
        
        if (argc != 2)  {
                fprintf(stderr, "usage: %s <npages>\n", argv[0]);
                return 0;
        }

        count = strtol(argv[1], &end, 0);
        if (count < 0 || *end != 0) {
                fprintf(stderr, "Can't parse page count '%s'\n", argv[1]);
                return -1;
        }

        PORTAL_IOC_INIT(data);
        data.ioc_count = count;
        rc = l_ioctl(PORTALS_DEV_ID, IOC_PORTAL_MEMHOG, &data);

        if (rc != 0) {
                fprintf(stderr, "memhog %d failed: %s\n", count, strerror(errno));
                return -1;
        }
        
        printf("memhog %d OK\n", count);
        return 0;
}

