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

#ifdef __CYGWIN__

#include <netinet/in.h>

#warning assuming little endian

#define __cpu_to_le64(x) ((__u64)(x))
#define __le64_to_cpu(x) ((__u64)(x))
#define __cpu_to_le32(x) ((__u32)(x))
#define __le32_to_cpu(x) ((__u32)(x))
#define __cpu_to_le16(x) ((__u16)(x))
#define __le16_to_cpu(x) ((__u16)(x))

#endif /* __CYGWIN__ */
 
#include <portals/api-support.h>
#include <portals/ptlctl.h>
#include <portals/list.h>
#include <portals/lib-types.h>
#include "parser.h"

unsigned int portal_debug;
unsigned int portal_printk;
unsigned int portal_stack;


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
        {"tcp",		SOCKNAL},
        {"toe",		TOENAL},
        {"elan",	QSWNAL},
        {"gm",	        GMNAL},
        {"scimac",      SCIMACNAL},
        {NULL,		-1}
};

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

        return ((e == NULL) ? 0 : e->num);
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
        __u32 ipaddr;
        long  lval;
        
        if (!strcmp (str, "_all_")) {
                *nidp = PTL_NID_ANY;
                return (0);
        }

        if (ptl_parse_ipaddr (&ipaddr, str) == 0) {
                *nidp = (ptl_nid_t)ipaddr;
                return (0);
        }

        if (sscanf (str, "%li", &lval) == 1)
        {
                *nidp = (ptl_nid_t)lval;
                return (0);
        }

        if (sscanf (str, "%lx", &lval) == 1)
        {
                *nidp = (ptl_nid_t)lval;
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
                sprintf (buffer, "0x"LPX64, nid);
        
        return (buffer);
}

int g_nal_is_compatible (char *cmd, ...)
{
        va_list       ap;
        int           nal;
        
        if (g_nal == 0) {
                fprintf (stderr, "Error: you must run the 'network' command first.\n");
                return (0);
        }
        
        va_start (ap, cmd);

        do {
                nal = va_arg (ap, int);
        } while (nal != 0 && nal != g_nal);
        
        va_end (ap);
        
        if (g_nal == nal)
                return (1);
        
        fprintf (stderr, "Command %s not compatible with nal %s\n",
                 cmd, nal2name (g_nal));
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
            (nal = ptl_name2nal (argv[1])) != 0) {
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
        struct portal_ioctl_data data;
        char                     buffer[64];
        int                      index;
        int                      rc;

        if (!g_nal_is_compatible (argv[0], SOCKNAL, 0))
                return -1;

        for (index = 0;;index++) {
                PORTAL_IOC_INIT (data);
                data.ioc_nal     = g_nal;
                data.ioc_nal_cmd = NAL_CMD_GET_AUTOCONN;
                data.ioc_count   = index;
                
                rc = l_ioctl (PORTALS_DEV_ID, IOC_PORTAL_NAL_CMD, &data);
                if (rc != 0)
                        break;

                printf (LPX64"@%s:%d #%d buffer %d nonagle %s xchg %s affinity %s share %d\n",
                        data.ioc_nid, ptl_ipaddr_2_str (data.ioc_id, buffer),
                        data.ioc_misc, data.ioc_count, data.ioc_size, 
                        (data.ioc_flags & 1) ? "on" : "off",
                        (data.ioc_flags & 2) ? "on" : "off",
                        (data.ioc_flags & 4) ? "on" : "off",
                        data.ioc_wait);
        }

        if (index == 0)
                printf ("<no autoconnect routes>\n");
        return 0;
}

int 
jt_ptl_add_autoconnect (int argc, char **argv)
{
        struct portal_ioctl_data data;
        ptl_nid_t                nid;
        __u32                    ip;
        int                      port;
        int                      xchange_nids = 0;
        int                      irq_affinity = 0;
        int                      share = 0;
        int                      rc;

        if (argc < 4 || argc > 5) {
                fprintf (stderr, "usage: %s nid ipaddr port [ixs]\n", argv[0]);
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

        port = atol (argv[3]);
        
        if (argc > 4) {
                char *opts = argv[4];
                
                while (*opts != 0)
                        switch (*opts++) {
                        case 'x':
                                xchange_nids = 1;
                                break;
                        case 'i':
                                irq_affinity = 1;
                                break;
                        case 's':
                                share = 1;
                                break;
                        default:
                                fprintf (stderr, "Can't parse options: %s\n",
                                         argv[4]);
                                return -1;
                        }
        }

        PORTAL_IOC_INIT (data);
        data.ioc_nal     = g_nal;
        data.ioc_nal_cmd = NAL_CMD_ADD_AUTOCONN;
        data.ioc_nid     = nid;
        data.ioc_id      = ip;
        data.ioc_misc    = port;
        /* only passing one buffer size! */
        data.ioc_size    = MAX (g_socket_rxmem, g_socket_txmem);
        data.ioc_flags   = (g_socket_nonagle ? 1 : 0) |
                           (xchange_nids     ? 2 : 0) |
                           (irq_affinity     ? 4 : 0) |
                           (share            ? 8 : 0);

        rc = l_ioctl (PORTALS_DEV_ID, IOC_PORTAL_NAL_CMD, &data);
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
        struct portal_ioctl_data data;
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

        PORTAL_IOC_INIT (data);
        data.ioc_nal     = g_nal;
        data.ioc_nal_cmd = NAL_CMD_DEL_AUTOCONN;
        data.ioc_nid     = nid;
        data.ioc_id      = ip;
        data.ioc_flags   = (share     ? 1 : 0) |
                           (keep_conn ? 2 : 0);
        
        rc = l_ioctl (PORTALS_DEV_ID, IOC_PORTAL_NAL_CMD, &data);
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
        struct portal_ioctl_data data;
        char                     buffer[64];
        int                      index;
        int                      rc;

        if (!g_nal_is_compatible (argv[0], SOCKNAL, 0))
                return -1;

        for (index = 0;;index++) {
                PORTAL_IOC_INIT (data);
                data.ioc_nal     = g_nal;
                data.ioc_nal_cmd = NAL_CMD_GET_CONN;
                data.ioc_count   = index;
                
                rc = l_ioctl (PORTALS_DEV_ID, IOC_PORTAL_NAL_CMD, &data);
                if (rc != 0)
                        break;

                printf (LPD64"@%s:%d\n",
                        data.ioc_nid, 
                        ptl_ipaddr_2_str (data.ioc_id, buffer),
                        data.ioc_misc);
        }

        if (index == 0)
                printf ("<no connections>\n");
        return 0;
}

int
exchange_nids (int cfd, ptl_nid_t my_nid, ptl_nid_t *peer_nid)
{
        int                      rc;
        ptl_hdr_t                hdr;
        ptl_magicversion_t      *hmv = (ptl_magicversion_t *)&hdr.dest_nid;

        LASSERT (sizeof (*hmv) == sizeof (hdr.dest_nid));

        memset (&hdr, 0, sizeof (hdr));
        
        hmv->magic          = __cpu_to_le32 (PORTALS_PROTO_MAGIC);
        hmv->version_major  = __cpu_to_le16 (PORTALS_PROTO_VERSION_MAJOR);
        hmv->version_minor  = __cpu_to_le16 (PORTALS_PROTO_VERSION_MINOR);

        hdr.src_nid = __cpu_to_le64 (my_nid);
        hdr.type = __cpu_to_le32 (PTL_MSG_HELLO);
        
        /* Assume there's sufficient socket buffering for a portals HELLO header */
        rc = sock_write (cfd, &hdr, sizeof (hdr));
        if (rc != 0) {
                perror ("Can't send initial HELLO");
                return (-1);
        }

        /* First few bytes down the wire are the portals protocol magic and
         * version, no matter what protocol version we're running. */

        rc = sock_read (cfd, hmv, sizeof (*hmv));
        if (rc != 0) {
                perror ("Can't read from peer");
                return (-1);
        }

        if (hmv->magic != __cpu_to_le32 (PORTALS_PROTO_MAGIC)) {
                fprintf (stderr, "Bad magic %#08x (%#08x expected)\n", 
                         __le32_to_cpu (hmv->magic), PORTALS_PROTO_MAGIC);
                return (-1);
        }

        if (hmv->version_major != __cpu_to_le16 (PORTALS_PROTO_VERSION_MAJOR) ||
            hmv->version_minor != __cpu_to_le16 (PORTALS_PROTO_VERSION_MINOR)) {
                fprintf (stderr, "Incompatible protocol version %d.%d (%d.%d expected)\n",
                         __le16_to_cpu (hmv->version_major),
                         __le16_to_cpu (hmv->version_minor),
                         PORTALS_PROTO_VERSION_MAJOR,
                         PORTALS_PROTO_VERSION_MINOR);
        }

        /* version 0 sends magic/version as the dest_nid of a 'hello' header,
         * so read the rest of it in now... */
        LASSERT (PORTALS_PROTO_VERSION_MAJOR == 0);
        rc = sock_read (cfd, hmv + 1, sizeof (hdr) - sizeof (*hmv));
        if (rc != 0) {
                perror ("Can't read rest of HELLO hdr");
                return (-1);
        }

        /* ...and check we got what we expected */
        if (hdr.type != __cpu_to_le32 (PTL_MSG_HELLO) ||
            PTL_HDR_LENGTH (&hdr) != __cpu_to_le32 (0)) {
                fprintf (stderr, "Expecting a HELLO hdr with 0 payload,"
                         " but got type %d with %d payload\n",
                         __le32_to_cpu (hdr.type),
                         __le32_to_cpu (PTL_HDR_LENGTH (&hdr)));
                return (-1);
        }
        
        *peer_nid = __le64_to_cpu (hdr.src_nid);
        return (0);
}

int jt_ptl_connect(int argc, char **argv)
{
        ptl_nid_t peer_nid;
        struct portal_ioctl_data data;
        struct sockaddr_in srvaddr;
        __u32 ipaddr;
        char *flag;
        int fd, rc;
        int nonagle = 0;
        int rxmem = 0;
        int txmem = 0;
        int bind_irq = 0;
        int xchange_nids = 0;
        int port;
        int o;
        int olen;

        if (argc < 3) {
                fprintf(stderr, "usage: %s ip port [xi]\n", argv[0]);
                return 0;
        }

        if (!g_nal_is_compatible (argv[0], SOCKNAL, TOENAL, 0))
                return -1;
        
        rc = ptl_parse_ipaddr (&ipaddr, argv[1]);
        if (rc != 0) {
                fprintf(stderr, "Can't parse hostname: %s\n", argv[1]);
                return -1;
        }

        port = atol(argv[2]);
        if (argc > 3)
                for (flag = argv[3]; *flag != 0; flag++)
                        switch (*flag)
                        {
                        case 'i':
                                bind_irq = 1;
                                break;
                                
                        case 'x':
                                xchange_nids = 1;
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

        if (!xchange_nids) 
                peer_nid = ipaddr;
        else {
                PORTAL_IOC_INIT (data);
                data.ioc_nal = g_nal;
                rc = l_ioctl(PORTALS_DEV_ID, IOC_PORTAL_GET_NID, &data);
                if (rc != 0) {
                        fprintf (stderr, "failed to get my nid: %s\n",
                                 strerror (errno));
                        close (fd);
                        return (-1);
                }

                rc = exchange_nids (fd, data.ioc_nid, &peer_nid);
                if (rc != 0) {
                        close (fd);
                        return (-1);
                }
        } 
        printf("Connected host: %s NID "LPX64" snd: %d rcv: %d nagle: %s\n", argv[1],
               peer_nid, txmem, rxmem, nonagle ? "Disabled" : "Enabled");

        PORTAL_IOC_INIT(data);
        data.ioc_fd = fd;
        data.ioc_nal = g_nal;
        data.ioc_nal_cmd = NAL_CMD_REGISTER_PEER_FD;
        data.ioc_nid = peer_nid;
        data.ioc_flags = bind_irq;

        rc = l_ioctl(PORTALS_DEV_ID, IOC_PORTAL_NAL_CMD, &data);
        if (rc) {
                fprintf(stderr, "failed to register fd with portals: %s\n", 
                        strerror(errno));
                close (fd);
                return -1;
        }

        printf("Connection to "LPX64" registered with socknal\n", peer_nid);

        rc = close(fd);
        if (rc)
                fprintf(stderr, "close failed: %d\n", rc);

        return 0;
}

int jt_ptl_disconnect(int argc, char **argv)
{
        struct portal_ioctl_data data;
        ptl_nid_t                nid = PTL_NID_ANY;
        __u32                    ipaddr = 0;
        int                      rc;

        if (argc > 3) {
                fprintf(stderr, "usage: %s [nid] [ipaddr]\n", argv[0]);
                return 0;
        }

        if (!g_nal_is_compatible (argv[0], SOCKNAL, TOENAL, 0))
                return -1;

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

        PORTAL_IOC_INIT(data);
        data.ioc_nal     = g_nal;
        data.ioc_nal_cmd = NAL_CMD_CLOSE_CONNECTION;
        data.ioc_nid     = nid;
        data.ioc_id      = ipaddr;
        
        rc = l_ioctl(PORTALS_DEV_ID, IOC_PORTAL_NAL_CMD, &data);
        if (rc) {
                fprintf(stderr, "failed to remove connection: %s\n",
                        strerror(errno));
                return -1;
        }

        return 0;
}

int jt_ptl_push_connection (int argc, char **argv)
{
        struct portal_ioctl_data data;
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

        PORTAL_IOC_INIT(data);
        data.ioc_nal     = g_nal;
        data.ioc_nal_cmd = NAL_CMD_PUSH_CONNECTION;
        data.ioc_nid     = nid;
        data.ioc_id      = ipaddr;

        rc = l_ioctl(PORTALS_DEV_ID, IOC_PORTAL_NAL_CMD, &data);
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
        struct portal_ioctl_data data;
        int                      index;
        int                      rc;

        if (!g_nal_is_compatible (argv[0], QSWNAL, 0))
                return -1;

        for (index = 0;;index++) {
                PORTAL_IOC_INIT (data);
                data.ioc_nal     = g_nal;
                data.ioc_nal_cmd = NAL_CMD_GET_TXDESC;
                data.ioc_count   = index;
                
                rc = l_ioctl (PORTALS_DEV_ID, IOC_PORTAL_NAL_CMD, &data);
                if (rc != 0)
                        break;

                printf ("%p: %5s payload %6d bytes to "LPX64" via "LPX64" by pid %6d: %s, %s, state %d\n",
                        data.ioc_pbuf1,
                        data.ioc_count == PTL_MSG_ACK ? "ACK" :
                        data.ioc_count == PTL_MSG_PUT ? "PUT" :
                        data.ioc_count == PTL_MSG_GET ? "GET" :
                        data.ioc_count == PTL_MSG_REPLY ? "REPLY" : "<wierd message>",
                        data.ioc_size,
                        data.ioc_nid,
                        data.ioc_nid2,
                        data.ioc_misc,
                        (data.ioc_flags & 1) ? "delayed" : "immediate",
                        (data.ioc_flags & 2) ? "nblk"    : "normal",
                        data.ioc_flags >> 2);
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

        if (g_nal == 0) {
                fprintf(stderr, "Error: you must run the 'network' command "
                        "first.\n");
                return -1;
        }

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
        
        if (g_nal == 0) {
                fprintf(stderr, "Error: you must run the 'network' command first\n");
                return -1;
        }
        
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
        struct portal_ioctl_data data;
        ptl_nid_t mynid;
        
        if (argc > 2) {
                fprintf(stderr, "usage: %s [NID]\n", argv[0]);
                fprintf(stderr, "NID defaults to the primary IP address of the machine.\n");
                return 0;
        }

        if (g_nal == 0) {
                fprintf(stderr, "Error: you must run the 'network' command "
                        "first.\n");
                return -1;
        }

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
        
        PORTAL_IOC_INIT(data);
        data.ioc_nid = mynid;
        data.ioc_nal = g_nal;
        data.ioc_nal_cmd = NAL_CMD_REGISTER_MYNID;

        rc = l_ioctl(PORTALS_DEV_ID, IOC_PORTAL_NAL_CMD, &data);
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
        
        if (g_nal == 0) {
                fprintf(stderr, "Error: you must run the 'network' command "
                        "first.\n");
                return (-1);
        }

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
                        return (0);
                }
                g_socket_nonagle = !enable;
        }
        printf ("Nagle %s\n", g_socket_nonagle ? "disabled" : "enabled");
        return (0);
}

int
jt_ptl_add_route (int argc, char **argv)
{
        struct portal_ioctl_data data;
        ptl_nid_t                nid1;
        ptl_nid_t                nid2;
        ptl_nid_t                gateway_nid;
        int                      rc;
        
        if (argc < 3)
        {
                fprintf (stderr, "usage: %s gateway target [target]\n", argv[0]);
                return (0);
        }

        if (g_nal == 0) {
                fprintf(stderr, "Error: you must run the 'network' command "
                        "first.\n");
                return (-1);
        }

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

        PORTAL_IOC_INIT(data);
        data.ioc_nid = gateway_nid;
        data.ioc_nal = g_nal;
        data.ioc_nid2 = MIN (nid1, nid2);
        data.ioc_nid3 = MAX (nid1, nid2);

        rc = l_ioctl(PORTALS_DEV_ID, IOC_PORTAL_ADD_ROUTE, &data);
        if (rc != 0) 
        {
                fprintf (stderr, "IOC_PORTAL_ADD_ROUTE failed: %s\n", strerror (errno));
                return (-1);
        }
        
        return (0);
}

int
jt_ptl_del_route (int argc, char **argv)
{
        struct portal_ioctl_data data;
        ptl_nid_t                nid;
        int                      rc;
        
        if (argc < 2)
        {
                fprintf (stderr, "usage: %s targetNID\n", argv[0]);
                return (0);
        }

        if (ptl_parse_nid (&nid, argv[1]) != 0)
        {
                fprintf (stderr, "Can't parse target NID \"%s\"\n", argv[1]);
                return (-1);
        }

        PORTAL_IOC_INIT(data);
        data.ioc_nid = nid;

        rc = l_ioctl(PORTALS_DEV_ID, IOC_PORTAL_DEL_ROUTE, &data);
        if (rc != 0) 
        {
                fprintf (stderr, "IOC_PORTAL_DEL_ROUTE ("LPX64") failed: %s\n", nid, strerror (errno));
                return (-1);
        }
        
        return (0);
}

int
jt_ptl_print_routes (int argc, char **argv)
{
        char                      buffer[3][128];
        struct portal_ioctl_data  data;
        int                       rc;
        int                       index;
        int			  gateway_nal;
        ptl_nid_t		  gateway_nid;
        ptl_nid_t		  nid1;
        ptl_nid_t		  nid2;
        
        
        for (index = 0;;index++)
        {
                PORTAL_IOC_INIT(data);
                data.ioc_count = index;
                
                rc = l_ioctl(PORTALS_DEV_ID, IOC_PORTAL_GET_ROUTE, &data);
                if (rc != 0)
                        break;

                gateway_nal = data.ioc_nal;
                gateway_nid = data.ioc_nid;
                nid1 = data.ioc_nid2;
                nid2 = data.ioc_nid3;
                
                printf ("%8s %18s : %s - %s\n", 
                        nal2name (gateway_nal), 
                        ptl_nid2str (buffer[0], gateway_nid),
                        ptl_nid2str (buffer[1], nid1),
                        ptl_nid2str (buffer[2], nid2));
        }
        return (0);
}

