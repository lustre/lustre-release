/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *   This file is a modified version of the ptlctl tool which is
 *   part of Portals, http://www.sf.net/projects/lustre/
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
#include <portals/api-support.h>

#include "lctl.h"

static char rawbuf[8192];
static char *buf = rawbuf;
static int max = 8192;

static unsigned int g_nid = 0;
static unsigned int g_nal = 0;
static unsigned short g_port = 0;
static int g_pfd = -1;

static int g_socket_txmem = 0;
static int g_socket_rxmem = 0;
static int g_socket_nonagle = 1;

static name2num_t nalnames[] = {
        {"tcp",		SOCKNAL},
        {"elan",	QSWNAL},
        {"gm",	        GMNAL},
        {NULL,		-1}
};

int network_setup(int argc, char **argv) {
        PORTALS_CONNECT;
        return 0;
}

static name2num_t *name2num_lookup_name(name2num_t *table, char *str) {
        while (table->name != NULL)
                if (!strcmp (str, table->name))
                        return (table);
                else
                        table++;
        return (NULL);
}

static name2num_t *name2num_lookup_num(name2num_t *table, int num) {
        while (table->name != NULL)
                if (num == table->num)
                        return (table);
                else
                        table++;
        return (NULL);
}

static int name2nal(char *str) {
        name2num_t *e = name2num_lookup_name (nalnames, str);

        return ((e == NULL) ? 0 : e->num);
}

static char *nal2name (int nal) {
        name2num_t *e = name2num_lookup_num (nalnames, nal);

        return ((e == NULL) ? "???" : e->name);
}

static int nid2nal(ptl_nid_t nid) {
        /* BIG pragmatic assumption */
        return ((((__u32)nid) & 0xffff0000) != 0 ? SOCKNAL : QSWNAL);
}

static int parse_nid(ptl_nid_t *nidp, char *str) {
        struct hostent *he;
        int             a;
        int             b;
        int             c;
        int             d;
        
        if (sscanf (str, "%d.%d.%d.%d", &a, &b, &c, &d) == 4 &&
            (a & ~0xff) == 0 && (b & ~0xff) == 0 &&
            (c & ~0xff) == 0 && (d & ~0xff) == 0) {
                __u32 addr = (a<<24)|(b<<16)|(c<<8)|d;
                *nidp = (ptl_nid_t)addr;
                return (0);
        }
        
        if ((('a' <= str[0] && str[0] <= 'z') ||
             ('A' <= str[0] && str[0] <= 'Z')) &&
             (he = gethostbyname (str)) != NULL) {
                __u32 addr = *(__u32 *)he->h_addr;
                *nidp = (ptl_nid_t)ntohl(addr);  /* HOST byte order */
                return (0);
        }

        if (sscanf (str, "%i", &a) == 1) {
                *nidp = (ptl_nid_t)a;
                return (0);
        }

        return (-1);
}

static char *nid2str (char *buffer, ptl_nid_t nid) {
        switch (nid2nal(nid)) {
        case QSWNAL:
                sprintf (buffer, "%Ld", nid);
                return (buffer);
                
        case SOCKNAL: {
                __u32 addr = htonl((__u32)nid); /* back to NETWORK byte order*/
                struct hostent *he = gethostbyaddr ((const char *)&addr,
                        sizeof(addr), AF_INET);
                
                if (he != NULL) {
                        strcpy (buffer, he->h_name);
                } else {
                        addr = (__u32)nid;
                        sprintf(buffer, "%d.%d.%d.%d", (addr>>24)&0xff,
                                (addr>>16)&0xff, (addr>>8)&0xff, addr&0xff);
                }
                return (buffer);
        }
        
        default:
                sprintf (buffer, "nid2nal broken");
                return (buffer);
        }
}
        
int jt_net_network(int argc, char **argv) {
        int  nal;
        
        if (argc != 2 || (nal = name2nal (argv[1])) == 0)
                return CMD_HELP;

        g_nal = nal;
        return (0);
}

int jt_net_connect(int argc, char **argv) {
        if (argc < 2)
                return CMD_HELP;

        if (g_nal == 0) {
                fprintf(stderr, "Error: you must run the 'setup' command "
                        "first.\n");
                return -1;
        }

        if (g_nal == SOCKNAL) {
                struct hostent *he;
                struct portal_ioctl_data data;
                struct sockaddr_in srvaddr;
                int fd, rc;
                int nonagle = 0;
                int rxmem = 0;
                int txmem = 0;
                int o;
                int olen;
                
                if (argc != 3)
                        return CMD_HELP;

                he = gethostbyname(argv[1]);
                if (!he) {
                        fprintf(stderr, "gethostbyname error: %s\n",
                                strerror(errno));
                        return -1;
                }

                g_port = atol(argv[2]);

                memset(&srvaddr, 0, sizeof(srvaddr));
                srvaddr.sin_family = AF_INET;
                srvaddr.sin_port = htons(g_port);
                srvaddr.sin_addr.s_addr = *(__u32 *)he->h_addr;
        
                fd = socket(PF_INET, SOCK_STREAM, 0);
                if ( fd < 0 ) {
                        fprintf(stderr, "socket() failed: %s\n",
                                strerror(errno));
                        return -1;
                }

                if (g_socket_nonagle) {
                        o = 1;
                        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                            &o, sizeof (o)) != 0) { 
                                fprintf(stderr, "cannot disable nagle: %s\n",
                                        strerror(errno));
                                return (-1);
                        }
                }

                if (g_socket_rxmem != 0) {
                        o = g_socket_rxmem;
                        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                            &o, sizeof (o)) != 0) { 
                                fprintf(stderr, "cannot set receive buffer "
                                        "size: %s\n", strerror(errno));
                                return (-1);
                        }
                }

                if (g_socket_txmem != 0) {
                        o = g_socket_txmem;
                        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF,
                            &o, sizeof (o)) != 0) { 
                                fprintf(stderr, "cannot set send buffer "
                                        "size: %s\n", strerror(errno));
                                return (-1);
                        }
                }

                rc = connect(fd, (struct sockaddr *)&srvaddr, sizeof(srvaddr));
                if ( rc == -1 ) { 
                        fprintf(stderr, "connect() failed: %s\n",
                                strerror(errno));
                        return -1;
                }

                olen = sizeof (txmem);
                if (getsockopt (fd, SOL_SOCKET, SO_SNDBUF, &txmem, &olen) != 0)
                        fprintf(stderr, "Can't get send buffer size: %s\n",
                                strerror(errno));
                olen = sizeof (rxmem);
                if (getsockopt (fd, SOL_SOCKET, SO_RCVBUF, &rxmem, &olen) != 0)
                        fprintf(stderr, "Can't get receive buffer size: %s\n",
                                strerror(errno));
                olen = sizeof (nonagle);
                if (getsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&nonagle,&olen) != 0)
                        fprintf(stderr, "Can't get nagle: %s\n",
                                strerror(errno));

                printf("Connected to %s (snd %d, rcv %d, nagle %s)\n",
                        argv[1],txmem,rxmem,nonagle ? "Disabled" : "Enabled");

                PORTAL_IOC_INIT(data);
                data.ioc_fd = fd;
                /* HOST byte order */
                data.ioc_nid = ntohl(srvaddr.sin_addr.s_addr);

                rc = ioctl(g_pfd, IOC_PORTAL_REGISTER_CLIENT_FD, &data);
                if (rc) {
                        fprintf(stderr, "failed to register fd with portals: "
                                "%s\n", strerror(errno));
                        return -1;
                }

                g_nid = ntohl (srvaddr.sin_addr.s_addr); /* HOST byte order */
                printf("Connection to 0x%x registered with socknal\n",
                        g_nid);

                rc = close(fd);
                if (rc) {
                        fprintf(stderr, "close failed: %d\n", rc);
                }
        } else if (g_nal == QSWNAL) {
                g_nid = atoi(argv[1]);
        } else if (g_nal == GMNAL) {
                g_nid = atoi(argv[1]);
        } else {
                fprintf(stderr, "This should never happen.  Also it is very "
                        "bad.\n");
        }

        return 0;
}

int jt_net_disconnect(int argc, char **argv) {
        if (argc > 2)
                return CMD_HELP;
        
        if (g_nal == 0) {
                fprintf(stderr, "Error: you must run the 'network' command "
                        "first.\n");
                return -1;
        }

        if (g_nal == SOCKNAL) {
                struct hostent *he;
                struct portal_ioctl_data data;
                int rc;

                PORTAL_IOC_INIT(data);
                if (argc == 2) {
                        he = gethostbyname(argv[1]);
                        if (!he) {
                                fprintf(stderr, "gethostbyname error: %s\n",
                                        strerror(errno));
                                return -1;
                        }
                        
                        /* HOST byte order */
                        data.ioc_nid = ntohl (*(__u32 *)he->h_addr);

                } else {
                        fprintf(stderr, "Disconnecting ALL connections.\n");
                        /* leave ioc_nid zeroed == disconnect all */
                }
                rc = ioctl(g_pfd, IOC_PORTAL_CLOSE_CONNECTION, &data);
                if (rc) {
                        fprintf(stderr, "failed to remove connection: %s\n",
                                strerror(errno));
                        return -1;
                }
        } else if (g_nal == QSWNAL) {
                printf("'disconnect' doesn't make any sense for "
                        "elan.\n");
        } else if (g_nal == GMNAL) {
                printf("'disconnect' doesn't make any sense for "
                        "GM.\n");
        } else {
                fprintf(stderr, "This should never happen.  Also it is very "
                        "bad.\n");
        }

        return 0;
}

/*
int jt_net_ping(int argc, char **argv) {
        int       rc;
        ptl_nid_t nid;
        long      count   = 1;
        long      size    = 4;
        long      timeout = 1;
        struct portal_ioctl_data data;

        if (argc < 2) {
                fprintf(stderr, "usage: %s nid [count] [size] [timeout "
                        (secs)]\n", argv[0]);
                return 0;
        }

        if (g_nal == 0) {
                fprintf(stderr, "Error: you must run the 'setup' command "
                        "first.\n");
                return -1;
        }

        if (parse_nid (&nid, argv[1]) != 0) {
                fprintf (stderr, "Can\'t parse nid \"%s\"\n", argv[1]);
                return (-1);
        }
        
        if (argc > 2) {
                count = atol(argv[2]);

                if (count < 0 || count > 20000) {
                        fprintf(stderr, "are you insane? "
                                "%ld is a crazy count.\n", count);
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
        data.ioc_nid     = (__u32)nid;
        data.ioc_nal     = g_nal;
        data.ioc_timeout = timeout;
        
        rc = ioctl(g_pfd, IOC_PORTAL_PING, &data);
        if (rc) {
                fprintf(stderr, "failed to start pinger: %s\n",
                        strerror(errno));
                return -1;
        }
        fprintf(stderr, "Pinger started, take cover...\n");
        return 0;
}
*/

int jt_net_mynid(int argc, char **argv) {
        int rc;
        struct hostent *h;
        char buf[1024], *hostname;
        struct portal_ioctl_data data;
        ptl_nid_t mynid;
        
        if (argc > 2)
                return CMD_HELP;

        if (g_nal == 0) {
                fprintf(stderr, "Error: you must run the 'setup' command "
                        "first.\n");
                return -1;
        }

        if (g_nal == QSWNAL) {
                fprintf(stderr, "'mynid' doesn't make any sense for elan.\n");
                return -1;
        } else  if (g_nal == GMNAL) {
                fprintf(stderr, "'mynid' doesn't make any sense for GM.\n");
                return -1;
        } 
        
        if (g_nal != SOCKNAL) {
                fprintf(stderr, "This should never happen.  Also it is very "
                        "bad.\n");
                return -1;
        }

        if (argc == 1) {
                if (gethostname(buf, sizeof(buf)) != 0) {
                        fprintf(stderr, "gethostname failed: %s\n",
                                strerror(errno));
                        return -1;
                }
                hostname = buf;
        } else {
                hostname = argv[1];
        }

        h = gethostbyname(hostname);

        if (!h) {
                fprintf(stderr, "cannot get address for host '%s': %d\n",
                        hostname, h_errno);
                return -1;
        }
        mynid = (ptl_nid_t)ntohl (*(__u32 *)h->h_addr); /* HOST byte order */
        
        PORTAL_IOC_INIT(data);
        data.ioc_nid = (__u32)mynid;

        rc = ioctl(g_pfd, IOC_PORTAL_REGISTER_MYNID, &data);
        if (rc < 0)
                fprintf(stderr, "IOC_PORTAL_REGISTER_MYNID failed: %s\n",
                       strerror(errno));
        else
                printf("registered my nid 0x%Lx (%s)\n",
                        mynid, hostname);
        return 0;
}

int jt_net_add_uuid(int argc, char **argv) {
        char tmp[64];
        int rc;
        struct portal_ioctl_data data;
        ptl_nid_t nid = g_nid;
        
        if (argc != 3)
                return CMD_HELP;

        if (parse_nid(&nid, argv[2]) != 0) {
                fprintf (stderr, "Can't parse NID %s\n", argv[2]);
                return (-1);
        }

        if (g_nal == 0) {
                fprintf(stderr, "Error: you must run the 'setup' command "
                        "first.\n");
                return -1;
        }

        memset(&data, 0, sizeof(data));
        data.ioc_nid = nid;
        data.ioc_inllen1 = strlen(argv[1]) + 1;
        data.ioc_inlbuf1 = argv[1];
        data.ioc_nal = g_nal;
        if (portal_ioctl_pack(&data, &buf, max) != 0) {
                fprintf(stderr, "portal_ioctl_pack failed.\n");
                return -1;
        }

        rc = ioctl(g_pfd, IOC_PORTAL_ADD_UUID, buf);
        if (rc) {
                fprintf(stderr, "IOC_PORTAL_ADD_UUID failed: %s\n",
                        strerror(errno));
                return -1;
        }

        printf ("Added uuid %s: %s\n", argv[1], nid2str (tmp, nid));
        return 0;
}

#if 0
static int jt_close_uuid(int argc, char **argv)
{
        int rc;
        struct portal_ioctl_data data;

        if (argc != 2) {
                fprintf(stderr, "usage: %s <uuid>\n", argv[0]);
                return 0;
        }

        if (g_nal == 0) {
                fprintf(stderr, "Error: you must run the 'setup' command "
                        "first.\n");
                return -1;
        }

        memset(&data, 0, sizeof(data));
        data.ioc_inllen1 = strlen(argv[1]) + 1;
        data.ioc_inlbuf1 = argv[1];
        data.ioc_nal = g_nal;
        if (portal_ioctl_pack(&data, &buf, max) != 0) {
                fprintf(stderr, "portal_ioctl_pack failed.\n");
                return -1;
        }

        rc = ioctl(g_pfd, IOC_PORTAL_CLOSE_UUID, buf);
        if (rc) {
                fprintf(stderr, "IOC_PORTAL_CLOSE_UUID failed: %s\n",
                        strerror(errno));
                return -1;
        }
        return 0;
}
#endif

int jt_net_del_uuid(int argc, char **argv) {
        int rc;
        struct portal_ioctl_data data;

        if (argc != 2)
                return CMD_HELP;

        if (g_nal == 0) {
                fprintf(stderr, "Error: you must run the 'setup' command "
                        "first.\n");
                return -1;
        }

        memset(&data, 0, sizeof(data));
        data.ioc_inllen1 = strlen(argv[1]) + 1;
        data.ioc_inlbuf1 = argv[1];
        data.ioc_nal = g_nal;
        if (portal_ioctl_pack(&data, &buf, max) != 0) {
                fprintf(stderr, "portal_ioctl_pack failed.\n");
                return -1;
        }

        rc = ioctl(g_pfd, IOC_PORTAL_DEL_UUID, buf);
        if (rc) {
                fprintf(stderr, "IOC_PORTAL_DEL_UUID failed: %s\n",
                        strerror(errno));
                return -1;
        }
        return 0;
}

int jt_net_add_route (int argc, char **argv) {
        struct portal_ioctl_data data;
        ptl_nid_t                nid1;
        ptl_nid_t                nid2;
        ptl_nid_t                gateway_nid;
        int                      gateway_nal;
        int                      rc;
        
        if (argc < 3)
                return CMD_HELP;

        if (parse_nid (&gateway_nid, argv[1]) != 0) {
                fprintf (stderr, "Can't parse gateway NID \"%s\"\n", argv[1]);
                return (-1);
        }

        gateway_nal = nid2nal (gateway_nid);
        if (parse_nid (&nid1, argv[2]) != 0) {
                fprintf(stderr, "Can't parse first target NID \"%s\"\n",
                        argv[2]);
                return (-1);
        }

        if (argc < 4) {
                nid2 = nid1;
        } else if (parse_nid (&nid2, argv[3]) != 0) {
                fprintf(stderr, "Can't parse second target NID \"%s\"\n",
                        argv[4]);
                return (-1);
        }

        PORTAL_IOC_INIT(data);
        data.ioc_nid = gateway_nid;
        data.ioc_nal = gateway_nal;
        data.ioc_nid2 = MIN (nid1, nid2);
        data.ioc_nid3 = MAX (nid1, nid2);

        rc = ioctl (g_pfd, IOC_PORTAL_ADD_ROUTE, &data);
        if (rc != 0) {
                fprintf(stderr, "IOC_PORTAL_ADD_ROUTE failed: %s\n",
                        strerror (errno));
                return (-1);
        }
        
        return (0);
}

int jt_net_del_route(int argc, char **argv) {
        struct portal_ioctl_data data;
        ptl_nid_t                nid;
        int                      rc;
        
        if (argc < 2)
                return CMD_HELP;

        if (parse_nid (&nid, argv[1]) != 0) {
                fprintf (stderr, "Can't parse target NID \"%s\"\n", argv[1]);
                return (-1);
        }

        PORTAL_IOC_INIT(data);
        data.ioc_nid = nid;

        rc = ioctl (g_pfd, IOC_PORTAL_DEL_ROUTE, &data);
        if (rc != 0) {
                fprintf(stderr, "IOC_PORTAL_DEL_ROUTE (0x%Lx) failed: %s\n",
                        nid, strerror (errno));
                return (-1);
        }
        
        return (0);
}

int jt_net_route_list(int argc, char **argv) {
        char                      buffer[3][128];
        struct portal_ioctl_data  data;
        int                       rc;
        int                       index;
        int			  gateway_nal;
        ptl_nid_t		  gateway_nid;
        ptl_nid_t		  nid1;
        ptl_nid_t		  nid2;
        
        for (index = 0;;index++) {
                PORTAL_IOC_INIT(data);
                data.ioc_count = index;
                
                rc = ioctl (g_pfd, IOC_PORTAL_GET_ROUTE, &data);
                if (rc != 0)
                        break;

                gateway_nal = data.ioc_nal;
                gateway_nid = data.ioc_nid;
                nid1 = data.ioc_nid2;
                nid2 = data.ioc_nid3;
                
                printf ("%8s %18s : %s - %s\n", 
                        nal2name (gateway_nal), 
                        nid2str (buffer[0], gateway_nid),
                        nid2str (buffer[1], nid1),
                        nid2str (buffer[2], nid2));
        }
        return (0);
}

int jt_net_recv_mem(int argc, char **argv) {
        int size;
        
        if (argc > 1) {
                if (Parser_size (&size, argv[1]) != 0 || size < 0) {
                        fprintf (stderr, "Can't parse size %s\n", argv[1]);
                        return (0);
                }

                g_socket_rxmem = size;
        }

        printf ("Socket rxmem = %d\n", g_socket_rxmem);        
        return (0);
}

int jt_net_send_mem(int argc, char **argv) {
        int size;
        
        if (argc > 1) {
                if (Parser_size (&size, argv[1]) != 0 || size < 0) {
                        fprintf (stderr, "Can't parse size %s\n", argv[1]);
                        return (0);
                }
                g_socket_txmem = size;
        }

        printf ("Socket txmem = %d\n", g_socket_txmem);
        return (0);
}

int jt_net_nagle(int argc, char **argv) {
        int enable;

        if (argc > 1) {
                if (Parser_bool (&enable, argv[1]) != 0) {
                        fprintf (stderr, "Can't parse boolean %s\n", argv[1]);
                        return (0);
                }
                g_socket_nonagle = !enable;
        }

        printf ("Nagle %s\n", g_socket_nonagle ? "disabled" : "enabled");
        return (0);
}
