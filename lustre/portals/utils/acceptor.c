/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
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
#include <unistd.h>
#include <asm/byteorder.h>
#include <syslog.h>

#include <errno.h>

#include <portals/api-support.h>
#include <portals/list.h>
#include <portals/lib-types.h>

/* should get this from autoconf somehow */
#ifndef PIDFILE_DIR
#define PIDFILE_DIR "/var/run"
#endif 

#define PROGNAME "acceptor"

void create_pidfile(char *name, int port)
{
        char pidfile[1024];
        FILE *fp;

        snprintf(pidfile, sizeof(pidfile), "%s/%s-%d.pid", 
                 PIDFILE_DIR, name, port);
        
        if ((fp = fopen(pidfile, "w"))) {
                fprintf(fp, "%d\n", getpid());
                fclose(fp);
        } else {
                syslog(LOG_ERR, "%s: %s\n", pidfile, 
                       strerror(errno));
        }
}

int pidfile_exists(char *name, int port)
{
        char pidfile[1024];

        snprintf(pidfile, sizeof(pidfile), "%s/%s-%d.pid", 
                 PIDFILE_DIR, name, port);
        
        if (!access(pidfile, F_OK)) {
                fprintf(stderr, "%s: exists, acceptor already running.\n", 
                        pidfile);
                return (1);
        } 
        return (0);
}

int
parse_size (int *sizep, char *str)
{
        int             size;
        char            mod[32];

        switch (sscanf (str, "%d%1[gGmMkK]", &size, mod))
        {
        default:
                return (-1);

        case 1:
                *sizep = size;
                return (0);

        case 2:
                switch (*mod)
                {
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

void
show_connection (int fd, __u32 net_ip, ptl_nid_t nid)
{
        struct hostent *h = gethostbyaddr ((char *)&net_ip, sizeof net_ip, AF_INET);
        __u32 host_ip = ntohl (net_ip);
        int  rxmem = 0;
        int  txmem = 0;
        int  nonagle = 0;
        int  len;
        char host[1024];
        
        len = sizeof (txmem);
        if (getsockopt (fd, SOL_SOCKET, SO_SNDBUF, &txmem, &len) != 0)
                perror ("Cannot get write buffer size");
        
        len = sizeof (rxmem);
        if (getsockopt (fd, SOL_SOCKET, SO_RCVBUF, &rxmem, &len) != 0)
                perror ("Cannot get read buffer size");
        
        len = sizeof (nonagle);
        if (getsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &nonagle, &len) != 0)
                perror ("Cannot get nagle");

        if (h == NULL)
                snprintf (host, sizeof(host), "%d.%d.%d.%d", (host_ip >> 24) & 0xff,
                                    (host_ip >> 16) & 0xff, (host_ip >> 8) & 0xff, host_ip & 0xff);
        else
                snprintf (host, sizeof(host), "%s", h->h_name);
                
        syslog (LOG_INFO, "Accepted host: %s NID: "LPX64" snd: %d rcv %d nagle: %s\n", 
                 host, nid, txmem, rxmem, nonagle ? "disabled" : "enabled");
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

        if (__cpu_to_le32 (hmv->magic) != PORTALS_PROTO_MAGIC) {
                fprintf (stderr, "Bad magic %#08x (%#08x expected)\n", 
                         __cpu_to_le32 (hmv->magic), PORTALS_PROTO_MAGIC);
                return (-1);
        }

        if (__cpu_to_le16 (hmv->version_major) != PORTALS_PROTO_VERSION_MAJOR ||
            __cpu_to_le16 (hmv->version_minor) != PORTALS_PROTO_VERSION_MINOR) {
                fprintf (stderr, "Incompatible protocol version %d.%d (%d.%d expected)\n",
                         __cpu_to_le16 (hmv->version_major),
                         __cpu_to_le16 (hmv->version_minor),
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
        if (__cpu_to_le32 (hdr.type) != PTL_MSG_HELLO ||
            __cpu_to_le32 (PTL_HDR_LENGTH (&hdr)) != 0) {
                fprintf (stderr, "Expecting a HELLO hdr with 0 payload,"
                         " but got type %d with %d payload\n",
                         __cpu_to_le32 (hdr.type),
                         __cpu_to_le32 (PTL_HDR_LENGTH (&hdr)));
                return (-1);
        }
        
        *peer_nid = __le64_to_cpu (hdr.src_nid);
        return (0);
}

void
usage (char *myname)
{
        fprintf (stderr, "Usage: %s [-r recv_mem] [-s send_mem] [-n] [-N nal_id] port\n", myname);
        exit (1);
}

int main(int argc, char **argv)
{
        int o, fd, rc, port, pfd;
        struct sockaddr_in srvaddr;
        int c;
        int rxmem = 0;
        int txmem = 0;
        int noclose = 0;
        int nonagle = 1;
        int nal = SOCKNAL;
        int xchg_nids = 0;
        int bind_irq = 0;
        
        while ((c = getopt (argc, argv, "N:r:s:nlxi")) != -1)
                switch (c)
                {
                case 'r':
                        if (parse_size (&rxmem, optarg) != 0 || rxmem < 0)
                                usage (argv[0]);
                        break;
                        
                case 's':
                        if (parse_size (&txmem, optarg) != 0 || txmem < 0)
                                usage (argv[0]);
                        break;

                case 'n':
                        nonagle = 0;
                        break;

                case 'l':
                        noclose = 1;
                        break;

                case 'x':
                        xchg_nids = 1;
                        break;

                case 'i':
                        bind_irq = 1;
                        break;
                        
                case 'N':
                        if (parse_size(&nal, optarg) != 0 || 
                            nal < 0 || nal > NAL_MAX_NR)
                                usage(argv[0]);
                        break;
                        
                default:
                        usage (argv[0]);
                        break;
                }

        if (optind >= argc)
                usage (argv[0]);

        port = atol(argv[optind++]);

        if (pidfile_exists(PROGNAME, port))
                exit(1);

        memset(&srvaddr, 0, sizeof(srvaddr));
        srvaddr.sin_family = AF_INET;
        srvaddr.sin_port = htons(port);
        srvaddr.sin_addr.s_addr = INADDR_ANY;

        fd = socket(PF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
                perror("opening socket");
                exit(1);
        }

        o = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &o, sizeof(o))) {
                perror("Cannot set REUSEADDR socket opt");
                exit(1);
        }

        if (nonagle)
        {
                o = 1;
                rc = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &o, sizeof (o));
                if (rc != 0) 
                { 
                        perror ("Cannot disable nagle");
                        exit (1);
                }
        }

        if (txmem != 0)
        {
                rc = setsockopt (fd, SOL_SOCKET, SO_SNDBUF, &txmem, sizeof (txmem));
                if (rc != 0)
                {
                        perror ("Cannot set write buffer size");
                        exit (1);
                }
        }
        
        if (rxmem != 0)
        {
                rc = setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &rxmem, sizeof (rxmem));
                if (rc != 0)
                {
                        perror ("Cannot set read buffer size");
                        exit (1);
               }
        }
                
        rc = bind(fd, (struct sockaddr *)&srvaddr, sizeof(srvaddr));
        if ( rc == -1 ) {
                perror("bind: ");
                exit(1);
        }

        if (listen(fd, 127)) {
                perror("listen: ");
                exit(1);
        }
        fprintf(stderr, "listening on port %d\n", port);

        pfd = open("/dev/portals", O_RDWR);
        if ( pfd < 0 ) {
                perror("opening portals device");
                exit(1);
        }

        rc = daemon(1, noclose);
        if (rc < 0) {
                perror("daemon(): ");
                exit(1);
        }

        openlog(PROGNAME, LOG_PID, LOG_DAEMON);
        syslog(LOG_INFO, "started, listening on port %d\n", port);
        create_pidfile(PROGNAME, port);

        while (1) {
                struct sockaddr_in clntaddr;
                int len = sizeof(clntaddr);
                int cfd;
                struct portal_ioctl_data data;
                ptl_nid_t peer_nid;
                
                cfd = accept(fd, (struct sockaddr *)&clntaddr, &len);
                if ( cfd < 0 ) {
                        perror("accept");
                        exit(0);
                        continue;
                }

                if (!xchg_nids)
                        peer_nid = ntohl (clntaddr.sin_addr.s_addr); /* HOST byte order */
                else
                {
                        PORTAL_IOC_INIT (data);
                        data.ioc_nal = nal;
                        rc = ioctl (pfd, IOC_PORTAL_GET_NID, &data);
                        if (rc < 0)
                        {
                                perror ("Can't get my NID");
                                close (cfd);
                                continue;
                        }
                        
                        rc = exchange_nids (cfd, data.ioc_nid, &peer_nid);
                        if (rc != 0)
                        {
                                close (cfd);
                                continue;
                        }
                }

                show_connection (cfd, clntaddr.sin_addr.s_addr, peer_nid);
                
                PORTAL_IOC_INIT(data);
                data.ioc_fd = cfd;
                data.ioc_nal = nal;
                data.ioc_nal_cmd = NAL_CMD_REGISTER_PEER_FD;
                data.ioc_nid = peer_nid;
                data.ioc_flags = bind_irq;
                
                if (ioctl(pfd, IOC_PORTAL_NAL_CMD, &data) < 0) {
                        perror("ioctl failed");

                } else {
                        printf("client registered\n");
                }
                rc = close(cfd);
                if (rc)
                        perror ("close failed");
        }

        closelog();
        exit(0);

}
