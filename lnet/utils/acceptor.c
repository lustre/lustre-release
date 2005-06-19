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
#include <syslog.h>
#include <errno.h>
#ifdef HAVE_LIBWRAP
#include <arpa/inet.h>
#include <netinet/in.h>
#include <tcpd.h>
#endif

#include <libcfs/portals_utils.h>
#include <portals/api-support.h>
#include <portals/lib-types.h>
#include <portals/socknal.h>

/* should get this from autoconf somehow */
#ifndef PIDFILE_DIR
#define PIDFILE_DIR "/var/run"
#endif

#define PROGNAME "acceptor"

#ifdef HAVE_LIBWRAP
/* needed because libwrap declares these as externs */
int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;
#endif

void usage(char *myname)
{
        fprintf(stderr, "usage: %s [-N nal_id] [-p] [-l] port\n\n"
                " -l\tKeep stdin/stdout open\n"
                " -p\tAllow connections from non-privileged ports\n", myname);
        exit (1);
}

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

void
show_connection (int fd, __u32 net_ip)
{
        static long last_time;
        static __u32 host_ip;
        long now = time(0);
        struct hostent *h;
        int  len;
        char host[1024];

        /* Don't show repeats for same host, it adds no value */
        if (host_ip == ntohl(net_ip) && (now - last_time) < 5)
                return;

        h = gethostbyaddr((char *)&net_ip, sizeof(net_ip), AF_INET);
        last_time = now;
        host_ip = ntohl(net_ip);

        if (h == NULL)
                snprintf(host, sizeof(host), "%d.%d.%d.%d",
                         (host_ip >> 24) & 0xff, (host_ip >> 16) & 0xff,
                         (host_ip >> 8)  & 0xff, host_ip & 0xff);
        else
                snprintf(host, sizeof(host), "%s", h->h_name);

        syslog(LOG_INFO, "Accepted host: %s\n", host);
}

int main(int argc, char **argv)
{
        int o, fd, rc, port, pfd;
        struct sockaddr_in srvaddr;
        int c;
        int noclose = 0;
        int nal = SOCKNAL;
        int rport;
        int require_privports = 1;

        while ((c = getopt (argc, argv, "N:lp")) != -1) {
                switch (c) {
                case 'N':
                        if (sscanf(optarg, "%d", &nal) != 1 ||
                            nal < 0 || nal > NAL_MAX_NR)
                                usage(argv[0]);
                        break;
                case 'l':
                        noclose = 1;
                        break;
                case 'p':
                        require_privports = 0;
                        break;
                default:
                        usage (argv[0]);
                        break;
                }
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

        rc = daemon(0, noclose);
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
                struct portals_cfg pcfg;
#ifdef HAVE_LIBWRAP
                struct request_info request;
#endif
                char addrstr[INET_ADDRSTRLEN];

                cfd = accept(fd, (struct sockaddr *)&clntaddr, &len);
                if ( cfd < 0 ) {
                        perror("accept");
                        exit(0);
                        continue;
                }

#ifdef HAVE_LIBWRAP
                /* libwrap access control */
                request_init(&request, RQ_DAEMON, "lustre", RQ_FILE, cfd, 0);
                sock_host(&request);
                if (!hosts_access(&request)) {
                        inet_ntop(AF_INET, &clntaddr.sin_addr,
                                  addrstr, INET_ADDRSTRLEN);
                        syslog(LOG_WARNING, "Unauthorized access from %s:%hd\n",
                               addrstr, ntohs(clntaddr.sin_port));
                        close (cfd);
                        continue;
                }
#endif

                if (require_privports && ntohs(clntaddr.sin_port) >= IPPORT_RESERVED) {
                        inet_ntop(AF_INET, &clntaddr.sin_addr,
                                  addrstr, INET_ADDRSTRLEN);
                        syslog(LOG_ERR, "Closing non-privileged connection from %s:%d\n",
                               addrstr, ntohs(clntaddr.sin_port));
                        rc = close(cfd);
                        if (rc)
                                perror ("close un-privileged client failed");
                        continue;
                }

                show_connection (cfd, clntaddr.sin_addr.s_addr);

                PCFG_INIT(pcfg, NAL_CMD_REGISTER_PEER_FD);
                pcfg.pcfg_nal = nal;
                pcfg.pcfg_fd = cfd;
                pcfg.pcfg_misc = SOCKNAL_CONN_NONE; /* == incoming connection */

                PORTAL_IOC_INIT(data);
                data.ioc_pbuf1 = (char*)&pcfg;
                data.ioc_plen1 = sizeof(pcfg);

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
