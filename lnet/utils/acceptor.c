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
#include <stdarg.h>
#include <signal.h>
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

char progname[] = "acceptor";
char name_port[40];             /* for signal handler */

#ifdef HAVE_LIBWRAP
/* needed because libwrap declares these as externs */
int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;
#endif

void usage(char *progname)
{
        fprintf(stderr, "usage: %s [-N nal_id] [-p] [-l] port\n\n"
                " -l\tKeep stdin/stdout open\n"
                " -p\tAllow connections from non-privileged ports\n", progname);
        exit (1);
}

void errlog(int level, const char *fmt, ...)
{
        va_list arg;
        FILE *out;

        switch (level) {
        case LOG_DEBUG:
        case LOG_INFO:
        case LOG_NOTICE:
                out = stdout;
                break;
        default:
                out = stderr;
                break;
        }
        va_start(arg, fmt);
        fprintf(out, "%s: ", name_port);
        vfprintf(out, fmt, arg);
        va_end(arg);
        va_start(arg, fmt);
        vsyslog(level, fmt, arg);
        va_end(arg);
}

char *pidfile_name(char *name_port)
{
        static char pidfile[1024];

        snprintf(pidfile, sizeof(pidfile), "%s/%s.pid", PIDFILE_DIR, name_port);

        return pidfile;
}

void pidfile_create(char *name_port)
{
        char *pidfile = pidfile_name(name_port);
        FILE *fp;

        if ((fp = fopen(pidfile, "w"))) {
                fprintf(fp, "%d\n", getpid());
                fclose(fp);
        } else {
                errlog(LOG_ERR, " error creating %s: %s\n",
                       pidfile, strerror(errno));
        }
}

int pidfile_cleanup(char *name_port)
{
        char *pidfile = pidfile_name(name_port);
        int rc;

        rc = unlink(pidfile);
        if (rc && errno != -ENOENT)
                fprintf(stderr, "%s: error removing %s: %s\n",
                        progname, pidfile, strerror(errno));

        return errno;
}

int pidfile_exists(char *name_port)
{
        char *pidfile = pidfile_name(name_port);
        FILE *fpid;
        int pid, rc;

        fpid = fopen(pidfile, "r+");
        if (fpid == NULL) {
                if (errno == ENOENT)
                        return 0;

                fprintf(stderr, "%s: error opening %s: %s.\n",
                        progname, pidfile, strerror(errno));
                return (1);
        }

        rc = fscanf(fpid, "%i", &pid);
        fclose(fpid);
        if (rc != 1) {
                fprintf(stderr,"%s: %s didn't contain a valid pid, removing.\n",
                        progname, pidfile);
                goto stale;
        }

        if (kill(pid, 0) == 0) {
                fprintf(stderr, "%s: %s exists, acceptor pid %d running.\n",
                        progname, pidfile, pid);
                return (1);
        }

        fprintf(stderr, "%s: stale %s exists, pid %d doesn't, removing.\n",
                progname, pidfile, pid);
stale:
        pidfile_cleanup(name_port);
        return (0);
}

void handler(int sig)
{
        pidfile_cleanup(name_port);
        exit(sig);
}

void show_connection(int fd, __u32 net_ip)
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

        syslog(LOG_INFO, "accepted host: %s\n", host);
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

        snprintf(name_port, sizeof(name_port) - 1, "%s-%d", progname, port);
        if (pidfile_exists(name_port))
                return(EEXIST);
        openlog(name_port, LOG_PID, LOG_DAEMON);

        memset(&srvaddr, 0, sizeof(srvaddr));
        srvaddr.sin_family = AF_INET;
        srvaddr.sin_port = htons(port);
        srvaddr.sin_addr.s_addr = INADDR_ANY;

        fd = socket(PF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
                rc = errno;
                errlog(LOG_ERR, "error opening socket: %s\n", strerror(errno));
                return(rc);
        }

        o = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &o, sizeof(o))) {
                rc = errno;
                errlog(LOG_ERR, "cannot set REUSEADDR socket opt: %s\n",
                       strerror(errno));
                return(rc);
        }

        rc = bind(fd, (struct sockaddr *)&srvaddr, sizeof(srvaddr));
        if (rc == -1) {
                rc = errno;
                errlog(LOG_ERR, "error binding to socket: %s\n",
                       strerror(errno));
                return(rc);
        }

        if (listen(fd, 127)) {
                rc = errno;
                perror("listen: ");
                return(rc);
        }
        printf("listening on port %d\n", port);

        pfd = open("/dev/portals", O_RDWR);
        if (pfd < 0) {
                rc = errno;
                errlog(LOG_ERR, "opening portals device: %s\n",strerror(errno));
                return(rc);
        }

        rc = daemon(0, noclose);
        if (rc < 0) {
                rc = errno;
                errlog(LOG_ERR, "error daemonizing: %s\n", strerror(errno));
                return(rc);
        }

        signal(SIGHUP, SIG_IGN);
        signal(SIGINT, handler);
        signal(SIGQUIT, handler);
        signal(SIGTERM, handler);

        errlog(LOG_NOTICE, "started, listening on port %d\n", port);
        pidfile_create(name_port);

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
                if (cfd < 0) {
                        errlog(LOG_ERR, "error accepting connection: %s\n",
                               strerror(errno));
                        break;
                        //continue;
                }

#ifdef HAVE_LIBWRAP
                /* libwrap access control */
                request_init(&request, RQ_DAEMON, "lustre", RQ_FILE, cfd, 0);
                sock_host(&request);
                if (!hosts_access(&request)) {
                        inet_ntop(AF_INET, &clntaddr.sin_addr,
                                  addrstr, INET_ADDRSTRLEN);
                        errlog(LOG_WARNING, "unauthorized access from %s:%hd\n",
                               addrstr, ntohs(clntaddr.sin_port));
                        close (cfd);
                        continue;
                }
#endif

                if (require_privports &&
                    ntohs(clntaddr.sin_port) >= IPPORT_RESERVED) {
                        inet_ntop(AF_INET, &clntaddr.sin_addr,
                                  addrstr, INET_ADDRSTRLEN);
                        errlog(LOG_ERR,
                               "closing non-privileged connection from %s:%d\n",
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
                        errlog(LOG_ERR,
                               "portals ioctl failed: %s\n", strerror(errno));
                } else {
                        errlog(LOG_DEBUG, "client registered\n");
                }
                rc = close(cfd);
                if (rc)
                        perror ("close failed");
        }

        closelog();
        pidfile_cleanup(name_port);

        return (0);
}
