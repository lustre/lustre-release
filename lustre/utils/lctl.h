#ifndef _LCTL_H_
#define _LCTL_H_

#include "parser.h"
extern command_t cmdlist[];

/* Network configuration commands */ 
int jt_net_network(int argc, char **argv);
int jt_net_connect(int argc, char **argv);
int jt_net_disconnect(int argc, char **argv);
int jt_net_add_uuid(int argc, char **argv);
int jt_net_del_uuid(int argc, char **argv);
int jt_net_mynid(int argc, char **argv);
int jt_net_add_route(int argc, char **argv);
int jt_net_del_route(int argc, char **argv);
int jt_net_route_list(int argc, char **argv);
int jt_net_recv_mem(int argc, char **argv);
int jt_net_send_mem(int argc, char **argv);
int jt_net_nagle(int argc, char **argv);

/* Device selection commands */
int jt_opt_device(int argc, char **argv);
int jt_dev_newdev(int argc, char **argv);
int jt_dev_uuid2dev(int argc, char **argv);
int jt_dev_name2dev(int argc, char **argv);
int jt_dev_device(int argc, char **argv);
int jt_dev_list(int argc, char **argv);

/* Device configuration commands */
int jt_dev_attach(int argc, char **argv);
int jt_dev_setup(int argc, char **argv);
int jt_dev_cleanup(int argc, char **argv);
int jt_dev_detach(int argc, char **argv);
int jt_dev_lov_config(int argc, char **argv);

/* Device operations */
int jt_dev_probe(int argc, char **argv);
int jt_dev_close(int argc, char **argv);
int jt_dev_getattr(int argc, char **argv);
int jt_dev_setattr(int argc, char **argv);
int jt_dev_test_getattr(int argc, char **argv);
int jt_dev_test_brw(int argc, char **argv);
int jt_dev_test_ldlm(int argc, char **argv);

/* Debug commands */
int jt_debug_kernel(int argc, char **argv);
int jt_debug_file(int argc, char **argv);
int jt_debug_clear(int argc, char **argv);
int jt_debug_mark(int argc, char **argv);
int jt_debug_filter(int argc, char **argv);
int jt_debug_show(int argc, char **argv);
int jt_debug_list(int argc, char **argv);
int jt_debug_modules(int argc, char **argv);
int jt_debug_panic(int argc, char **argv);
int jt_debug_lctl(int argc, char **argv);

int do_disconnect(char *func, int verbose);
int network_setup(int argc, char **argv);
int device_setup(int argc, char **argv);
int debug_setup(int argc, char **argv);

int jt_opt_threads(int argc, char **argv);
char *cmdname(char *func);
int get_verbose(const char *arg);
int be_verbose(int verbose, struct timeval *next_time,
	       int num, int *next_num, int num_total);

#define LCTL_DEBUG
#ifdef LCTL_DEBUG
extern int lctl_debug;
#define D_LCTL 1

#ifdef CDEBUG
#undef CDEBUG
#endif
#define CDEBUG(mask, format, a...)                                    \
        do {                                                            \
                if (lctl_debug & mask) {                           \
                        printf("(%s:%s L%d): " format, __FILE__,        \
                               __FUNCTION__, __LINE__ , ## a);          \
                }                                                       \
        } while (0)
#else  /* !LCTL_DEBUG */
#  define CDEBUG(mask, format, a...) do {} while (0)
#endif /* LCTL_DEBUG */


#ifdef CERROR
#undef CERROR
#endif
#define CERROR(format, a...)                                    \
do {                                                            \
        fprintf(stderr, "(%s:%s L%d): " format, __FILE__, __FUNCTION__, \
               __LINE__ , ## a);                                \
} while (0)

/* So we can tell between error codes and devices */
#define N2D_OFF         0x100

#define IOCINIT(data)                                                   \
do {                                                                    \
        memset(&data, 0, sizeof(data));                                 \
        data.ioc_version = OBD_IOCTL_VERSION;                           \
        data.ioc_addr = conn_addr;                                      \
        data.ioc_cookie = conn_cookie;                                  \
        data.ioc_len = sizeof(data);                                    \
        if (fd < 0) {                                                   \
                fprintf(stderr, "No device open, use device\n");        \
                return 1;                                               \
        }                                                               \
} while (0)

#define PORTALS_CONNECT                                                 \
do {                                                                    \
        if (g_pfd != -1)                                                \
                break;                                                  \
                                                                        \
        g_pfd = open("/dev/portals", O_RDWR);                           \
        if (g_pfd < 0) {                                                \
                fprintf(stderr, "error: failed to open /dev/portals: %s\n" \
			"hint: the portals module may not be loaded\n",	   \
		        strerror(errno));                               \
                return -1;                                              \
        }                                                               \
} while(0)

#define LUSTRE_CONNECT(func)                                            \
do {                                                                    \
        if (fd != -1)                                                   \
                break;                                                  \
                                                                        \
        fd = open("/dev/obd", O_RDWR);                                  \
        if (fd < 0) {                                                   \
                fprintf(stderr, "error: %s failed to open /dev/obd: %s\n" \
			"hint: the lustre modules may not be loaded\n",   \
		        cmdname(func), strerror(errno));                \
                return -1;                                              \
        }                                                               \
} while(0)

#define difftime(a, b)                                                  \
        ((double)((a)->tv_sec - (b)->tv_sec) +                          \
        ((double)((a)->tv_usec - (b)->tv_usec) / 1000000))


typedef struct {
	char *name;
	int num;
} name2num_t;


#endif

