/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */


#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdarg.h>
#include <signal.h>
#define printk printf

#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_dlm.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include <unistd.h>
#include <sys/un.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>

#define __KERNEL__
#include <linux/list.h>
#undef __KERNEL__

#include "parser.h"
#include <stdio.h>

static int jt_newdev(int argc, char **argv);
static int jt_attach(int argc, char **argv);
static int jt_setup(int argc, char **argv);


int fd = -1;
uint64_t conn_addr = -1;
uint64_t conn_cookie;
char rawbuf[8192];
char *buf = rawbuf;
int max = 8192;
int thread;
int rc = 0;

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

/*
    pack "LL LL LL LL LL LL LL L L L L L L L L L a60 a60 L L L",
    $obdo->{id}, 0,
    $obdo->{gr}, 0,
    $obdo->{atime}, 0,
    $obdo->{mtime}, 0 ,
    $obdo->{ctime}, 0,
    $obdo->{size}, 0,
    $obdo->{blocks}, 0,
    $obdo->{blksize},
    $obdo->{mode},
    $obdo->{uid},
    $obdo->{gid},
    $obdo->{flags},
    $obdo->{obdflags},
    $obdo->{nlink},
    $obdo->{generation},
    $obdo->{valid},
    $obdo->{inline},
    $obdo->{obdmd},
    0, 0, # struct list_head
    0;  #  struct obd_ops
}

*/

char * obdo_print(struct obdo *obd)
{
        char buf[1024];

        sprintf(buf, "id: %Ld\ngrp: %Ld\natime: %Ld\nmtime: %Ld\nctime: %Ld\n"
                "size: %Ld\nblocks: %Ld\nblksize: %d\nmode: %o\nuid: %d\n"
                "gid: %d\nflags: %x\nobdflags: %x\nnlink: %d,\nvalid %x\n",
                obd->o_id,
                obd->o_gr,
                obd->o_atime,
                obd->o_mtime,
                obd->o_ctime,
                obd->o_size,
                obd->o_blocks,
                obd->o_blksize,
                obd->o_mode,
                obd->o_uid,
                obd->o_gid,
                obd->o_flags,
                obd->o_obdflags,
                obd->o_nlink,
                obd->o_valid);
        return strdup(buf);
}

static char *cmdname(char *func)
{
        static char buf[512];

        if (thread) {
                sprintf(buf, "%s-%d", func, thread);
                return buf;
        }

        return func;
}

int getfd(char *func)
{
        if (fd == -1)
                fd = open("/dev/obd", O_RDWR);
        if (fd == -1) {
                fprintf(stderr, "error: %s: opening /dev/obd: %s\n",
                        cmdname(func), strerror(errno));
                return -1;
        }
        return 0;
}

#define difftime(a, b)                                          \
        ((double)(a)->tv_sec - (b)->tv_sec +                    \
         ((double)((a)->tv_usec - (b)->tv_usec) / 1000000))

static int be_verbose(int verbose, struct timeval *next_time,
                      int num, int *next_num, int num_total)
{
        struct timeval now;

        if (!verbose)
                return 0;

        if (next_time != NULL)
                gettimeofday(&now, NULL);

        /* A positive verbosity means to print every X iterations */
        if (verbose > 0 &&
            (next_num == NULL || num >= *next_num || num >= num_total)) {
                *next_num += verbose;
                if (next_time) {
                        next_time->tv_sec = now.tv_sec - verbose;
                        next_time->tv_usec = now.tv_usec;
                }
                return 1;
        }

        /* A negative verbosity means to print at most each X seconds */
        if (verbose < 0 && next_time != NULL && difftime(&now, next_time) >= 0){
                next_time->tv_sec = now.tv_sec - verbose;
                next_time->tv_usec = now.tv_usec;
                if (next_num)
                        *next_num = num;
                return 1;
        }

        return 0;
}

static int get_verbose(const char *arg)
{
        int verbose;

        if (!arg || arg[0] == 'v')
                verbose = 1;
        else if (arg[0] == 's' || arg[0] == 'q')
                verbose = 0;
        else
                verbose = (int) strtoul(arg, NULL, 0);

        if (verbose < 0)
                printf("Print status every %d seconds\n", -verbose);
        else if (verbose == 1)
                printf("Print status every operation\n");
        else if (verbose > 1)
                printf("Print status every %d operations\n", verbose);

        return verbose;
}

static int do_disconnect(char *func, int verbose)
{
        struct obd_ioctl_data data;

        if (conn_addr == -1) 
                return 0; 

        IOCINIT(data);

        rc = ioctl(fd, OBD_IOC_DISCONNECT , &data);
        if (rc < 0) {
                fprintf(stderr, "error: %s: %x %s\n", cmdname(func),
                        OBD_IOC_DISCONNECT, strerror(errno));
        } else {
                if (verbose)
                        printf("%s: disconnected conn %Lx\n", cmdname(func),
                               conn_addr);
                conn_addr = -1;
        }

        return rc;
}

extern command_t cmdlist[];

static int xml_command(char *cmd, ...) {
        va_list args;
        char *arg, *cmds[8];
        int i = 1, j;
       
        cmds[0] = cmd; 
        va_start(args, cmd);

        while (((arg = va_arg(args, char *)) != NULL) && (i < 8)) {
                cmds[i] = arg;
                i++;
        }

        va_end(args);

        printf("obdctl > ");
        for (j = 0; j < i; j++)
          printf("%s ", cmds[j]);

        printf("\n");

        return Parser_execarg(i, cmds, cmdlist);
}

static network_t *xml_network(xmlDocPtr doc, xmlNodePtr root) {
        xmlNodePtr cur = root->xmlChildrenNode;
        network_t *net;
        
        if ((net = (network_t *)calloc(1, sizeof(network_t))) == NULL) {
                printf("error: unable to malloc network_t\n");
                return NULL;
        }
        
        net->type = xmlGetProp(root, "type");
        if (net->type == NULL) {
                printf("error: type attrib required (tcp, elan, myrinet)\n");
                free(net);
                return NULL;
        }

        while (cur != NULL) {
                if (!xmlStrcmp(cur->name, "server"))
                        net->server = xmlNodeGetContent(cur);

                if (!xmlStrcmp(cur->name, "port"))
                        net->port = atoi(xmlNodeGetContent(cur));

                cur = cur->next;
        } 

        if (net->server == NULL) {
                printf("error: <server> tag required\n");
                free(net);
                return NULL;
        }
        
        return net;
}

static int xml_mds(xmlDocPtr doc, xmlNodePtr root, 
                   char *serv_id, char *serv_uuid) {
        xmlNodePtr cur = root->xmlChildrenNode;
        char *fstype = NULL, *device = NULL;
        int rc;

        printf("--- Setting up MDS ---\n");
        while (cur != NULL) {
                if (!xmlStrcmp(cur->name, "fstype"))
                        fstype = xmlNodeGetContent(cur);

                if (!xmlStrcmp(cur->name, "device"))
                        device = xmlNodeGetContent(cur);
 
                cur = cur->next;
        } 

        if ((fstype == NULL) || (device == NULL)) {
                printf("error: <fstype> and <device> tags required\n");
                return -1;
        }

        if ((rc = xml_command("newdev", NULL)) != 0)
                return rc;

        if ((rc = xml_command("attach", "mds", "MDSDEV", NULL)) != 0)
                return rc;

        if ((rc = xml_command("setup", device, fstype, NULL)) != 0)
                return rc;

        return 0;
}
        
static int xml_obd(xmlDocPtr doc, xmlNodePtr root, 
                   char *serv_id, char *serv_uuid) {
        xmlNodePtr cur = root->xmlChildrenNode;
        char *obdtype, *format = NULL, *fstype = NULL, *device = NULL;
        int rc;

        obdtype = xmlGetProp(root, "type");
        printf("--- Setting up OBD ---\n");

        while (cur != NULL) {
                if (!xmlStrcmp(cur->name, "fstype"))
                        fstype = xmlNodeGetContent(cur);

                if (!xmlStrcmp(cur->name, "device"))
                        device = xmlNodeGetContent(cur);
 
                if (!xmlStrcmp(cur->name, "autoformat"))
                        format = xmlNodeGetContent(cur);

                cur = cur->next;
        } 

        if ((obdtype == NULL) || (fstype == NULL) || (device == NULL)) {
                printf("error: 'type' attrib and <fstype> and <device> tags required\n");
                return -1;
        }

        /* FIXME: Building and configuring loopback devices should go here
         * but is currently unsupported.  You'll have to use the scripts
         * for now until support is added, or specify a real device.
         */
        
        if ((rc = xml_command("newdev", NULL)) != 0)
                return rc;

        if ((rc = xml_command("attach", obdtype, "OBDDEV", NULL)) != 0)
                return rc;

        if ((rc = xml_command("setup", device, fstype, NULL)) != 0)
                return rc;

        return 0;
}

static int xml_ost(xmlDocPtr doc, xmlNodePtr root, 
                   char *serv_id, char *serv_uuid) {
        int rc;

        printf("--- Setting up OST ---\n");
        if ((rc = xml_command("newdev", NULL)) != 0)
                return rc;

        if ((rc = xml_command("attach", "ost", "OSTDEV", NULL)) != 0)
                return rc;

        if ((rc = xml_command("setup", "$OBDDEV", NULL)) != 0)
                return rc;

        return 0;
}

static int xml_osc(xmlDocPtr doc, xmlNodePtr root, 
                   char *serv_id, char *serv_uuid) {
        xmlNodePtr cur = root->xmlChildrenNode;
        network_t *net = NULL;
        int rc = 0;

        printf("--- Setting up OSC ---\n");
        while (cur != NULL) {
                if (!xmlStrcmp(cur->name, "network")) {
                        net = xml_network(doc, cur);
                        if (net == NULL)
                                return -1;
                }
                cur = cur->next;
        } 

        if (net == NULL) {
                printf("error: <network> tag required\n");
                return -1;
        }

        if ((rc = xml_command("newdev", NULL)) != 0) {
                rc = -1;
                goto xml_osc_error;
        }

        if ((rc = xml_command("attach", "osc", "OSCDEV", NULL)) != 0) {
                rc = -1;
                goto xml_osc_error;
        }

        if ((rc = xml_command("setup", "OSTDEV", net->server, NULL)) != 0) {
                rc = -1;
                goto xml_osc_error;
        }

xml_osc_error:
        free(net);
        return rc;
}

static int xml_mdc(xmlDocPtr doc, xmlNodePtr root, 
                   char *serv_id, char *serv_uuid) {
        xmlNodePtr cur = root->xmlChildrenNode;
        network_t *net = NULL;
        int rc = 0;

        printf("--- Setting up MDC ---\n");
        while (cur != NULL) {
                if (!xmlStrcmp(cur->name, "network")) {
                        net = xml_network(doc, cur);
                        if (net == NULL)
                                return -1;
                }
                cur = cur->next;
        } 

        if (net == NULL) {
                printf("error: <network> tag required\n");
                return -1;
        }

        if ((rc = xml_command("newdev", NULL)) != 0) {
                rc = -1;
                goto xml_mdc_error;
        }

        if ((rc = xml_command("attach", "mdc", "MDCDEV", NULL)) != 0) {
                rc = -1;
                goto xml_mdc_error;
        }

        if ((rc = xml_command("setup", "MDSDEV", net->server, NULL)) != 0) {
                rc = -1;
                goto xml_mdc_error;
        }

xml_mdc_error:
        free(net);
        return rc;
}

static int xml_lov(xmlDocPtr doc, xmlNodePtr root, 
                   char *serv_id, char *serv_uuid) {
        printf("--- Setting up LOV ---\n");
        return 0;
}

static int xml_router(xmlDocPtr doc, xmlNodePtr root, 
                   char *serv_id, char *serv_uuid) {
        printf("--- Setting up ROUTER ---\n");
        return 0;
}

static int xml_ldlm(xmlDocPtr doc, xmlNodePtr root, 
                   char *serv_id, char *serv_uuid) {
        int rc;

        printf("--- Setting up LDLM ---\n");
        if ((rc = xml_command("newdev", NULL)) != 0)
                return rc;

        if ((rc = xml_command("attach", "ldlm", "LDLMDEV", NULL)) != 0)
                return rc;

        if ((rc = xml_command("setup", NULL)) != 0)
                return rc;

        return 0;
}

static int xml_service(xmlDocPtr doc, xmlNodePtr root, 
                       int serv_num, char *serv_id, char *serv_uuid) {
        xmlNodePtr cur = root;
        char *id, *uuid;

        while (cur != NULL) {
                id = xmlGetProp(cur, "id");
                uuid = xmlGetProp(cur, "uuid");

                if (xmlStrcmp(id, serv_id) ||
                    xmlStrcmp(uuid, serv_uuid)) {
                        cur = cur->next;
                        continue;
                }

                if (!xmlStrcmp(cur->name, "mds"))
                        return xml_mds(doc, cur, serv_id, serv_uuid);
                else if (!xmlStrcmp(cur->name, "obd"))
                        return xml_obd(doc, cur, serv_id, serv_uuid);
                else if (!xmlStrcmp(cur->name, "ost"))
                        return xml_ost(doc, cur, serv_id, serv_uuid);
                else if (!xmlStrcmp(cur->name, "osc"))
                        return xml_osc(doc, cur, serv_id, serv_uuid);
                else if (!xmlStrcmp(cur->name, "mdc"))
                        return xml_mdc(doc, cur, serv_id, serv_uuid);
                else if (!xmlStrcmp(cur->name, "lov"))
                        return xml_lov(doc, cur, serv_id, serv_uuid);
                else if (!xmlStrcmp(cur->name, "router"))
                        return xml_router(doc, cur, serv_id, serv_uuid);
                else if (!xmlStrcmp(cur->name, "ldlm"))
                        return xml_ldlm(doc, cur, serv_id, serv_uuid);
                else
                        return -1;        

                cur = cur->next;
        }

        printf("error: No XML config branch for id=%s uuid=%s\n",
                serv_id, serv_uuid); 
        return -1; 
}

static int xml_profile(xmlDocPtr doc, xmlNodePtr root, 
                       int prof_num, char *prof_id, char *prof_uuid) {
        xmlNodePtr parent, cur = root;
        char *id, *uuid, *srv_id, *srv_uuid;
        int rc = 0, num;

        while (cur != NULL) {
                id = xmlGetProp(cur, "id");
                uuid = xmlGetProp(cur, "uuid");

                if (xmlStrcmp(cur->name, "profile") || 
                    xmlStrcmp(id, prof_id)          ||
                    xmlStrcmp(uuid, prof_uuid)) {
                        cur = cur->next;
                        continue;
                }

                /* FIXME: Doesn't understand mountpoints yet
                 *        xml_mountpoint(doc, root, ...);
                 */    

                /* Setup each service in turn
                 * FIXME: Should be sorted by "num" attr, we shouldn't
                 *        assume they're in order in the XML document.
                 */
                parent = cur;
                cur = cur->xmlChildrenNode;
                while (cur != NULL) {
                        if (!xmlStrcmp(cur->name, "service_id")) {
                                num = atoi(xmlGetProp(cur, "num"));
                                rc = xml_service(doc, root, num,
                                        srv_id = xmlGetProp(cur, "id"),
                                        srv_uuid = xmlGetProp(cur, "uuid"));
                                if (rc != 0) {
                                        printf("error: service config\n");
                                        return rc;
                                }
                        }

                        cur = cur->next;
                }

                cur = parent->next;
        }

        return rc; 
}

static int xml_node(xmlDocPtr doc, xmlNodePtr root) {
        xmlNodePtr parent, cur = root;
        char *id, *uuid;
        int rc = 0, num;
        
        /* Walk the node tags looking for ours */
        while (cur != NULL) {
                if (xmlStrcmp(cur->name, "node")) {
                        cur = cur->next;
                        continue;
                }

                id = xmlGetProp(cur, "id");
                if (id == NULL)
                        return -1;

                uuid = xmlGetProp(cur, "uuid");
                if (uuid == NULL)
                        return -1;

                /* FIXME: Verify our ID and UUID against /etc/lustre/id
                 *        so we're sure we are who we think we are.
                 */

                /* Setup each profile in turn
                 * FIXME: Should be sorted by "num" attr, we shouldn't
                 *        assume they're in order in the XML document.
                 */
                parent = cur;
                cur = cur->xmlChildrenNode;
                while (cur != NULL) {
                        if (!xmlStrcmp(cur->name, "profile_id")) {
                                num = atoi(xmlGetProp(cur, "num"));
                                rc = xml_profile(doc, root, num,
                                                 xmlGetProp(cur, "id"),
                                                 xmlGetProp(cur, "uuid"));
                                if (rc != 0)
                                        return rc;
                        }

                        cur = cur->next;
                }

                cur = parent->next;
        }

        return rc;
}

static int do_xml(char *func, char *file)
{
        xmlDocPtr doc;
        xmlNodePtr cur;
        int rc;

        doc = xmlParseFile(file);
        if (doc == NULL) {
                fprintf(stderr, "error: Unable to parse XML\n");
                return -1; 
        }

        cur = xmlDocGetRootElement(doc);
        if (cur == NULL) {
                fprintf(stderr, "error: Empty XML\n");
                xmlFreeDoc(doc);
                return -1;
        }
        
        if (xmlStrcmp(cur->name, (const xmlChar *)"lustre")) {
                fprintf(stderr, "error: Root node != <lustre>\n");
                xmlFreeDoc(doc);
                return -1;
        }

        /* FIXME: Validate the XML against the DTD here */
    
        /* FIXME: Merge all the text nodes under each branch and 
         *        prune empty nodes.  Just to make the parsing more
         *        tolerant, the exact location of nested tags isn't
         *        critical for this.
         */
        
        rc = xml_node(doc, cur->xmlChildrenNode);
        xmlFreeDoc(doc);

        return rc;
}

static int do_device(char *func, int dev)
{
        struct obd_ioctl_data data;

        memset(&data, 0, sizeof(data));

        data.ioc_dev = dev;

        if (getfd(func))
                return -1;

        if (obd_ioctl_pack(&data, &buf, max)) {
                fprintf(stderr, "error: %s: invalid ioctl\n", cmdname(func));
                return -2;
        }

        return ioctl(fd, OBD_IOC_DEVICE , buf);
}

static int jt_device(int argc, char **argv)
{
        do_disconnect(argv[0], 1);

        if (argc != 2) {
                fprintf(stderr, "usage: %s devno\n", cmdname(argv[0]));
                return -1;
        }

        rc = do_device(argv[0], strtoul(argv[1], NULL, 0));

        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc = errno));

        return rc;
}

static int jt_connect(int argc, char **argv)
{
        struct obd_ioctl_data data;

        IOCINIT(data);

        do_disconnect(argv[0], 1);

        if (argc != 1) {
                fprintf(stderr, "usage: %s\n", cmdname(argv[0]));
                return -1;
        }

        rc = ioctl(fd, OBD_IOC_CONNECT , &data);
        if (rc < 0)
                fprintf(stderr, "error: %s: %x %s\n", cmdname(argv[0]),
                        OBD_IOC_CONNECT, strerror(rc = errno));
        else
                conn_addr = data.ioc_addr;
                conn_cookie = data.ioc_cookie;
        return rc;
}

static int jt_disconnect(int argc, char **argv)
{
        if (argc != 1) {
                fprintf(stderr, "usage: %s\n", cmdname(argv[0]));
                return -1;
        }

        if (conn_addr == -1)
                return 0;

        return do_disconnect(argv[0], 0);
}

static int jt__xml(int argc, char **argv)
{
        if (argc < 2) {
                fprintf(stderr, "usage: %s <xml file> <command [args ...]>\n",
                        cmdname(argv[0]));
                return -1;
        }

        return do_xml("xml", argv[1]);
}

static int jt__device(int argc, char **argv)
{
        char *arg2[3];
        int ret;

        if (argc < 3) {
                fprintf(stderr, "usage: %s devno <command [args ...]>\n",
                        cmdname(argv[0]));
                return -1;
        }

        rc = do_device("device", strtoul(argv[1], NULL, 0));

        if (!rc) {
                arg2[0] = "connect";
                arg2[1] = NULL;
                rc = jt_connect(1, arg2);
        }

        if (!rc)
                rc = Parser_execarg(argc - 2, argv + 2, cmdlist);

        ret = do_disconnect(argv[0], 0);
        if (!rc)
                rc = ret;

        return rc;
}

static int jt__threads(int argc, char **argv)
{
        int threads, next_thread;
        int verbose;
        int i, j;

        if (argc < 5) {
                fprintf(stderr,
                        "usage: %s numthreads verbose devno <cmd [args ...]>\n",
                        argv[0]);
                return -1;
        }

        threads = strtoul(argv[1], NULL, 0);

        verbose = get_verbose(argv[2]);

        printf("%s: starting %d threads on device %s running %s\n",
               argv[0], threads, argv[3], argv[4]);

        for (i = 1, next_thread = verbose; i <= threads; i++) {
                rc = fork();
                if (rc < 0) {
                        fprintf(stderr, "error: %s: #%d - %s\n", argv[0], i,
                                strerror(rc = errno));
                        break;
                } else if (rc == 0) {
                        thread = i;
                        argv[2] = "--device";
                        return jt__device(argc - 2, argv + 2);
                } else if (be_verbose(verbose, NULL, i, &next_thread, threads))
                        printf("%s: thread #%d (PID %d) started\n",
                               argv[0], i, rc);
                rc = 0;
        }

        if (!thread) { /* parent process */
                if (!verbose)
                        printf("%s: started %d threads\n\n", argv[0], i - 1);
                else
                        printf("\n");

                for (j = 1; j < i; j++) {
                        int status;
                        int ret = wait(&status);

                        if (ret < 0) {
                                fprintf(stderr, "error: %s: wait - %s\n",
                                        argv[0], strerror(errno));
                                if (!rc)
                                        rc = errno;
                        } else {
                                /*
                                 * This is a hack.  We _should_ be able to use
                                 * WIFEXITED(status) to see if there was an
                                 * error, but it appears to be broken and it
                                 * always returns 1 (OK).  See wait(2).
                                 */
                                int err = WEXITSTATUS(status);
                                if (err)
                                        fprintf(stderr,
                                                "%s: PID %d had rc=%d\n",
                                                argv[0], ret, err);
                                if (!rc)
                                        rc = err;
                        }
                }
        }

        return rc;
}

static int jt_detach(int argc, char **argv)
{
        struct obd_ioctl_data data;

        IOCINIT(data);

        if (argc != 1) {
                fprintf(stderr, "usage: %s\n", cmdname(argv[0]));
                return -1;
        }

        if (obd_ioctl_pack(&data, &buf, max)) {
                fprintf(stderr, "error: %s: invalid ioctl\n", cmdname(argv[0]));
                return -2;
        }

        rc = ioctl(fd, OBD_IOC_DETACH , buf);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc=errno));

        return rc;
}

static int jt_cleanup(int argc, char **argv)
{
        struct obd_ioctl_data data;

        IOCINIT(data);

        if (argc != 1) {
                fprintf(stderr, "usage: %s\n", cmdname(argv[0]));
                return -1;
        }

        rc = ioctl(fd, OBD_IOC_CLEANUP , &data);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc=errno));

        return rc;
}

static int jt_newdev(int argc, char **argv)
{
        struct obd_ioctl_data data;

        if (getfd(argv[0]))
                return -1;

        IOCINIT(data);

        if (argc != 1) {
                fprintf(stderr, "usage: %s\n", cmdname(argv[0]));
                return -1;
        }

        rc = ioctl(fd, OBD_IOC_NEWDEV , &data);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc=errno));
        else {
                printf("Current device set to %d\n", data.ioc_dev);
        }

        return rc;
}

static int jt_list(int argc, char **argv)
{
        char buf[1024];
        struct obd_ioctl_data *data = (struct obd_ioctl_data *)buf;

        if (getfd(argv[0]))
                return -1;

        memset(buf, 0, sizeof(buf));
        data->ioc_version = OBD_IOCTL_VERSION;
        data->ioc_addr = conn_addr;
        data->ioc_cookie = conn_addr;
        data->ioc_len = sizeof(buf);
        data->ioc_inllen1 = sizeof(buf) - size_round(sizeof(*data));

        if (argc != 1) {
                fprintf(stderr, "usage: %s\n", cmdname(argv[0]));
                return -1;
        }

        rc = ioctl(fd, OBD_IOC_LIST , data);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc=errno));
        else {
                printf("%s", data->ioc_bulk);
        }

        return rc;
}

static int jt_attach(int argc, char **argv)
{
        struct obd_ioctl_data data;

        IOCINIT(data);

        if (argc != 2 && argc != 3 && argc != 4) {
                fprintf(stderr, "usage: %s type [name [uuid]]\n",
                        cmdname(argv[0]));
                return -1;
        }

        data.ioc_inllen1 =  strlen(argv[1]) + 1;
        data.ioc_inlbuf1 = argv[1];
        if (argc >= 3) {
                data.ioc_inllen2 = strlen(argv[2]) + 1;
                data.ioc_inlbuf2 = argv[2];
        }

        if (argc == 4) {
                data.ioc_inllen3 = strlen(argv[3]) + 1;
                data.ioc_inlbuf3 = argv[3];
        }

        if (obd_ioctl_pack(&data, &buf, max)) {
                fprintf(stderr, "error: %s: invalid ioctl\n", cmdname(argv[0]));
                return -2;
        }

        rc = ioctl(fd, OBD_IOC_ATTACH , buf);
        if (rc < 0)
                fprintf(stderr, "error: %s: %x %s\n", cmdname(argv[0]),
                        OBD_IOC_ATTACH, strerror(rc = errno));
        else if (argc == 3) {
                char name[1024];
                if (strlen(argv[2]) > 128) {
                        printf("Name too long to set environment\n");
                        return -EINVAL;
                }
                snprintf(name, 512, "LUSTRE_DEV_%s", argv[2]);
                rc = setenv(name, argv[1], 1);
                if (rc) {
                        printf("error setting env variable %s\n", name);
                }
        }

        return rc;
}

#define N2D_OFF 0x100    /* So we can tell between error codes and devices */

static int do_name2dev(char *func, char *name)
{
        struct obd_ioctl_data data;

        if (getfd(func))
                return -1;

        IOCINIT(data);

        data.ioc_inllen1 = strlen(name) + 1;
        data.ioc_inlbuf1 = name;

        if (obd_ioctl_pack(&data, &buf, max)) {
                fprintf(stderr, "error: %s: invalid ioctl\n", cmdname(func));
                return -2;
        }
        rc = ioctl(fd, OBD_IOC_NAME2DEV , buf);
        if (rc < 0) {
                fprintf(stderr, "error: %s: %s - %s\n", cmdname(func),
                        name, strerror(rc = errno));
                return rc;
        }

        memcpy((char *)(&data), buf, sizeof(data));

        return data.ioc_dev + N2D_OFF;
}

static int jt_name2dev(int argc, char **argv)
{
        if (argc != 2) {
                fprintf(stderr, "usage: %s name\n", cmdname(argv[0]));
                return -1;
        }

        rc = do_name2dev(argv[0], argv[1]);
        if (rc >= N2D_OFF) {
                int dev = rc - N2D_OFF;
                rc = do_device(argv[0], dev);
                if (rc == 0)
                        printf("%d\n", dev);
        }
        return rc;
}

static int jt_setup(int argc, char **argv)
{
        struct obd_ioctl_data data;

        IOCINIT(data);

        if ( argc > 3) {
                fprintf(stderr, "usage: %s [device] [fstype]\n",
                        cmdname(argv[0]));
                return -1;
        }

        data.ioc_dev = -1;
        if (argc > 1) {
                if (argv[1][0] == '$') {
                        rc = do_name2dev(argv[0], argv[1] + 1);
                        if (rc >= N2D_OFF) {
                                printf("%s is device %d\n", argv[1],
                                       rc - N2D_OFF);
                                data.ioc_dev = rc - N2D_OFF;
                        }
                } else
                        data.ioc_dev = strtoul(argv[1], NULL, 0);
                data.ioc_inllen1 = strlen(argv[1]) + 1;
                data.ioc_inlbuf1 = argv[1];
        }
        if ( argc == 3 ) {
                data.ioc_inllen2 = strlen(argv[2]) + 1;
                data.ioc_inlbuf2 = argv[2];
        }

        if (obd_ioctl_pack(&data, &buf, max)) {
                fprintf(stderr, "error: %s: invalid ioctl\n", cmdname(argv[0]));
                return -2;
        }
        rc = ioctl(fd, OBD_IOC_SETUP , buf);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc = errno));

        return rc;
}


static int jt_create(int argc, char **argv)
{
        struct obd_ioctl_data data;
        struct timeval next_time;
        int count = 1, next_count;
        int verbose;
        int i;

        IOCINIT(data);
        if (argc < 2 || argc > 4) {
                fprintf(stderr, "usage: %s num [mode] [verbose]\n",
                        cmdname(argv[0]));
                return -1;
        }
        count = strtoul(argv[1], NULL, 0);

        if (argc > 2)
                data.ioc_obdo1.o_mode = strtoul(argv[2], NULL, 0);
        else
                data.ioc_obdo1.o_mode = 0100644;
        data.ioc_obdo1.o_valid = OBD_MD_FLMODE;

        verbose = get_verbose(argv[3]);

        printf("%s: %d obdos\n", cmdname(argv[0]), count);
        gettimeofday(&next_time, NULL);
        next_time.tv_sec -= verbose;

        for (i = 1, next_count = verbose; i <= count ; i++) {
                rc = ioctl(fd, OBD_IOC_CREATE , &data);
                if (rc < 0) {
                        fprintf(stderr, "error: %s: #%d - %s\n",
                                cmdname(argv[0]), i, strerror(rc = errno));
                        break;
                }
                if (be_verbose(verbose, &next_time, i, &next_count, count))
                        printf("%s: #%d is object id %Ld\n", cmdname(argv[0]),
                               i, data.ioc_obdo1.o_id);
        }
        return rc;
}

static int jt_setattr(int argc, char **argv)
{
        struct obd_ioctl_data data;

        IOCINIT(data);
        if (argc != 2) {
                fprintf(stderr, "usage: %s id mode\n", cmdname(argv[0]));
                return -1;
        }

        data.ioc_obdo1.o_id = strtoul(argv[1], NULL, 0);
        data.ioc_obdo1.o_mode = S_IFREG | strtoul(argv[2], NULL, 0);
        data.ioc_obdo1.o_valid = OBD_MD_FLMODE;

        rc = ioctl(fd, OBD_IOC_SETATTR , &data);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc = errno));

        return rc;
}

static int jt_destroy(int argc, char **argv)
{
        struct obd_ioctl_data data;

        IOCINIT(data);
        if (argc != 2) {
                fprintf(stderr, "usage: %s id\n", cmdname(argv[0]));
                return -1;
        }

        data.ioc_obdo1.o_id = strtoul(argv[1], NULL, 0);
        data.ioc_obdo1.o_mode = S_IFREG|0644;

        rc = ioctl(fd, OBD_IOC_DESTROY , &data);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc = errno));

        return rc;
}

static int jt_getattr(int argc, char **argv)
{
        struct obd_ioctl_data data;

        if (argc != 2) {
                fprintf(stderr, "usage: %s id\n", cmdname(argv[0]));
                return -1;
        }

        IOCINIT(data);
        data.ioc_obdo1.o_id = strtoul(argv[1], NULL, 0);
        /* to help obd filter */
        data.ioc_obdo1.o_mode = 0100644;
        data.ioc_obdo1.o_valid = 0xffffffff;
        printf("%s: object id %Ld\n", cmdname(argv[0]), data.ioc_obdo1.o_id);

        rc = ioctl(fd, OBD_IOC_GETATTR , &data);
        if (rc) {
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc=errno));
        } else {
                printf("%s: object id %Ld, mode %o\n", cmdname(argv[0]),
                       data.ioc_obdo1.o_id, data.ioc_obdo1.o_mode);
        }
        return rc;
}

static int jt_test_getattr(int argc, char **argv)
{
        struct obd_ioctl_data data;
        struct timeval start, next_time;
        int i, count, next_count;
        int verbose;

        if (argc != 2 && argc != 3) {
                fprintf(stderr, "usage: %s count [verbose]\n",cmdname(argv[0]));
                return -1;
        }

        IOCINIT(data);
        count = strtoul(argv[1], NULL, 0);

        if (argc == 3)
                verbose = get_verbose(argv[2]);
        else
                verbose = 1;

        data.ioc_obdo1.o_valid = 0xffffffff;
        data.ioc_obdo1.o_id = 2;
        gettimeofday(&start, NULL);
        next_time.tv_sec = start.tv_sec - verbose;
        next_time.tv_usec = start.tv_usec;
        printf("%s: getting %d attrs (testing only): %s", cmdname(argv[0]),
               count, ctime(&start.tv_sec));

        for (i = 1, next_count = verbose; i <= count; i++) {
                rc = ioctl(fd, OBD_IOC_GETATTR , &data);
                if (rc < 0) {
                        fprintf(stderr, "error: %s: #%d - %s\n",
                                cmdname(argv[0]), i, strerror(rc = errno));
                        break;
                } else {
                        if (be_verbose(verbose, &next_time, i,&next_count,count))
                        printf("%s: got attr #%d\n", cmdname(argv[0]), i);
        	}
	}

        if (!rc) {
                struct timeval end;
                double diff;

                gettimeofday(&end, NULL);

                diff = difftime(&end, &start);

                --i;
                printf("%s: %d attrs in %.4gs (%.4g attr/s): %s",
                       cmdname(argv[0]), i, diff, (double)i / diff,
                       ctime(&end.tv_sec));
        }
        return rc;
}

static int jt_test_brw(int argc, char **argv)
{
        struct obd_ioctl_data data;
        struct timeval start, next_time;
        char *bulk, *b;
        int pages = 1, obdos = 1, count, next_count;
        int verbose = 1, write = 0, rw;
        int i, o, p;
        int len;

        if (argc < 2 || argc > 6) {
                fprintf(stderr,
                        "usage: %s count [write [verbose [pages [obdos]]]]\n",
                        cmdname(argv[0]));
                return -1;
        }

        count = strtoul(argv[1], NULL, 0);

        if (argc >= 3) {
                if (argv[2][0] == 'w' || argv[2][0] == '1')
                        write = 1;
                else if (argv[2][0] == 'r' || argv[2][0] == '0')
                        write = 0;

                verbose = get_verbose(argv[3]);
        }

        if (argc >= 5)
                pages = strtoul(argv[4], NULL, 0);
        if (argc >= 6)
                obdos = strtoul(argv[5], NULL, 0);

        if (obdos != 1 && obdos != 2) {
                fprintf(stderr, "error: %s: only 1 or 2 obdos supported\n",
                        cmdname(argv[0]));
                return -2;
        }

        len = pages * PAGE_SIZE;

        bulk = calloc(obdos, len);
        if (!bulk) {
                fprintf(stderr, "error: %s: no memory allocating %dx%d pages\n",
                        cmdname(argv[0]), obdos, pages);
                return -2;
        }
        IOCINIT(data);
        data.ioc_obdo1.o_id = 2;
        data.ioc_count = len;
        data.ioc_offset = 0;
        data.ioc_plen1 = len;
        data.ioc_pbuf1 = bulk;
        if (obdos > 1) {
                data.ioc_obdo2.o_id = 3;
                data.ioc_plen2 = len;
                data.ioc_pbuf2 = bulk + len;
        }

        gettimeofday(&start, NULL);
        next_time.tv_sec = start.tv_sec - verbose;
        next_time.tv_usec = start.tv_usec;

        printf("%s: %s %d (%dx%d pages) (testing only): %s",
               cmdname(argv[0]), write ? "writing" : "reading",
               count, obdos, pages, ctime(&start.tv_sec));

        /*
         * We will put in the start time (and loop count inside the loop)
         * at the beginning of each page so that we will be able to validate
         * (at some later time) whether the data actually made it or not.
         *
         * XXX we do not currently use any of this memory in OBD_IOC_BRW_*
         *     just to avoid the overhead of the copy_{to,from}_user.  It
         *     can be fixed if we ever need to send real data around.
         */
        for (o = 0, b = bulk; o < obdos; o++)
                for (p = 0; p < pages; p++, b += PAGE_SIZE)
                        memcpy(b, &start, sizeof(start));

        rw = write ? OBD_IOC_BRW_WRITE : OBD_IOC_BRW_READ;
        for (i = 1, next_count = verbose; i <= count; i++) {
                if (write) {
                        b = bulk + sizeof(struct timeval);
                        for (o = 0; o < obdos; o++)
                                for (p = 0; p < pages; p++, b += PAGE_SIZE)
                                        memcpy(b, &count, sizeof(count));
                }

                rc = ioctl(fd, rw, &data);
                if (rc) {
                        fprintf(stderr, "error: %s: #%d - %s on %s\n",
                                cmdname(argv[0]), i, strerror(rc = errno),
                                write ? "write" : "read");
                        break;
                } else if (be_verbose(verbose, &next_time, i,&next_count,count))
                        printf("%s: %s number %d\n", cmdname(argv[0]),
                               write ? "write" : "read", i);
        }

        free(bulk);

        if (!rc) {
                struct timeval end;
                double diff;

                gettimeofday(&end, NULL);

                diff = difftime(&end, &start);

                --i;
                printf("%s: %s %dx%dx%d pages in %.4gs (%.4g pg/s): %s",
                       cmdname(argv[0]), write ? "wrote" : "read", obdos,
                       pages, i, diff, (double)obdos * i * pages / diff,
                       ctime(&end.tv_sec));
        }
        return rc;
}

static int jt_test_ldlm(int argc, char **argv)
{
        struct obd_ioctl_data data;

        IOCINIT(data);
        if (argc != 1) {
                fprintf(stderr, "usage: %s\n", cmdname(argv[0]));
                return 1;
        }

        rc = ioctl(fd, IOC_LDLM_TEST, &data);
        if (rc)
                fprintf(stderr, "error: %s: test failed: %s\n",
                        cmdname(argv[0]), strerror(rc = errno));
        return rc;
}

static int jt_newconn(int argc, char **argv)
{
        struct obd_ioctl_data data;

        IOCINIT(data);
        if (argc != 1) {
                fprintf(stderr, "usage: %s\n", cmdname(argv[0]));
                return -1;
        }

        rc = ioctl(fd, OBD_IOC_RECOVD_NEWCONN , &data);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", cmdname(argv[0]),
                        strerror(rc = errno));

        return rc;
}

static int jt_quit(int argc, char **argv)
{
        Parser_quit(argc, argv);

        return rc;
}

command_t cmdlist[] = {
        /* Metacommands */
        {"--xml", jt__xml, 0, "--xml <xml file> <command [args ...]>"},
        {"--device", jt__device, 0, "--device <devno> <command [args ...]>"},
        {"--threads", jt__threads, 0,
                "--threads <threads> <devno> <command [args ...]>"},

        /* Device configuration commands */
        {"list", jt_list, 0, "list the devices (no args)"},
        {"newdev", jt_newdev, 0, "set device to a new unused obd (no args)"},
        {"device", jt_device, 0, "set current device (args device_no name)"},
        {"name2dev", jt_name2dev, 0, "set device by name (args name)"},
        {"attach", jt_attach, 0, "name the type of device (args: type data"},
        {"setup", jt_setup, 0, "setup device (args: <blkdev> [data]"},
        {"detach", jt_detach, 0, "detach the current device (arg: )"},
        {"cleanup", jt_cleanup, 0, "cleanup the current device (arg: )"},

        /* Session commands */
        {"connect", jt_connect, 0, "connect - get a connection to device"},
        {"disconnect", jt_disconnect, 0,
                "disconnect - break connection to device"},

        /* Session operations */
        {"create", jt_create, 0, "create [count [mode [verbose]]]"},
        {"destroy", jt_destroy, 0, "destroy <id>"},
        {"getattr", jt_getattr, 0, "getattr <id>"},
        {"setattr", jt_setattr, 0, "setattr <id> <mode>"},
        {"newconn", jt_newconn, 0, "newconn [newuuid]"},
        {"test_getattr", jt_test_getattr, 0, "test_getattr <count> [verbose]"},
        {"test_brw", jt_test_brw, 0, "test_brw <count> [write [verbose]]"},
        {"test_ldlm", jt_test_ldlm, 0, "test lock manager (no args)"},

        /* User interface commands */
        {"help", Parser_help, 0, "help"},
        {"exit", jt_quit, 0, "quit"},
        {"quit", jt_quit, 0, "quit"},
        { 0, 0, 0, NULL }
};


static void signal_server(int sig)
{
        if (sig == SIGINT) {
                do_disconnect("sigint", 1);
                exit(1);
        } else {
                fprintf(stderr, "%s: got signal %d\n", cmdname("sigint"), sig);
        }
}

int main(int argc, char **argv)
{
        struct sigaction sigact;

        sigact.sa_handler = signal_server;
        sigfillset(&sigact.sa_mask);
        sigact.sa_flags = SA_RESTART;
        sigaction(SIGINT, &sigact, NULL);


        if (argc > 1) {
                rc = Parser_execarg(argc - 1, argv + 1, cmdlist);
        } else {
                Parser_init("obdctl > ", cmdlist);
                rc = Parser_commands();
        }

        do_disconnect(argv[0], 1);
        return rc;
}

