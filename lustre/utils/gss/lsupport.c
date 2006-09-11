/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2005 Cluster File Systems, Inc.
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
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "config.h"
#include <sys/param.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>

#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <dirent.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <assert.h>

#include "err_util.h"
#include "gssd.h"
#include "lsupport.h"

/****************************************
 * exclusive startup                    *
 ****************************************/

static struct __sem_s {
        char           *name;
        key_t           sem_key;
        int             sem_id;
} sems[2] = {
        [GSSD_CLI] = { "client",  0x3a92d473, 0 },
        [GSSD_SVC] = { "server",  0x3b92d473, 0 },
};

void gssd_init_unique(int type)
{
        struct __sem_s *sem = &sems[type];
        struct sembuf   sembuf;

        assert(type == GSSD_CLI || type == GSSD_SVC);

again:
        sem->sem_id = semget(sem->sem_key, 1, IPC_CREAT | IPC_EXCL | 0700);
        if (sem->sem_id == -1) {
                if (errno != EEXIST) {
                        printerr(0, "Create sem: %s\n", strerror(errno));
                        exit(-1);
                }

                /* already exist. Note there's still a small window racing
                 * with other processes, due to the stupid semaphore semantics.
                 */
                sem->sem_id = semget(sem->sem_key, 0, 0700);
                if (sem->sem_id == -1) {
                        if (errno == ENOENT) {
                                printerr(0, "another instance just exit, "
                                         "try again\n");
                                goto again;
                        }

                        printerr(0, "Obtain sem: %s\n", strerror(errno));
                        exit(-1);
                }
        } else {
                int val = 1;

                if (semctl(sem->sem_id, 0, SETVAL, val) == -1) {
                        printerr(0, "Initialize sem: %s\n",
                                 strerror(errno));
                        exit(-1);
                }
        }

        sembuf.sem_num = 0;
        sembuf.sem_op = -1;
        sembuf.sem_flg = IPC_NOWAIT | SEM_UNDO;

        if (semop(sem->sem_id, &sembuf, 1) != 0) {
                if (errno == EAGAIN) {
                        printerr(0, "Another instance is running, exit\n");
                        exit(0);
                }
                printerr(0, "Grab sem: %s\n", strerror(errno));
                exit(0);
        }

        printerr(2, "Successfully created %s global identity\n", sem->name);
}

void gssd_exit_unique(int type)
{
        assert(type == GSSD_CLI || type == GSSD_SVC);

        /*
         * do nothing. we can't remove the sem here, otherwise the race
         * window would be much bigger. So it's sad we have to leave the
         * sem in the system forever.
         */
}

/****************************************
 * client side resolvation:             *
 *    nal/netid/nid => hostname         *
 ****************************************/

char gethostname_ex[PATH_MAX] = GSSD_DEFAULT_GETHOSTNAME_EX;

typedef int ptl_nid2hostname_t(char *nal, uint32_t net, uint32_t addr,
                               char *buf, int buflen);

/* FIXME what about IPv6? */
static
int socknal_nid2hostname(char *nal, uint32_t net, uint32_t addr,
                         char *buf, int buflen)
{
        struct hostent  *ent;

        addr = htonl(addr);
        ent = gethostbyaddr(&addr, sizeof(addr), AF_INET);
        if (!ent) {
                printerr(0, "%s: can't resolve 0x%x\n", nal, addr);
                return -1;
        }
        if (strlen(ent->h_name) >= buflen) {
                printerr(0, "%s: name too long: %s\n", nal, ent->h_name);
                return -1;
        }
        strcpy(buf, ent->h_name);

        printerr(2, "%s: net 0x%x, addr 0x%x => %s\n",
                 nal, net, addr, buf);
        return 0;
}

static
int lonal_nid2hostname(char *nal, uint32_t net, uint32_t addr,
                       char *buf, int buflen)
{
        struct utsname   uts;
        struct hostent  *ent;

        if (addr) {
                printerr(0, "%s: addr is 0x%x, we expect 0\n", nal, addr);
                return -1;
        }

        if (uname(&uts)) {
                printerr(0, "%s: failed obtain local machine name\n", nal);
                return -1;
        }

        ent = gethostbyname(uts.nodename);
        if (!ent) {
                printerr(0, "%s: failed obtain canonical name of %s\n",
                         nal, uts.nodename);
                return -1;
        }

        if (strlen(ent->h_name) >= buflen) {
                printerr(0, "%s: name too long: %s\n", nal, ent->h_name);
                return -1;
        }
        strcpy(buf, ent->h_name);

        printerr(2, "%s: addr 0x%x => %s\n", nal, addr, buf);
        return 0;
}

static int is_space(char c)
{
        return (c == ' ' || c == '\t' || c == '\n');
}

static
int external_nid2hostname(char *nal, uint32_t net, uint32_t addr,
                           char *namebuf, int namebuflen)
{
        const int bufsize = PATH_MAX + 256;
        char buf[bufsize], *head, *tail;
        FILE *fghn;

        sprintf(buf, "%s %s 0x%x 0x%x", gethostname_ex, nal, net, addr);
        printerr(2, "cmd: %s\n", buf);

        fghn = popen(buf, "r");
        if (fghn == NULL) {
                printerr(0, "failed to call %s\n", gethostname_ex);
                return -1;
        }

        head = fgets(buf, bufsize, fghn);
        if (head == NULL) {
                printerr(0, "can't read\n");
                return -1;
        }
        if (pclose(fghn) == -1)
                printerr(1, "pclose failed, continue\n");

        /* trim head/tail space */
        while (is_space(*head))
                head++;

        tail = head + strlen(head);
        if (tail <= head) {
                printerr(0, "no output\n");
                return -1;
        }
        while (is_space(*(tail - 1)))
                tail--;
        if (tail <= head) {
                printerr(0, "output are all space\n");
                return -1;
        }
        *tail = '\0';

        /* start with '@' means error msg */
        if (head[0] == '@') {
                printerr(0, "%s\n", &head[1]);
                return -1;
        }

        if (tail - head > namebuflen) {
                printerr(0, "hostname too long: %s\n", head);
                return -1;
        }

        printerr(2, "%s: net 0x%x, addr 0x%x => %s\n",
                 nal, net, addr, head);
        strcpy(namebuf, head);
        return 0;
}

enum {
        QSWNAL    = 1,
        SOCKNAL   = 2,
        GMNAL     = 3,
        /*          4 unused */
        TCPNAL    = 5,
        ROUTER    = 6,
        OPENIBNAL = 7,
        IIBNAL    = 8,
        LONAL     = 9,
        RANAL     = 10,
        VIBNAL    = 11,
        NAL_ENUM_END_MARKER
};

static struct {
        char                    *name;
        ptl_nid2hostname_t      *nid2name;
} converter[NAL_ENUM_END_MARKER] = {
        {"UNUSED0",     NULL},
        {"QSWNAL",      external_nid2hostname},
        {"SOCKNAL",     socknal_nid2hostname},
        {"GMNAL",       external_nid2hostname},
        {"UNUSED4",     NULL},
        {"TCPNAL",      NULL},
        {"ROUTER",      NULL},
        {"OPENIBNAL",   external_nid2hostname},
        {"IIBNAL",      external_nid2hostname},
        {"LONAL",       lonal_nid2hostname},
        {"RANAL",       NULL},
        {"VIBNAL",      external_nid2hostname},
};

int ptl_nid2hostname(uint64_t nid, char *buf, int buflen)
{
        uint32_t nal, net, addr;

        addr = LNET_NIDADDR(nid);
        net = LNET_NIDNET(nid);
        nal = LNET_NETTYP(net);

        if (nal >= NAL_ENUM_END_MARKER) {
                printerr(0, "ERROR: Unrecognized NAL %u\n", nal);
                return -1;
        }

        if (converter[nal].nid2name == NULL) {
                printerr(0, "ERROR: NAL %s converter not ready\n",
                        converter[nal].name);
                return -1;
        }

        return converter[nal].nid2name(converter[nal].name, net, addr,
                                       buf, buflen);
}


/****************************************
 * portals support routine              *
 ****************************************/

static struct hostent *
ptl_gethostbyname(char * hname) {
        struct hostent *he;

        he = gethostbyname(hname);
        if (!he) {
                switch(h_errno) {
                case HOST_NOT_FOUND:
                case NO_ADDRESS:
                        printerr(0, "Unable to resolve hostname: %s\n",
                                 hname);
                        break;
                default:
                        printerr(0, "gethostbyname %s: %s\n",
                                 hname, strerror(h_errno));
                        break;
                }
                return NULL;
        }
        return he;
}

int
ptl_parse_ipquad (uint32_t *ipaddrp, char *str)
{
        int             a;
        int             b;
        int             c;
        int             d;

        if (sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d) == 4 &&
            (a & ~0xff) == 0 && (b & ~0xff) == 0 &&
            (c & ~0xff) == 0 && (d & ~0xff) == 0)
        {
                *ipaddrp = (a<<24)|(b<<16)|(c<<8)|d;
                return (0);
        }

        return (-1);
}

int
ptl_parse_ipaddr (uint32_t *ipaddrp, char *str)
{
        struct hostent *he;

        if (!strcmp (str, "_all_")) {
                *ipaddrp = 0;
                return (0);
        }

        if (ptl_parse_ipquad(ipaddrp, str) == 0)
                return (0);

        if ((('a' <= str[0] && str[0] <= 'z') ||
             ('A' <= str[0] && str[0] <= 'Z')) &&
             (he = ptl_gethostbyname (str)) != NULL) {
                uint32_t addr = *(uint32_t *)he->h_addr;

                *ipaddrp = ntohl(addr);         /* HOST byte order */
                return (0);
        }

        return (-1);
}

int
ptl_parse_nid (ptl_nid_t *nidp, char *str)
{
        uint32_t            ipaddr;
        char               *end;
        unsigned long long  ullval;

        if (ptl_parse_ipaddr (&ipaddr, str) == 0) {
#if !CRAY_PORTALS
                *nidp = (ptl_nid_t)ipaddr;
#else
                *nidp = (((ptl_nid_t)ipaddr & PNAL_HOSTID_MASK) << PNAL_VNODE_SHIFT);
#endif
                return (0);
        }

        ullval = strtoull(str, &end, 0);
        if (end != str && *end == 0) {
                /* parsed whole non-empty string */
                *nidp = (ptl_nid_t)ullval;
                return (0);
        }

        return (-1);
}


/****************************************
 * user mapping database handling       *
 * (very rudiment)                      *
 ****************************************/

#define MAPPING_GROW_SIZE       512
#define MAX_LINE_LEN            1024

struct user_map_item {
        char        *principal; /* NULL means match all */
        ptl_netid_t  netid;
        ptl_nid_t    nid;
        uid_t        uid;
};

struct user_mapping {
        int                   size;
        int                   nitems;
        struct user_map_item *items;
};

static struct user_mapping mapping = {0, 0, NULL};
/* FIXME to be finished: monitor change of mapping database */
static int mapping_changed = 1;

static
void cleanup_mapping(void)
{
        int n;

        for (n = 0; n < mapping.nitems; n++) {
                assert(mapping.items[n].principal);
                free(mapping.items[n].principal);
        }
        mapping.nitems = 0;
}

static
int grow_mapping(int size)
{
        struct user_map_item *new;
        int newsize;

        if (size <= mapping.size)
                return 0;

        newsize = mapping.size + MAPPING_GROW_SIZE;
        while (newsize < size)
                newsize += MAPPING_GROW_SIZE;

        new = malloc(newsize * sizeof(struct user_map_item));
        if (!new) {
                printerr(0, "can't alloc mapping size %d\n", newsize);
                return -1;
        }
        memcpy(new, mapping.items, mapping.nitems * sizeof(void*));
        free(mapping.items);
        mapping.items = new;
        mapping.size = newsize;
        return 0;
}

uid_t parse_uid(char *uidstr)
{
        struct passwd *pw;
        char *p = NULL;
        long uid;

        pw = getpwnam(uidstr);
        if (pw)
                return pw->pw_uid;

        uid = strtol(uidstr, &p, 0);
        if (*p == '\0')
                return (uid_t) uid;

        return -1;
}

static
int read_mapping_db(void)
{
        char princ[MAX_LINE_LEN];
        char nid_str[MAX_LINE_LEN];
        char dest[MAX_LINE_LEN];
        ptl_nid_t ptl_nid;
        uid_t dest_uid;
        FILE *f;
        char *line, linebuf[MAX_LINE_LEN];

        /* cleanup old mappings */
        cleanup_mapping();

        f = fopen(MAPPING_DATABASE_FILE, "r");
        if (!f) {
                printerr(0, "can't open mapping database: %s\n",
                         MAPPING_DATABASE_FILE);
                return -1;
        }

        while ((line = fgets(linebuf, MAX_LINE_LEN, f))) {
                char *name;

                if (strlen(line) >= MAX_LINE_LEN) {
                        printerr(0, "invalid mapping db: line too long (%d)\n",
                                 strlen(line));
                        cleanup_mapping();
                        fclose(f);
                        return -1;
                }
                if (sscanf(line, "%s %s %s", princ, nid_str, dest) != 3) {
                        printerr(0, "mapping db: syntax error\n");
                        cleanup_mapping();
                        fclose(f);
                        return -1;
                }
                if (grow_mapping(mapping.nitems + 1)) {
                        printerr(0, "fail to grow mapping to %d\n",
                                 mapping.nitems + 1);
                        fclose(f);
                        return -1;
                }
                if (!strcmp(princ, "*")) {
                        name = NULL;
                } else {
                        name = strdup(princ);
                        if (!name) {
                                printerr(0, "fail to dup str %s\n", princ);
                                fclose(f);
                                return -1;
                        }
                }
                if (ptl_parse_nid(&ptl_nid, nid_str)) {
                        printerr(0, "fail to parse nid %s\n", nid_str);
                        fclose(f);
                        return -1;
                }
                dest_uid = parse_uid(dest);
                if (dest_uid == -1) {
                        printerr(0, "no valid user: %s\n", dest);
                        free(name);
                        fclose(f);
                        return -1;
                }

                mapping.items[mapping.nitems].principal = name;
                mapping.items[mapping.nitems].netid = 0;
                mapping.items[mapping.nitems].nid = ptl_nid;
                mapping.items[mapping.nitems].uid = dest_uid;
                mapping.nitems++;
                printerr(1, "add mapping: %s(%s/0x%llx) ==> %d\n",
                         name ? name : "*", nid_str, ptl_nid, dest_uid);
        }

        return 0;
}

int lookup_mapping(char *princ, uint32_t nal, ptl_netid_t netid,
                   ptl_nid_t nid, uid_t *uid)
{
        int n;

        /* FIXME race condition here */
        if (mapping_changed) {
                if (read_mapping_db())
                        printerr(0, "all remote users will be denied\n");
                mapping_changed = 0;
        }

        for (n = 0; n < mapping.nitems; n++) {
                struct user_map_item *entry = &mapping.items[n];

                if (entry->netid != netid || entry->nid != nid)
                        continue;
                if (!entry->principal ||
                    !strcasecmp(entry->principal, princ)) {
                        printerr(1, "found mapping: %s ==> %d\n",
                                 princ, entry->uid);
                        *uid = entry->uid;
                        return 0;
                }
        }
        printerr(1, "no mapping for %s\n", princ);
        *uid = -1;
        return -1;
}

