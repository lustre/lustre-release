/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
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

#include <stdbool.h>
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
#include <assert.h>
#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif
#ifdef _NEW_BUILD_
# include "lgss_utils.h"
#else
# include "err_util.h"
# include "gssd.h"
#endif
#include "lsupport.h"

const char * lustre_svc_name[] =
{
	[LUSTRE_GSS_SVC_MGS]    = "MGS",
	[LUSTRE_GSS_SVC_MDS]    = "MDS",
	[LUSTRE_GSS_SVC_OSS]    = "OSS",
};

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
 *    lnd/netid/nid => hostname         *
 ****************************************/

char gethostname_ex[PATH_MAX] = GSSD_DEFAULT_GETHOSTNAME_EX;

typedef int lnd_nid2hostname_t(char *lnd, uint32_t net, uint32_t addr,
                               char *buf, int buflen);

/* FIXME what about IPv6? */
static
int ipv4_nid2hostname(char *lnd, uint32_t net, uint32_t addr,
                      char *buf, int buflen)
{
        struct hostent  *ent;

        addr = htonl(addr);
        ent = gethostbyaddr(&addr, sizeof(addr), AF_INET);
        if (!ent) {
                printerr(0, "%s: can't resolve 0x%x\n", lnd, addr);
                return -1;
        }
        if (strlen(ent->h_name) >= buflen) {
                printerr(0, "%s: name too long: %s\n", lnd, ent->h_name);
                return -1;
        }
        strcpy(buf, ent->h_name);

        printerr(2, "%s: net 0x%x, addr 0x%x => %s\n",
                 lnd, net, addr, buf);
        return 0;
}

static
int lolnd_nid2hostname(char *lnd, uint32_t net, uint32_t addr,
                       char *buf, int buflen)
{
        struct utsname   uts;
        struct hostent  *ent;

        if (addr) {
                printerr(0, "%s: addr is 0x%x, we expect 0\n", lnd, addr);
                return -1;
        }

        if (uname(&uts)) {
                printerr(0, "%s: failed obtain local machine name\n", lnd);
                return -1;
        }

        ent = gethostbyname(uts.nodename);
        if (!ent) {
                printerr(0, "%s: failed obtain canonical name of %s\n",
                         lnd, uts.nodename);
                return -1;
        }

        if (strlen(ent->h_name) >= buflen) {
                printerr(0, "%s: name too long: %s\n", lnd, ent->h_name);
                return -1;
        }
        strcpy(buf, ent->h_name);

        printerr(3, "%s: addr 0x%x => %s\n", lnd, addr, buf);
        return 0;
}

static int is_space(char c)
{
        return (c == ' ' || c == '\t' || c == '\n');
}

static
int external_nid2hostname(char *lnd, uint32_t net, uint32_t addr,
                          char *namebuf, int namebuflen)
{
        const int bufsize = PATH_MAX + 256;
        char buf[bufsize], *head, *tail;
        FILE *fghn;

        sprintf(buf, "%s %s 0x%x 0x%x", gethostname_ex, lnd, net, addr);
        printerr(2, "cmd: %s\n", buf);

        fghn = popen(buf, "r");
        if (fghn == NULL) {
                printerr(0, "failed to call %s\n", gethostname_ex);
                return -1;
        }

        head = fgets(buf, bufsize, fghn);
        if (head == NULL) {
                printerr(0, "can't read from %s\n", gethostname_ex);
		pclose(fghn);
                return -1;
        }
        if (pclose(fghn) == -1)
                printerr(1, "pclose failed, continue\n");

        /* trim head/tail space */
        while (is_space(*head))
                head++;

        tail = head + strlen(head);
	if (tail <= head) {
                printerr(0, "no output from %s\n", gethostname_ex);
                return -1;
        }
        while (is_space(*(tail - 1)))
                tail--;
        if (tail <= head) {
                printerr(0, "output are all space from %s\n", gethostname_ex);
                return -1;
        }
        *tail = '\0';

        /* start with '@' means error msg */
        if (head[0] == '@') {
                printerr(0, "error from %s: %s\n", gethostname_ex, &head[1]);
                return -1;
        }

        if (tail - head > namebuflen) {
                printerr(0, "external hostname too long: %s\n", head);
                return -1;
        }

        printerr(2, "%s: net 0x%x, addr 0x%x => %s\n",
                 lnd, net, addr, head);
        strcpy(namebuf, head);
        return 0;
}

struct convert_struct {
        char                    *name;
        lnd_nid2hostname_t      *nid2name;
};

static struct convert_struct converter[] = {
	[0]	  = { .name = "UNUSED0" },
	[SOCKLND] = { .name = "SOCKLND", .nid2name = ipv4_nid2hostname },
	[O2IBLND] = { .name = "O2IBLND", .nid2name = ipv4_nid2hostname },
	[LOLND]	  = { .name = "LOLND",	 .nid2name = lolnd_nid2hostname },
	[PTL4LND] = { .name = "PTL4LND", .nid2name = external_nid2hostname }
};

#define LND_MAX         (sizeof(converter) / sizeof(converter[0]))

int lnet_nid2hostname(lnet_nid_t nid, char *buf, int buflen)
{
        uint32_t lnd, net, addr;

        addr = LNET_NIDADDR(nid);
        net = LNET_NIDNET(nid);
        lnd = LNET_NETTYP(net);

        if (lnd >= LND_MAX) {
                printerr(0, "ERROR: Unrecognized LND %u\n", lnd);
                return -1;
        }

        if (converter[lnd].nid2name == NULL) {
                printerr(0, "ERROR: %s converter not ready\n",
                        converter[lnd].name);
                return -1;
        }

        return converter[lnd].nid2name(converter[lnd].name, net, addr,
                                       buf, buflen);
}


/****************************************
 * user mapping database handling       *
 * (very rudiment)                      *
 ****************************************/

#define MAPPING_GROW_SIZE       512
#define MAX_LINE_LEN            256

struct user_map_item {
        char        *principal; /* NULL means match all */
        lnet_nid_t   nid;
        uid_t        uid;
};

struct user_mapping {
        int                   nitems;
        struct user_map_item *items;
};

static struct user_mapping mapping;
/* FIXME to be finished: monitor change of mapping database */
static int mapping_mtime = 0;

void cleanup_mapping(void)
{
        if (mapping.items) {
                for (; mapping.nitems > 0; mapping.nitems--)
                        if (mapping.items[mapping.nitems-1].principal)
                                free(mapping.items[mapping.nitems-1].principal);

                free(mapping.items);
                mapping.items = NULL;
        }
}

static int grow_mapping(int nitems)
{
        struct user_map_item *new;
        int oldsize, newsize;

        oldsize = (mapping.nitems * sizeof(struct user_map_item) +
                   MAPPING_GROW_SIZE - 1) / MAPPING_GROW_SIZE;
        newsize = (nitems * sizeof(struct user_map_item) +
                   MAPPING_GROW_SIZE - 1) / MAPPING_GROW_SIZE;
        while (newsize <= oldsize)
                return 0;

        newsize *= MAPPING_GROW_SIZE;
        new = malloc(newsize);
        if (!new) {
                printerr(0, "can't alloc mapping size %d\n", newsize);
                return -1;
        }

        if (mapping.items) {
                memcpy(new, mapping.items,
                       mapping.nitems * sizeof(struct user_map_item));
                free(mapping.items);
        }
        mapping.items = new;
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

static int read_mapping_db(void)
{
        char princ[MAX_LINE_LEN];
        char nid_str[MAX_LINE_LEN];
        char dest[MAX_LINE_LEN];
        char linebuf[MAX_LINE_LEN];
        char *line;
        lnet_nid_t nid;
        uid_t dest_uid;
        FILE *f;

        /* cleanup old mappings */
        cleanup_mapping();

        f = fopen(MAPPING_DATABASE_FILE, "r");
        if (!f) {
                printerr(0, "can't open mapping database: %s\n",
                         MAPPING_DATABASE_FILE);
                return -1;
        }

        while ((line = fgets(linebuf, MAX_LINE_LEN, f)) != NULL) {
                char *name;

                if (sscanf(line, "%s %s %s", princ, nid_str, dest) != 3) {
                        printerr(0, "mapping db: syntax error\n");
                        continue;
                }

                if (!strcmp(princ, "*")) {
                        name = NULL;
                } else {
                        name = strdup(princ);
                        if (!name) {
                                printerr(0, "fail to dup str %s\n", princ);
                                continue;
                        }
                }

                if (!strcmp(nid_str, "*")) {
                        nid = LNET_NID_ANY;
                } else {
                        nid = libcfs_str2nid(nid_str);
                        if (nid == LNET_NID_ANY) {
                                printerr(0, "fail to parse nid %s\n", nid_str);
                                if (name)
                                free(name);
                                continue;
                        }
                }

                dest_uid = parse_uid(dest);
                if (dest_uid == -1) {
                        printerr(0, "no valid user: %s\n", dest);
                        if (name)
                        free(name);
                        continue;
                }

                if (grow_mapping(mapping.nitems + 1)) {
                        printerr(0, "fail to grow mapping to %d\n",
                                 mapping.nitems + 1);
                        if (name)
                        free(name);
                        fclose(f);
                        return -1;
                }

                mapping.items[mapping.nitems].principal = name;
                mapping.items[mapping.nitems].nid = nid;
                mapping.items[mapping.nitems].uid = dest_uid;
                mapping.nitems++;
                printerr(1, "add mapping: %s(%s/0x%llx) ==> %d\n",
                         name, nid_str, nid, dest_uid);
        }

        fclose(f);
        return 0;
}

static inline int mapping_changed(void)
{
        struct stat st;

        if (stat(MAPPING_DATABASE_FILE, &st) == -1) {
                /* stat failed, treat it like doesn't exist or be removed */
                if (mapping_mtime == 0) {
                        return 0;
                } else {
                        printerr(0, "Warning: stat %s failed: %s\n",
                                 MAPPING_DATABASE_FILE, strerror(errno));

                        mapping_mtime = 0;
                        return 1;
                }
        }

        if (st.st_mtime != mapping_mtime) {
                mapping_mtime = st.st_mtime;
                return 1;
        }

        return 0;
}

int lookup_mapping(char *princ, lnet_nid_t nid, uid_t *uid)
{
        int n;

        *uid = -1;

        /* FIXME race condition here */
        if (mapping_changed()) {
                if (read_mapping_db())
                        printerr(0, "all remote users will be denied\n");
        }

        for (n = 0; n < mapping.nitems; n++) {
                struct user_map_item *entry = &mapping.items[n];

                if (entry->nid != LNET_NID_ANY && entry->nid != nid)
                        continue;
                if (!entry->principal || !strcasecmp(entry->principal, princ)) {
                        printerr(1, "found mapping: %s ==> %d\n",
                                 princ, entry->uid);
                        *uid = entry->uid;
                        return 0;
                }
        }

        printerr(2, "no mapping for %s/%#Lx\n", princ, nid);
        return -1;
}
