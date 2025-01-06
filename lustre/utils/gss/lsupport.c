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
# include <gssapi/gssapi.h>
#endif
#include "lsupport.h"

const char * lustre_svc_name[] =
{
	[LUSTRE_GSS_SVC_MGS]    = "MGS",
	[LUSTRE_GSS_SVC_MDS]    = "MDS",
	[LUSTRE_GSS_SVC_OSS]    = "OSS",
};

/* exclusive startup */

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
			printerr(LL_ERR, "Create sem: %s\n", strerror(errno));
			exit(-1);
		}

		/* already exist. Note there's still a small window racing
		 * with other processes, due to the stupid semaphore semantics.
		 */
		sem->sem_id = semget(sem->sem_key, 0, 0700);
		if (sem->sem_id == -1) {
			if (errno == ENOENT) {
				printerr(LL_ERR,
					 "another instance just exit, try again\n");
				goto again;
			}

			printerr(LL_ERR, "Obtain sem: %s\n", strerror(errno));
			exit(-1);
		}
	} else {
		int val = 1;

		if (semctl(sem->sem_id, 0, SETVAL, val) == -1) {
			printerr(LL_ERR, "Initialize sem: %s\n",
				 strerror(errno));
			exit(-1);
		}
	}

	sembuf.sem_num = 0;
	sembuf.sem_op = -1;
	sembuf.sem_flg = IPC_NOWAIT | SEM_UNDO;

	if (semop(sem->sem_id, &sembuf, 1) != 0) {
		if (errno == EAGAIN) {
			printerr(LL_ERR, "Another instance is running, exit\n");
			exit(0);
		}
		printerr(LL_ERR, "Grab sem: %s\n", strerror(errno));
		exit(0);
	}

	printerr(LL_INFO, "Successfully created %s global identity\n",
		 sem->name);
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

int getcanonname(const char *host, char *buf, int buflen)
{
	struct addrinfo hints;
	struct addrinfo *ai = NULL;
	struct addrinfo *aip = NULL;
	int err = 0;
	int rc = 0;

	if (!host || host[0] == '\0') {
		printerr(LL_ERR,
			 "network address or hostname was not specified\n");
		return -1;
	}

	if (!buf) {
		printerr(LL_ERR,
			 "canonical name buffer was not defined\n");
		return -1;
	}

	if (buflen <= 0) {
		printerr(LL_ERR,
			 "invalid canonical name buffer length: %d\n", buflen);
		return -1;
	}

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_flags = AI_CANONNAME;

	err = getaddrinfo(host, NULL, &hints, &ai);
	if (err != 0) {
		printerr(LL_ERR,
			 "failed to get addrinfo for %s: %s\n",
			 host, gai_strerror(err));
		return -1;
	}

	for (aip = ai; aip; aip = aip->ai_next) {
		if (aip->ai_canonname && aip->ai_canonname[0] != '\0')
			break;
	}

	if (!aip) {
		printerr(LL_ERR, "failed to get canonical name of %s\n", host);
		rc = -1;
		goto out;
	}

	if (strlen(aip->ai_canonname) >= buflen) {
		printerr(LL_ERR, "canonical name is too long: %s\n",
			 aip->ai_canonname);
		rc = -1;
		goto out;
	}

	strncpy(buf, aip->ai_canonname, buflen);

out:
	if (ai != NULL)
		freeaddrinfo(ai);
	return rc;
}

static int getaddrcanonname(const uint32_t addr, char *buf, int buflen)
{
	struct sockaddr_in srcaddr;
	int err = 0;
	int rc = -1;

	if (!buf) {
		printerr(LL_ERR,
			 "canonical name buffer was not defined\n");
		goto out;
	}

	if (buflen <= 0) {
		printerr(LL_ERR,
			 "invalid canonical name buffer length: %d\n", buflen);
		goto out;
	}

	memset(&srcaddr, 0, sizeof(srcaddr));
	srcaddr.sin_family = AF_INET;
	srcaddr.sin_addr.s_addr = (in_addr_t)addr;

	err = getnameinfo((struct sockaddr *)&srcaddr, sizeof(srcaddr),
			  buf, buflen, NULL, 0, 0);
	if (err != 0) {
		printerr(LL_ERR,
			 "failed to get nameinfo for 0x%x: %s\n",
			 addr, gai_strerror(err));
		goto out;
	}
	rc = 0;

out:
	return rc;
}

/* FIXME what about IPv6? */
static
int ipv4_nid2hostname(char *lnd, uint32_t net, uint32_t addr,
		      char *buf, int buflen)
{
	addr = htonl(addr);

	if (getaddrcanonname(addr, buf, buflen) != 0) {
		printerr(LL_ERR, "%s: failed to get canonical name of 0x%x\n",
			 lnd, addr);
		return -1;
	}

	printerr(LL_INFO, "%s: net 0x%x, addr 0x%x => %s\n",
		 lnd, net, addr, buf);
	return 0;
}

static
int lolnd_nid2hostname(char *lnd, uint32_t net, uint32_t addr,
		       char *buf, int buflen)
{
	struct utsname uts;

	if (addr) {
		printerr(LL_ERR, "%s: addr is 0x%x, we expect 0\n", lnd, addr);
		return -1;
	}

	if (uname(&uts)) {
		printerr(LL_ERR, "%s: failed obtain local machine name\n", lnd);
		return -1;
	}

	if (getcanonname(uts.nodename, buf, buflen) != 0) {
		printerr(LL_ERR, "%s: failed to obtain canonical name of %s\n",
			 lnd, uts.nodename);
		return -1;
	}

	printerr(LL_DEBUG, "%s: addr 0x%x => %s\n", lnd, addr, buf);
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
	printerr(LL_INFO, "cmd: %s\n", buf);

	fghn = popen(buf, "r");
	if (fghn == NULL) {
		printerr(LL_ERR, "failed to call %s\n", gethostname_ex);
		return -1;
	}

	head = fgets(buf, bufsize, fghn);
	if (head == NULL) {
		printerr(LL_ERR, "can't read from %s\n", gethostname_ex);
		pclose(fghn);
		return -1;
	}
	if (pclose(fghn) == -1)
		printerr(LL_WARN, "pclose failed, continue\n");

	/* trim head/tail space */
	while (is_space(*head))
		head++;

	tail = head + strlen(head);
	if (tail <= head) {
		printerr(LL_ERR, "no output from %s\n", gethostname_ex);
		return -1;
	}
	while (is_space(*(tail - 1)))
		tail--;
	if (tail <= head) {
		printerr(LL_ERR, "output are all space from %s\n",
			 gethostname_ex);
		return -1;
	}
	*tail = '\0';

	/* start with '@' means error msg */
	if (head[0] == '@') {
		printerr(LL_ERR, "error from %s: %s\n",
			 gethostname_ex, &head[1]);
		return -1;
	}

	if (tail - head > namebuflen) {
		printerr(LL_ERR, "external hostname too long: %s\n", head);
		return -1;
	}

	printerr(LL_INFO, "%s: net 0x%x, addr 0x%x => %s\n",
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
	[PTL4LND] = { .name = "PTL4LND", .nid2name = external_nid2hostname },
	[KFILND]  = { .name = "KFILND",  .nid2name = ipv4_nid2hostname }
};

#define LND_MAX         (sizeof(converter) / sizeof(converter[0]))

int lnet_nid2hostname(lnet_nid_t nid, char *buf, int buflen)
{
	uint32_t lnd, net, addr;

	addr = LNET_NIDADDR(nid);
	net = LNET_NIDNET(nid);
	lnd = LNET_NETTYP(net);

	if (lnd >= LND_MAX) {
		printerr(LL_ERR, "ERROR: Unrecognized LND %u\n", lnd);
		return -1;
	}

	if (converter[lnd].nid2name == NULL) {
		printerr(LL_ERR, "ERROR: %s converter not ready\n",
			converter[lnd].name);
		return -1;
	}

	return converter[lnd].nid2name(converter[lnd].name, net, addr,
				       buf, buflen);
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

/* realm of this node */
char *krb5_this_realm;

static int gss_get_provided_realm(char *realm)
{
	if (krb5_this_realm)
		return 0;

	if (!realm)
		return -1;

	krb5_this_realm = strdup(realm);
	return 0;
}

static int gss_get_local_realm(void)
{
	krb5_context context = NULL;
	krb5_error_code code;

	if (krb5_this_realm != NULL)
		return 0;

	code = krb5_init_context(&context);
	if (code)
		return code;

	code = krb5_get_default_realm(context, &krb5_this_realm);
	krb5_free_context(context);

	if (code)
		return code;

	return 0;
}

int gss_get_realm(char *realm)
{
	int rc;

	/* Try to use provided realm first.
	 * If no provided realm, get default local realm.
	 */
	rc = gss_get_provided_realm(realm);
	if (rc)
		rc = gss_get_local_realm();

	return rc;
}
