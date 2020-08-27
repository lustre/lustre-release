/*
 * Modifications for Lustre
 *
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 2011, Intel Corporation.
 *
 * Author: Eric Mei <ericm@clusterfs.com>
 */

/*
 *  Adapted in part from MIT Kerberos 5-1.2.1 slave/kprop.c and from
 *  http://docs.sun.com/?p=/doc/816-1331/6m7oo9sms&a=view
 *
 *  Copyright (c) 2002 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Andy Adamson <andros@umich.edu>
 *  J. Bruce Fields <bfields@umich.edu>
 *  Marius Aamodt Eriksen <marius@umich.edu>
 */

/*
 * slave/kprop.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

/*
 * Copyright 1994 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "config.h"
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>
#include <syslog.h>
#include <gssapi/gssapi.h>
#if defined(HAVE_KRB5) && !defined(GSS_C_NT_HOSTBASED_SERVICE)
#include <gssapi/gssapi_generic.h>
#define GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#ifdef HAVE_COM_ERR_H
#include <com_err.h>
#endif
#include <libcfs/util/string.h>

#include "lsupport.h"
#include "lgss_utils.h"
#include "lgss_krb5_utils.h"

const char *lgss_svc_str[LGSS_SVC_MAX] = {
	[LGSS_SVC_MGS] = LGSS_SVC_MGS_STR,
	[LGSS_SVC_MDS] = LGSS_SVC_MDS_STR,
	[LGSS_SVC_OSS] = LGSS_SVC_OSS_STR,
};

/****************************************
 * inter-process locking                *
 ****************************************/

static struct lgss_mutex_s {
	char *sem_name;
	key_t sem_key;
	int   sem_id;
} lgss_mutexes[LGSS_MUTEX_MAX] = {
	[LGSS_MUTEX_KRB5] = { "keyring", 0x4292d473, 0 },
};

static int lgss_mutex_get(struct lgss_mutex_s *mutex)
{
	mutex->sem_id = semget(mutex->sem_key, 1, IPC_CREAT | IPC_EXCL | 0700);
	if (mutex->sem_id != -1) {
		if (semctl(mutex->sem_id, 0, SETVAL, 1) == -1) {
			logmsg(LL_ERR, "initialize sem %x: %s\n",
			       mutex->sem_key, strerror(errno));
			return -1;
		}

		logmsg(LL_DEBUG, "created & initialized sem %x id %d for %s\n",
		       mutex->sem_key, mutex->sem_id, mutex->sem_name);
	} else {
		if (errno != EEXIST) {
			logmsg(LL_ERR, "create sem %x: %s\n",
			       mutex->sem_key, strerror(errno));
			return -1;
		}

		/* already created by someone else, simply get it.
		 * Note there's still a small window of racing between create
		 * and initialize, a flaw in semaphore semantics */
		mutex->sem_id = semget(mutex->sem_key, 0, 0700);
		if (mutex->sem_id == -1) {
			if (errno == ENOENT) {
				logmsg(LL_WARN, "sem %x just disappeared "
				       "under us, try again\n", mutex->sem_key);
				return 1;
			}

			logmsg(LL_ERR, "get sem %x: %s\n", mutex->sem_key,
			       strerror(errno));
			return -1;
		}

		logmsg(LL_TRACE, "got sem %x id %d for %s\n",
		       mutex->sem_key, mutex->sem_id, mutex->sem_name);
	}

	return 0;
}

int lgss_mutex_lock(lgss_mutex_id_t mid)
{
	struct lgss_mutex_s *sem = &lgss_mutexes[mid];
	struct sembuf sembuf;
	int rc;

	lassert(mid < LGSS_MUTEX_MAX);

	logmsg(LL_TRACE, "locking mutex %x for %s\n",
	       sem->sem_key, sem->sem_name);

	do {
		rc = lgss_mutex_get(sem);
		if (rc < 0)
			return rc;
	} while (rc);

	sembuf.sem_num = 0;
	sembuf.sem_op = -1;
	sembuf.sem_flg = SEM_UNDO;

	if (semop(sem->sem_id, &sembuf, 1) != 0) {
		logmsg(LL_ERR, "lock mutex %x: %s\n", sem->sem_key,
		       strerror(errno));
		return -1;
	}

	logmsg(LL_DEBUG, "locked mutex %x for %s\n",
	       sem->sem_key, sem->sem_name);
	return 0;
}

int lgss_mutex_unlock(lgss_mutex_id_t mid)
{
	struct lgss_mutex_s *sem = &lgss_mutexes[mid];
	struct sembuf sembuf;

	lassert(mid < LGSS_MUTEX_MAX);
	lassert(sem->sem_id >= 0);

	logmsg(LL_TRACE, "unlocking mutex %x for %s\n",
	       sem->sem_key, sem->sem_name);

	sembuf.sem_num = 0;
	sembuf.sem_op = 1;
	sembuf.sem_flg = SEM_UNDO;

	if (semop(sem->sem_id, &sembuf, 1) != 0) {
		logmsg(LL_ERR, "unlock mutex %x: %s\n", sem->sem_key,
		       strerror(errno));
		return -1;
	}

	logmsg(LL_DEBUG, "unlocked mutex %x for %s\n",
	       sem->sem_key, sem->sem_name);
	return 0;
}

/****************************************
 * GSS OIDs, MECH                       *
 ****************************************/

/* from kerberos source, gssapi_krb5.c */
gss_OID_desc krb5oid = {
	.length = 9,
	.elements = "\052\206\110\206\367\022\001\002\002"
};
gss_OID_desc spkm3oid = {
	.length = 7,
	.elements = "\053\006\001\005\005\001\003"
};
/* null and sk come from IU's oid space */
gss_OID_desc nulloid = {
	.length = 12,
	.elements = "\053\006\001\004\001\311\146\215\126\001\000\000"
};
#ifdef HAVE_OPENSSL_SSK
gss_OID_desc skoid = {
	.length = 12,
	.elements = "\053\006\001\004\001\311\146\215\126\001\000\001"
};
#endif

/****************************************
 * log facilities                       *
 ****************************************/

loglevel_t g_log_level = LL_WARN;

static const char *const log_prefix[] = {
	[LL_ERR]        = "ERROR",
	[LL_WARN]       = "WARNING",
	[LL_INFO]       = "INFO",
	[LL_DEBUG]      = "DEBUG",
	[LL_TRACE]      = "TRACE",
};

void lgss_set_loglevel(loglevel_t level)
{
	lassert(level < LL_MAX);
	g_log_level = level;
}

void __logmsg(loglevel_t level, const char *func, const char *format, ...)
{
	va_list ap;
	int offset;
	char buf[1024];

	offset = scnprintf(buf, sizeof(buf), "[%d]:%s:%s(): ",
			   getpid(), log_prefix[level], func);

	va_start(ap, format);
	vsnprintf(buf + offset, sizeof(buf) - offset, format, ap);
	va_end(ap);

	syslog(LOG_INFO, "%s", buf);
}

void __logmsg_gss(loglevel_t level, const char *func, const gss_OID mech,
                  uint32_t major, uint32_t minor, const char *format, ...)
{
	va_list ap;
	uint32_t maj_stat1, min_stat1;
	uint32_t maj_stat2, min_stat2;
	gss_buffer_desc maj_gss_buf = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc min_gss_buf = GSS_C_EMPTY_BUFFER;
	char buf[1024];
	char maj_buf[30], min_buf[30];
	char *maj_msg, *min_msg;
	int offset;
	uint32_t msg_ctx = 0;

	/* Get major status message */
	maj_stat1 = gss_display_status(&min_stat1, major, GSS_C_GSS_CODE,
				       mech, &msg_ctx, &maj_gss_buf);
	if (maj_stat1 != GSS_S_COMPLETE) {
		snprintf(maj_buf, sizeof(maj_buf), "(0x%08x)", major);
		maj_msg = &maj_buf[0];
	} else {
		maj_msg = maj_gss_buf.value;
	}

	/* Get minor status message */
	maj_stat2 = gss_display_status(&min_stat2, minor, GSS_C_MECH_CODE,
				       mech, &msg_ctx, &min_gss_buf);
	if (maj_stat2 != GSS_S_COMPLETE) {
		snprintf(min_buf, sizeof(min_buf), "(0x%08x)", minor);
		min_msg = &min_buf[0];
	} else {
		min_msg = min_gss_buf.value;
	}

	/* arrange & log message */
	offset = scnprintf(buf, sizeof(buf), "[%d]:%s:%s(): ",
			   getpid(), log_prefix[level], func);

	va_start(ap, format);
	offset += vscnprintf(buf + offset, sizeof(buf) - offset, format, ap);
	va_end(ap);

	snprintf(buf + offset, sizeof(buf) - offset, ": GSSAPI: %s - %s\n",
		 maj_msg, min_msg);

	syslog(LOG_INFO, "%s", buf);

	/* release buffers */
	if (maj_gss_buf.length != 0)
		gss_release_buffer(&min_stat1, &maj_gss_buf);
	if (min_gss_buf.length != 0)
		gss_release_buffer(&min_stat2, &min_gss_buf);
}

/****************************************
 * client credentials                   *
 ****************************************/

struct lgss_mech_type *lgss_name2mech(const char *mech_name)
{
	if (strcmp(mech_name, "krb5") == 0)
		return &lgss_mech_krb5;
	if (strcmp(mech_name, "gssnull") == 0)
		return &lgss_mech_null;
#ifdef HAVE_OPENSSL_SSK
	if (strcmp(mech_name, "sk") == 0)
		return &lgss_mech_sk;
#endif
	return NULL;
}

int lgss_mech_initialize(struct lgss_mech_type *mech)
{
	logmsg(LL_TRACE, "initialize mech %s\n", mech->lmt_name);
	if (mech->lmt_init)
		return mech->lmt_init();
	return 0;
}

void lgss_mech_finalize(struct lgss_mech_type *mech)
{
	logmsg(LL_TRACE, "finalize mech %s\n", mech->lmt_name);
	if (mech->lmt_fini)
		mech->lmt_fini();
}

struct lgss_cred * lgss_create_cred(struct lgss_mech_type *mech)
{
	struct lgss_cred *cred;

	cred = malloc(sizeof(*cred));
	if (cred) {
		memset(cred, 0, sizeof(*cred));
		cred->lc_mech = mech;
	}

	logmsg(LL_TRACE, "create a %s cred at %p\n", mech->lmt_name, cred);
	return cred;
}

void lgss_destroy_cred(struct lgss_cred *cred)
{
	lassert(cred->lc_mech != NULL);
	lassert(cred->lc_mech_cred == NULL);

	logmsg(LL_TRACE, "destroying a %s cred at %p\n",
	       cred->lc_mech->lmt_name, cred);
	free(cred);
}

int lgss_prepare_cred(struct lgss_cred *cred)
{
	struct lgss_mech_type *mech = cred->lc_mech;

	lassert(mech != NULL);

	logmsg(LL_TRACE, "preparing %s cred %p\n", mech->lmt_name, cred);

	if (mech->lmt_prepare_cred)
		return mech->lmt_prepare_cred(cred);
	return 0;
}

void lgss_release_cred(struct lgss_cred *cred)
{
	struct lgss_mech_type *mech = cred->lc_mech;

	lassert(mech != NULL);

	logmsg(LL_TRACE, "releasing %s cred %p\n", mech->lmt_name, cred);

	if (cred->lc_mech_cred) {
		lassert(cred->lc_mech != NULL);
		lassert(cred->lc_mech->lmt_release_cred != NULL);

		cred->lc_mech->lmt_release_cred(cred);
	}
}

int lgss_using_cred(struct lgss_cred *cred)
{
	struct lgss_mech_type *mech = cred->lc_mech;

	lassert(mech != NULL);

	logmsg(LL_TRACE, "using %s cred %p\n", mech->lmt_name, cred);

	if (mech->lmt_using_cred)
		return mech->lmt_using_cred(cred);
	return 0;
}

int lgss_validate_cred(struct lgss_cred *cred, gss_buffer_desc *token,
		       gss_buffer_desc *ctx_token)
{
	struct lgss_mech_type *mech = cred->lc_mech;

	lassert(mech != NULL);

	logmsg(LL_TRACE, "validate %s cred %p with token %p\n", mech->lmt_name,
	       cred, token);

	if (mech->lmt_validate_cred)
		return mech->lmt_validate_cred(cred, token, ctx_token);

	return 0;
}

/****************************************
 * helper functions                     *
 ****************************************/

int lgss_get_service_str(char **string, uint32_t lsvc, uint64_t tgt_nid)
{
	const int max_namelen = 512;
	char namebuf[max_namelen];
	int alloc_size;

	lassert(*string == NULL);

	if (lsvc >= LGSS_SVC_MAX) {
		logmsg(LL_ERR, "invalid lgss service %d\n", lsvc);
		return -1;
	}

        if (lnet_nid2hostname(tgt_nid, namebuf, max_namelen)) {
		logmsg(LL_ERR, "cannot resolve hostname from nid %"PRIx64"\n",
		       tgt_nid);
		return -1;
	}

	alloc_size = 32 + strlen(namebuf);

	*string = malloc(alloc_size);
	if (*string == NULL) {
		logmsg(LL_ERR, "can't malloc %d bytes\n", alloc_size);
		return 1;
	}

	snprintf(*string, alloc_size, "%s@%s",
		 lgss_svc_str[lsvc], namebuf);

	logmsg(LL_DEBUG, "constructed service string: %s\n", *string);
	return 0;
}
