/*
 * Modifications for Lustre
 *
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Author: Eric Mei <ericm@clusterfs.com>
 */

/*
 *  Adapted in part from MIT Kerberos 5-1.2.1 slave/kprop.c and from
 *  http://docs.sun.com/?p=/doc/816-1331/6m7oo9sms&a=view
 *
 *  Copyright (c) 2002-2004 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Andy Adamson <andros@umich.edu>
 *  J. Bruce Fields <bfields@umich.edu>
 *  Marius Aamodt Eriksen <marius@umich.edu>
 *  Kevin Coffman <kwc@umich.edu>
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
/*
  krb5_util.c

  Copyright (c) 2004 The Regents of the University of Michigan.
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.
  3. Neither the name of the University nor the names of its
     contributors may be used to endorse or promote products derived
     from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "config.h"
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <krb5.h>

#include "lsupport.h"
#include "lgss_utils.h"
#include "lgss_krb5_utils.h"

char *lgss_client_realm;

static void lgss_krb5_mutex_lock(void)
{
        if (lgss_mutex_lock(LGSS_MUTEX_KRB5)) {
                logmsg(LL_ERR, "can't lock process, abort!\n");
                exit(-1);
        }
}

static void lgss_krb5_mutex_unlock(void)
{
        if (lgss_mutex_unlock(LGSS_MUTEX_KRB5)) {
                logmsg(LL_WARN, "can't unlock process, other processes "
                       "might need to wait long time\n");
        }
}

#define krb5_err_msg(code)      error_message(code)

const char *krb5_cred_root_suffix  = "lustre_root";
const char *krb5_cred_mds_suffix   = "lustre_mds";
const char *krb5_cred_oss_suffix   = "lustre_oss";

char    *krb5_keytab_file       = "/etc/krb5.keytab";

static int lgss_krb5_set_ccache_name(const char *ccname)
{
	unsigned int	maj_stat, min_stat;

	maj_stat = gss_krb5_ccache_name(&min_stat, ccname, NULL);
	if (maj_stat != GSS_S_COMPLETE) {
		logmsg(LL_ERR, "failed to set ccache name\n");
		return -1;
	}

	logmsg(LL_DEBUG, "set cc: %s\n", ccname);
	return 0;
}

static
int princ_is_local_realm(krb5_context ctx, krb5_principal princ)
{
        return (lgss_krb5_strcasecmp(krb5_princ_realm(ctx, princ),
                                     krb5_this_realm) == 0);
}

static
int svc_princ_verify_host(krb5_context ctx,
			  krb5_principal princ,
			  uint64_t self_nid,
			  loglevel_t loglevel)
{
	struct utsname utsbuf;
	const int max_namelen = 512;
	char namebuf[max_namelen];

	if (krb5_princ_component(ctx, princ, 1) == NULL) {
		logmsg(loglevel, "service principal has no host part\n");
		return -1;
	}

	if (self_nid != 0) {
		if (lnet_nid2hostname(self_nid, namebuf, max_namelen)) {
			logmsg(loglevel,
			       "can't resolve hostname from nid %"PRIx64"\n",
			       self_nid);
			return -1;
		}
	} else {
		if (uname(&utsbuf)) {
			logmsg(loglevel, "get UTS name: %s\n", strerror(errno));
			return -1;
		}

		if (getcanonname(utsbuf.nodename, namebuf, max_namelen) != 0) {
			logmsg(loglevel,
				"failed to get canonical name of %s\n",
				utsbuf.nodename);
			return -1;
		}
	}

	if (lgss_krb5_strcasecmp(krb5_princ_component(ctx, princ, 1),
				 namebuf)) {
		logmsg(loglevel, "service principal: hostname %.*s "
		       "doesn't match localhost %s\n",
		       krb5_princ_component(ctx, princ, 1)->length,
		       krb5_princ_component(ctx, princ, 1)->data,
		       namebuf);
		return -1;
	}

	return 0;
}

static int lkrb5_cc_check_tgt_princ(krb5_context ctx,
			     krb5_ccache ccache,
			     krb5_principal princ,
			     unsigned int flag,
			     uint64_t self_nid)
{
	unsigned int cred_type = 0;

	logmsg(LL_DEBUG, "principal: realm %.*s, type %d, size %d, name %.*s\n",
	       krb5_princ_realm(ctx, princ)->length,
	       krb5_princ_realm(ctx, princ)->data,
	       krb5_princ_type(ctx, princ),
	       krb5_princ_size(ctx, princ),
	       krb5_princ_name(ctx, princ)->length,
	       krb5_princ_name(ctx, princ)->data);

	/* check type */
	if (krb5_princ_type(ctx, princ) != KRB5_NT_PRINCIPAL) {
		logmsg(LL_WARN, "principal type %d is not I want\n",
		       krb5_princ_type(ctx, princ));
		return -1;
	}

	/* check local realm */
	if (!princ_is_local_realm(ctx, princ)) {
		logmsg(LL_WARN, "principal realm %.*s not local: %s\n",
		       krb5_princ_realm(ctx, princ)->length,
		       krb5_princ_realm(ctx, princ)->data,
		       krb5_this_realm);
		return -1;
	}

	/* check principal name against flag for cred type */
	if (lgss_krb5_strcmp(krb5_princ_name(ctx, princ),
			     LGSS_SVC_HOST_STR) == 0 ||
	    lgss_krb5_strcmp(krb5_princ_name(ctx, princ),
			     LGSS_USR_ROOT_STR) == 0)
		cred_type = LGSS_ROOT_CRED_ROOT;
	else if (lgss_krb5_strcmp(krb5_princ_name(ctx, princ),
				  LGSS_SVC_MGS_STR) == 0)
		cred_type = LGSS_ROOT_CRED_ROOT |
			     LGSS_ROOT_CRED_MDT |
			     LGSS_ROOT_CRED_OST;
	else if (lgss_krb5_strcmp(krb5_princ_name(ctx, princ),
				  LGSS_SVC_MDS_STR) == 0)
		cred_type = LGSS_ROOT_CRED_MDT;
	else if (lgss_krb5_strcmp(krb5_princ_name(ctx, princ),
				  LGSS_SVC_OSS_STR) == 0)
		cred_type = LGSS_ROOT_CRED_OST;

	if (!(flag & cred_type)) {
		char wanted[50];
		char *buf = wanted;

		if (flag & LGSS_ROOT_CRED_MDT)
			buf += snprintf(buf, sizeof(wanted) - (buf - wanted),
					"%s", LGSS_SVC_MDS_STR);
		if (flag & LGSS_ROOT_CRED_OST)
			buf += snprintf(buf, sizeof(wanted) - (buf - wanted),
					"%s%s",
				       buf == wanted ? "" : ",",
				       LGSS_SVC_OSS_STR);
		if (flag & LGSS_ROOT_CRED_ROOT) {
			buf += snprintf(buf, sizeof(wanted) - (buf - wanted),
					"%s%s",
					buf == wanted ? "" : ",",
					LGSS_USR_ROOT_STR);
			snprintf(buf, sizeof(wanted) - (buf - wanted), ",%s",
				 LGSS_SVC_HOST_STR);
		}
		logmsg(LL_WARN,
		       "Found in cc principal %.*s, but expecting one of %s instead\n",
		       krb5_princ_name(ctx, princ)->length,
		       krb5_princ_name(ctx, princ)->data,
		       wanted);
		return -1;
	}

	/*
	 * verify the hostname part of the principal, except we do allow
	 * lustre_root without binding to a host.
	 */
	if (krb5_princ_component(ctx, princ, 1) == NULL) {
		if (flag != LGSS_ROOT_CRED_ROOT) {
			logmsg(LL_WARN, "%.*s: missing hostname\n",
			       krb5_princ_name(ctx, princ)->length,
			       krb5_princ_name(ctx, princ)->data);
			return -1;
		}
	} else {
		if (svc_princ_verify_host(ctx, princ, self_nid, LL_WARN)) {
			logmsg(LL_DEBUG, "%.*s: doesn't belong to this node\n",
			       krb5_princ_name(ctx, princ)->length,
			       krb5_princ_name(ctx, princ)->data);
			return -1;
		}
	}

	logmsg(LL_TRACE, "principal is OK\n");
	return 0;
}

static inline int lgss_krb5_get_default_ccache_name(krb5_context ctx,
						    char *ccname, int size)
{
	if (snprintf(ccname, size, "%s", krb5_cc_default_name(ctx)) >= size)
		return -ENAMETOOLONG;

	return 0;
}

/**
 * compose the TGT cc name, abiding to system configuration.
 */
static int get_root_tgt_ccname(krb5_context ctx, char *ccname, int size)
{
	return lgss_krb5_get_default_ccache_name(ctx, ccname, size);
}

static int acquire_user_cred_and_check(char *ccname)
{
	gss_OID mech = (gss_OID)&krb5oid;
	gss_OID_set_desc desired_mechs = { 1, mech };
	gss_cred_id_t gss_cred;
	OM_uint32 maj_stat, min_stat, lifetime;
	int rc = 0;

	if (lgss_krb5_set_ccache_name(ccname)) {
		logmsg(LL_ERR, "cannot set ccache name: %s\n", ccname);
		return -1;
	}

	maj_stat = gss_acquire_cred(&min_stat, GSS_C_NO_NAME, GSS_C_INDEFINITE,
				    &desired_mechs, GSS_C_INITIATE,
				    &gss_cred, NULL, NULL);
	if (maj_stat != GSS_S_COMPLETE) {
		logmsg_gss(LL_INFO, mech, maj_stat, min_stat,
			   "failed gss_acquire_cred");
		return -1;
	}

	/* force validation of cred to check for expiry */
	maj_stat = gss_inquire_cred(&min_stat, gss_cred,
				    NULL, &lifetime, NULL, NULL);
	if (maj_stat != GSS_S_COMPLETE) {
		logmsg_gss(LL_INFO, mech, maj_stat, min_stat,
			   "failed gss_inquire_cred");
		rc = -1;
	}

	if (gss_cred != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&min_stat, &gss_cred);

	return rc;
}

static int filter_krb5_ccache(const struct dirent *d)
{
	if (strstr(d->d_name, LGSS_DEFAULT_CRED_PREFIX))
		return 1;
	else
		return 0;
}

/*
 * Look in dirname for a possibly valid ccache for uid.
 *
 * Returns 0 if a potential entry is found.
 * Otherwise, a negative errno is returned.
 */
static int find_existing_krb5_ccache(uid_t uid, char *dir,
				     char *ccname, int size)
{
	struct dirent **namelist;
	int found = 0;
	struct stat tmp_stat;
	char dirname[PATH_MAX], buf[PATH_MAX];
	int num_ents, i, j = 0, rc = -1;

	/* provided dir can be a pattern */
	for (i = 0; dir[i] != '\0'; i++) {
		switch (dir[i]) {
		case '%':
			switch (dir[i + 1]) {
			case 'U':
				j += sprintf(dirname + j, "%lu",
					     (unsigned long)uid);
				i++;
				break;
			}
			break;
		default:
			dirname[j++] = dir[i];
			break;
		}
	}
	dirname[j] = '\0';

	num_ents = scandir(dirname, &namelist, filter_krb5_ccache, 0);
	if (num_ents < 0) {
		logmsg(LL_INFO, "scandir %s failed: %s\n",
		       dirname, strerror(errno));
		goto end_find;
	}

	for (i = 0; i < num_ents; i++) {
		if (found)
			goto next_find;

		if (snprintf(buf, sizeof(buf), "%s/%s",
			     dirname, namelist[i]->d_name) >= sizeof(buf)) {
			logmsg(LL_INFO, "%s/%s name too long\n",
			       dirname, namelist[i]->d_name);
			goto next_find;
		}

		if (lstat(buf, &tmp_stat)) {
			logmsg(LL_INFO, "lstat %s failed: %s\n",
			       buf, strerror(errno));
			goto next_find;
		}

		/* we only look for files as credentials caches */
		if (!S_ISREG(tmp_stat.st_mode))
			goto next_find;

		/* make sure it is owned by uid */
		if (tmp_stat.st_uid != uid) {
			logmsg(LL_INFO, "%s not owned by %u\n",
			       buf, uid);
			goto next_find;
		}

		/* check user has rw perms */
		if (!(tmp_stat.st_mode & S_IRUSR &&
		      tmp_stat.st_mode & S_IWUSR)) {
			logmsg(LL_INFO, "%s does not have rw perms for %u\n",
			       buf, uid);
			goto next_find;
		}

		if (snprintf(ccname, size, "FILE:%s", buf) >= size) {
			logmsg(LL_INFO, "FILE:%s name too long\n", buf);
			goto next_find;
		}

		rc = acquire_user_cred_and_check(ccname);
		if (!rc)
			found = 1;

next_find:
		free(namelist[i]);
	}
	free(namelist);

end_find:
	return rc;
}

/**
 * Compose the TGT cc name for user, needs to fork process and switch identity.
 * For that reason, ccname buffer passed in must be mmapped with MAP_SHARED.
 */
static int get_user_tgt_ccname(struct lgss_cred *cred, krb5_context ctx,
			       char *ccname, int size)
{
	pid_t child;
	int status, rc = 0;

	/* fork to not change identity in main process, it needs to stay root
	 * in order to proceed to ioctls
	 */
	child = fork();
	if (child == -1) {
		logmsg(LL_ERR, "cannot fork child for user %u: %s\n",
		       cred->lc_uid, strerror(errno));
		rc = -errno;
	} else if (child == 0) {
		/* switch identity */
		rc = switch_identity(cred->lc_uid);
		if (rc)
			exit(1);

		/* getting default ccname requires impersonating user */
		rc = lgss_krb5_get_default_ccache_name(ctx, ccname, size);
		if (rc) {
			logmsg(LL_ERR,
			       "cannot get default ccname for user %u\n",
			       cred->lc_uid);
			exit(1);
		}

		/* job done for child */
		exit(0);
	} else {
		logmsg(LL_TRACE, "forked child %d\n", child);
		if (wait(&status) < 0) {
			logmsg(LL_ERR, "wait child %d failed: %s\n",
			       child, strerror(errno));
			return -errno;
		}
		if (!WIFEXITED(status)) {
			logmsg(LL_ERR, "child %d terminated with %d\n",
			       child, status);
			return status;
		}
	}

	/* try ccname as fetched by child */
	rc = acquire_user_cred_and_check(ccname);
	if (!rc)
		/* user's creds found in default ccache */
		goto end_ccache;

	/* fallback: look at every file matching
	 * - /tmp/ *krb5cc*
	 * - /run/user/<uid>/ *krb5cc*
	 */
	rc = find_existing_krb5_ccache(cred->lc_uid, LGSS_DEFAULT_CRED_DIR,
				       ccname, size);
	if (!rc)
		/* user's creds found in LGSS_DEFAULT_CRED_DIR */
		goto end_ccache;

	rc = find_existing_krb5_ccache(cred->lc_uid, LGSS_USER_CRED_DIR,
				       ccname, size);
	if (!rc)
		/* user's creds found in LGSS_USER_CRED_DIR */
		goto end_ccache;

	rc = -ENODATA;

end_ccache:
	return rc;
}

/**
 * find out whether current TGT cache is valid or not
 */
static int lkrb5_check_root_tgt_cc(krb5_context ctx, unsigned int flag,
				   uint64_t self_nid)
{
	krb5_ccache tgt_ccache;
	krb5_principal princ;
	krb5_cc_cursor cursor;
	krb5_error_code code;
	char ccname[PATH_MAX];
	krb5_creds cred;
	time_t now;
	int found;

	found = get_root_tgt_ccname(ctx, ccname, sizeof(ccname));
	if (found)
		return found;
	logmsg(LL_DEBUG, "root krb5 TGT ccname: %s\n", ccname);

	/* prepare parsing the cache file */
	code = krb5_cc_resolve(ctx, ccname, &tgt_ccache);
	if (code) {
		logmsg(LL_ERR, "resolve krb5 cc %s: %s\n",
		       ccname, krb5_err_msg(code));
		goto out_fail;
	}

	/* checks the principal */
	code = krb5_cc_get_principal(ctx, tgt_ccache, &princ);
	if (code) {
		logmsg(LL_ERR, "get cc principal: %s\n", krb5_err_msg(code));
		goto out_cc;
	}

	if (lkrb5_cc_check_tgt_princ(ctx, tgt_ccache, princ, flag, self_nid))
		goto out_princ;

	/*
	 * find a valid entry
	 */
	code = krb5_cc_start_seq_get(ctx, tgt_ccache, &cursor);
	if (code) {
		logmsg(LL_ERR, "start cc iteration: %s\n", krb5_err_msg(code));
		goto out_princ;
	}

	now = time(0);
	do {
		krb5_timestamp	duration, delta;

		code = krb5_cc_next_cred(ctx, tgt_ccache, &cursor, &cred);
		if (code != 0)
			break;

		logmsg(LL_DEBUG,
		       "cred: server realm %.*s, type %d, name %.*s; time (%lld-%lld, renew till %lld), valid %lld\n",
		       krb5_princ_realm(ctx, cred.server)->length,
		       krb5_princ_realm(ctx, cred.server)->data,
		       krb5_princ_type(ctx, cred.server),
		       krb5_princ_name(ctx, cred.server)->length,
		       krb5_princ_name(ctx, cred.server)->data,
		       (long long)cred.times.starttime,
		       (long long)cred.times.endtime,
		       (long long)cred.times.renew_till,
		       (long long)(cred.times.endtime - now));

		/* FIXME
		 * we found the princ type is always 0 (KRB5_NT_UNKNOWN), why???
		 */

		/* FIXME how about inter-realm TGT??? FIXME */
		if (lgss_krb5_strcasecmp(krb5_princ_name(ctx, cred.server),
					 "krbtgt"))
			continue;

		if (lgss_krb5_strcasecmp(krb5_princ_realm(ctx, cred.server),
					 krb5_this_realm))
			continue;

		/* check validity of time */
		delta = 60 * 30; /* half an hour */
		duration = cred.times.endtime - cred.times.starttime;
		if (duration / 4 < delta)
			delta = duration / 4;

		if (cred.times.starttime <= now &&
		    cred.times.endtime >= now + delta) {
			found = 1;
			break;
		}
	} while (1);

	krb5_cc_end_seq_get(ctx, tgt_ccache, &cursor);
out_princ:
	krb5_free_principal(ctx, princ);
out_cc:
	krb5_cc_close(ctx, tgt_ccache);

	if (found) {
		logmsg(LL_TRACE, "found good TGT cache\n");
		return lgss_krb5_set_ccache_name(ccname);
	}

out_fail:
	logmsg(LL_TRACE, "did not find good TGT cache\n");
	return -1;
}

static int lkrb5_get_root_tgt_keytab(krb5_context ctx, krb5_keytab kt,
				     krb5_principal princ, const char *ccname)
{
	krb5_get_init_creds_opt opts;
	krb5_creds cred;
	krb5_ccache tgt_ccache;
	krb5_error_code code;
	int rc = -1;

	krb5_get_init_creds_opt_init(&opts);
	krb5_get_init_creds_opt_set_address_list(&opts, NULL);
	/*
	 * by default krb5 library obtain ticket with lifetime shorter
	 * than the max value. we can change it here if we want. but
	 * seems not necessary now.
	 *
	 * krb5_get_init_creds_opt_set_tkt_life(&opts, very-long-time);
	 *
	 */

	/*
	 * obtain TGT and store into cache
	 */
	code = krb5_get_init_creds_keytab(ctx, &cred, princ, kt,
					  0, NULL, &opts);
	if (code) {
		logmsg(LL_ERR,
		       "failed to get root TGT for principal %.*s: %s\n",
		       krb5_princ_name(ctx, princ)->length,
		       krb5_princ_name(ctx, princ)->data,
		       krb5_err_msg(code));
		return -1;
	}

	code = krb5_cc_resolve(ctx, ccname, &tgt_ccache);
	if (code) {
		logmsg(LL_ERR, "resolve cc %s: %s\n",
		       ccname, krb5_err_msg(code));
		goto out_cred;
	}

	code = krb5_cc_initialize(ctx, tgt_ccache, princ);
	if (code) {
		logmsg(LL_ERR, "initialize cc %s: %s\n",
		       ccname, krb5_err_msg(code));
		goto out_cc;
	}

	code = krb5_cc_store_cred(ctx, tgt_ccache, &cred);
	if (code) {
		logmsg(LL_ERR, "store cred to cc %s: %s\n",
		       ccname, krb5_err_msg(code));
		goto out_cc;
	}

	logmsg(LL_INFO, "installed TGT of %.*s in cc %s\n",
	       krb5_princ_name(ctx, princ)->length,
	       krb5_princ_name(ctx, princ)->data,
	       ccname);

	rc = lgss_krb5_set_ccache_name(ccname);

out_cc:
	krb5_cc_close(ctx, tgt_ccache);
out_cred:
	krb5_free_cred_contents(ctx, &cred);
	return rc;
}

/*
 * obtain a new root TGT
 */
static int lkrb5_refresh_root_tgt_cc(krb5_context ctx, unsigned int root_flags,
				     uint64_t self_nid)
{
	krb5_keytab kt;
	krb5_keytab_entry kte;
	krb5_kt_cursor cursor;
	krb5_principal princ = NULL;
	krb5_error_code code;
	char ccname[PATH_MAX];
	unsigned int flag = 0;
	int rc = -1;

	/* prepare parsing the keytab file */
	code = krb5_kt_resolve(ctx, krb5_keytab_file, &kt);
	if (code) {
		logmsg(LL_ERR, "resolve keytab %s: %s\n",
		       krb5_keytab_file, krb5_err_msg(code));
		return -1;
	}

	code = krb5_kt_start_seq_get(ctx, kt, &cursor);
	if (code) {
		logmsg(LL_ERR, "start kt iteration: %s\n", krb5_err_msg(code));
		goto out_kt;
	}

	/* iterate keytab to find proper an entry */
	do {
		krb5_data      *princname;

		code = krb5_kt_next_entry(ctx, kt, &kte, &cursor);
		if (code != 0)
			break;

		logmsg(LL_TRACE,
		       "kt entry: realm %.*s, type %d, size %d, name %.*s\n",
		       krb5_princ_realm(ctx, kte.principal)->length,
		       krb5_princ_realm(ctx, kte.principal)->data,
		       krb5_princ_type(ctx, kte.principal),
		       krb5_princ_size(ctx, kte.principal),
		       krb5_princ_name(ctx, kte.principal)->length,
		       krb5_princ_name(ctx, kte.principal)->data);

		if (!princ_is_local_realm(ctx, kte.principal))
			continue;

		princname = krb5_princ_name(ctx, kte.principal);

		if ((root_flags & LGSS_ROOT_CRED_ROOT) != 0 &&
		    (!lgss_krb5_strcmp(princname, LGSS_USR_ROOT_STR) ||
		     !lgss_krb5_strcmp(princname, LGSS_SVC_HOST_STR))) {
			flag = LGSS_ROOT_CRED_ROOT;
		} else if ((root_flags & LGSS_ROOT_CRED_MDT) != 0 &&
			   !lgss_krb5_strcmp(princname, LGSS_SVC_MDS_STR)) {
			flag = LGSS_ROOT_CRED_MDT;
		} else if ((root_flags & LGSS_ROOT_CRED_OST) != 0 &&
			   !lgss_krb5_strcmp(princname, LGSS_SVC_OSS_STR)) {
			flag = LGSS_ROOT_CRED_OST;
		} else {
			logmsg(LL_TRACE, "not what we want, skip\n");
			continue;
		}

		if (krb5_princ_component(ctx, kte.principal, 1) == NULL) {
			if (flag != LGSS_ROOT_CRED_ROOT) {
				logmsg(LL_TRACE, "no hostname, skip\n");
				continue;
			}
		} else {
			if (svc_princ_verify_host(ctx, kte.principal, self_nid,
						  LL_TRACE)) {
				logmsg(LL_TRACE, "doesn't belong to this "
				       "node, skip\n");
				continue;
			}
		}

		code = krb5_copy_principal(ctx, kte.principal, &princ);
		if (code) {
			logmsg(LL_ERR, "copy princ: %s\n", krb5_err_msg(code));
			continue;
		}

		lassert(princ != NULL);
		break;
	} while (1);

	krb5_kt_end_seq_get(ctx, kt, &cursor);

	if (princ == NULL) {
		logmsg(LL_ERR, "can't find proper keytab entry\n");
		goto out_kt;
	}

	/* obtain root TGT */
	rc = get_root_tgt_ccname(ctx, ccname, sizeof(ccname));
	if (!rc)
		rc = lkrb5_get_root_tgt_keytab(ctx, kt, princ, ccname);

	krb5_free_principal(ctx, princ);
out_kt:
	krb5_kt_close(ctx, kt);
	return rc;
}

static int lkrb5_prepare_root_cred(struct lgss_cred *cred)
{
	krb5_context ctx;
	krb5_error_code code;
	int rc = -1;

	lassert(krb5_this_realm != NULL);

	code = krb5_init_context(&ctx);
	if (code) {
		logmsg(LL_ERR, "initialize krb5 context: %s\n",
		       krb5_err_msg(code));
		return -1;
	}

	/*
	 * search and/or obtain root TGT credential.
	 * it touched global (on-disk) tgt cache, do it inside mutex locking
	 */
	lgss_krb5_mutex_lock();
	rc = lkrb5_check_root_tgt_cc(ctx, cred->lc_root_flags,
				     cred->lc_self_nid);
	if (rc)
		rc = lkrb5_refresh_root_tgt_cc(ctx, cred->lc_root_flags,
					       cred->lc_self_nid);

	lgss_krb5_mutex_unlock();
	krb5_free_context(ctx);

	logmsg(LL_DEBUG, "prepare root credentail %s\n", rc ? "failed" : "OK");
	return rc;
}

static int lkrb5_prepare_user_cred(struct lgss_cred *cred)
{
	krb5_context ctx;
	krb5_error_code code;
	int size = PATH_MAX;
	void *ccname;
	int rc;

	lassert(krb5_this_realm == NULL);

	code = krb5_init_context(&ctx);
	if (code) {
		logmsg(LL_ERR, "initialize krb5 context: %s\n",
		       krb5_err_msg(code));
		return -1;
	}

	/* buffer passed to get_user_tgt_ccname() must be mmapped with
	 * MAP_SHARED because it is accessed read/write from a child process
	 */
	ccname = mmap(NULL, size, PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (ccname == MAP_FAILED) {
		logmsg(LL_ERR, "cannot mmap memory for user %u: %s\n",
		       cred->lc_uid, strerror(errno));
		rc = -errno;
		goto free;
	}

	rc = get_user_tgt_ccname(cred, ctx, ccname, size);
	if (rc)
		logmsg(LL_ERR, "cannot get user %u ccname: %s\n",
		       cred->lc_uid, strerror(-rc));
	else
		logmsg(LL_INFO, "using krb5 cache name: %s\n", (char *)ccname);

	if (munmap(ccname, size) == -1) {
		logmsg(LL_ERR, "cannot munmap memory for user %u: %s\n",
		       cred->lc_uid, strerror(errno));
		rc = rc ? rc : -errno;
	}

free:
	krb5_free_context(ctx);
	return rc;
}

static int lgss_krb5_prepare_cred(struct lgss_cred *cred)
{
	int rc;

	cred->lc_mech_cred = NULL;

	if (cred->lc_root_flags != 0) {
		rc = gss_get_realm(lgss_client_realm);
		if (rc) {
			logmsg(LL_ERR, "ERROR: no Kerberos realm: %s\n",
			       error_message(rc));
			return -1;
		}
		logmsg(LL_DEBUG, "Kerberos realm: %s\n", krb5_this_realm);

		rc = lkrb5_prepare_root_cred(cred);
	} else {
		rc = lkrb5_prepare_user_cred(cred);
	}

	return rc;
}

static
void lgss_krb5_release_cred(struct lgss_cred *cred)
{
        cred->lc_mech_cred = NULL;
}

static void lgss_krb5_fini(void)
{
	krb5_context context = NULL;
	krb5_error_code code;

	if (krb5_this_realm) {
		code = krb5_init_context(&context);
		if (code) {
			logmsg(LL_ERR, "ERROR: krb5 fini: init ctx: %s\n",
				 error_message(code));
		} else {
			krb5_free_string(context, krb5_this_realm);
			krb5_this_realm = NULL;
			krb5_free_context(context);
		}
	}
}

struct lgss_mech_type lgss_mech_krb5 =
{
	.lmt_name		= "krb5",
	.lmt_mech_n		= LGSS_MECH_KRB5,
	.lmt_prepare_cred	= lgss_krb5_prepare_cred,
	.lmt_release_cred	= lgss_krb5_release_cred,
	.lmt_fini		= lgss_krb5_fini,
};
