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
//#include <rpc/rpc.h>
#include <sys/types.h>
#include <sys/stat.h>
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
#ifdef USE_PRIVATE_KRB5_FUNCTIONS
#include <gssapi/gssapi_krb5.h>
#endif
#include <krb5.h>

#include "lsupport.h"
#include "lgss_utils.h"
#include "lgss_krb5_utils.h"

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

/*
 * NOTE
 *  - currently we only support "normal" cache types: "FILE" and "MEMORY".
 */

#define krb5_err_msg(code)      error_message(code)

const char *krb5_cc_type_mem    = "MEMORY:";
const char *krb5_cc_type_file   = "FILE:";
const char *krb5_cred_root_suffix  = "lustre_root";
const char *krb5_cred_mds_suffix   = "lustre_mds";
const char *krb5_cred_oss_suffix   = "lustre_oss";

char    *krb5_this_realm        = NULL;
char    *krb5_keytab_file       = "/etc/krb5.keytab";
char    *krb5_cc_type           = "FILE:";
char    *krb5_cc_dir            = "/tmp";
char    *krb5_cred_prefix       = "krb5cc_";

struct lgss_krb5_cred {
        char            kc_ccname[128];
        int             kc_remove;        /* remove cache upon release */
};

static
int lgss_krb5_set_ccache_name(const char *ccname)
{
#ifdef USE_GSS_KRB5_CCACHE_NAME
        unsigned int    maj_stat, min_stat;

        maj_stat = gss_krb5_ccache_name(&min_stat, ccname, NULL);
        if (maj_stat != GSS_S_COMPLETE) {
                logmsg(LL_ERR, "failed to set ccache name\n");
                return -1;
        }
#else
        /*
         * Set the KRB5CCNAME environment variable to tell the krb5 code
         * which credentials cache to use.  (Instead of using the private
         * function above for which there is no generic gssapi equivalent)
         */
        if (setenv("KRB5CCNAME", ccname, 1)) {
                logmsg(LL_ERR, "set env of krb5 ccname: %s\n",
                       strerror(errno));
                return -1;
        }
#endif
        logmsg(LL_DEBUG, "set cc: %s\n", ccname);
        return 0;
}

static
int lgss_krb5_get_local_realm(void)
{
        krb5_context    context = NULL;
        krb5_error_code code;
        int             retval = -1;

        if (krb5_this_realm != NULL)
                return 0;

        code = krb5_init_context(&context);
        if (code) {
                logmsg(LL_ERR, "init ctx: %s\n", krb5_err_msg(code));
                return -1;
        }

        code = krb5_get_default_realm(context, &krb5_this_realm);
        if (code) {
                logmsg(LL_ERR, "get default realm: %s\n", krb5_err_msg(code));
                goto out;
        }

        logmsg(LL_DEBUG, "Local realm: %s\n", krb5_this_realm);
        retval = 0;
out:
        krb5_free_context(context);
        return retval;
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
	struct hostent *host;
	const int max_namelen = 512;
	char namebuf[max_namelen];
	char *h_name;

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
		h_name = namebuf;
	} else {
		if (uname(&utsbuf)) {
			logmsg(loglevel, "get UTS name: %s\n", strerror(errno));
			return -1;
		}

		host = gethostbyname(utsbuf.nodename);
		if (host == NULL) {
			logmsg(loglevel, "failed to get local hostname\n");
			return -1;
		}
		h_name = host->h_name;
	}

	if (lgss_krb5_strcasecmp(krb5_princ_component(ctx, princ, 1),
				 h_name)) {
		logmsg(loglevel, "service principal: hostname %.*s "
		       "doesn't match localhost %s\n",
		       krb5_princ_component(ctx, princ, 1)->length,
		       krb5_princ_component(ctx, princ, 1)->data,
		       h_name);
		return -1;
	}

	return 0;
}

static
int lkrb5_cc_check_tgt_princ(krb5_context ctx,
			     krb5_ccache ccache,
			     krb5_principal princ,
			     unsigned int flag,
			     uint64_t self_nid)
{
        const char     *princ_name;

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

        /* check principal name */
        switch (flag) {
        case LGSS_ROOT_CRED_ROOT:
                princ_name = LGSS_USR_ROOT_STR;
                break;
        case LGSS_ROOT_CRED_MDT:
                princ_name = LGSS_SVC_MDS_STR;
                break;
        case LGSS_ROOT_CRED_OST:
                princ_name = LGSS_SVC_OSS_STR;
                break;
        default:
                lassert(0);
        }

        if (lgss_krb5_strcmp(krb5_princ_name(ctx, princ), princ_name)) {
                logmsg(LL_WARN, "%.*s: we expect %s instead\n",
                       krb5_princ_name(ctx, princ)->length,
                       krb5_princ_name(ctx, princ)->data,
                       princ_name);
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

/**
 * compose the TGT cc name, according to the root flags.
 */
static
void get_root_tgt_ccname(char *ccname, int size, unsigned int flag)
{
        const char *suffix;

        switch (flag) {
        case LGSS_ROOT_CRED_ROOT:
                suffix = krb5_cred_root_suffix;
                break;
        case LGSS_ROOT_CRED_MDT:
                suffix = krb5_cred_mds_suffix;
                break;
        case LGSS_ROOT_CRED_OST:
                suffix = krb5_cred_oss_suffix;
                break;
        default:
                lassert(0);
        }

        snprintf(ccname, size, "%s%s/%s%s_%s",
                 krb5_cc_type, krb5_cc_dir, krb5_cred_prefix,
                 suffix, krb5_this_realm);
}

static
int lkrb5_check_root_tgt_cc_base(krb5_context ctx,
				 krb5_ccache ccache,
				 char *ccname,
				 unsigned int flag,
				 uint64_t self_nid)
{
        krb5_ccache             tgt_ccache;
        krb5_creds              cred;
        krb5_principal          princ;
        krb5_cc_cursor          cursor;
        krb5_error_code         code;
        time_t                  now;
        int                     rc = -1, found = 0;

        /* prepare parsing the cache file */
        code = krb5_cc_resolve(ctx, ccname, &tgt_ccache);
        if (code) {
                logmsg(LL_ERR, "resolve krb5 cc %s: %s\n",
                       ccname, krb5_err_msg(code));
                return -1;
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
                krb5_timestamp  duration, delta;

                code = krb5_cc_next_cred(ctx, tgt_ccache, &cursor, &cred);
                if (code != 0)
                        break;

		logmsg(LL_DEBUG, "cred: server realm %.*s, type %d, name %.*s; "
		       "time (%lld-%lld, renew till %lld), valid %lld\n",
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

        if (!found) {
                logmsg(LL_DEBUG, "doesn't find good TGT cache\n");
                goto out_seq;
        }

        /* found a good cred, store it into @ccache */
        logmsg(LL_DEBUG, "found good TGT cache\n");

        code = krb5_cc_initialize(ctx, ccache, princ);
        if (code) {
                logmsg(LL_ERR, "init private cc: %s\n", krb5_err_msg(code));
                goto out_seq;
        }

        code = krb5_cc_store_cred(ctx, ccache, &cred);
        if (code) {
                logmsg(LL_ERR, "store private cred: %s\n", krb5_err_msg(code));
                goto out_seq;
        }

        logmsg(LL_DEBUG, "store private ccache OK\n");
        rc = 0;

out_seq:
        krb5_cc_end_seq_get(ctx, tgt_ccache, &cursor);
out_princ:
        krb5_free_principal(ctx, princ);
out_cc:
        krb5_cc_close(ctx, tgt_ccache);

        return rc;
}

/**
 * find out whether current TGT cache is valid or not
 */
static
int lkrb5_check_root_tgt_cc(krb5_context ctx,
			    krb5_ccache ccache,
			    unsigned int root_flags,
			    uint64_t self_nid)
{
        struct stat             statbuf;
        unsigned int            flag;
        char                    ccname[1024];
        char                   *ccfile;
        int                     i, rc;

        for (i = 0; i < LGSS_ROOT_CRED_NR; i++) {
                flag = 1 << i;

                if ((root_flags & flag) == 0)
                        continue;

                get_root_tgt_ccname(ccname, sizeof(ccname), flag);
                logmsg(LL_DEBUG, "root krb5 TGT ccname: %s\n", ccname);

                /* currently we only support type "FILE", firstly make sure
                 * the cache file is there */
                ccfile = ccname + strlen(krb5_cc_type);
                if (stat(ccfile, &statbuf)) {
                        logmsg(LL_DEBUG, "krb5 cc %s: %s\n",
                               ccname, strerror(errno));
                        continue;
                }

		rc = lkrb5_check_root_tgt_cc_base(ctx, ccache, ccname, flag,
						  self_nid);
                if (rc == 0)
                        return 0;
        }

        logmsg(LL_TRACE, "doesn't find a valid tgt cc\n");
        return -1;
}

static
int lkrb5_get_root_tgt_keytab(krb5_context ctx,
                              krb5_ccache ccache,
                              krb5_keytab kt,
                              krb5_principal princ,
                              const char *ccname)
{
        krb5_get_init_creds_opt opts;
        krb5_creds              cred;
        krb5_ccache             tgt_ccache;
        krb5_error_code         code;
        int                     rc = -1;

        krb5_get_init_creds_opt_init(&opts);
        krb5_get_init_creds_opt_set_address_list(&opts, NULL);
        /*
         * by default krb5 library obtain ticket with lifetime shorter
         * than the max value. we can change it here if we want. but
         * seems not necessary now.
         *
        krb5_get_init_creds_opt_set_tkt_life(&opts, very-long-time);
         *
         */

        /*
         * obtain TGT and store into global ccache
         */
        code = krb5_get_init_creds_keytab(ctx, &cred, princ, kt,
                                          0, NULL, &opts);
        if (code) {
                logmsg(LL_ERR, "failed to get root TGT for "
                       "principal %.*s: %s\n",
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

        /*
         * now store the cred into my own cc too
         */
        code = krb5_cc_initialize(ctx, ccache, princ);
        if (code) {
                logmsg(LL_ERR, "init mem cc: %s\n", krb5_err_msg(code));
                goto out_cc;
        }

        code = krb5_cc_store_cred(ctx, ccache, &cred);
        if (code) {
                logmsg(LL_ERR, "store mm cred: %s\n", krb5_err_msg(code));
                goto out_cc;
        }

        logmsg(LL_DEBUG, "stored TGT into mem cc OK\n");
        rc = 0;
out_cc:
        krb5_cc_close(ctx, tgt_ccache);
out_cred:
        krb5_free_cred_contents(ctx, &cred);
        return rc;
}

/*
 * obtain a new root TGT
 */
static
int lkrb5_refresh_root_tgt_cc(krb5_context ctx,
			      krb5_ccache ccache,
			      unsigned int root_flags,
			      uint64_t self_nid)
{
        krb5_keytab             kt;
        krb5_keytab_entry       kte;
        krb5_kt_cursor          cursor;
        krb5_principal          princ = NULL;
        krb5_error_code         code;
        char                    ccname[1024];
        unsigned int            flag = 0;
        int                     rc = -1;

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

                logmsg(LL_TRACE, "kt entry: realm %.*s, type %d, "
                       "size %d, name %.*s\n",
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
                    lgss_krb5_strcmp(princname, LGSS_USR_ROOT_STR) == 0) {
                        flag = LGSS_ROOT_CRED_ROOT;
                } else if ((root_flags & LGSS_ROOT_CRED_MDT) != 0 &&
                           lgss_krb5_strcmp(princname, LGSS_SVC_MDS_STR) == 0) {
                        flag = LGSS_ROOT_CRED_MDT;
                } else if ((root_flags & LGSS_ROOT_CRED_OST) != 0 &&
                           lgss_krb5_strcmp(princname, LGSS_SVC_OSS_STR) == 0) {
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
        get_root_tgt_ccname(ccname, sizeof(ccname), flag);
        rc = lkrb5_get_root_tgt_keytab(ctx, ccache, kt, princ, ccname);

        krb5_free_principal(ctx, princ);
out_kt:
        krb5_kt_close(ctx, kt);
        return rc;
}

static
int lkrb5_prepare_root_cred(struct lgss_cred *cred)
{
        krb5_context            ctx;
        krb5_ccache             ccache;
        krb5_error_code         code;
        struct lgss_krb5_cred  *kcred;
        int                     rc = -1;

        lassert(krb5_this_realm != NULL);

        kcred = (struct lgss_krb5_cred *) cred->lc_mech_cred;

        /* compose the memory cc name, since the only user is myself,
         * the name could be fixed */
        snprintf(kcred->kc_ccname, sizeof(kcred->kc_ccname),
                 "%s/self", krb5_cc_type_mem);
        logmsg(LL_TRACE, "private cc: %s\n", kcred->kc_ccname);

        code = krb5_init_context(&ctx);
        if (code) {
                logmsg(LL_ERR, "initialize krb5 context: %s\n",
                       krb5_err_msg(code));
                return -1;
        }

        code = krb5_cc_resolve(ctx, kcred->kc_ccname, &ccache);
        if (code) {
                logmsg(LL_ERR, "resolve krb5 cc %s: %s\n",
                       kcred->kc_ccname, krb5_err_msg(code));
                goto out_ctx;
        }

        /*
         * search and/or obtain root TGT credential.
         * it touched global (on-disk) tgt cache, do it inside mutex locking
         */
        lgss_krb5_mutex_lock();

	rc = lkrb5_check_root_tgt_cc(ctx, ccache, cred->lc_root_flags,
				     cred->lc_self_nid);
	if (rc != 0)
		rc = lkrb5_refresh_root_tgt_cc(ctx, ccache,
					       cred->lc_root_flags,
					       cred->lc_self_nid);

        if (rc == 0)
                rc = lgss_krb5_set_ccache_name(kcred->kc_ccname);

        lgss_krb5_mutex_unlock();

        krb5_cc_close(ctx, ccache);
out_ctx:
        krb5_free_context(ctx);

        logmsg(LL_DEBUG, "prepare root credentail %s\n", rc ? "failed" : "OK");
        return rc;
}

static
int lkrb5_prepare_user_cred(struct lgss_cred *cred)
{
        struct lgss_krb5_cred   *kcred;
        int                      rc;

        lassert(krb5_this_realm == NULL);

        kcred = (struct lgss_krb5_cred *) cred->lc_mech_cred;

        /*
         * here we just specified a fix ccname, instead of searching
         * entire cc dir. is this OK??
         */
        snprintf(kcred->kc_ccname, sizeof(kcred->kc_ccname),
                 "%s%s/%s%u",
                 krb5_cc_type, krb5_cc_dir, krb5_cred_prefix, cred->lc_uid);
        logmsg(LL_DEBUG, "using krb5 cache name: %s\n", kcred->kc_ccname);

        rc = lgss_krb5_set_ccache_name(kcred->kc_ccname);
        if (rc)
                logmsg(LL_ERR, "can't set krb5 ccache name: %s\n",
                       kcred->kc_ccname);

        return rc;
}

static
int lgss_krb5_prepare_cred(struct lgss_cred *cred)
{
        struct lgss_krb5_cred  *kcred;
        int                     rc;

        kcred = malloc(sizeof(*kcred));
        if (kcred == NULL) {
                logmsg(LL_ERR, "can't allocate krb5 cred\n");
                return -1;
        }

        kcred->kc_ccname[0] = '\0';
        kcred->kc_remove = 0;
        cred->lc_mech_cred = kcred;

        if (cred->lc_root_flags != 0) {
                if (lgss_krb5_get_local_realm())
                        return -1;

                rc = lkrb5_prepare_root_cred(cred);
        } else {
                rc = lkrb5_prepare_user_cred(cred);
        }

        return rc;
}

static
void lgss_krb5_release_cred(struct lgss_cred *cred)
{
        struct lgss_krb5_cred   *kcred;

        kcred = (struct lgss_krb5_cred *) cred->lc_mech_cred;

        free(kcred);
        cred->lc_mech_cred = NULL;
}

struct lgss_mech_type lgss_mech_krb5 = 
{
        .lmt_name               = "krb5",
        .lmt_mech_n             = LGSS_MECH_KRB5,
        .lmt_prepare_cred       = lgss_krb5_prepare_cred,
        .lmt_release_cred       = lgss_krb5_release_cred,
};
