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
#include <rpc/rpc.h>
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

#include "gssd.h"
#include "err_util.h"
#include "gss_util.h"
#include "gss_oids.h"
#include "krb5_util.h"

/* Global list of principals/cache file names for machine credentials */
struct gssd_k5_kt_princ *gssd_k5_kt_princ_list = NULL;

/* Encryption types supported by the kernel rpcsec_gss code */
int num_krb5_enctypes = 0;
krb5_enctype *krb5_enctypes = NULL;

/* credential expire time in advance */
unsigned long machine_cred_expire_advance = 300; /* 5 mins */

/*==========================*/
/*===  Internal routines ===*/
/*==========================*/

static int select_krb5_ccache(const struct dirent *d);
static int gssd_find_existing_krb5_ccache(uid_t uid, struct dirent **d);
static int gssd_get_single_krb5_cred(krb5_context context,
		krb5_keytab kt, struct gssd_k5_kt_princ *ple);
static int gssd_process_krb5_keytab(krb5_context context, krb5_keytab kt,
		char *kt_name);

/*
 * convenient macros, these perhaps need further cleanup
 */
#ifdef HAVE_KRB5

#define KEYTAB_ENTRY_MATCH(kte, name)					       \
	(								       \
	 (kte).principal->data[0].length == (sizeof(name)-1) &&		       \
	 strncmp((kte).principal->data[0].data, (name), sizeof(name)-1) == 0   \
	)
#define KRB5_FREE_UNPARSED_NAME(ctx, name)				       \
		krb5_free_unparsed_name((ctx), (name));
#define KRB5_STRDUP(str)						       \
		strndup((str).data, (str).length)
#define KRB5_STRCMP(str, name)						       \
	(								       \
	 (str)->length != strlen(name) ||				       \
	 strncmp((str)->data, (name), (str)->length) != 0		       \
	)
#define KRB5_STRCASECMP(str, name)					       \
	(								       \
	 (str)->length != strlen(name) ||				       \
	 strncasecmp((str)->data, (name), (str)->length) != 0		       \
	)

#else /* !HAVE_KRB5 */

#define KEYTAB_ENTRY_MATCH(kte, name)					       \
	(								       \
	 strlen((kte).principal->name.name_string.val[0]) ==		       \
	 (sizeof(name)-1) &&						       \
	 strncmp(kte.principal->name.name_string.val[0], (name),	       \
		 sizeof(name)-1) == 0					       \
	)
#define KRB5_FREE_UNPARSED_NAME(ctx, name)				       \
		free(pname);
#define KRB5_STRDUP(str)						       \
		strdup(str)
#define KRB5_STRCMP(str, name)						       \
		strcmp((str), (name))
#define KRB5_STRCASECMP(str, name)					       \
		strcmp((str), (name))

#endif /* HAVE_KRB5 */

/*
 * Called from the scandir function to weed out potential krb5
 * credentials cache files
 *
 * Returns:
 *	0 => don't select this one
 *	1 => select this one
 */
static int
select_krb5_ccache(const struct dirent *d)
{
	/*
	 * Note: We used to check d->d_type for DT_REG here,
	 * but apparenlty reiser4 always has DT_UNKNOWN.
	 * Check for IS_REG after stat() call instead.
	 */
	if (strstr(d->d_name, GSSD_DEFAULT_CRED_PREFIX))
		return 1;
	else
		return 0;
}

/*
 * Look in the ccachedir for files that look like they
 * are Kerberos Credential Cache files for a given UID.  Return
 * non-zero and the dirent pointer for the entry most likely to be
 * what we want. Otherwise, return zero and no dirent pointer.
 * The caller is responsible for freeing the dirent if one is returned.
 *
 * Returns:
 *	0 => could not find an existing entry
 *	1 => found an existing entry
 */
static int
gssd_find_existing_krb5_ccache(uid_t uid, struct dirent **d)
{
	struct dirent **namelist;
	int n;
	int i;
	int found = 0;
	struct dirent *best_match_dir = NULL;
	struct stat best_match_stat, tmp_stat;

	memset(&best_match_stat, 0, sizeof(best_match_stat));
	*d = NULL;
	n = scandir(ccachedir, &namelist, select_krb5_ccache, 0);
	if (n < 0) {
		perror("scandir looking for krb5 credentials caches");
	}
	else if (n > 0) {
		char statname[1024];
		for (i = 0; i < n; i++) {
			printerr(3, "CC file '%s' being considered\n",
				 namelist[i]->d_name);
			snprintf(statname, sizeof(statname),
				 "%s/%s", ccachedir, namelist[i]->d_name);
			if (stat(statname, &tmp_stat)) {
				printerr(0, "Error doing stat on file '%s'\n",
					 statname);
				free(namelist[i]);
				continue;
			}
			/* Only pick caches owned by the user (uid) */
			if (tmp_stat.st_uid != uid) {
				printerr(3, "'%s' owned by %u, not %u\n",
					 statname, tmp_stat.st_uid, uid);
				free(namelist[i]);
				continue;
			}
			if (!S_ISREG(tmp_stat.st_mode)) {
				printerr(3, "'%s' is not a regular file\n",
					 statname);
				free(namelist[i]);
				continue;
			}
			printerr(3, "CC file '%s' matches owner check and has "
				 "mtime of %u\n",
				 namelist[i]->d_name, tmp_stat.st_mtime);
			/*
			 * if more than one match is found, return the most
			 * recent (the one with the latest mtime), and
			 * don't free the dirent
			 */
			if (!found) {
				best_match_dir = namelist[i];
				best_match_stat = tmp_stat;
				found++;
			}
			else {
				/*
				 * If the current match has an mtime later
				 * than the one we are looking at, then use
				 * the current match.  Otherwise, we still
				 * have the best match.
				 */
				if (tmp_stat.st_mtime >
					    best_match_stat.st_mtime) {
					free(best_match_dir);
					best_match_dir = namelist[i];
					best_match_stat = tmp_stat;
				}
				else {
					free(namelist[i]);
				}
				printerr(3, "CC file '%s' is our "
					    "current best match "
					    "with mtime of %u\n",
					 best_match_dir->d_name,
					 best_match_stat.st_mtime);
			}
		}
		free(namelist);
	}
	if (found)
	{
		*d = best_match_dir;
	}
	return found;
}


/*
 * Obtain credentials via a key in the keytab given
 * a keytab handle and a gssd_k5_kt_princ structure.
 * Checks to see if current credentials are expired,
 * if not, uses the keytab to obtain new credentials.
 *
 * Returns:
 *	0 => success (or credentials have not expired)
 *	nonzero => error
 */
static int
gssd_get_single_krb5_cred(krb5_context context,
			  krb5_keytab kt,
			  struct gssd_k5_kt_princ *ple)
{
	krb5_get_init_creds_opt options;
	krb5_creds my_creds;
	krb5_ccache ccache = NULL;
	char kt_name[BUFSIZ];
	char cc_name[BUFSIZ];
	int code;
	time_t now = time(0);
	char *cache_type;

	memset(&my_creds, 0, sizeof(my_creds));

	if (ple->ccname && ple->endtime > now + machine_cred_expire_advance) {
		printerr(2, "INFO: Credentials in CC '%s' are good until %d\n",
			 ple->ccname, ple->endtime);
		code = 0;
		goto out;
	}

	if ((code = krb5_kt_get_name(context, kt, kt_name, BUFSIZ))) {
		printerr(0, "ERROR: Unable to get keytab name in "
			    "gssd_get_single_krb5_cred\n");
		goto out;
	}

	krb5_get_init_creds_opt_init(&options);
	krb5_get_init_creds_opt_set_address_list(&options, NULL);

#ifdef TEST_SHORT_LIFETIME
	/* set a short lifetime (for debugging only!) */
	printerr(0, "WARNING: Using (debug) short machine cred lifetime!\n");
	krb5_get_init_creds_opt_set_tkt_life(&options, 5*60);
#else
	/* FIXME try to get the ticket with lifetime as long as possible,
	 * to work around ticket-expiry + recovery problem in cmd3-11
	 * remove this!!!
	 */
	krb5_get_init_creds_opt_set_tkt_life(&options, 30*24*60*60);
#endif
        if ((code = krb5_get_init_creds_keytab(context, &my_creds, ple->princ,
	                                  kt, 0, NULL, &options))) {
		char *pname;
		if ((krb5_unparse_name(context, ple->princ, &pname))) {
			pname = NULL;
		}
		printerr(0, "WARNING: %s while getting initial ticket for "
			    "principal '%s' from keytab '%s'\n",
			 error_message(code),
			 pname ? pname : "<unparsable>", kt_name);
		if (pname) KRB5_FREE_UNPARSED_NAME(context, pname);
		goto out;
	}

	/*
	 * Initialize cache file which we're going to be using
	 */

	if (use_memcache)
	    cache_type = "MEMORY";
	else
	    cache_type = "FILE";
	snprintf(cc_name, sizeof(cc_name), "%s:%s/%s%s_%s",
		cache_type,
		GSSD_DEFAULT_CRED_DIR, GSSD_DEFAULT_CRED_PREFIX,
		GSSD_DEFAULT_MACHINE_CRED_SUFFIX, ple->realm);
	ple->endtime = my_creds.times.endtime;
	ple->ccname = strdup(cc_name);
	if (ple->ccname == NULL) {
		printerr(0, "ERROR: no storage to duplicate credentials "
			    "cache name\n");
		code = ENOMEM;
		goto out;
	}
	if ((code = krb5_cc_resolve(context, cc_name, &ccache))) {
		printerr(0, "ERROR: %s while opening credential cache '%s'\n",
			 error_message(code), cc_name);
		goto out;
	}
	if ((code = krb5_cc_initialize(context, ccache, ple->princ))) {
		printerr(0, "ERROR: %s while initializing credential "
			 "cache '%s'\n", error_message(code), cc_name);
		goto out;
	}
	if ((code = krb5_cc_store_cred(context, ccache, &my_creds))) {
		printerr(0, "ERROR: %s while storing credentials in '%s'\n",
			 error_message(code), cc_name);
		goto out;
	}

	code = 0;
	printerr(1, "Using (machine) credentials cache: '%s'\n", cc_name);
  out:
	if (ccache)
		krb5_cc_close(context, ccache);
	krb5_free_cred_contents(context, &my_creds);
	return (code);
}

static struct gssd_k5_kt_princ * gssd_get_realm_ple(void *r)
{
	struct gssd_k5_kt_princ *ple;
#ifdef HAVE_KRB5
	krb5_data *realm = (krb5_data *)r;
#else
	char *realm = (char *)r;
#endif

	for (ple = gssd_k5_kt_princ_list; ple; ple = ple->next) {
		if (KRB5_STRCMP(realm, ple->realm) == 0)
		    return ple;
	}
	return NULL;
}

static void gssd_free_ple(krb5_context kctx, struct gssd_k5_kt_princ *ple)
{
	if (ple->princ)
		krb5_free_principal(kctx, ple->princ);
	if (ple->realm)
		free(ple->realm);
	if (ple->ccname)
		free(ple->ccname);
	free(ple);
}

static int gssd_remove_ple(krb5_context kctx, struct gssd_k5_kt_princ *ple)
{
	struct gssd_k5_kt_princ **prev = &gssd_k5_kt_princ_list;
	struct gssd_k5_kt_princ  *ent = gssd_k5_kt_princ_list;

	for (; ent; prev = &ent->next, ent = ent->next) {
		if (ent != ple)
			continue;

		*prev = ent->next;
		gssd_free_ple(kctx, ent);
		return 1;
	}
	return 0;
}

static
struct gssd_k5_kt_princ *gssd_create_ple(krb5_context kctx,
					 krb5_principal principal)
{
	struct gssd_k5_kt_princ	*ple;
	krb5_error_code 	 code;

	ple = malloc(sizeof(*ple));
	if (ple == NULL) {
		printerr(0, "ERROR: could not allocate storage "
			    "for principal list entry\n");
		return NULL;
	}

	memset(ple, 0, sizeof(*ple));

	ple->realm = KRB5_STRDUP(principal->realm);
	if (ple->realm == NULL) {
		printerr(0, "ERROR: not enough memory while copying realm to "
			    "principal list entry\n");
		goto err_free;
	}

	code = krb5_copy_principal(kctx, principal, &ple->princ);
	if (code) {
		printerr(0, "ERROR: %s while copying principal "
			    "to principal list entry\n",
			 error_message(code));
		goto err_free;
	}

	return ple;
err_free:
	gssd_free_ple(kctx, ple);
	return NULL;
}

/*
 * Process the given keytab file and create a list of principals we
 * might use to perform mount operations.
 *
 * Returns:
 *	0 => Success
 *	nonzero => Error
 */
static int
gssd_process_krb5_keytab(krb5_context context, krb5_keytab kt, char *kt_name)
{
	krb5_kt_cursor cursor;
	krb5_keytab_entry kte;
	krb5_error_code code;
	struct gssd_k5_kt_princ *ple;
	int retval = -1;

	/*
	 * Look through each entry in the keytab file and determine
	 * if we might want to use it later to do a mount.  If so,
	 * save info in the global principal list
	 * (gssd_k5_kt_princ_list).
	 * Note: (ple == principal list entry)
	 */
	if ((code = krb5_kt_start_seq_get(context, kt, &cursor))) {
		printerr(0, "ERROR: %s while beginning keytab scan "
			    "for keytab '%s'\n",
			error_message(code), kt_name);
		retval = code;
		goto out;
	}

	while ((code = krb5_kt_next_entry(context, kt, &kte, &cursor)) == 0) {
		char *pname;
		if ((code = krb5_unparse_name(context, kte.principal,
					      &pname))) {
			printerr(0, "WARNING: Skipping keytab entry because "
				    "we failed to unparse principal name: %s\n",
				 error_message(code));
			continue;
		}
		printerr(2, "Processing keytab entry for principal '%s'\n",
			 pname);

		/* mds service entry:
		 *   - hostname and realm should match this node
		 *   - replace existing non-mds entry of this realm
		 */
		if (KEYTAB_ENTRY_MATCH(kte, GSSD_SERVICE_MDS)) {
			krb5_principal princ = kte.principal;
			krb5_data *princ_host;
			struct utsname utsbuf;
			struct hostent *host;

			if (KRB5_STRCASECMP(krb5_princ_realm(context, princ),
					    this_realm) != 0) {
				printerr(2, "alien mds service entry, skip\n");
				goto next;
			}

			princ_host = krb5_princ_component(context, princ, 1);
			if (princ_host == NULL) {
				printerr(2, "mds service entry: no hostname in "
					 "principal, skip\n");
				goto next;
			}

			if (uname(&utsbuf)) {
				printerr(2, "mds service entry: unable to get "
					 "UTS name, skip\n");
				goto next;
			}
			host = gethostbyname(utsbuf.nodename);
			if (host == NULL) {
				printerr(2, "mds service entry: unable to get "
					 "local hostname, skip\n");
				goto next;
			}

			if (KRB5_STRCASECMP(princ_host, host->h_name) != 0) {
				printerr(2, "mds service entry: hostname "
					 "doesn't match: %s - %.*s, skip\n",
					 host->h_name,
					 princ_host->length, princ_host->data);
				goto next;
			}

			ple = gssd_get_realm_ple((void *)&kte.principal->realm);
			if (ple) {
				if (ple->fl_mds) {
					printerr(2,"mds service entry: found a"
						 "duplicated one, it's like a "
						 "mis-configuration, skip\n");
					goto next;
				}

				gssd_remove_ple(context, ple);
				printerr(2, "mds service entry: replace an "
					 "existed non-mds one\n");
			}
		} else if (KEYTAB_ENTRY_MATCH(kte, LUSTRE_ROOT_NAME)) {
			ple = gssd_get_realm_ple((void *)&kte.principal->realm);
			if (ple) {
				if (ple->fl_mds || ple->fl_root) {
					printerr(2, "root entry: found a "
						 "existed %s entry, skip\n",
						 ple->fl_mds ? "mds" : "root");
					goto next;
				}

				gssd_remove_ple(context, ple);
				printerr(2, "root entry: replace an existed "
					 "non-mds non-root one\n");
			}
		} else {
			printerr(2, "We will NOT use this entry (%s)\n",
				pname);
			goto next;
		}

		/* construct ple */
		printerr(2, "We will use this entry (%s)\n", pname);
		ple = gssd_create_ple(context, kte.principal);
		if (ple == NULL) {
			KRB5_FREE_UNPARSED_NAME(context, pname);
			goto out;
		}

		/* add proper flags */
		if (KEYTAB_ENTRY_MATCH(kte, GSSD_SERVICE_MDS))
			ple->fl_mds = 1;
		else if (KEYTAB_ENTRY_MATCH(kte, LUSTRE_ROOT_NAME))
			ple->fl_root = 1;

		/* enqueue */
		if (gssd_k5_kt_princ_list == NULL)
			gssd_k5_kt_princ_list = ple;
		else {
			ple->next = gssd_k5_kt_princ_list;
			gssd_k5_kt_princ_list = ple;
		}
 next:
		KRB5_FREE_UNPARSED_NAME(context, pname);
	}

	if ((code = krb5_kt_end_seq_get(context, kt, &cursor))) {
		printerr(0, "WARNING: %s while ending keytab scan for "
			    "keytab '%s'\n",
			 error_message(code), kt_name);
	}

	retval = 0;
  out:
	return retval;
}

/*
 * Depending on the version of Kerberos, we either need to use
 * a private function, or simply set the environment variable.
 */
static void
gssd_set_krb5_ccache_name(char *ccname)
{
#ifdef USE_GSS_KRB5_CCACHE_NAME
	unsigned int	maj_stat, min_stat;

	printerr(2, "using gss_krb5_ccache_name to select krb5 ccache %s\n",
		 ccname);
	maj_stat = gss_krb5_ccache_name(&min_stat, ccname, NULL);
	if (maj_stat != GSS_S_COMPLETE) {
		printerr(0, "WARNING: gss_krb5_ccache_name with "
			"name '%s' failed (%s)\n",
			ccname, error_message(min_stat));
	}
#else
	/*
	 * Set the KRB5CCNAME environment variable to tell the krb5 code
	 * which credentials cache to use.  (Instead of using the private
	 * function above for which there is no generic gssapi
	 * equivalent.)
	 */
	printerr(2, "using environment variable to select krb5 ccache %s\n",
		 ccname);
	setenv("KRB5CCNAME", ccname, 1);
#endif
}

/*
 * Parse the supported encryption type information
 */
static int
parse_enctypes(char *enctypes)
{
	int n = 0;
	char *curr, *comma;
	int i;

	/* Just in case this ever gets called more than once */
	if (krb5_enctypes != NULL) {
		free(krb5_enctypes);
		krb5_enctypes = NULL;
		num_krb5_enctypes = 0;
	}

	/* count the number of commas */
	for (curr = enctypes; curr && *curr != '\0'; curr = ++comma) {
		comma = strchr(curr, ',');
		if (comma != NULL)
			n++;
		else
			break;
	}
	/* If no more commas and we're not at the end, there's one more value */
	if (*curr != '\0')
		n++;

	/* Empty string, return an error */
	if (n == 0)
		return ENOENT;

	/* Allocate space for enctypes array */
	if ((krb5_enctypes = (int *) calloc(n, sizeof(int))) == NULL) {
		return ENOMEM;
	}

	/* Now parse each value into the array */
	for (curr = enctypes, i = 0; curr && *curr != '\0'; curr = ++comma) {
		krb5_enctypes[i++] = atoi(curr);
		comma = strchr(curr, ',');
		if (comma == NULL)
			break;
	}

	num_krb5_enctypes = n;
	return 0;
}

/*==========================*/
/*===  External routines ===*/
/*==========================*/

/*
 * Attempt to find the best match for a credentials cache file
 * given only a UID.  We really need more information, but we
 * do the best we can.
 *
 * Returns:
 *	void
 */
void
gssd_setup_krb5_user_gss_ccache(uid_t uid, char *servername)
{
	char			buf[MAX_NETOBJ_SZ];
	struct dirent		*d;

	printerr(2, "getting credentials for client with uid %u for "
		    "server %s\n", uid, servername);
	memset(buf, 0, sizeof(buf));

	if (gssd_find_existing_krb5_ccache(uid, &d)) {
		snprintf(buf, sizeof(buf), "FILE:%s/%s",
			ccachedir, d->d_name);
		free(d);
	}
	else
		snprintf(buf, sizeof(buf), "FILE:%s/%s%u",
			ccachedir, GSSD_DEFAULT_CRED_PREFIX, uid);
	printerr(2, "using %s as credentials cache for client with "
		    "uid %u for server %s\n", buf, uid, servername);
	gssd_set_krb5_ccache_name(buf);
}

/*
 * Let the gss code know where to find the machine credentials ccache.
 *
 * Returns:
 *	void
 */
void
gssd_setup_krb5_machine_gss_ccache(char *ccname)
{
	printerr(2, "using %s as credentials cache for machine creds\n",
		 ccname);
	gssd_set_krb5_ccache_name(ccname);
}

/*
 * The first time through this routine, go through the keytab and
 * determine which keys we will try to use as machine credentials.
 * Every time through this routine, try to obtain credentials using
 * the keytab entries selected the first time through.
 *
 * Returns:
 *	0 => obtained one or more credentials
 *	nonzero => error
 *
 */

int
gssd_refresh_krb5_machine_creds(void)
{
	krb5_context context = NULL;
	krb5_keytab kt = NULL;;
	krb5_error_code code;
	int retval = -1;
	struct gssd_k5_kt_princ *ple;
	int gotone = 0;
	static int processed_keytab = 0;


	code = krb5_init_context(&context);
	if (code) {
		printerr(0, "ERROR: %s while initializing krb5 in "
			    "gssd_refresh_krb5_machine_creds\n",
			 error_message(code));
		retval = code;
		goto out;
	}

	printerr(2, "Using keytab file '%s'\n", keytabfile);

	if ((code = krb5_kt_resolve(context, keytabfile, &kt))) {
		printerr(0, "ERROR: %s while resolving keytab '%s'\n",
			 error_message(code), keytabfile);
		goto out;
	}

	/* Only go through the keytab file once.  Only print messages once. */
	if (gssd_k5_kt_princ_list == NULL && !processed_keytab) {
		processed_keytab = 1;
		gssd_process_krb5_keytab(context, kt, keytabfile);
		if (gssd_k5_kt_princ_list == NULL) {
			printerr(0, "ERROR: No usable keytab entries found in "
				    "keytab '%s'\n", keytabfile);
			printerr(0, "You must have a valid keytab entry for "
				    "%s/<your.host>@<YOUR.REALM> on MDT nodes, "
				    "and %s@<YOUR.REALM> on client nodes, in "
				    "keytab file %s ?\n",
				    GSSD_SERVICE_MDS, LUSTRE_ROOT_NAME,
				    keytabfile);
		}
	}

	/*
	 * If we don't have any keytab entries we liked, then we have a problem
	 */
	if (gssd_k5_kt_princ_list == NULL) {
		retval = ENOENT;
		goto out;
	}

	/*
	 * Now go through the list of saved entries and get initial
	 * credentials for them (We can't do this while making the
	 * list because it messes up the keytab iteration cursor
	 * when we use the keytab to get credentials.)
	 */
	for (ple = gssd_k5_kt_princ_list; ple; ple = ple->next) {
		if ((gssd_get_single_krb5_cred(context, kt, ple)) == 0) {
			gotone++;
		}
	}
	if (!gotone) {
		printerr(0, "ERROR: No usable machine credentials obtained\n");
		goto out;
	}

	retval = 0;
  out:
  	if (kt) krb5_kt_close(context, kt);
	krb5_free_context(context);

	return retval;
}


/*
 * Return an array of pointers to names of credential cache files
 * which can be used to try to create gss contexts with a server.
 *
 * Returns:
 *	0 => list is attached
 *	nonzero => error
 */
int
gssd_get_krb5_machine_cred_list(char ***list)
{
	char **l;
	int listinc = 10;
	int listsize = listinc;
	int i = 0;
	int retval;
	struct gssd_k5_kt_princ *ple;

	/* Assume failure */
	*list = NULL;

	/* Refresh machine credentials */
	retval = gssd_refresh_krb5_machine_creds();
	if (retval)
		goto out;

	l = malloc(listsize * sizeof(char *));
	if (l == NULL) {
		retval = ENOMEM;
		goto out;
	}

	for (ple = gssd_k5_kt_princ_list; ple; ple = ple->next) {
		if (ple->ccname) {
			if (i + 1 > listsize) {
				void *tmp;

				listsize += listinc;
				tmp = realloc(l, listsize * sizeof(char *));
				if (tmp == NULL) {
					retval = ENOMEM;
					goto out_free;
				}
				l = tmp;
			}
			l[i] = strdup(ple->ccname);
			if (l[i++] == NULL) {
				retval = ENOMEM;
				goto out_free;
			}
		}
	}
	if (i > 0) {
		l[i] = NULL;
		*list = l;
		return 0;
	}
out_free:
	while (i > 0)
		free(l[i--]);
	free(l);
out:
	return retval;
}

/*
 * Frees the list of names returned in get_krb5_machine_cred_list()
 */
void
gssd_free_krb5_machine_cred_list(char **list)
{
	char **n;

	if (list == NULL)
		return;
	for (n = list; n && *n; n++) {
		free(*n);
	}
	free(list);
}

/*
 * Called upon exit.  Destroys machine credentials.
 */
void
gssd_destroy_krb5_machine_creds(void)
{
	krb5_context context;
	krb5_error_code code = 0;
	krb5_ccache ccache;
	struct gssd_k5_kt_princ *ple;

	code = krb5_init_context(&context);
	if (code) {
		printerr(0, "ERROR: %s while initializing krb5\n",
			 error_message(code));
		goto out;
	}

	for (ple = gssd_k5_kt_princ_list; ple; ple = ple->next) {
		if (!ple->ccname)
			continue;
		if ((code = krb5_cc_resolve(context, ple->ccname, &ccache))) {
			printerr(0, "WARNING: %s while resolving credential "
				    "cache '%s' for destruction\n",
				 error_message(code), ple->ccname);
			continue;
		}

		if ((code = krb5_cc_destroy(context, ccache))) {
			printerr(0, "WARNING: %s while destroying credential "
				    "cache '%s'\n",
				 error_message(code), ple->ccname);
		}
	}
  out:
	krb5_free_context(context);
}


