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
#include "config.h"
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <sys/param.h>
#include <gssapi/gssapi.h>
#if defined(HAVE_KRB5) && !defined(GSS_C_NT_HOSTBASED_SERVICE)
#include <gssapi/gssapi_generic.h>
#define GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#endif
#include "gss_util.h"
#include "err_util.h"
#include "gssd.h"
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <stdlib.h>
#ifdef HAVE_COM_ERR_H
# include <com_err.h>
#endif
#include "lsupport.h"

/* Global gssd_credentials handle */
gss_cred_id_t  gssd_cred_mgs;
gss_cred_id_t  gssd_cred_mds;
gss_cred_id_t  gssd_cred_oss;
int            gssd_cred_mgs_valid = 0;
int            gssd_cred_mds_valid = 0;
int            gssd_cred_oss_valid = 0;

char *mgs_local_realm = NULL;
char *mds_local_realm = NULL;
char *oss_local_realm = NULL;

gss_OID g_mechOid = GSS_C_NULL_OID;;

#if 0
static void
display_status_1(char *m, u_int32_t code, int type, const gss_OID mech)
{
	u_int32_t maj_stat, min_stat;
	gss_buffer_desc msg = GSS_C_EMPTY_BUFFER;
	u_int32_t msg_ctx = 0;
	char *typestr;

	switch (type) {
	case GSS_C_GSS_CODE:
		typestr = "GSS";
		break;
	case GSS_C_MECH_CODE:
		typestr = "mechanism";
		break;
	default:
		return;
		/* NOTREACHED */
	}

	for (;;) {
		maj_stat = gss_display_status(&min_stat, code,
		    type, mech, &msg_ctx, &msg);
		if (maj_stat != GSS_S_COMPLETE) {
			printerr(0, "ERROR: in call to "
				"gss_display_status called from %s\n", m);
			break;
		} else {
			printerr(0, "ERROR: GSS-API: (%s) error in %s(): %s\n",
			    typestr, m, (char *)msg.value);
		}

		if (msg.length != 0)
			(void) gss_release_buffer(&min_stat, &msg);

		if (msg_ctx == 0)
			break;
	}
}
#endif

static void
display_status_2(char *m, u_int32_t major, u_int32_t minor, const gss_OID mech)
{
	u_int32_t maj_stat1, min_stat1;
	u_int32_t maj_stat2, min_stat2;
	gss_buffer_desc maj_gss_buf = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc min_gss_buf = GSS_C_EMPTY_BUFFER;
	char maj_buf[30], min_buf[30];
	char *maj, *min;
	u_int32_t msg_ctx = 0;

	/* Get major status message */
	maj_stat1 = gss_display_status(&min_stat1, major,
		GSS_C_GSS_CODE, mech, &msg_ctx, &maj_gss_buf);

	if (maj_stat1 != GSS_S_COMPLETE) {
		snprintf(maj_buf, sizeof(maj_buf), "(0x%08x)", major);
		maj = &maj_buf[0];
	} else {
		maj = maj_gss_buf.value;
	}

	/* Get minor status message */
	maj_stat2 = gss_display_status(&min_stat2, minor,
		GSS_C_MECH_CODE, mech, &msg_ctx, &min_gss_buf);

	if (maj_stat2 != GSS_S_COMPLETE) {
		snprintf(min_buf, sizeof(min_buf), "(0x%08x)", minor);
		min = &min_buf[0];
	} else {
		min = min_gss_buf.value;
	}

	printerr(0, "ERROR: GSS-API: error in %s(): %s - %s\n",
		 m, maj, min);

	if (maj_gss_buf.length != 0)
		(void) gss_release_buffer(&min_stat1, &maj_gss_buf);
	if (min_gss_buf.length != 0)
		(void) gss_release_buffer(&min_stat2, &min_gss_buf);
}

void
pgsserr(char *msg, u_int32_t maj_stat, u_int32_t min_stat, const gss_OID mech)
{
	display_status_2(msg, maj_stat, min_stat, mech);
}

static
int extract_realm_name(gss_buffer_desc *name, char **realm)
{
        char *sname, *c;
	int   rc = 0;

        sname = malloc(name->length + 1);
        if (!sname) {
                printerr(0, "out of memory\n");
                return -ENOMEM;
        }

        memcpy(sname, name->value, name->length);
        sname[name->length] = '\0';
        printerr(1, "service principal: %s\n", sname);

        c = strchr(sname, '@');
        if (!c) {
        	printerr(2, "no realm found in principal, use default\n");
		*realm = strdup(this_realm);
                if (!*realm) {
                        printerr(0, "failed to duplicate default realm\n");
                        rc = -ENOMEM;
                }
        } else {
                c++;
                *realm = strdup(c);
                if (!*realm) {
                        printerr(0, "failed to duplicated realm\n");
                        rc = -ENOMEM;
                }
        }
        free(sname);

        return rc;
}

static
int gssd_acquire_cred(char *server_name, gss_cred_id_t *cred,
		      char **local_realm, int *valid)
{
	gss_buffer_desc name;
	gss_name_t target_name;
	u_int32_t maj_stat, min_stat;
	u_int32_t ignore_maj_stat, ignore_min_stat;
	gss_OID name_type;
	gss_buffer_desc pbuf;

	*valid = 0;

	name.value = (void *)server_name;
	name.length = strlen(server_name);

	maj_stat = gss_import_name(&min_stat, &name,
			(const gss_OID) GSS_C_NT_HOSTBASED_SERVICE,
			&target_name);

	if (maj_stat != GSS_S_COMPLETE) {
		pgsserr("gss_import_name", maj_stat, min_stat, g_mechOid);
		return -1;
	}

	maj_stat = gss_display_name(&min_stat, target_name, &name, &name_type);
	if (maj_stat != GSS_S_COMPLETE) {
		pgsserr(0, maj_stat, min_stat, g_mechOid);
		return -1;
	}
	if (extract_realm_name(&name, local_realm))
		return -1;

	maj_stat = gss_acquire_cred(&min_stat, target_name, 0,
			GSS_C_NULL_OID_SET, GSS_C_ACCEPT,
			cred, NULL, NULL);

	if (maj_stat != GSS_S_COMPLETE) {
		pgsserr("gss_acquire_cred", maj_stat, min_stat, g_mechOid);
		ignore_maj_stat = gss_display_name(&ignore_min_stat,
				target_name, &pbuf, NULL);
		if (ignore_maj_stat == GSS_S_COMPLETE) {
			printerr(0, "Unable to obtain credentials for '%.*s'\n",
				 (int) pbuf.length, (char *) pbuf.value);
			ignore_maj_stat = gss_release_buffer(&ignore_min_stat,
							     &pbuf);
		}
	} else
		*valid = 1;

	ignore_maj_stat = gss_release_name(&ignore_min_stat, &target_name);

	if (maj_stat != GSS_S_COMPLETE)
		return -1;
	return 0;
}

int gssd_prepare_creds(int must_srv_mgs, int must_srv_mds, int must_srv_oss)
{
        if (gssd_acquire_cred(GSSD_SERVICE_MGS, &gssd_cred_mgs,
                              &mgs_local_realm, &gssd_cred_mgs_valid)) {
                if (must_srv_mgs)
                        return -1;
        }

        if (gssd_acquire_cred(GSSD_SERVICE_MDS, &gssd_cred_mds,
                              &mds_local_realm, &gssd_cred_mds_valid)) {
                if (must_srv_mds)
                        return -1;
        }

        if (gssd_acquire_cred(GSSD_SERVICE_OSS, &gssd_cred_oss,
                              &oss_local_realm, &gssd_cred_oss_valid)) {
                if (must_srv_oss)
                        return -1;
        }

        if (!gssd_cred_mgs_valid &&
	    !gssd_cred_mds_valid &&
            !gssd_cred_oss_valid) {
                printerr(0, "can't obtain any service creds, exit\n");
                return -1;
        }

	if (gssd_cred_mgs_valid)
		printerr(0, "Ready to serve Lustre MGS in realm %s\n",
			 mgs_local_realm ? mgs_local_realm : "N/A");
	if (gssd_cred_mds_valid)
		printerr(0, "Ready to serve Lustre MDS in realm %s\n",
			 mds_local_realm ? mds_local_realm : "N/A");
	if (gssd_cred_oss_valid)
		printerr(0, "Ready to serve Lustre OSS in realm %s\n",
			 oss_local_realm ? oss_local_realm : "N/A");

        return 0;
}

gss_cred_id_t gssd_select_svc_cred(int lustre_svc)
{
        switch (lustre_svc) {
	case LUSTRE_GSS_SVC_MGS:
		if (!gssd_cred_mgs_valid) {
                        printerr(0, "ERROR: service cred for mgs not ready\n");
                        return NULL;
		}
		return gssd_cred_mgs;
        case LUSTRE_GSS_SVC_MDS:
                if (!gssd_cred_mds_valid) {
                        printerr(0, "ERROR: service cred for mds not ready\n");
                        return NULL;
                }
		printerr(2, "select mds service cred\n");
                return gssd_cred_mds;
        case LUSTRE_GSS_SVC_OSS:
                if (!gssd_cred_oss_valid) {
                        printerr(0, "ERROR: service cred for oss not ready\n");
                        return NULL;
                }
		printerr(2, "select oss service cred\n");
                return gssd_cred_oss;
        default:
                printerr(0, "ERROR: invalid lustre svc id %d\n", lustre_svc);
        }

        return NULL;
}

int gssd_check_mechs(void)
{
	u_int32_t maj_stat, min_stat;
	gss_OID_set supported_mechs = GSS_C_NO_OID_SET;
	int retval = -1;

	maj_stat = gss_indicate_mechs(&min_stat, &supported_mechs);
	if (maj_stat != GSS_S_COMPLETE) {
		printerr(0, "Unable to obtain list of supported mechanisms. "
			 "Check that gss library is properly configured.\n");
		goto out;
	}
	if (supported_mechs == GSS_C_NO_OID_SET ||
	    supported_mechs->count == 0) {
		printerr(0, "Unable to obtain list of supported mechanisms. "
			 "Check that gss library is properly configured.\n");
		goto out;
	}
	maj_stat = gss_release_oid_set(&min_stat, &supported_mechs);
	retval = 0;
out:
	return retval;
}

/*********************************
 * FIXME should be in krb5_util.c
 *********************************/

#include "krb5_util.h"

/* realm of this node */
char *this_realm = NULL;

int gssd_get_local_realm(void)
{
	krb5_context context = NULL;
	krb5_error_code code;
	int retval = -1;

	if (this_realm != NULL)
		return 0;

	code = krb5_init_context(&context);
	if (code) {
		printerr(0, "ERROR: get default realm: init ctx: %s\n",
			 error_message(code));
		goto out;
	}

	code = krb5_get_default_realm(context, &this_realm);
	if (code) {
		printerr(0, "ERROR: get default realm: %s\n",
			 error_message(code));
		goto out;
	}
	retval = 0;

	printerr(1, "Local realm: %s\n", this_realm);
out:
	krb5_free_context(context);
	return retval;
}

