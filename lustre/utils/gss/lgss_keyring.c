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
 * Copyright (c) 2011, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/utils/gss/lgss_keyring.c
 *
 * user-space upcall to create GSS context, using keyring interface to kernel
 *
 * Author: Eric Mei <ericm@clusterfs.com>
 */

#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <keyutils.h>
#include <gssapi/gssapi.h>
#include <sys/wait.h>

#include <libcfs/util/param.h>
#include <libcfs/util/string.h>
#include "lsupport.h"
#include "lgss_utils.h"
#include "write_bytes.h"
#include "context.h"

/*
 * gss target string of lustre service we are negotiating for
 */
static char *g_service = NULL;

/*
 * all data about negotiation
 */
struct lgss_nego_data {
	uint32_t	lnd_established:1;

	int		lnd_secid;
	uint32_t	lnd_uid;
	uint32_t	lnd_lsvc;
	char		*lnd_uuid;

	gss_OID		lnd_mech;		/* mech OID */
	gss_name_t	lnd_svc_name;		/* service name */
	unsigned int	lnd_req_flags;		/* request flags */
	gss_cred_id_t	lnd_cred;		/* credential */
	gss_ctx_id_t	lnd_ctx;		/* session context */
	gss_buffer_desc	lnd_rmt_ctx;		/* remote handle of context */
	gss_buffer_desc	lnd_ctx_token;		/* context token for kernel */
	uint32_t	lnd_seq_win;		/* sequence window */

	int		lnd_rpc_err;
	int		lnd_gss_err;
};

/*
 * context creation response
 */
struct lgss_init_res {
	gss_buffer_desc gr_ctx;         /* context handle */
	unsigned int    gr_major;       /* major status */
	unsigned int    gr_minor;       /* minor status */
	unsigned int    gr_win;         /* sequence window */
	gss_buffer_desc gr_token;       /* token */
};

struct keyring_upcall_param {
	uint32_t        kup_ver;
	uint32_t        kup_secid;
	uint32_t        kup_uid;
	uint32_t        kup_fsuid;
	uint32_t        kup_gid;
	uint32_t        kup_fsgid;
	uint32_t        kup_svc;
	uint64_t        kup_nid;
	uint64_t        kup_selfnid;
	char		kup_svc_type;
	char            kup_tgt[64];
	char            kup_mech[16];
	unsigned int    kup_is_root:1,
			kup_is_mdt:1,
			kup_is_ost:1;
	uint32_t        kup_pid;
};

/****************************************
 * child process: gss negotiation       *
 ****************************************/

static int send_to(int fd, const void *buf, size_t size)
{
	ssize_t sz;

	sz = write(fd, buf, size);
	if (sz == -1) {
		logmsg(LL_ERR, "cannot send to GSS process: %s\n",
		       strerror(errno));
		return -errno;
	}
	if (sz < size) {
		logmsg(LL_ERR, "short write sending to GSS process: %d/%d\n",
		       (int)sz, (int)size);
		return -EPROTO;
	}

	return 0;
}

static int receive_from(int fd, void *buf, size_t size)
{
	ssize_t sz;

	sz = read(fd, buf, size);
	if (sz == -1) {
		logmsg(LL_ERR, "cannot receive from GSS process: %s\n",
		       strerror(errno));
		return -errno;
	}
	if (sz < size) {
		logmsg(LL_ERR, "short read receiving from GSS process: %d/%d\n",
		       (int)sz, (int)size);
		return -EPROTO;
	}

	return 0;
}

static int gss_do_ioctl(struct lgssd_ioctl_param *param)
{
	int fd, ret;
	glob_t path;
	int rc;

	rc = cfs_get_param_paths(&path, "sptlrpc/gss/init_channel");
	if (rc != 0)
		return rc;

	logmsg(LL_TRACE, "to open %s\n", path.gl_pathv[0]);

	fd = open(path.gl_pathv[0], O_WRONLY);
	if (fd < 0) {
		logmsg(LL_ERR, "can't open %s\n", path.gl_pathv[0]);
		rc = -EACCES;
		goto out_params;
	}

	logmsg(LL_TRACE, "to down-write\n");

	ret = write(fd, param, sizeof(*param));
	close(fd);
	if (ret != sizeof(*param)) {
		logmsg(LL_ERR, "lustre ioctl err: %s\n", strerror(errno));
		rc = -EACCES;
	}

out_params:
	cfs_free_param_data(&path);
	return rc;
}

int do_nego_rpc(struct lgss_nego_data *lnd,
		gss_buffer_desc *gss_token,
		struct lgss_init_res *gr,
		int req_fd[2], int reply_fd[2])
{
	struct lgssd_ioctl_param param;
	struct passwd *pw;
	int res;
	char outbuf[8192] = { 0 };
	unsigned int *p;
	int rc = 0;

	logmsg(LL_TRACE, "start negotiation rpc\n");

	pw = getpwuid(lnd->lnd_uid);
	if (!pw) {
		logmsg(LL_ERR, "no uid %u in local user database\n",
		       lnd->lnd_uid);
		return -EACCES;
	}

	param.version = GSSD_INTERFACE_VERSION;
	param.secid = lnd->lnd_secid;
	param.uuid = lnd->lnd_uuid;
	param.lustre_svc = lnd->lnd_lsvc;
	param.uid = lnd->lnd_uid;
	param.gid = pw->pw_gid;
	param.send_token_size = gss_token->length;
	param.send_token = (char *) gss_token->value;

	if (req_fd[0] == -1 && reply_fd[0] == -1) {
		/* we can do the ioctl directly */
		param.reply_buf_size = sizeof(outbuf);
		param.reply_buf = outbuf;

		rc = gss_do_ioctl(&param);
		if (rc != 0)
			return rc;
	} else {
		/* looks like we are running in a container,
		 * so we cannot do the ioctl ourselves: delegate to
		 * parent process running directly on host */

		/* send ioctl buffer to parent */
		rc = send_to(req_fd[1], &param, sizeof(param));
		if (rc != 0)
			return rc;
		/* send gss token to parent */
		rc = send_to(req_fd[1], gss_token->value, gss_token->length);
		if (rc != 0)
			return rc;

		/* read ioctl status from parent */
		rc = receive_from(reply_fd[0], &param.status,
				  sizeof(param.status));
		if (rc != 0)
			return rc;

		if (param.status == 0) {
			/* read reply buffer from parent */
			rc = receive_from(reply_fd[0], outbuf, sizeof(outbuf));
			if (rc != 0)
				return rc;
		}
	}

	logmsg(LL_TRACE, "do_nego_rpc: to parse reply\n");
	if (param.status) {
		logmsg(LL_ERR, "status: %ld (%s)\n",
		       param.status, strerror((int)(-param.status)));
		return param.status;
	}

	p = (unsigned int *)outbuf;
	res = *p++;
	gr->gr_major = *p++;
	gr->gr_minor = *p++;
	gr->gr_win = *p++;

	gr->gr_ctx.length = *p++;
	gr->gr_ctx.value = malloc(gr->gr_ctx.length);
	if (gr->gr_ctx.value == NULL)
		return -ENOMEM;
	memcpy(gr->gr_ctx.value, p, gr->gr_ctx.length);
	p += (((gr->gr_ctx.length + 3) & ~3) / 4);

	gr->gr_token.length = *p++;
	gr->gr_token.value = malloc(gr->gr_token.length);
	if (gr->gr_token.value == NULL) {
		free(gr->gr_ctx.value);
		return -ENOMEM;
	}
	memcpy(gr->gr_token.value, p, gr->gr_token.length);
	p += (((gr->gr_token.length + 3) & ~3) / 4);

	logmsg(LL_DEBUG, "do_nego_rpc: receive handle len %zu, token len %zu, "
	       "res %d\n", gr->gr_ctx.length, gr->gr_token.length, res);

	return rc;
}

/* This is used by incomplete GSSAPI implementations that can't use
 * gss_init_sec_context and will parse the token themselves (gssnull and sk).
 * Callers should have cred->lc_mech_token pointing to a gss_buffer_desc
 * token to send to the peer as part of the SEC_CTX_INIT operation.  The return
 * RPC's token with be in gr.gr_token which is validated using
 * lgss_validate_cred. */
static int lgssc_negotiation_manual(struct lgss_nego_data *lnd,
				    struct lgss_cred *cred,
				    int req_fd[2], int reply_fd[2])
{
	struct lgss_init_res gr;
	OM_uint32 min_stat;
	int rc;

	logmsg(LL_TRACE, "starting gss negotation\n");
	memset(&gr, 0, sizeof(gr));

	lnd->lnd_rpc_err = do_nego_rpc(lnd, &cred->lc_mech_token, &gr,
				       req_fd, reply_fd);
	if (lnd->lnd_rpc_err) {
		logmsg(LL_ERR, "negotiation rpc error %d\n", lnd->lnd_rpc_err);
		rc = lnd->lnd_rpc_err;
		goto out_error;
	}

	if (gr.gr_major == GSS_S_CONTINUE_NEEDED) {
		rc = -EAGAIN;
		goto out_error;

	} else if (gr.gr_major != GSS_S_COMPLETE) {
		lnd->lnd_gss_err = gr.gr_major;
		logmsg(LL_ERR, "negotiation gss error %x\n", lnd->lnd_gss_err);
		rc = -ENOTCONN;
		goto out_error;
	}

	if (gr.gr_ctx.length == 0 || gr.gr_token.length == 0) {
		logmsg(LL_ERR, "zero length context or token received\n");
		rc = -EINVAL;
		goto out_error;
	}

	rc = lgss_validate_cred(cred, &gr.gr_token, &lnd->lnd_ctx_token);
	if (rc) {
		logmsg(LL_ERR, "peer token failed validation\n");
		goto out_error;
	}

	lnd->lnd_established = 1;
	lnd->lnd_seq_win = gr.gr_win;
	lnd->lnd_rmt_ctx = gr.gr_ctx;

	if (gr.gr_token.length != 0)
		gss_release_buffer(&min_stat, &gr.gr_token);

	logmsg(LL_DEBUG, "successfully negotiated a context\n");
	return 0;

out_error:
	if (gr.gr_ctx.length != 0)
		gss_release_buffer(&min_stat, &gr.gr_ctx);
	if (gr.gr_token.length != 0)
		gss_release_buffer(&min_stat, &gr.gr_token);

	return rc;
}

/*
 * if return error, the lnd_rpc_err or lnd_gss_err is set.
 */
static int lgssc_negotiation(struct lgss_nego_data *lnd, int req_fd[2],
			     int reply_fd[2])
{
	struct lgss_init_res    gr;
	gss_buffer_desc        *recv_tokenp, send_token;
	OM_uint32               maj_stat, min_stat, ret_flags;

	logmsg(LL_TRACE, "start gss negotiation\n");

	/* GSS context establishment loop. */
	memset(&gr, 0, sizeof(gr));
	recv_tokenp = GSS_C_NO_BUFFER;

	for (;;) {
		maj_stat = gss_init_sec_context(&min_stat,
						lnd->lnd_cred,
						&lnd->lnd_ctx,
						lnd->lnd_svc_name,
						lnd->lnd_mech,
						lnd->lnd_req_flags,
						0,            /* time req */
						NULL,         /* channel */
						recv_tokenp,
						NULL,         /* used mech */
						&send_token,
						&ret_flags,
						NULL);        /* time rec */

		if (recv_tokenp != GSS_C_NO_BUFFER) {
			gss_release_buffer(&min_stat, &gr.gr_token);
			recv_tokenp = GSS_C_NO_BUFFER;
		}

		if (maj_stat != GSS_S_COMPLETE &&
		    maj_stat != GSS_S_CONTINUE_NEEDED) {
			lnd->lnd_gss_err = maj_stat;

			logmsg_gss(LL_ERR, lnd->lnd_mech, maj_stat, min_stat,
				   "failed init context");
			break;
		}

		if (send_token.length != 0) {
			memset(&gr, 0, sizeof(gr));

			lnd->lnd_rpc_err = do_nego_rpc(lnd, &send_token, &gr,
						       req_fd, reply_fd);
			gss_release_buffer(&min_stat, &send_token);

			if (lnd->lnd_rpc_err) {
				logmsg(LL_ERR, "negotiation rpc error: %d\n",
				       lnd->lnd_rpc_err);
				return lnd->lnd_rpc_err;
			}

			if (gr.gr_major != GSS_S_COMPLETE &&
			    gr.gr_major != GSS_S_CONTINUE_NEEDED) {
				lnd->lnd_gss_err = gr.gr_major;

				logmsg(LL_ERR, "negotiation gss error %x\n",
				       lnd->lnd_gss_err);
				return -ENOTCONN;
			}

			if (gr.gr_ctx.length != 0) {
				if (lnd->lnd_rmt_ctx.value)
					gss_release_buffer(&min_stat,
							   &lnd->lnd_rmt_ctx);
				lnd->lnd_rmt_ctx = gr.gr_ctx;
			}

			if (gr.gr_token.length != 0) {
				if (maj_stat != GSS_S_CONTINUE_NEEDED)
					break;
				recv_tokenp = &gr.gr_token;
			}
		}

		/* GSS_S_COMPLETE => check gss header verifier,
		 * usually checked in gss_validate
		 */
		if (maj_stat == GSS_S_COMPLETE) {
			lnd->lnd_established = 1;
			lnd->lnd_seq_win = gr.gr_win;
			break;
		}
	}

	/* End context negotiation loop. */
	if (!lnd->lnd_established) {
		if (gr.gr_token.length != 0)
			gss_release_buffer(&min_stat, &gr.gr_token);

		if (lnd->lnd_gss_err == GSS_S_COMPLETE)
			lnd->lnd_rpc_err = -EACCES;

		logmsg(LL_ERR, "context negotiation failed\n");
		return -1;
	}

	logmsg(LL_DEBUG, "successfully negotiated a context\n");
	return 0;
}

/*
 * if return error, the lnd_rpc_err or lnd_gss_err is set.
 */
static int lgssc_init_nego_data(struct lgss_nego_data *lnd,
				struct keyring_upcall_param *kup,
				enum lgss_mech mech)
{
        gss_buffer_desc         sname;
        OM_uint32               maj_stat, min_stat;

        memset(lnd, 0, sizeof(*lnd));

	lnd->lnd_secid = kup->kup_secid;
	lnd->lnd_uid = kup->kup_uid;
	lnd->lnd_lsvc = kup->kup_svc | mech << LUSTRE_GSS_MECH_SHIFT;
	lnd->lnd_uuid = kup->kup_tgt;

        lnd->lnd_established = 0;
        lnd->lnd_svc_name = GSS_C_NO_NAME;
        lnd->lnd_cred = GSS_C_NO_CREDENTIAL;
        lnd->lnd_ctx = GSS_C_NO_CONTEXT;
        lnd->lnd_rmt_ctx = (gss_buffer_desc) GSS_C_EMPTY_BUFFER;
        lnd->lnd_seq_win = 0;

        switch (mech) {
	case LGSS_MECH_KRB5:
		lnd->lnd_mech = (gss_OID)&krb5oid;
		lnd->lnd_req_flags = GSS_C_MUTUAL_FLAG;
		break;
	case LGSS_MECH_NULL:
		lnd->lnd_mech = (gss_OID)&nulloid;
		break;
#ifdef HAVE_OPENSSL_SSK
	case LGSS_MECH_SK:
		lnd->lnd_mech = (gss_OID)&skoid;
		lnd->lnd_req_flags = GSS_C_MUTUAL_FLAG;
		break;
#endif
	default:
		logmsg(LL_ERR, "invalid mech: %d\n", mech);
		lnd->lnd_rpc_err = -EACCES;
		return -1;
        }

        sname.value = g_service;
        sname.length = strlen(g_service);

        maj_stat = gss_import_name(&min_stat, &sname,
                                   (gss_OID) GSS_C_NT_HOSTBASED_SERVICE,
                                   &lnd->lnd_svc_name);
        if (maj_stat != GSS_S_COMPLETE) {
                logmsg_gss(LL_ERR, lnd->lnd_mech, maj_stat, min_stat,
                           "can't import svc name");
                lnd->lnd_gss_err = maj_stat;
                return -1;
        }

        return 0;
}

void lgssc_fini_nego_data(struct lgss_nego_data *lnd)
{
        OM_uint32       maj_stat, min_stat;

        if (lnd->lnd_svc_name != GSS_C_NO_NAME) {
                maj_stat = gss_release_name(&min_stat, &lnd->lnd_svc_name);
                if (maj_stat != GSS_S_COMPLETE)
                        logmsg_gss(LL_ERR, lnd->lnd_mech, maj_stat, min_stat,
                                   "can't release service name");
        }

        if (lnd->lnd_cred != GSS_C_NO_CREDENTIAL) {
                maj_stat = gss_release_cred(&min_stat, &lnd->lnd_cred);
                if (maj_stat != GSS_S_COMPLETE)
                        logmsg_gss(LL_ERR, lnd->lnd_mech, maj_stat, min_stat,
                                   "can't release credential");
        }
}

static
int error_kernel_key(key_serial_t keyid, int rpc_error, int gss_error)
{
        int      seqwin = 0;
        char     buf[32];
        char    *p, *end;

        logmsg(LL_TRACE, "revoking kernel key %08x\n", keyid);

        p = buf;
        end = buf + sizeof(buf);

        WRITE_BYTES(&p, end, seqwin);
        WRITE_BYTES(&p, end, rpc_error);
        WRITE_BYTES(&p, end, gss_error);

again:
        if (keyctl_update(keyid, buf, p - buf)) {
                if (errno != EAGAIN) {
                        logmsg(LL_ERR, "revoke key %08x: %s\n",
                               keyid, strerror(errno));
                        return -1;
                }

                logmsg(LL_WARN, "key %08x: revoking too soon, try again\n",
                       keyid);
                sleep(2);
                goto again;
        }

        logmsg(LL_INFO, "key %08x: revoked\n", keyid);
        return 0;
}

static
int update_kernel_key(key_serial_t keyid,
                      struct lgss_nego_data *lnd,
                      gss_buffer_desc *ctx_token)
{
        char        *buf = NULL, *p = NULL, *end = NULL;
        unsigned int buf_size = 0;
        int          rc;

        logmsg(LL_TRACE, "updating kernel key %08x\n", keyid);

        buf_size = sizeof(lnd->lnd_seq_win) +
                   sizeof(lnd->lnd_rmt_ctx.length) + lnd->lnd_rmt_ctx.length +
                   sizeof(ctx_token->length) + ctx_token->length;
        buf = malloc(buf_size);
        if (buf == NULL) {
                logmsg(LL_ERR, "key %08x: can't alloc update buf: size %d\n",
                       keyid, buf_size);
                return 1;
        }

        p = buf;
        end = buf + buf_size;
        rc = -1;

        if (WRITE_BYTES(&p, end, lnd->lnd_seq_win))
                goto out;
        if (write_buffer(&p, end, &lnd->lnd_rmt_ctx))
                goto out;
        if (write_buffer(&p, end, ctx_token))
                goto out;

again:
        if (keyctl_update(keyid, buf, p - buf)) {
                if (errno != EAGAIN) {
                        logmsg(LL_ERR, "update key %08x: %s\n",
                               keyid, strerror(errno));
                        goto out;
                }

                logmsg(LL_DEBUG, "key %08x: updating too soon, try again\n",
                       keyid);
                sleep(2);
                goto again;
        }

        rc = 0;
        logmsg(LL_DEBUG, "key %08x: updated\n", keyid);
out:
        free(buf);
        return rc;
}

static int lgssc_kr_negotiate_krb(key_serial_t keyid, struct lgss_cred *cred,
				  struct keyring_upcall_param *kup,
				  int req_fd[2], int reply_fd[2])
{
	struct lgss_nego_data lnd;
	OM_uint32 min_stat;
	int rc = -1;
	bool redo = true;

	if (lgss_get_service_str(&g_service, kup->kup_svc, kup->kup_nid)) {
		logmsg(LL_ERR, "key %08x: failed to construct service "
		       "string\n", keyid);
		error_kernel_key(keyid, -EACCES, 0);
		goto out_cred;
	}

	if (lgss_using_cred(cred)) {
		logmsg(LL_ERR, "key %08x: can't using cred\n", keyid);
		error_kernel_key(keyid, -EACCES, 0);
		goto out_cred;
	}

retry_nego:
	memset(&lnd, 0, sizeof(lnd));
	if (lgssc_init_nego_data(&lnd, kup, cred->lc_mech->lmt_mech_n)) {
		logmsg(LL_ERR, "key %08x: failed to initialize "
		       "negotiation data\n", keyid);
		error_kernel_key(keyid, lnd.lnd_rpc_err, lnd.lnd_gss_err);
		goto out_cred;
	}

	rc = lgssc_negotiation(&lnd, req_fd, reply_fd);
	if (rc == -EAGAIN || (rc == -ETIMEDOUT && redo)) {
		logmsg(LL_ERR, "Failed negotiation must retry\n");
		redo = false;
		goto retry_nego;
	} else if (rc) {
		logmsg(LL_ERR, "key %08x: failed to negotiation\n", keyid);
		error_kernel_key(keyid, lnd.lnd_rpc_err, lnd.lnd_gss_err);
		goto out;
	}

	rc = serialize_context_for_kernel(lnd.lnd_ctx, &lnd.lnd_ctx_token,
					  lnd.lnd_mech);
	if (rc) {
		logmsg(LL_ERR, "key %08x: failed to export context\n", keyid);
		error_kernel_key(keyid, rc, lnd.lnd_gss_err);
		goto out;
	}

	rc = update_kernel_key(keyid,  &lnd, &lnd.lnd_ctx_token);
	if (rc)
		goto out;

	rc = 0;
	logmsg(LL_INFO, "key %08x for user %u is updated OK!\n",
	       keyid, kup->kup_uid);
out:
	if (lnd.lnd_ctx_token.length != 0)
		gss_release_buffer(&min_stat, &lnd.lnd_ctx_token);

	lgssc_fini_nego_data(&lnd);

out_cred:
	lgss_release_cred(cred);
	return rc;
}

static int lgssc_kr_negotiate_manual(key_serial_t keyid, struct lgss_cred *cred,
				     struct keyring_upcall_param *kup,
				     int req_fd[2], int reply_fd[2])
{
	struct lgss_nego_data lnd;
	OM_uint32 min_stat;
	int rc;
	bool redo = true;

	rc = lgss_get_service_str(&g_service, kup->kup_svc, kup->kup_nid);
	if (rc) {
		logmsg(LL_ERR, "key %08x: failed to construct service "
		       "string\n", keyid);
		error_kernel_key(keyid, -EACCES, 0);
		goto out_cred;
	}

	rc = lgss_using_cred(cred);
	if (rc) {
		logmsg(LL_ERR, "key %08x: can't use cred\n", keyid);
		error_kernel_key(keyid, -EACCES, 0);
		goto out_cred;
	}

retry:
	memset(&lnd, 0, sizeof(lnd));
	rc = lgssc_init_nego_data(&lnd, kup, cred->lc_mech->lmt_mech_n);
	if (rc) {
		logmsg(LL_ERR, "key %08x: failed to initialize "
		       "negotiation data\n", keyid);
		error_kernel_key(keyid, lnd.lnd_rpc_err, lnd.lnd_gss_err);
		goto out_cred;
	}

	/*
	 * Handles the negotiation but then calls lgss_validate to make sure
	 * the token is valid.  It also populates the lnd_ctx_token for the
	 * update to the kernel key
	 */
	rc = lgssc_negotiation_manual(&lnd, cred, req_fd, reply_fd);
	if (rc == -EAGAIN || (rc == -ETIMEDOUT && redo)) {
		logmsg(LL_ERR, "Failed negotiation must retry\n");
		redo = false;
		goto retry;
	} else if (rc) {
		logmsg(LL_ERR, "key %08x: failed to negotiate\n", keyid);
		error_kernel_key(keyid, lnd.lnd_rpc_err, lnd.lnd_gss_err);
		goto out;
	}

	rc = update_kernel_key(keyid,  &lnd, &lnd.lnd_ctx_token);
	if (rc)
		goto out;

	logmsg(LL_INFO, "key %08x for user %u is updated OK!\n",
	       keyid, kup->kup_uid);
out:
	if (lnd.lnd_ctx_token.length != 0)
		gss_release_buffer(&min_stat, &lnd.lnd_ctx_token);

	lgssc_fini_nego_data(&lnd);

out_cred:
	lgss_release_cred(cred);
	return rc;
}

/*
 * note we inherited assumed authority from parent process
 */
static int lgssc_kr_negotiate(key_serial_t keyid, struct lgss_cred *cred,
			      struct keyring_upcall_param *kup,
			      int req_fd[2], int reply_fd[2])
{
	int rc;

	logmsg(LL_TRACE, "child start on behalf of key %08x: "
	       "cred %p, uid %u, svc %u, nid %"PRIx64", uids: %u:%u/%u:%u\n",
	       keyid, cred, cred->lc_uid, cred->lc_tgt_svc, cred->lc_tgt_nid,
	       kup->kup_uid, kup->kup_gid, kup->kup_fsuid, kup->kup_fsgid);

	switch (cred->lc_mech->lmt_mech_n) {
	case LGSS_MECH_NULL:
	case LGSS_MECH_SK:
		rc = lgssc_kr_negotiate_manual(keyid, cred, kup,
					       req_fd, reply_fd);
		break;
	case LGSS_MECH_KRB5:
	default:
		rc = lgssc_kr_negotiate_krb(keyid, cred, kup, req_fd, reply_fd);
		break;
	}

	return rc;
}

/*
 * call out info format: s[:s]...
 *  [0]: secid          (uint)
 *  [1]: mech_name      (string)
 *  [2]: uid            (uint)
 *  [3]: gid            (uint)
 *  [4]: flags          (string) FMT: r-root; m-mdt; o-ost
 *  [5]: svc type       (char)
 *  [6]: lustre_svc     (int)
 *  [7]: target_nid     (uint64)
 *  [8]: target_uuid    (string)
 *  [9]: self_nid        (uint64)
 *  [10]: pid            (uint)
 */
static int parse_callout_info(const char *coinfo,
                              struct keyring_upcall_param *uparam)
{
	const int       nargs = 11;
	char            buf[1024];
	char           *string = buf;
	int             length, i;
	char           *data[nargs];
	char           *pos;

        length = strlen(coinfo) + 1;
        if (length > 1024) {
                logmsg(LL_ERR, "coinfo too long\n");
                return -1;
        }
        memcpy(buf, coinfo, length);

        for (i = 0; i < nargs - 1; i++) {
                pos = strchr(string, ':');
                if (pos == NULL) {
                        logmsg(LL_ERR, "short of components\n");
                        return -1;
                }

                *pos = '\0';
                data[i] = string;
                string = pos + 1;
        }
        data[i] = string;

	logmsg(LL_TRACE, "components: %s,%s,%s,%s,%s,%c,%s,%s,%s,%s,%s\n",
	       data[0], data[1], data[2], data[3], data[4], data[5][0],
	       data[6], data[7], data[8], data[9], data[10]);

	uparam->kup_secid = strtol(data[0], NULL, 0);
	snprintf(uparam->kup_mech, sizeof(uparam->kup_mech), "%s", data[1]);
	uparam->kup_uid = strtol(data[2], NULL, 0);
	uparam->kup_gid = strtol(data[3], NULL, 0);
	if (strchr(data[4], 'r'))
		uparam->kup_is_root = 1;
	if (strchr(data[4], 'm'))
		uparam->kup_is_mdt = 1;
	if (strchr(data[4], 'o'))
		uparam->kup_is_ost = 1;
	uparam->kup_svc_type = data[5][0];
	uparam->kup_svc = strtol(data[6], NULL, 0);
	uparam->kup_nid = strtoll(data[7], NULL, 0);
	snprintf(uparam->kup_tgt, sizeof(uparam->kup_tgt), "%s", data[8]);
	uparam->kup_selfnid = strtoll(data[9], NULL, 0);
	uparam->kup_pid = strtol(data[10], NULL, 0);

	logmsg(LL_DEBUG, "parse call out info: secid %d, mech %s, ugid %u:%u, "
	       "is_root %d, is_mdt %d, is_ost %d, svc type %c, svc %d, "
	       "nid 0x%"PRIx64", tgt %s, self nid 0x%"PRIx64", pid %d\n",
	       uparam->kup_secid, uparam->kup_mech,
	       uparam->kup_uid, uparam->kup_gid,
	       uparam->kup_is_root, uparam->kup_is_mdt, uparam->kup_is_ost,
	       uparam->kup_svc_type, uparam->kup_svc, uparam->kup_nid,
	       uparam->kup_tgt, uparam->kup_selfnid, uparam->kup_pid);
	return 0;
}

static void set_log_level()
{
	unsigned int level;
	glob_t path;
	FILE *file;

	if (cfs_get_param_paths(&path,
				"sptlrpc/gss/lgss_keyring/debug_level") != 0)
		return;
	file = fopen(path.gl_pathv[0], "r");
	if (file == NULL) {
		cfs_free_param_data(&path);
		return;
	}

	if (fscanf(file, "%u", &level) != 1)
		goto out;

	if (level >= LL_MAX)
		goto out;

	lgss_set_loglevel(level);
out:
	cfs_free_param_data(&path);
	fclose(file);
}

static int associate_with_ns(char *path)
{
	int fd, rc = -1;

	fd = open(path, O_RDONLY);
	if (fd != -1) {
		rc = setns(fd, 0);
		close(fd);
	}

	return rc;
}

static int prepare_and_instantiate(struct lgss_cred *cred, key_serial_t keyid,
				   uint32_t uid)
{
	key_serial_t inst_keyring;

	if (lgss_prepare_cred(cred)) {
		logmsg(LL_ERR, "key %08x: failed to prepare credentials "
		       "for user %d\n", keyid, uid);
		return 1;
	}

	/* pre initialize the key. note the keyring linked to is actually of the
	 * original requesting process, not _this_ upcall process. if it's for
	 * root user, don't link to any keyrings because we want fully control
	 * on it, and share it among all root sessions; otherswise link to
	 * session keyring.
	 */
	if (cred->lc_root_flags != 0)
		inst_keyring = 0;
	else
		inst_keyring = KEY_SPEC_SESSION_KEYRING;

	if (keyctl_instantiate(keyid, NULL, 0, inst_keyring)) {
		logmsg(LL_ERR, "instantiate key %08x: %s\n",
		       keyid, strerror(errno));
		return 1;
	}

	logmsg(LL_TRACE, "instantiated kernel key %08x\n", keyid);

	return 0;
}

/****************************************
 * main process                         *
 ****************************************/

int main(int argc, char *argv[])
{
	struct keyring_upcall_param   uparam;
	key_serial_t                  keyid;
	key_serial_t                  sring;
	pid_t                         child;
	int			      req_fd[2] = { -1, -1 };
	int			      reply_fd[2] = { -1, -1 };
	struct lgss_mech_type        *mech;
	struct lgss_cred             *cred;
	char			      path[PATH_MAX] = "";
	int			      other_ns = 0;
	int			      rc = 0;
	struct stat		      parent_ns = { .st_ino = 0 };
	struct stat		      caller_ns = { .st_ino = 0 };

	set_log_level();

	logmsg(LL_TRACE, "start parsing parameters\n");
	/*
	 * parse & sanity check upcall parameters
	 * expected to be called with:
	 * [1]:  operation
	 * [2]:  key ID
	 * [3]:  key type
	 * [4]:  key description
	 * [5]:  call out info
	 * [6]:  UID
	 * [7]:  GID
	 * [8]:  thread keyring
	 * [9]:  process keyring
	 * [10]: session keyring
	 */
	if (argc != 10 + 1) {
		logmsg(LL_ERR, "invalid parameter number %d\n", argc);
		return 1;
	}

	logmsg(LL_INFO, "key %s, desc %s, ugid %s:%s, sring %s, coinfo %s\n",
	       argv[2], argv[4], argv[6], argv[7], argv[10], argv[5]);

	memset(&uparam, 0, sizeof(uparam));

	if (strcmp(argv[1], "create") != 0) {
		logmsg(LL_ERR, "invalid OP %s\n", argv[1]);
		return 1;
	}

	if (sscanf(argv[2], "%d", &keyid) != 1) {
		logmsg(LL_ERR, "can't extract KeyID: %s\n", argv[2]);
		return 1;
	}

	if (sscanf(argv[6], "%d", &uparam.kup_fsuid) != 1) {
		logmsg(LL_ERR, "can't extract UID: %s\n", argv[6]);
		return 1;
	}

	if (sscanf(argv[7], "%d", &uparam.kup_fsgid) != 1) {
		logmsg(LL_ERR, "can't extract GID: %s\n", argv[7]);
		return 1;
	}

	if (sscanf(argv[10], "%d", &sring) != 1) {
		logmsg(LL_ERR, "can't extract session keyring: %s\n", argv[10]);
		return 1;
	}

	if (parse_callout_info(argv[5], &uparam)) {
		logmsg(LL_ERR, "can't extract callout info: %s\n", argv[5]);
		return 1;
	}

	logmsg(LL_TRACE, "parsing parameters OK\n");

	/*
	 * prepare a cred
	 */
	mech = lgss_name2mech(uparam.kup_mech);
	if (mech == NULL) {
		logmsg(LL_ERR, "key %08x: unsupported mech: %s\n",
		       keyid, uparam.kup_mech);
		return 1;
	}

	if (lgss_mech_initialize(mech)) {
		logmsg(LL_ERR, "key %08x: can't initialize mech %s\n",
		       keyid, mech->lmt_name);
		return 1;
	}

	cred = lgss_create_cred(mech);
	if (cred == NULL) {
		logmsg(LL_ERR, "key %08x: can't create a new %s cred\n",
		       keyid, mech->lmt_name);
		return 1;
	}

	cred->lc_uid = uparam.kup_uid;
	cred->lc_root_flags |= uparam.kup_is_root ? LGSS_ROOT_CRED_ROOT : 0;
	cred->lc_root_flags |= uparam.kup_is_mdt ? LGSS_ROOT_CRED_MDT : 0;
	cred->lc_root_flags |= uparam.kup_is_ost ? LGSS_ROOT_CRED_OST : 0;
	cred->lc_tgt_nid = uparam.kup_nid;
	cred->lc_tgt_svc = uparam.kup_svc;
	cred->lc_tgt_uuid = uparam.kup_tgt;
	cred->lc_svc_type = uparam.kup_svc_type;
	cred->lc_self_nid = uparam.kup_selfnid;

	/* Is caller in different namespace? */
	/* If passed caller's pid is 0, it means we have to stick
	 * with current namespace.
	 */
	if (uparam.kup_pid) {
		snprintf(path, sizeof(path), "/proc/%d/ns/mnt", getpid());
		if (stat(path, &parent_ns)) {
			logmsg(LL_DEBUG, "cannot stat %s: %s\n",
			       path, strerror(errno));
		} else {
			snprintf(path, sizeof(path), "/proc/%d/ns/mnt",
				 uparam.kup_pid);
			if (stat(path, &caller_ns))
				logmsg(LL_DEBUG, "cannot stat %s: %s\n",
				       path, strerror(errno));
			else if (caller_ns.st_ino != parent_ns.st_ino)
				other_ns = 1;
		}
	}

	/*
	 * if caller's namespace is different, fork a child and associate it
	 * with caller's namespace to do credentials preparation
	 */
	if (other_ns) {
		logmsg(LL_TRACE, "caller's namespace is different\n");

		/* use pipes to pass info between child and parent processes */
		if (pipe(req_fd) == -1) {
			logmsg(LL_ERR, "key %08x: pipe failed: %s\n",
			       keyid, strerror(errno));
			return 1;
		}
		if (pipe(reply_fd) == -1) {
			logmsg(LL_ERR, "key %08x: pipe failed: %s\n",
			       keyid, strerror(errno));
			return 1;
		}

		child = fork();
		if (child == -1) {
			logmsg(LL_ERR, "key %08x: can't create child: %s\n",
			       keyid, strerror(errno));
			rc = 1;
			goto out_pipe;
		} else if (child == 0) {
			int rc2;
			/* child process: carry out credentials preparation
			 * in caller's namespace */

			close(req_fd[0]); /* close unsed read end */
			req_fd[0] = -1;
			close(reply_fd[1]); /* close unsed write end */
			reply_fd[1] = -1;

			if (associate_with_ns(path) != 0) {
				logmsg(LL_ERR,
				       "failed to attach to pid %d namespace: "
				       "%s\n", uparam.kup_pid, strerror(errno));
				rc = 1;
				goto out_pipe;
			}
			logmsg(LL_TRACE, "working in namespace of pid %d\n",
			       uparam.kup_pid);

			rc = prepare_and_instantiate(cred, keyid,
						     uparam.kup_uid);

			/* send to parent the status of credentials preparation
			 * and key instantiation */
			rc2 = send_to(req_fd[1], &rc, sizeof(rc));
			rc = (rc == 0 ? rc2 : rc);
			if (rc != 0)
				goto out_pipe;

			/* now do real gss negotiation
			 * parent main process will not wait for us,
			 * as it has to be done in the background */
			rc = lgssc_kr_negotiate(keyid, cred, &uparam,
						req_fd, reply_fd);
			goto out_pipe;
		} else {
			int rc2;
			/* parent process: exchange info with child carrying out
			 * credentials preparation */

			close(req_fd[1]); /* close unsed write end */
			req_fd[1] = -1;
			close(reply_fd[0]); /* close unsed read end */
			reply_fd[0] = -1;

			/* get status of credentials preparation
			 * and key instantiation */
			rc2 = receive_from(req_fd[0], &rc, sizeof(rc));
			if (rc2 != 0 || rc != 0) {
				logmsg(LL_ERR, "child failed preparing creds: "
				       "%s\n",
				       rc2 != 0 ? strerror(-rc2)
						: strerror(rc));
				goto out_pipe;
			}

			/*
			 * fork a child here to participate in gss negotiation,
			 * as it has to be done in the background
			 */
			child = fork();
			if (child == -1) {
				logmsg(LL_ERR,
				       "key %08x: can't create child: %s\n",
				       keyid, strerror(errno));
				rc = 1;
				goto out_pipe;
			} else if (child == 0) {
				struct lgssd_ioctl_param param;
				char outbuf[8192] = { 0 };
				void *gss_token = NULL;

				/* get ioctl buffer from child */
				rc = receive_from(req_fd[0], &param,
						  sizeof(param));
				if (rc != 0)
					goto out_pipe;

				gss_token = calloc(1, param.send_token_size);
				if (gss_token == NULL)
					goto out_pipe;

				/* get gss token from child */
				rc = receive_from(req_fd[0], gss_token,
						  param.send_token_size);
				if (rc != 0)
					goto out_token;

				param.send_token = (char *)gss_token;
				param.reply_buf_size = sizeof(outbuf);
				param.reply_buf = outbuf;

				/* do ioctl in place of child process carrying
				 * out credentials negotiation: as it runs in
				 * a container, it might not be able to
				 * perform ioctl */
				rc = gss_do_ioctl(&param);
				if (rc != 0)
					goto out_token;

				/* send ioctl status to child */
				rc = send_to(reply_fd[1], &param.status,
					     sizeof(param.status));
				if (rc != 0)
					goto out_token;
				/* send reply buffer to child */
				rc = send_to(reply_fd[1], outbuf,
					     sizeof(outbuf));
				if (rc != 0)
					goto out_token;

out_token:
				free(gss_token);
				goto out_pipe;
			}

			logmsg(LL_TRACE, "forked child %d\n", child);
		}
out_pipe:
		close(req_fd[0]);
		close(req_fd[1]);
		close(reply_fd[0]);
		close(reply_fd[1]);
		return rc;
	} else {
		if (uparam.kup_pid)
			logmsg(LL_TRACE, "caller's namespace is the same\n");
		else
			logmsg(LL_TRACE, "stick with current namespace\n");

		rc = prepare_and_instantiate(cred, keyid, uparam.kup_uid);
		if (rc != 0)
			return rc;

		/*
		 * fork a child to do the real gss negotiation
		 */
		child = fork();
		if (child == -1) {
			logmsg(LL_ERR, "key %08x: can't create child: %s\n",
			       keyid, strerror(errno));
			return 1;
		} else if (child == 0) {
			return lgssc_kr_negotiate(keyid, cred, &uparam,
						  req_fd, reply_fd);
		}

		logmsg(LL_TRACE, "forked child %d\n", child);
		return 0;
	}
}
