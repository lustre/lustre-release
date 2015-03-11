/*
  svc_in_gssd_proc.c

  Copyright (c) 2000 The Regents of the University of Michigan.
  All rights reserved.

  Copyright (c) 2002 Bruce Fields <bfields@UMICH.EDU>

  Copyright (c) 2014, Intel Corporation.

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

#include <sys/param.h>
#include <sys/stat.h>

#include <pwd.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>

#include "svcgssd.h"
#include "gss_util.h"
#include "err_util.h"
#include "context.h"
#include "cacheio.h"
#include "lsupport.h"

extern char * mech2file(gss_OID mech);
#define SVCGSSD_CONTEXT_CHANNEL "/proc/net/rpc/auth.sptlrpc.context/channel"
#define SVCGSSD_INIT_CHANNEL    "/proc/net/rpc/auth.sptlrpc.init/channel"

#define TOKEN_BUF_SIZE		8192

struct svc_cred {
	uint32_t cr_remote;
	uint32_t cr_usr_root;
	uint32_t cr_usr_mds;
	uint32_t cr_usr_oss;
	uid_t    cr_uid;
	uid_t    cr_mapped_uid;
	uid_t    cr_gid;
};

static int
do_svc_downcall(gss_buffer_desc *out_handle, struct svc_cred *cred,
		gss_OID mech, gss_buffer_desc *context_token)
{
	FILE *f;
	char *fname = NULL;
	int err;

	printerr(2, "doing downcall\n");
	if ((fname = mech2file(mech)) == NULL)
		goto out_err;
	f = fopen(SVCGSSD_CONTEXT_CHANNEL, "w");
	if (f == NULL) {
		printerr(0, "WARNING: unable to open downcall channel "
			     "%s: %s\n",
			     SVCGSSD_CONTEXT_CHANNEL, strerror(errno));
		goto out_err;
	}
	qword_printhex(f, out_handle->value, out_handle->length);
	/* XXX are types OK for the rest of this? */
	qword_printint(f, 0x7fffffff); /*XXX need a better timeout */
	qword_printint(f, cred->cr_remote);
	qword_printint(f, cred->cr_usr_root);
	qword_printint(f, cred->cr_usr_mds);
	qword_printint(f, cred->cr_usr_oss);
	qword_printint(f, cred->cr_mapped_uid);
	qword_printint(f, cred->cr_uid);
	qword_printint(f, cred->cr_gid);
	qword_print(f, fname);
	qword_printhex(f, context_token->value, context_token->length);
	err = qword_eol(f);
	fclose(f);
	return err;
out_err:
	printerr(0, "WARNING: downcall failed\n");
	return -1;
}

struct gss_verifier {
	u_int32_t	flav;
	gss_buffer_desc	body;
};

#define RPCSEC_GSS_SEQ_WIN	5

static int
send_response(FILE *f, gss_buffer_desc *in_handle, gss_buffer_desc *in_token,
	      u_int32_t maj_stat, u_int32_t min_stat,
	      gss_buffer_desc *out_handle, gss_buffer_desc *out_token)
{
	char buf[2 * TOKEN_BUF_SIZE];
	char *bp = buf;
	int blen = sizeof(buf);
	/* XXXARG: */
	int g;

	printerr(2, "sending null reply\n");

	qword_addhex(&bp, &blen, in_handle->value, in_handle->length);
	qword_addhex(&bp, &blen, in_token->value, in_token->length);
	qword_addint(&bp, &blen, 0x7fffffff); /*XXX need a better timeout */
	qword_adduint(&bp, &blen, maj_stat);
	qword_adduint(&bp, &blen, min_stat);
	qword_addhex(&bp, &blen, out_handle->value, out_handle->length);
	qword_addhex(&bp, &blen, out_token->value, out_token->length);
	qword_addeol(&bp, &blen);
	if (blen <= 0) {
		printerr(0, "WARNING: send_respsonse: message too long\n");
		return -1;
	}
	g = open(SVCGSSD_INIT_CHANNEL, O_WRONLY);
	if (g == -1) {
		printerr(0, "WARNING: open %s failed: %s\n",
				SVCGSSD_INIT_CHANNEL, strerror(errno));
		return -1;
	}
	*bp = '\0';
	printerr(3, "writing message: %s", buf);
	if (write(g, buf, bp - buf) == -1) {
		printerr(0, "WARNING: failed to write message\n");
		close(g);
		return -1;
	}
	close(g);
	return 0;
}

#define rpc_auth_ok			0
#define rpc_autherr_badcred		1
#define rpc_autherr_rejectedcred	2
#define rpc_autherr_badverf		3
#define rpc_autherr_rejectedverf	4
#define rpc_autherr_tooweak		5
#define rpcsec_gsserr_credproblem	13
#define rpcsec_gsserr_ctxproblem	14

#if 0
static void
add_supplementary_groups(char *secname, char *name, struct svc_cred *cred)
{
	int ret;
	static gid_t *groups = NULL;

	cred->cr_ngroups = NGROUPS;
	ret = nfs4_gss_princ_to_grouplist(secname, name,
			cred->cr_groups, &cred->cr_ngroups);
	if (ret < 0) {
		groups = realloc(groups, cred->cr_ngroups*sizeof(gid_t));
		ret = nfs4_gss_princ_to_grouplist(secname, name,
				groups, &cred->cr_ngroups);
		if (ret < 0)
			cred->cr_ngroups = 0;
		else {
			if (cred->cr_ngroups > NGROUPS)
				cred->cr_ngroups = NGROUPS;
			memcpy(cred->cr_groups, groups,
					cred->cr_ngroups*sizeof(gid_t));
		}
	}
}
#endif

#if 0
static int
get_ids(gss_name_t client_name, gss_OID mech, struct svc_cred *cred)
{
	u_int32_t	maj_stat, min_stat;
	gss_buffer_desc	name;
	char		*sname;
	int		res = -1;
	uid_t		uid, gid;
	gss_OID		name_type = GSS_C_NO_OID;
	char		*secname;

	maj_stat = gss_display_name(&min_stat, client_name, &name, &name_type);
	if (maj_stat != GSS_S_COMPLETE) {
		pgsserr("get_ids: gss_display_name",
			maj_stat, min_stat, mech);
		goto out;
	}
	if (name.length >= 0xffff || /* be certain name.length+1 doesn't overflow */
	    !(sname = calloc(name.length + 1, 1))) {
		printerr(0, "WARNING: get_ids: error allocating %d bytes "
			"for sname\n", name.length + 1);
		gss_release_buffer(&min_stat, &name);
		goto out;
	}
	memcpy(sname, name.value, name.length);
	printerr(1, "sname = %s\n", sname);
	gss_release_buffer(&min_stat, &name);

	res = -EINVAL;
	if ((secname = mech2file(mech)) == NULL) {
		printerr(0, "WARNING: get_ids: error mapping mech to "
			"file for name '%s'\n", sname);
		goto out_free;
	}
	nfs4_init_name_mapping(NULL); /* XXX: should only do this once */
	res = nfs4_gss_princ_to_ids(secname, sname, &uid, &gid);
	if (res < 0) {
		/*
		 * -ENOENT means there was no mapping, any other error
		 * value means there was an error trying to do the
		 * mapping.
		 * If there was no mapping, we send down the value -1
		 * to indicate that the anonuid/anongid for the export
		 * should be used.
		 */
		if (res == -ENOENT) {
			cred->cr_uid = -1;
			cred->cr_gid = -1;
			cred->cr_ngroups = 0;
			res = 0;
			goto out_free;
		}
		printerr(0, "WARNING: get_ids: failed to map name '%s' "
			"to uid/gid: %s\n", sname, strerror(-res));
		goto out_free;
	}
	cred->cr_uid = uid;
	cred->cr_gid = gid;
	add_supplementary_groups(secname, sname, cred);
	res = 0;
out_free:
	free(sname);
out:
	return res;
}
#endif

#if 0
void
print_hexl(int pri, unsigned char *cp, int length)
{
	int i, j, jm;
	unsigned char c;

	printerr(pri, "length %d\n",length);
	printerr(pri, "\n");

	for (i = 0; i < length; i += 0x10) {
		printerr(pri, "  %04x: ", (u_int)i);
		jm = length - i;
		jm = jm > 16 ? 16 : jm;

		for (j = 0; j < jm; j++) {
			if ((j % 2) == 1)
				printerr(pri,"%02x ", (u_int)cp[i+j]);
			else
				printerr(pri,"%02x", (u_int)cp[i+j]);
		}
		for (; j < 16; j++) {
			if ((j % 2) == 1)
				printerr(pri,"   ");
			else
				printerr(pri,"  ");
		}
		printerr(pri," ");

		for (j = 0; j < jm; j++) {
			c = cp[i+j];
			c = isprint(c) ? c : '.';
			printerr(pri,"%c", c);
		}
		printerr(pri,"\n");
	}
}
#endif

static int
get_ids(gss_name_t client_name, gss_OID mech, struct svc_cred *cred,
	lnet_nid_t nid, uint32_t lustre_svc)
{
	u_int32_t	maj_stat, min_stat;
	gss_buffer_desc	name;
	char		*sname, *host, *realm;
	const int	namebuf_size = 512;
	char		namebuf[namebuf_size];
	int		res = -1;
	gss_OID		name_type = GSS_C_NO_OID;
	struct passwd	*pw;

	cred->cr_remote = 0;
	cred->cr_usr_root = cred->cr_usr_mds = cred->cr_usr_oss = 0;
	cred->cr_uid = cred->cr_mapped_uid = cred->cr_gid = -1;

	maj_stat = gss_display_name(&min_stat, client_name, &name, &name_type);
	if (maj_stat != GSS_S_COMPLETE) {
		pgsserr("get_ids: gss_display_name",
			maj_stat, min_stat, mech);
		return -1;
	}
	if (name.length >= 0xffff || /* be certain name.length+1 doesn't overflow */
	    !(sname = calloc(name.length + 1, 1))) {
		printerr(0, "WARNING: get_ids: error allocating %d bytes "
			"for sname\n", name.length + 1);
		gss_release_buffer(&min_stat, &name);
		return -1;
	}
	memcpy(sname, name.value, name.length);
	sname[name.length] = '\0';
	gss_release_buffer(&min_stat, &name);

	if (lustre_svc == LUSTRE_GSS_SVC_MDS)
		lookup_mapping(sname, nid, &cred->cr_mapped_uid);
	else
		cred->cr_mapped_uid = -1;

        realm = strchr(sname, '@');
	if (realm) {
                *realm++ = '\0';
	} else {
		printerr(0, "ERROR: %s has no realm name\n", sname);
		goto out_free;
	}

        host = strchr(sname, '/');
        if (host)
                *host++ = '\0';

	if (strcmp(sname, GSSD_SERVICE_MGS) == 0) {
		printerr(0, "forbid %s as a user name\n", sname);
		goto out_free;
	}

	/* 1. check host part */
	if (host) {
		if (lnet_nid2hostname(nid, namebuf, namebuf_size)) {
			printerr(0, "ERROR: failed to resolve hostname for "
				 "%s/%s@%s from %016llx\n",
				 sname, host, realm, nid);
			goto out_free;
		}

		if (strcasecmp(host, namebuf)) {
			printerr(0, "ERROR: %s/%s@%s claimed hostname doesn't "
				 "match %s, nid %016llx\n", sname, host, realm,
				 namebuf, nid);
			goto out_free;
		}
	} else {
		if (!strcmp(sname, GSSD_SERVICE_MDS) ||
		    !strcmp(sname, GSSD_SERVICE_OSS)) {
			printerr(0, "ERROR: %s@%s from %016llx doesn't "
				 "bind with hostname\n", sname, realm, nid);
			goto out_free;
		}
	}

	/* 2. check realm and user */
	switch (lustre_svc) {
	case LUSTRE_GSS_SVC_MDS:
		if (strcasecmp(mds_local_realm, realm)) {
			cred->cr_remote = 1;

			/* only allow mapped user from remote realm */
			if (cred->cr_mapped_uid == -1) {
				printerr(0, "ERROR: %s%s%s@%s from %016llx "
					 "is remote but without mapping\n",
					 sname, host ? "/" : "",
					 host ? host : "", realm, nid);
				break;
			}
		} else {
			if (!strcmp(sname, LUSTRE_ROOT_NAME)) {
				cred->cr_uid = 0;
				cred->cr_usr_root = 1;
			} else if (!strcmp(sname, GSSD_SERVICE_MDS)) {
				cred->cr_uid = 0;
				cred->cr_usr_mds = 1;
			} else if (!strcmp(sname, GSSD_SERVICE_OSS)) {
				cred->cr_uid = 0;
				cred->cr_usr_oss = 1;
			} else {
				pw = getpwnam(sname);
				if (pw != NULL) {
					cred->cr_uid = pw->pw_uid;
					printerr(2, "%s resolve to uid %u\n",
						 sname, cred->cr_uid);
				} else if (cred->cr_mapped_uid != -1) {
					printerr(2, "user %s from %016llx is "
						 "mapped to %u\n", sname, nid,
						 cred->cr_mapped_uid);
				} else {
					printerr(0, "ERROR: invalid user, "
						 "%s/%s@%s from %016llx\n",
						 sname, host, realm, nid);
					break;
				}
			}
		}

		res = 0;
		break;
	case LUSTRE_GSS_SVC_MGS:
		if (!strcmp(sname, GSSD_SERVICE_OSS)) {
			cred->cr_uid = 0;
			cred->cr_usr_oss = 1;
		}
		/* fall through */
	case LUSTRE_GSS_SVC_OSS:
		if (!strcmp(sname, LUSTRE_ROOT_NAME)) {
			cred->cr_uid = 0;
			cred->cr_usr_root = 1;
		} else if (!strcmp(sname, GSSD_SERVICE_MDS)) {
			cred->cr_uid = 0;
			cred->cr_usr_mds = 1;
		}
		if (cred->cr_uid == -1) {
			printerr(0, "ERROR: svc %d doesn't accept user %s "
				 "from %016llx\n", lustre_svc, sname, nid);
			break;
		}
		res = 0;
		break;
	default:
		assert(0);
	}

out_free:
	if (!res)
		printerr(1, "%s: authenticated %s%s%s@%s from %016llx\n",
			 lustre_svc_name[lustre_svc], sname,
			 host ? "/" : "", host ? host : "", realm, nid);
        free(sname);
        return res;
}

typedef struct gss_union_ctx_id_t {
	gss_OID         mech_type;
	gss_ctx_id_t    internal_ctx_id;
} gss_union_ctx_id_desc, *gss_union_ctx_id_t;

/*
 * return -1 only if we detect error during reading from upcall channel,
 * all other cases return 0.
 */
int
handle_nullreq(FILE *f) {
	uint64_t		handle_seq;
	char			in_tok_buf[TOKEN_BUF_SIZE];
	char			in_handle_buf[15];
	char			out_handle_buf[15];
	gss_buffer_desc		in_tok = {.value = in_tok_buf},
				out_tok = {.value = NULL},
				in_handle = {.value = in_handle_buf},
				out_handle = {.value = out_handle_buf},
				ctx_token = {.value = NULL},
				ignore_out_tok = {.value = NULL},
	/* XXX isn't there a define for this?: */
				null_token = {.value = NULL};
	uint32_t		lustre_svc;
	lnet_nid_t		nid;
	u_int32_t		ret_flags;
	gss_ctx_id_t		ctx = GSS_C_NO_CONTEXT;
	gss_name_t		client_name;
	gss_OID			mech = GSS_C_NO_OID;
	gss_cred_id_t		svc_cred;
	u_int32_t		maj_stat = GSS_S_FAILURE, min_stat = 0;
	u_int32_t		ignore_min_stat;
	int			get_len;
	struct svc_cred		cred;
	static char		*lbuf = NULL;
	static int		lbuflen = 0;
	static char		*cp;

	printerr(2, "handling null request\n");

	if (readline(fileno(f), &lbuf, &lbuflen) != 1) {
		printerr(0, "WARNING: handle_nullreq: "
			    "failed reading request\n");
		return -1;
	}

	cp = lbuf;

	qword_get(&cp, (char *) &lustre_svc, sizeof(lustre_svc));
	qword_get(&cp, (char *) &nid, sizeof(nid));
	qword_get(&cp, (char *) &handle_seq, sizeof(handle_seq));
	printerr(2, "handling req: svc %u, nid %016llx, idx %llx\n",
		 lustre_svc, nid, handle_seq);

	get_len = qword_get(&cp, in_handle.value, sizeof(in_handle_buf));
	if (get_len < 0) {
		printerr(0, "WARNING: handle_nullreq: "
			    "failed parsing request\n");
		goto out_err;
	}
	in_handle.length = (size_t)get_len;

	printerr(3, "in_handle:\n");
	print_hexl(3, in_handle.value, in_handle.length);

	get_len = qword_get(&cp, in_tok.value, sizeof(in_tok_buf));
	if (get_len < 0) {
		printerr(0, "WARNING: handle_nullreq: "
			    "failed parsing request\n");
		goto out_err;
	}
	in_tok.length = (size_t)get_len;

	printerr(3, "in_tok:\n");
	print_hexl(3, in_tok.value, in_tok.length);

	if (in_handle.length != 0) { /* CONTINUE_INIT case */
		if (in_handle.length != sizeof(ctx)) {
			printerr(0, "WARNING: handle_nullreq: "
				    "input handle has unexpected length %d\n",
				    in_handle.length);
			goto out_err;
		}
		/* in_handle is the context id stored in the out_handle
		 * for the GSS_S_CONTINUE_NEEDED case below.  */
		memcpy(&ctx, in_handle.value, in_handle.length);
	}

	svc_cred = gssd_select_svc_cred(lustre_svc);
	if (!svc_cred) {
		printerr(0, "no service credential for svc %u\n", lustre_svc);
		goto out_err;
	}

	maj_stat = gss_accept_sec_context(&min_stat, &ctx, svc_cred,
			&in_tok, GSS_C_NO_CHANNEL_BINDINGS, &client_name,
			&mech, &out_tok, &ret_flags, NULL, NULL);

	if (maj_stat == GSS_S_CONTINUE_NEEDED) {
		printerr(1, "gss_accept_sec_context GSS_S_CONTINUE_NEEDED\n");

		/* Save the context handle for future calls */
		out_handle.length = sizeof(ctx);
		memcpy(out_handle.value, &ctx, sizeof(ctx));
		goto continue_needed;
	}
	else if (maj_stat != GSS_S_COMPLETE) {
		printerr(0, "WARNING: gss_accept_sec_context failed\n");
		pgsserr("handle_nullreq: gss_accept_sec_context",
			maj_stat, min_stat, mech);
		goto out_err;
	}

	if (get_ids(client_name, mech, &cred, nid, lustre_svc)) {
		/* get_ids() prints error msg */
		maj_stat = GSS_S_BAD_NAME; /* XXX ? */
		gss_release_name(&ignore_min_stat, &client_name);
		goto out_err;
	}
	gss_release_name(&ignore_min_stat, &client_name);

	/* Context complete. Pass handle_seq in out_handle to use
	 * for context lookup in the kernel. */
	out_handle.length = sizeof(handle_seq);
	memcpy(out_handle.value, &handle_seq, sizeof(handle_seq));

	/* kernel needs ctx to calculate verifier on null response, so
	 * must give it context before doing null call: */
	if (serialize_context_for_kernel(ctx, &ctx_token, mech)) {
		printerr(0, "WARNING: handle_nullreq: "
			    "serialize_context_for_kernel failed\n");
		maj_stat = GSS_S_FAILURE;
		goto out_err;
	}
	/* We no longer need the gss context */
	gss_delete_sec_context(&ignore_min_stat, &ctx, &ignore_out_tok);

	do_svc_downcall(&out_handle, &cred, mech, &ctx_token);
continue_needed:
	send_response(f, &in_handle, &in_tok, maj_stat, min_stat,
			&out_handle, &out_tok);
out:
	if (ctx_token.value != NULL)
		free(ctx_token.value);
	if (out_tok.value != NULL)
		gss_release_buffer(&ignore_min_stat, &out_tok);
	return 0;

out_err:
	if (ctx != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&ignore_min_stat, &ctx, &ignore_out_tok);
	send_response(f, &in_handle, &in_tok, maj_stat, min_stat,
			&null_token, &null_token);
	goto out;
}
