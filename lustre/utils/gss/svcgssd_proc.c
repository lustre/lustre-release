/*
 * svc_in_gssd_proc.c
 *
 * Copyright (c) 2000 The Regents of the University of Michigan.
 * All rights reserved.
 *
 * Copyright (c) 2002 Bruce Fields <bfields@UMICH.EDU>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <inttypes.h>
#include <pwd.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif

#include <stdbool.h>
#include <lnet/nidstr.h>

#include "svcgssd.h"
#include "gss_util.h"
#include "err_util.h"
#include "context.h"
#include "cacheio.h"
#include "lsupport.h"
#include "gss_oids.h"
#include "sk_utils.h"
#include <lustre/lustre_idl.h>

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

struct svc_nego_data {
	/* kernel data*/
	uint32_t	lustre_svc;
	lnet_nid_t	nid;
	uint64_t	handle_seq;
	char		nm_name[LUSTRE_NODEMAP_NAME_LENGTH + 1];
	gss_buffer_desc	in_tok;
	gss_buffer_desc	out_tok;
	gss_buffer_desc	in_handle;
	gss_buffer_desc	out_handle;
	uint32_t	maj_stat;
	uint32_t	min_stat;

	/* userspace data */
	gss_OID			mech;
	gss_ctx_id_t		ctx;
	gss_buffer_desc		ctx_token;
};

static int
do_svc_downcall(gss_buffer_desc *out_handle, struct svc_cred *cred,
		gss_OID mechoid, gss_buffer_desc *context_token)
{
	FILE *f;
	const char *mechname;
	int err;

	printerr(2, "doing downcall\n");
	mechname = gss_OID_mech_name(mechoid);
	if (mechname == NULL)
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
	qword_printint(f, time(NULL) + 3600);   /* 1 hour should be ok */
	qword_printint(f, cred->cr_remote);
	qword_printint(f, cred->cr_usr_root);
	qword_printint(f, cred->cr_usr_mds);
	qword_printint(f, cred->cr_usr_oss);
	qword_printint(f, cred->cr_mapped_uid);
	qword_printint(f, cred->cr_uid);
	qword_printint(f, cred->cr_gid);
	qword_print(f, mechname);
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

	printerr(2, "sending reply\n");
	qword_addhex(&bp, &blen, in_handle->value, in_handle->length);
	qword_addhex(&bp, &blen, in_token->value, in_token->length);
	qword_addint(&bp, &blen, time(NULL) + 3600);   /* 1 hour should be ok */
	qword_adduint(&bp, &blen, maj_stat);
	qword_adduint(&bp, &blen, min_stat);
	qword_addhex(&bp, &blen, out_handle->value, out_handle->length);
	qword_addhex(&bp, &blen, out_token->value, out_token->length);
	qword_addeol(&bp, &blen);
	if (blen <= 0) {
		printerr(0, "WARNING: send_response: message too long\n");
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
		printerr(0, "WARNING: get_ids: error allocating %zu bytes "
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

int handle_sk(struct svc_nego_data *snd)
{
#ifdef HAVE_OPENSSL_SSK
	struct sk_cred *skc = NULL;
	struct svc_cred cred;
	gss_buffer_desc bufs[SK_INIT_BUFFERS];
	gss_buffer_desc remote_pub_key = GSS_C_EMPTY_BUFFER;
	char *target;
	uint32_t rc = GSS_S_DEFECTIVE_TOKEN;
	uint32_t version;
	uint32_t flags;
	int i;

	printerr(3, "Handling sk request\n");
	memset(bufs, 0, sizeof(gss_buffer_desc) * SK_INIT_BUFFERS);

	/* See lgss_sk_using_cred() for client side token formation.
	 * Decoding initiator buffers */
	i = sk_decode_netstring(bufs, SK_INIT_BUFFERS, &snd->in_tok);
	if (i < SK_INIT_BUFFERS) {
		printerr(0, "Invalid netstring token received from peer\n");
		goto cleanup_buffers;
	}

	/* Allowing for a larger length first buffer in the future */
	if (bufs[SK_INIT_VERSION].length < sizeof(version)) {
		printerr(0, "Invalid version received (wrong size)\n");
		goto cleanup_buffers;
	}
	memcpy(&version, bufs[SK_INIT_VERSION].value, sizeof(version));
	version = be32toh(version);
	if (version != SK_MSG_VERSION) {
		printerr(0, "Invalid version received: %d\n", version);
		goto cleanup_buffers;
	}

	rc = GSS_S_FAILURE;

	/* target must be a null terminated string */
	i = bufs[SK_INIT_TARGET].length - 1;
	target = bufs[SK_INIT_TARGET].value;
	if (i >= 0 && target[i] != '\0') {
		printerr(0, "Invalid target from netstring\n");
		goto cleanup_buffers;
	}

	if (bufs[SK_INIT_FLAGS].length != sizeof(flags)) {
		printerr(0, "Invalid flags from netstring\n");
		goto cleanup_buffers;
	}
	memcpy(&flags, bufs[SK_INIT_FLAGS].value, sizeof(flags));

	skc = sk_create_cred(target, snd->nm_name, be32toh(flags));
	if (!skc) {
		printerr(0, "Failed to create sk credentials\n");
		goto cleanup_buffers;
	}

	/* Verify that the peer has used a prime size greater or equal to
	 * the size specified in the key file which may contain only zero
	 * fill but the size specifies the mimimum supported size on
	 * servers */
	if (skc->sc_flags & LGSS_SVC_PRIV &&
	    bufs[SK_INIT_P].length < skc->sc_p.length) {
		printerr(0, "Peer DHKE prime does not meet the size required "
			 "by keyfile: %zd bits\n", skc->sc_p.length * 8);
		goto cleanup_buffers;
	}

	/* Throw out the p from the server and use the wire data */
	free(skc->sc_p.value);
	skc->sc_p.value = NULL;
	skc->sc_p.length = 0;

	/* Take control of all the allocated buffers from decoding */
	if (bufs[SK_INIT_RANDOM].length !=
	    sizeof(skc->sc_kctx.skc_peer_random)) {
		printerr(0, "Invalid size for client random\n");
		goto cleanup_buffers;
	}

	memcpy(&skc->sc_kctx.skc_peer_random, bufs[SK_INIT_RANDOM].value,
	       sizeof(skc->sc_kctx.skc_peer_random));
	skc->sc_p = bufs[SK_INIT_P];
	remote_pub_key = bufs[SK_INIT_PUB_KEY];
	skc->sc_nodemap_hash = bufs[SK_INIT_NODEMAP];
	skc->sc_hmac = bufs[SK_INIT_HMAC];

	/* Verify HMAC from peer.  Ideally this would happen before anything
	 * else but we don't have enough information to lookup key without the
	 * token (fsname and cluster_hash) so it's done after. */
	rc = sk_verify_hmac(skc, bufs, SK_INIT_BUFFERS - 1, EVP_sha256(),
			    &skc->sc_hmac);
	if (rc != GSS_S_COMPLETE) {
		printerr(0, "HMAC verification error: 0x%x from peer %s\n",
			 rc, libcfs_nid2str((lnet_nid_t)snd->nid));
		goto cleanup_partial;
	}

	/* Check that the cluster hash matches the hash of nodemap name */
	rc = sk_verify_hash(snd->nm_name, EVP_sha256(), &skc->sc_nodemap_hash);
	if (rc != GSS_S_COMPLETE) {
		printerr(0, "Cluster hash failed validation: 0x%x\n", rc);
		goto cleanup_partial;
	}

	rc = sk_gen_params(skc);
	if (rc != GSS_S_COMPLETE) {
		printerr(0, "Failed to generate DH params for responder\n");
		goto cleanup_partial;
	}
	if (sk_compute_dh_key(skc, &remote_pub_key)) {
		printerr(0, "Failed to compute session key from DH params\n");
		goto cleanup_partial;
	}

	/* Cleanup init buffers we have copied or don't need anymore */
	free(bufs[SK_INIT_VERSION].value);
	free(bufs[SK_INIT_RANDOM].value);
	free(bufs[SK_INIT_TARGET].value);
	free(bufs[SK_INIT_FLAGS].value);

	/* Server reply contains the servers public key, random,  and HMAC */
	version = htobe32(SK_MSG_VERSION);
	bufs[SK_RESP_VERSION].value = &version;
	bufs[SK_RESP_VERSION].length = sizeof(version);
	bufs[SK_RESP_RANDOM].value = &skc->sc_kctx.skc_host_random;
	bufs[SK_RESP_RANDOM].length = sizeof(skc->sc_kctx.skc_host_random);
	bufs[SK_RESP_PUB_KEY] = skc->sc_pub_key;
	if (sk_sign_bufs(&skc->sc_kctx.skc_shared_key, bufs,
			 SK_RESP_BUFFERS - 1, EVP_sha256(),
			 &skc->sc_hmac)) {
		printerr(0, "Failed to sign parameters\n");
		goto out_err;
	}
	bufs[SK_RESP_HMAC] = skc->sc_hmac;
	if (sk_encode_netstring(bufs, SK_RESP_BUFFERS, &snd->out_tok)) {
		printerr(0, "Failed to encode netstring for token\n");
		goto out_err;
	}
	printerr(2, "Created netstring of %zd bytes\n", snd->out_tok.length);

	if (sk_session_kdf(skc, snd->nid, &snd->in_tok, &snd->out_tok)) {
		printerr(0, "Failed to calulate derviced session key\n");
		goto out_err;
	}
	if (sk_compute_keys(skc)) {
		printerr(0, "Failed to compute HMAC and encryption keys\n");
		goto out_err;
	}
	if (sk_serialize_kctx(skc, &snd->ctx_token)) {
		printerr(0, "Failed to serialize context for kernel\n");
		goto out_err;
	}

	snd->out_handle.length = sizeof(snd->handle_seq);
	memcpy(snd->out_handle.value, &snd->handle_seq,
	       sizeof(snd->handle_seq));
	snd->maj_stat = GSS_S_COMPLETE;

	/* fix credentials */
	memset(&cred, 0, sizeof(cred));
	cred.cr_mapped_uid = -1;

	if (skc->sc_flags & LGSS_ROOT_CRED_ROOT)
		cred.cr_usr_root = 1;
	if (skc->sc_flags & LGSS_ROOT_CRED_MDT)
		cred.cr_usr_mds = 1;
	if (skc->sc_flags & LGSS_ROOT_CRED_OST)
		cred.cr_usr_oss = 1;

	do_svc_downcall(&snd->out_handle, &cred, snd->mech, &snd->ctx_token);

	/* cleanup ctx_token, out_tok is cleaned up in handle_channel_req */
	free(remote_pub_key.value);
	free(snd->ctx_token.value);
	snd->ctx_token.length = 0;

	printerr(3, "sk returning success\n");
	return 0;

cleanup_buffers:
	for (i = 0; i < SK_INIT_BUFFERS; i++)
		free(bufs[i].value);
	sk_free_cred(skc);
	snd->maj_stat = rc;
	return -1;

cleanup_partial:
	free(bufs[SK_INIT_VERSION].value);
	free(bufs[SK_INIT_RANDOM].value);
	free(bufs[SK_INIT_TARGET].value);
	free(bufs[SK_INIT_FLAGS].value);
	free(remote_pub_key.value);
	sk_free_cred(skc);
	snd->maj_stat = rc;
	return -1;

out_err:
	snd->maj_stat = rc;
	if (snd->ctx_token.value) {
		free(snd->ctx_token.value);
		snd->ctx_token.value = 0;
		snd->ctx_token.length = 0;
	}
	free(remote_pub_key.value);
	sk_free_cred(skc);
	printerr(3, "sk returning failure\n");
#else /* !HAVE_OPENSSL_SSK */
	printerr(0, "ERROR: shared key subflavour is not enabled\n");
#endif /* HAVE_OPENSSL_SSK */
	return -1;
}

int handle_null(struct svc_nego_data *snd)
{
	struct svc_cred cred;
	uint64_t tmp;
	uint32_t flags;

	/* null just uses the same token as the return token and for
	 * for sending to the kernel.  It is a single uint64_t. */
	if (snd->in_tok.length != sizeof(uint64_t)) {
		snd->maj_stat = GSS_S_DEFECTIVE_TOKEN;
		printerr(0, "Invalid token size (%zd) received\n",
			 snd->in_tok.length);
		return -1;
	}
	snd->out_tok.length = snd->in_tok.length;
	snd->out_tok.value = malloc(snd->out_tok.length);
	if (!snd->out_tok.value) {
		snd->maj_stat = GSS_S_FAILURE;
		printerr(0, "Failed to allocate out_tok\n");
		return -1;
	}

	snd->ctx_token.length = snd->in_tok.length;
	snd->ctx_token.value = malloc(snd->ctx_token.length);
	if (!snd->ctx_token.value) {
		snd->maj_stat = GSS_S_FAILURE;
		printerr(0, "Failed to allocate ctx_token\n");
		return -1;
	}

	snd->out_handle.length = sizeof(snd->handle_seq);
	memcpy(snd->out_handle.value, &snd->handle_seq,
	       sizeof(snd->handle_seq));
	snd->maj_stat = GSS_S_COMPLETE;

	memcpy(&tmp, snd->in_tok.value, sizeof(tmp));
	tmp = be64toh(tmp);
	flags = (uint32_t)(tmp & 0x00000000ffffffff);
	memset(&cred, 0, sizeof(cred));
	cred.cr_mapped_uid = -1;

	if (flags & LGSS_ROOT_CRED_ROOT)
		cred.cr_usr_root = 1;
	if (flags & LGSS_ROOT_CRED_MDT)
		cred.cr_usr_mds = 1;
	if (flags & LGSS_ROOT_CRED_OST)
		cred.cr_usr_oss = 1;

	do_svc_downcall(&snd->out_handle, &cred, snd->mech, &snd->ctx_token);

	/* cleanup ctx_token, out_tok is cleaned up in handle_channel_req */
	free(snd->ctx_token.value);
	snd->ctx_token.length = 0;

	return 0;
}

static int handle_krb(struct svc_nego_data *snd)
{
	u_int32_t               ret_flags;
	gss_name_t              client_name;
	gss_buffer_desc         ignore_out_tok = {.value = NULL};
	gss_OID                 mech = GSS_C_NO_OID;
	gss_cred_id_t           svc_cred;
	u_int32_t               ignore_min_stat;
	struct svc_cred         cred;

	svc_cred = gssd_select_svc_cred(snd->lustre_svc);
	if (!svc_cred) {
		printerr(0, "no service credential for svc %u\n",
			 snd->lustre_svc);
		goto out_err;
	}

	snd->maj_stat = gss_accept_sec_context(&snd->min_stat, &snd->ctx,
					       svc_cred, &snd->in_tok,
					       GSS_C_NO_CHANNEL_BINDINGS,
					       &client_name, &mech,
					       &snd->out_tok, &ret_flags, NULL,
					       NULL);

	if (snd->maj_stat == GSS_S_CONTINUE_NEEDED) {
		printerr(1, "gss_accept_sec_context GSS_S_CONTINUE_NEEDED\n");

		/* Save the context handle for future calls */
		snd->out_handle.length = sizeof(snd->ctx);
		memcpy(snd->out_handle.value, &snd->ctx, sizeof(snd->ctx));
		return 0;
	} else if (snd->maj_stat != GSS_S_COMPLETE) {
		printerr(0, "WARNING: gss_accept_sec_context failed\n");
		pgsserr("handle_krb: gss_accept_sec_context",
			snd->maj_stat, snd->min_stat, mech);
		goto out_err;
	}

	if (get_ids(client_name, mech, &cred, snd->nid, snd->lustre_svc)) {
		/* get_ids() prints error msg */
		snd->maj_stat = GSS_S_BAD_NAME; /* XXX ? */
		gss_release_name(&ignore_min_stat, &client_name);
		goto out_err;
	}
	gss_release_name(&ignore_min_stat, &client_name);

	/* Context complete. Pass handle_seq in out_handle to use
	 * for context lookup in the kernel. */
	snd->out_handle.length = sizeof(snd->handle_seq);
	memcpy(snd->out_handle.value, &snd->handle_seq,
	       sizeof(snd->handle_seq));

	/* kernel needs ctx to calculate verifier on null response, so
	 * must give it context before doing null call: */
	if (serialize_context_for_kernel(snd->ctx, &snd->ctx_token, mech)) {
		printerr(0, "WARNING: handle_krb: "
			 "serialize_context_for_kernel failed\n");
		snd->maj_stat = GSS_S_FAILURE;
		goto out_err;
	}
	/* We no longer need the gss context */
	gss_delete_sec_context(&ignore_min_stat, &snd->ctx, &ignore_out_tok);
	do_svc_downcall(&snd->out_handle, &cred, mech, &snd->ctx_token);

	return 0;

out_err:
	if (snd->ctx != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&ignore_min_stat, &snd->ctx,
				       &ignore_out_tok);

	return 1;
}

/*
 * return -1 only if we detect error during reading from upcall channel,
 * all other cases return 0.
 */
int handle_channel_request(FILE *f)
{
	char			in_tok_buf[TOKEN_BUF_SIZE];
	char			in_handle_buf[15];
	char			out_handle_buf[15];
	gss_buffer_desc		ctx_token      = {.value = NULL},
				null_token     = {.value = NULL};
	uint32_t		lustre_mech;
	static char		*lbuf;
	static int		lbuflen;
	static char		*cp;
	int			get_len;
	int			rc = 1;
	u_int32_t		ignore_min_stat;
	struct svc_nego_data	snd = {
		.in_tok.value		= in_tok_buf,
		.in_handle.value	= in_handle_buf,
		.out_handle.value	= out_handle_buf,
		.maj_stat		= GSS_S_FAILURE,
		.ctx			= GSS_C_NO_CONTEXT,
	};

	printerr(2, "handling request\n");
	if (readline(fileno(f), &lbuf, &lbuflen) != 1) {
		printerr(0, "WARNING: failed reading request\n");
		return -1;
	}

	cp = lbuf;

	/* see rsi_request() for the format of data being input here */
	qword_get(&cp, (char *)&snd.lustre_svc, sizeof(snd.lustre_svc));

	/* lustre_svc is the svc and gss subflavor */
	lustre_mech = (snd.lustre_svc & LUSTRE_GSS_MECH_MASK) >>
		      LUSTRE_GSS_MECH_SHIFT;
	snd.lustre_svc = snd.lustre_svc & LUSTRE_GSS_SVC_MASK;
	switch (lustre_mech) {
	case LGSS_MECH_KRB5:
		if (!krb_enabled) {
			static time_t next_krb;

			if (time(NULL) > next_krb) {
				printerr(1, "warning: Request for kerberos but "
					 "service support not enabled\n");
				next_krb = time(NULL) + 3600;
			}
			goto ignore;
		}
		snd.mech = &krb5oid;
		break;
	case LGSS_MECH_NULL:
		if (!null_enabled) {
			static time_t next_null;

			if (time(NULL) > next_null) {
				printerr(1, "warning: Request for gssnull but "
					 "service support not enabled\n");
				next_null = time(NULL) + 3600;
			}
			goto ignore;
		}
		snd.mech = &nulloid;
		break;
	case LGSS_MECH_SK:
		if (!sk_enabled) {
			static time_t next_ssk;

			if (time(NULL) > next_ssk) {
				printerr(1, "warning: Request for SSK but "
					 "service support not %s\n",
#ifdef HAVE_OPENSSL_SSK
					 "enabled"
#else
					 "included"
#endif
					);
				next_ssk = time(NULL) + 3600;
			}

			goto ignore;
		}
		snd.mech = &skoid;
		break;
	default:
		printerr(0, "WARNING: invalid mechanism recevied: %d\n",
			 lustre_mech);
		goto out_err;
		break;
	}

	qword_get(&cp, (char *)&snd.nid, sizeof(snd.nid));
	qword_get(&cp, (char *)&snd.handle_seq, sizeof(snd.handle_seq));
	qword_get(&cp, snd.nm_name, sizeof(snd.nm_name));
	printerr(2, "handling req: svc %u, nid %016llx, idx %"PRIx64" nodemap "
		 "%s\n", snd.lustre_svc, snd.nid, snd.handle_seq, snd.nm_name);

	get_len = qword_get(&cp, snd.in_handle.value, sizeof(in_handle_buf));
	if (get_len < 0) {
		printerr(0, "WARNING: failed parsing request\n");
		goto out_err;
	}
	snd.in_handle.length = (size_t)get_len;

	printerr(3, "in_handle:\n");
	print_hexl(3, snd.in_handle.value, snd.in_handle.length);

	get_len = qword_get(&cp, snd.in_tok.value, sizeof(in_tok_buf));
	if (get_len < 0) {
		printerr(0, "WARNING: failed parsing request\n");
		goto out_err;
	}
	snd.in_tok.length = (size_t)get_len;

	printerr(3, "in_tok:\n");
	print_hexl(3, snd.in_tok.value, snd.in_tok.length);

	if (snd.in_handle.length != 0) { /* CONTINUE_INIT case */
		if (snd.in_handle.length != sizeof(snd.ctx)) {
			printerr(0, "WARNING: input handle has unexpected "
				 "length %zu\n", snd.in_handle.length);
			goto out_err;
		}
		/* in_handle is the context id stored in the out_handle
		 * for the GSS_S_CONTINUE_NEEDED case below.  */
		memcpy(&snd.ctx, snd.in_handle.value, snd.in_handle.length);
	}

	if (lustre_mech == LGSS_MECH_KRB5)
		rc = handle_krb(&snd);
	else if (lustre_mech == LGSS_MECH_SK)
		rc = handle_sk(&snd);
	else if (lustre_mech == LGSS_MECH_NULL)
		rc = handle_null(&snd);
	else
		printerr(0, "WARNING: Received or request for"
			 "subflavor that is not enabled: %d\n", lustre_mech);

out_err:
	/* Failures send a null token */
	if (rc == 0)
		send_response(f, &snd.in_handle, &snd.in_tok, snd.maj_stat,
			      snd.min_stat, &snd.out_handle, &snd.out_tok);
	else
		send_response(f, &snd.in_handle, &snd.in_tok, snd.maj_stat,
			      snd.min_stat, &null_token, &null_token);

	/* cleanup buffers */
	if (snd.ctx_token.value != NULL)
		free(ctx_token.value);
	if (snd.out_tok.value != NULL)
		gss_release_buffer(&ignore_min_stat, &snd.out_tok);

	/* For junk wire data just ignore */
ignore:
	return 0;
}
