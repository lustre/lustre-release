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

#include "svcgssd.h"
#include "gss_util.h"
#include "err_util.h"
#include "context.h"
#include "cacheio.h"
#include "lsupport.h"
#include "gss_oids.h"
#include <time.h>
#include <linux/lustre/lustre_idl.h>
#include "sk_utils.h"
#include <sys/time.h>
#include <gssapi/gssapi_krb5.h>
#include <libcfs/util/param.h>

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

static int do_svc_downcall(gss_buffer_desc *out_handle, struct svc_cred *cred,
			   gss_OID mechoid, gss_buffer_desc *ctx_token)
{
	struct rsc_downcall_data *rsc_dd;
	int blen, fd, size, rc = -1;
	const char *mechname;
	glob_t path;
	char *bp;

	printerr(LL_INFO, "doing downcall\n");

	size = out_handle->length + sizeof(__u32) +
		ctx_token->length + sizeof(__u32);
	blen = size;

	size += offsetof(struct rsc_downcall_data, scd_val[0]);
	rsc_dd = calloc(1, size);
	if (!rsc_dd) {
		printerr(LL_ERR, "malloc downcall data (%d) failed\n", size);
		return -ENOMEM;
	}
	rsc_dd->scd_magic = RSC_DOWNCALL_MAGIC;
	rsc_dd->scd_err = 0;

	rsc_dd->scd_flags =
		(cred->cr_remote ? RSC_DATA_FLAG_REMOTE : 0) |
		(cred->cr_usr_root ? RSC_DATA_FLAG_ROOT : 0) |
		(cred->cr_usr_mds ? RSC_DATA_FLAG_MDS : 0) |
		(cred->cr_usr_oss ? RSC_DATA_FLAG_OSS : 0);
	rsc_dd->scd_mapped_uid = cred->cr_mapped_uid;
	rsc_dd->scd_uid = cred->cr_uid;
	rsc_dd->scd_gid = cred->cr_gid;
	mechname = gss_OID_mech_name(mechoid);
	if (mechname == NULL)
		goto out;
	if (snprintf(rsc_dd->scd_mechname, sizeof(rsc_dd->scd_mechname),
		     "%s", mechname) >= sizeof(rsc_dd->scd_mechname))
		goto out;

	bp = rsc_dd->scd_val;
	gss_buffer_write(&bp, &blen, out_handle->value, out_handle->length);
	gss_buffer_write(&bp, &blen, ctx_token->value, ctx_token->length);
	if (blen < 0) {
		printerr(LL_ERR, "ERROR: %s: message too long > %d\n",
			 __func__, size);
		rc = -EMSGSIZE;
		goto out;
	}
	rsc_dd->scd_len = bp - rsc_dd->scd_val;

	rc = cfs_get_param_paths(&path, RSC_DOWNCALL_PATH);
	if (rc != 0) {
		rc = -errno;
		goto out;
	}

	fd = open(path.gl_pathv[0], O_WRONLY);
	if (fd == -1) {
		rc = -errno;
		printerr(LL_ERR, "ERROR: %s: open %s failed: %s\n",
			 __func__, RSC_DOWNCALL_PATH, strerror(-rc));
		goto out_path;
	}
	size = offsetof(struct rsc_downcall_data,
			scd_val[bp - rsc_dd->scd_val]);
	printerr(LL_DEBUG, "writing downcall data, size %d\n", size);
	if (write(fd, rsc_dd, size) == -1) {
		rc = -errno;
		printerr(LL_ERR, "ERROR: %s failed: %s\n",
			 __func__, strerror(-rc));
	}
	printerr(LL_DEBUG, "downcall data written ok\n");

	close(fd);
out_path:
	cfs_free_param_data(&path);
out:
	free(rsc_dd);
	if (rc)
		printerr(LL_ERR, "ERROR: downcall failed\n");
	return rc;
}

#define RPCSEC_GSS_SEQ_WIN	5

static int send_response(int auth_res, __u64 hash,
			gss_buffer_desc *in_handle, gss_buffer_desc *in_token,
			u_int32_t maj_stat, u_int32_t min_stat,
			gss_buffer_desc *out_handle, gss_buffer_desc *out_token)
{
	struct rsi_downcall_data *rsi_dd;
	int blen, fd, size, rc = 0;
	glob_t path;
	char *bp;

	printerr(LL_INFO, "sending reply\n");

	size = in_handle->length + sizeof(__u32) +
		in_token->length + sizeof(__u32) +
		sizeof(__u32) + sizeof(__u32);
	if (!auth_res)
		size += out_handle->length + out_token->length;
	blen = size;

	size += offsetof(struct rsi_downcall_data, sid_val[0]);
	rsi_dd = calloc(1, size);
	if (!rsi_dd) {
		printerr(LL_ERR, "malloc downcall data (%d) failed\n", size);
		return -ENOMEM;
	}
	rsi_dd->sid_magic = RSI_DOWNCALL_MAGIC;
	rsi_dd->sid_hash = hash;
	rsi_dd->sid_maj_stat = maj_stat;
	rsi_dd->sid_min_stat = min_stat;

	bp = rsi_dd->sid_val;
	gss_buffer_write(&bp, &blen, in_handle->value, in_handle->length);
	gss_buffer_write(&bp, &blen, in_token->value, in_token->length);
	if (!auth_res) {
		gss_buffer_write(&bp, &blen, out_handle->value,
				 out_handle->length);
		gss_buffer_write(&bp, &blen, out_token->value,
				 out_token->length);
	} else {
		rsi_dd->sid_err = -EACCES;
		gss_buffer_write(&bp, &blen, NULL, 0);
		gss_buffer_write(&bp, &blen, NULL, 0);
	}
	if (blen < 0) {
		printerr(LL_ERR, "ERROR: %s: message too long > %d\n",
			 __func__, size);
		rc = -EMSGSIZE;
		goto out;
	}
	rsi_dd->sid_len = bp - rsi_dd->sid_val;

	rc = cfs_get_param_paths(&path, RSI_DOWNCALL_PATH);
	if (rc != 0) {
		rc = -errno;
		printerr(LL_ERR, "ERROR: %s: cannot get param path %s: %s\n",
			 __func__, RSI_DOWNCALL_PATH, strerror(-rc));
		goto out;
	}

	fd = open(path.gl_pathv[0], O_WRONLY);
	if (fd == -1) {
		rc = -errno;
		printerr(LL_ERR, "ERROR: %s: open %s failed: %s\n",
			 __func__, RSI_DOWNCALL_PATH, strerror(-rc));
		goto out_path;
	}
	size = offsetof(struct rsi_downcall_data,
			sid_val[bp - rsi_dd->sid_val]);
	printerr(LL_DEBUG, "writing response, size %d\n", size);
	if (write(fd, rsi_dd, size) == -1) {
		rc = -errno;
		printerr(LL_ERR, "ERROR: %s failed: %s\n",
			 __func__, strerror(-rc));
	} else {
		printerr(LL_DEBUG, "response written ok\n");
	}

	close(fd);
out_path:
	cfs_free_param_data(&path);
out:
	free(rsi_dd);
	return rc;
}

#define rpc_auth_ok			0
#define rpc_autherr_badcred		1
#define rpc_autherr_rejectedcred	2
#define rpc_autherr_badverf		3
#define rpc_autherr_rejectedverf	4
#define rpc_autherr_tooweak		5
#define rpcsec_gsserr_credproblem	13
#define rpcsec_gsserr_ctxproblem	14

static int lookup_localname(gss_name_t client_name, char *princ, lnet_nid_t nid,
			    uid_t *uid)
{
	u_int32_t maj_stat, min_stat;
	gss_buffer_desc	localname;
	char *sname;
	int rc = -1;

	*uid = -1;
	maj_stat = gss_localname(&min_stat, client_name, GSS_C_NO_OID,
				 &localname);
	if (maj_stat != GSS_S_COMPLETE) {
		printerr(LL_INFO, "no local name for %s/%#Lx\n", princ, nid);
		return rc;
	}

	sname = calloc(localname.length + 1, 1);
	if (!sname) {
		printerr(LL_ERR, "%s: error allocating %zu bytes\n",
			 __func__, localname.length + 1);
		goto free;
	}
	memcpy(sname, localname.value, localname.length);
	sname[localname.length] = '\0';

	*uid = parse_uid(sname);
	free(sname);
	printerr(LL_WARN, "found local uid: %s ==> %d\n", princ, *uid);
	rc = 0;

free:
	gss_release_buffer(&min_stat, &localname);
	return rc;
}

static int lookup_id(gss_name_t client_name, char *princ, lnet_nid_t nid,
		     uid_t *uid)
{
	if (!mapping_empty())
		return lookup_mapping(princ, nid, uid);

	return lookup_localname(client_name, princ, nid, uid);
}

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
	/* be certain name.length+1 doesn't overflow */
	if (name.length >= 0xffff ||
	    !(sname = calloc(name.length + 1, 1))) {
		printerr(LL_ERR,
			 "ERROR: %s: error allocating %zu bytes for sname\n",
			 __func__, name.length + 1);
		gss_release_buffer(&min_stat, &name);
		return -1;
	}
	memcpy(sname, name.value, name.length);
	sname[name.length] = '\0';
	gss_release_buffer(&min_stat, &name);

	if ((lustre_svc == LUSTRE_GSS_SVC_MDS ||
	     lustre_svc == LUSTRE_GSS_SVC_MGS) &&
	    lookup_id(client_name, sname, nid, &cred->cr_mapped_uid))
		printerr(LL_DEBUG, "no id found for %s\n", sname);

	realm = strchr(sname, '@');
	if (realm) {
		*realm++ = '\0';
	} else {
		printerr(LL_ERR, "ERROR: %s has no realm name\n", sname);
		goto out_free;
	}

	host = strchr(sname, '/');
	if (host)
		*host++ = '\0';

	if (strcmp(sname, GSSD_SERVICE_MGS) == 0) {
		printerr(LL_ERR, "forbid %s as a user name\n", sname);
		goto out_free;
	}

	/* 1. check host part */
	if (host) {
		if (lnet_nid2hostname(nid, namebuf, namebuf_size)) {
			printerr(LL_ERR,
				 "ERROR: failed to resolve hostname for %s/%s@%s from %s\n",
				 sname, host, realm, libcfs_nid2str(nid));
			goto out_free;
		}

		if (strcasecmp(host, namebuf)) {
			printerr(LL_ERR,
				 "ERROR: %s/%s@%s claimed hostname doesn't match %s, nid %s\n",
				 sname, host, realm,
				 namebuf, libcfs_nid2str(nid));
			goto out_free;
		}
	} else {
		if (!strcmp(sname, GSSD_SERVICE_MDS) ||
		    !strcmp(sname, GSSD_SERVICE_OSS)) {
			printerr(LL_ERR,
				 "ERROR: %s@%s from %s doesn't bind with hostname\n",
				 sname, realm, libcfs_nid2str(nid));
			goto out_free;
		}
	}

	/* 2. check realm and user */
	switch (lustre_svc) {
	case LUSTRE_GSS_SVC_MDS:
		if (strcasecmp(mds_local_realm, realm) != 0) {
			/* Remote realm case */
			cred->cr_remote = 1;

			/* Prevent access to unmapped user from remote realm */
			if (cred->cr_mapped_uid == -1) {
				printerr(LL_ERR,
					 "ERROR: %s%s%s@%s from %s is remote but without mapping\n",
					 sname, host ? "/" : "",
					 host ? host : "", realm,
					 libcfs_nid2str(nid));
				break;
			}
			goto valid;
		}

		/* Now we know we are dealing with a local realm */

		if (!strcmp(sname, LUSTRE_ROOT_NAME) ||
		    !strcmp(sname, GSSD_SERVICE_HOST)) {
			cred->cr_uid = 0;
			cred->cr_usr_root = 1;
			goto valid;
		}
		if (!strcmp(sname, GSSD_SERVICE_MDS)) {
			cred->cr_uid = 0;
			cred->cr_usr_mds = 1;
			goto valid;
		}
		if (!strcmp(sname, GSSD_SERVICE_OSS)) {
			cred->cr_uid = 0;
			cred->cr_usr_oss = 1;
			goto valid;
		}
		if (cred->cr_mapped_uid != -1) {
			printerr(LL_INFO,
				 "user %s from %s is mapped to %u\n",
				 sname, libcfs_nid2str(nid),
				 cred->cr_mapped_uid);
			goto valid;
		}
		pw = getpwnam(sname);
		if (pw != NULL) {
			cred->cr_uid = pw->pw_uid;
			printerr(LL_INFO, "%s resolve to uid %u\n",
				 sname, cred->cr_uid);
			goto valid;
		}
		printerr(LL_ERR, "ERROR: invalid user, %s/%s@%s from %s\n",
			 sname, host, realm, libcfs_nid2str(nid));
		break;

valid:
		res = 0;
		break;
	case LUSTRE_GSS_SVC_MGS:
		if (!strcmp(sname, GSSD_SERVICE_OSS)) {
			cred->cr_uid = 0;
			cred->cr_usr_oss = 1;
		}
		fallthrough;
	case LUSTRE_GSS_SVC_OSS:
		if (!strcmp(sname, LUSTRE_ROOT_NAME) ||
		    !strcmp(sname, GSSD_SERVICE_HOST)) {
			cred->cr_uid = 0;
			cred->cr_usr_root = 1;
		} else if (!strcmp(sname, GSSD_SERVICE_MDS)) {
			cred->cr_uid = 0;
			cred->cr_usr_mds = 1;
		}
		if (cred->cr_mapped_uid != -1) {
			printerr(LL_INFO,
				 "user %s from %s is mapped to %u\n",
				 sname, libcfs_nid2str(nid),
				 cred->cr_mapped_uid);
			goto valid;
		}
		if (cred->cr_uid == -1) {
			printerr(LL_ERR,
				 "ERROR: svc %d doesn't accept user %s from %s\n",
				 lustre_svc, sname, libcfs_nid2str(nid));
			break;
		}
		res = 0;
		break;
	default:
		assert(0);
	}

out_free:
	if (!res)
		printerr(LL_WARN, "%s: authenticated %s%s%s@%s from %s\n",
			 lustre_svc_name[lustre_svc], sname,
			 host ? "/" : "", host ? host : "", realm,
			 libcfs_nid2str(nid));
	free(sname);
	return res;
}

static int handle_sk(struct svc_nego_data *snd)
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
	int attempts = 0;

	printerr(LL_DEBUG, "Handling sk request\n");
	memset(bufs, 0, sizeof(gss_buffer_desc) * SK_INIT_BUFFERS);

	/* See lgss_sk_using_cred() for client side token formation.
	 * Decoding initiator buffers */
	i = sk_decode_netstring(bufs, SK_INIT_BUFFERS, &snd->in_tok);
	if (i < SK_INIT_BUFFERS) {
		printerr(LL_ERR,
			 "Invalid netstring token received from peer\n");
		goto cleanup_buffers;
	}

	/* Allowing for a larger length first buffer in the future */
	if (bufs[SK_INIT_VERSION].length < sizeof(version)) {
		printerr(LL_ERR, "Invalid version received (wrong size)\n");
		goto cleanup_buffers;
	}
	memcpy(&version, bufs[SK_INIT_VERSION].value, sizeof(version));
	version = be32toh(version);
	if (version != SK_MSG_VERSION) {
		printerr(LL_ERR, "Invalid version received: %d\n", version);
		goto cleanup_buffers;
	}

	rc = GSS_S_FAILURE;

	/* target must be a null terminated string */
	i = bufs[SK_INIT_TARGET].length - 1;
	target = bufs[SK_INIT_TARGET].value;
	if (i >= 0 && target[i] != '\0') {
		printerr(LL_ERR, "Invalid target from netstring\n");
		goto cleanup_buffers;
	}

	if (bufs[SK_INIT_FLAGS].length != sizeof(flags)) {
		printerr(LL_ERR, "Invalid flags from netstring\n");
		goto cleanup_buffers;
	}
	memcpy(&flags, bufs[SK_INIT_FLAGS].value, sizeof(flags));

	skc = sk_create_cred(target, snd->nm_name, be32toh(flags));
	if (!skc) {
		printerr(LL_ERR, "Failed to create sk credentials\n");
		goto cleanup_buffers;
	}

	/* Verify that the peer has used a prime size greater or equal to
	 * the size specified in the key file which may contain only zero
	 * fill but the size specifies the mimimum supported size on
	 * servers */
	if (skc->sc_flags & LGSS_SVC_PRIV &&
	    bufs[SK_INIT_P].length < skc->sc_p.length) {
		printerr(LL_ERR,
			 "Peer DHKE prime does not meet the size required by keyfile: %zd bits\n",
			 skc->sc_p.length * 8);
		goto cleanup_buffers;
	}

	/* Throw out the p from the server and use the wire data */
	free(skc->sc_p.value);
	skc->sc_p.value = NULL;
	skc->sc_p.length = 0;

	/* Take control of all the allocated buffers from decoding */
	if (bufs[SK_INIT_RANDOM].length !=
	    sizeof(skc->sc_kctx.skc_peer_random)) {
		printerr(LL_ERR, "Invalid size for client random\n");
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
		printerr(LL_ERR, "HMAC verification error: 0x%x from peer %s\n",
			 rc, libcfs_nid2str((lnet_nid_t)snd->nid));
		goto cleanup_partial;
	}

	/* Check that the cluster hash matches the hash of nodemap name */
	rc = sk_verify_hash(snd->nm_name, EVP_sha256(), &skc->sc_nodemap_hash);
	if (rc != GSS_S_COMPLETE) {
		printerr(LL_ERR, "Cluster hash failed validation: 0x%x\n", rc);
		goto cleanup_partial;
	}

redo:
	rc = sk_gen_params(skc, *sk_dh_checks);
	if (rc != GSS_S_COMPLETE) {
		printerr(LL_ERR,
			 "Failed to generate DH params for responder\n");
		goto cleanup_partial;
	}
	rc = sk_compute_dh_key(skc, &remote_pub_key);
	if (rc == GSS_S_BAD_QOP && attempts < 2) {
		/* GSS_S_BAD_QOP means the generated shared key was shorter
		 * than expected. Just retry twice before giving up.
		 */
		attempts++;
		if (skc->sc_params) {
			EVP_PKEY_free(skc->sc_params);
			skc->sc_params = NULL;
		}
		if (skc->sc_pub_key.value) {
			free(skc->sc_pub_key.value);
			skc->sc_pub_key.value = NULL;
		}
		skc->sc_pub_key.length = 0;
		if (skc->sc_dh_shared_key.value) {
			/* erase secret key before freeing memory */
			memset(skc->sc_dh_shared_key.value, 0,
			       skc->sc_dh_shared_key.length);
			free(skc->sc_dh_shared_key.value);
			skc->sc_dh_shared_key.value = NULL;
		}
		skc->sc_dh_shared_key.length = 0;
		goto redo;
	} else if (rc != GSS_S_COMPLETE) {
		printerr(LL_ERR,
			 "Failed to compute session key from DH params\n");
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
		printerr(LL_ERR, "Failed to sign parameters\n");
		goto out_err;
	}
	bufs[SK_RESP_HMAC] = skc->sc_hmac;
	if (sk_encode_netstring(bufs, SK_RESP_BUFFERS, &snd->out_tok)) {
		printerr(LL_ERR, "Failed to encode netstring for token\n");
		goto out_err;
	}
	printerr(LL_INFO, "Created netstring of %zd bytes\n",
		 snd->out_tok.length);

	if (sk_session_kdf(skc, snd->nid, &snd->in_tok, &snd->out_tok)) {
		printerr(LL_ERR, "Failed to calculate derived session key\n");
		goto out_err;
	}
	if (sk_compute_keys(skc)) {
		printerr(LL_ERR,
			 "Failed to compute HMAC and encryption keys\n");
		goto out_err;
	}
	if (sk_serialize_kctx(skc, &snd->ctx_token)) {
		printerr(LL_ERR, "Failed to serialize context for kernel\n");
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

	/* cleanup ctx_token, out_tok is cleaned up in handle_channel_request */
	if (remote_pub_key.length != 0) {
		free(remote_pub_key.value);
		remote_pub_key.value = NULL;
		remote_pub_key.length = 0;
	}
	if (snd->ctx_token.value) {
		free(snd->ctx_token.value);
		snd->ctx_token.value = NULL;
		snd->ctx_token.length = 0;
	}

	printerr(LL_DEBUG, "sk returning success\n");
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
	if (remote_pub_key.length != 0) {
		free(remote_pub_key.value);
		remote_pub_key.value = NULL;
		remote_pub_key.length = 0;
	}
	sk_free_cred(skc);
	snd->maj_stat = rc;
	return -1;

out_err:
	snd->maj_stat = rc;
	if (snd->ctx_token.value) {
		free(snd->ctx_token.value);
		snd->ctx_token.value = NULL;
		snd->ctx_token.length = 0;
	}
	if (remote_pub_key.length != 0) {
		free(remote_pub_key.value);
		remote_pub_key.value = NULL;
		remote_pub_key.length = 0;
	}
	sk_free_cred(skc);
	printerr(LL_DEBUG, "sk returning failure\n");
#else /* !HAVE_OPENSSL_SSK */
	printerr(LL_ERR, "ERROR: shared key subflavour is not enabled\n");
#endif /* HAVE_OPENSSL_SSK */
	return -1;
}

static int handle_null(struct svc_nego_data *snd)
{
	struct svc_cred cred;
	uint64_t tmp;
	uint32_t flags;

	/* null just uses the same token as the return token and for
	 * for sending to the kernel.  It is a single uint64_t. */
	if (snd->in_tok.length != sizeof(uint64_t)) {
		snd->maj_stat = GSS_S_DEFECTIVE_TOKEN;
		printerr(LL_ERR, "Invalid token size (%zd) received\n",
			 snd->in_tok.length);
		return -1;
	}
	snd->out_tok.length = snd->in_tok.length;
	snd->out_tok.value = malloc(snd->out_tok.length);
	if (!snd->out_tok.value) {
		snd->maj_stat = GSS_S_FAILURE;
		printerr(LL_ERR, "Failed to allocate out_tok\n");
		return -1;
	}

	snd->ctx_token.length = snd->in_tok.length;
	snd->ctx_token.value = malloc(snd->ctx_token.length);
	if (!snd->ctx_token.value) {
		snd->maj_stat = GSS_S_FAILURE;
		printerr(LL_ERR, "Failed to allocate ctx_token\n");
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
		printerr(LL_ERR, "no service credential for svc %u\n",
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
		printerr(LL_WARN,
			 "gss_accept_sec_context GSS_S_CONTINUE_NEEDED\n");

		/* Save the context handle for future calls */
		snd->out_handle.length = sizeof(snd->ctx);
		memcpy(snd->out_handle.value, &snd->ctx, sizeof(snd->ctx));
		return 0;
	} else if (snd->maj_stat != GSS_S_COMPLETE) {
		printerr(LL_ERR, "ERROR: gss_accept_sec_context failed\n");
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
	if (serialize_context_for_kernel(&snd->ctx, &snd->ctx_token, mech)) {
		printerr(LL_ERR,
			 "ERROR: %s: serialize_context_for_kernel failed\n",
			__func__);
		snd->maj_stat = GSS_S_FAILURE;
		goto out_err;
	}

	/* heimdal/MIT implementations do not delete context at all */
	if (snd->ctx != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&ignore_min_stat, &snd->ctx,
				       &ignore_out_tok);

	do_svc_downcall(&snd->out_handle, &cred, mech, &snd->ctx_token);
	/* We no longer need the context token */
	if (snd->ctx_token.length)
		(void)gss_release_buffer(&ignore_min_stat, &snd->ctx_token);
	return 0;

out_err:
	if (snd->ctx != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&ignore_min_stat, &snd->ctx,
				       &ignore_out_tok);

	return 1;
}

int handle_channel_request(int fd)
{
	char in_handle_buf[15];
	char out_handle_buf[15];
	uint32_t lustre_mech;
	static char *lbuf;
	static ssize_t lbuflen;
	static char *cp;
	int get_len;
	int rc;
	u_int32_t ignore_min_stat;
	struct svc_nego_data snd = {
		.in_tok.value		= NULL,
		.in_handle.value	= in_handle_buf,
		.out_handle.value	= out_handle_buf,
		.maj_stat		= GSS_S_FAILURE,
		.ctx			= GSS_C_NO_CONTEXT,
	};
	__u64 hash = 0;
	__u64 tmp_lustre_svc = 0;

	printerr(LL_INFO, "handling request\n");
	if (readline(fd, &lbuf, &lbuflen) != 1) {
		printerr(LL_ERR, "ERROR: failed reading request\n");
		return -1;
	}

	cp = lbuf;

	/* see rsi_do_upcall() for the format of data being input here */
	rc = gss_u64_read_string(&cp, &hash);
	if (rc < 0) {
		printerr(LL_ERR, "ERROR: failed parsing request: hash\n");
		goto out_err;
	}
	rc = gss_u64_read_string(&cp, &tmp_lustre_svc);
	if (rc < 0) {
		printerr(LL_ERR, "ERROR: failed parsing request: lustre svc\n");
		goto out_err;
	}
	snd.lustre_svc = tmp_lustre_svc;
	/* lustre_svc is the svc and gss subflavor */
	lustre_mech = (snd.lustre_svc & LUSTRE_GSS_MECH_MASK) >>
		LUSTRE_GSS_MECH_SHIFT;
	snd.lustre_svc = snd.lustre_svc & LUSTRE_GSS_SVC_MASK;
	switch (lustre_mech) {
	case LGSS_MECH_KRB5:
		if (!krb_enabled) {
			static time_t next_krb;

			if (time(NULL) > next_krb) {
				printerr(LL_WARN,
					 "warning: Request for kerberos but service support not enabled\n");
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
				printerr(LL_WARN,
					 "warning: Request for gssnull but service support not enabled\n");
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
				printerr(LL_WARN,
					 "warning: Request for SSK but service support not %s\n",
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
		printerr(LL_ERR, "WARNING: invalid mechanism recevied: %d\n",
			 lustre_mech);
		goto out_err;
		break;
	}

	rc = gss_u64_read_string(&cp, (__u64 *)&snd.nid);
	if (rc < 0) {
		printerr(LL_ERR, "ERROR: failed parsing request: source nid\n");
		goto out_err;
	}
	rc = gss_u64_read_string(&cp, (__u64 *)&snd.handle_seq);
	if (rc < 0) {
		printerr(LL_ERR, "ERROR: failed parsing request: handle seq\n");
		goto out_err;
	}
	get_len = gss_string_read(&cp, snd.nm_name, sizeof(snd.nm_name), 0);
	if (get_len <= 0) {
		printerr(LL_ERR,
			 "ERROR: failed parsing request: nodemap name\n");
		goto out_err;
	}
	snd.nm_name[get_len] = '\0';
	printerr(LL_INFO,
		 "handling req: svc %u, nid %016llx, idx %"PRIx64" nodemap %s\n",
		 snd.lustre_svc, snd.nid, snd.handle_seq, snd.nm_name);

	get_len = gss_base64url_decode(&cp, snd.in_handle.value,
				       sizeof(in_handle_buf));
	if (get_len < 0) {
		printerr(LL_ERR, "ERROR: failed parsing request: in handle\n");
		goto out_err;
	}
	snd.in_handle.length = (size_t)get_len;

	printerr(LL_DEBUG, "in_handle:\n");
	print_hexl(3, snd.in_handle.value, snd.in_handle.length);

	snd.in_tok.value = malloc(strlen(cp));
	if (!snd.in_tok.value) {
		printerr(LL_ERR, "ERROR: failed alloc for in token\n");
		goto out_err;
	}
	get_len = gss_base64url_decode(&cp, snd.in_tok.value, strlen(cp));
	if (get_len < 0) {
		printerr(LL_ERR, "ERROR: failed parsing request: in token\n");
		goto out_err;
	}
	snd.in_tok.length = (size_t)get_len;

	printerr(LL_DEBUG, "in_tok:\n");
	print_hexl(3, snd.in_tok.value, snd.in_tok.length);

	if (snd.in_handle.length != 0) { /* CONTINUE_INIT case */
		if (snd.in_handle.length != sizeof(snd.ctx)) {
			printerr(LL_ERR,
				 "ERROR: input handle has unexpected length %zu\n",
				 snd.in_handle.length);
			goto out_err;
		}
		/* in_handle is the context id stored in the out_handle
		 * for the GSS_S_CONTINUE_NEEDED case below.  */
		memcpy(&snd.ctx, snd.in_handle.value, snd.in_handle.length);
	}

	rc = -1;
	if (lustre_mech == LGSS_MECH_KRB5)
		rc = handle_krb(&snd);
	else if (lustre_mech == LGSS_MECH_SK)
		rc = handle_sk(&snd);
	else if (lustre_mech == LGSS_MECH_NULL)
		rc = handle_null(&snd);
	else
		printerr(LL_ERR,
			 "ERROR: Received or request for subflavor that is not enabled: %d\n",
			 lustre_mech);

out_err:
	printerr(LL_INFO, "to send response with rc=%d\n", rc ? -EACCES : 0);
	/* Failures send a null token */
	rc = send_response(rc, hash, &snd.in_handle, &snd.in_tok,
			   snd.maj_stat, snd.min_stat,
			   &snd.out_handle, &snd.out_tok);

	/* cleanup buffers */
	if (snd.in_tok.value)
		free(snd.in_tok.value);
	if (snd.out_tok.value != NULL)
		gss_release_buffer(&ignore_min_stat, &snd.out_tok);

	/* For junk wire data just ignore */
ignore:
	return rc;
}
