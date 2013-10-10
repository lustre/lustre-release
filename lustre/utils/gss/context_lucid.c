/*
 * COPYRIGHT (c) 2006
 * The Regents of the University of Michigan
 * ALL RIGHTS RESERVED
 *
 * Permission is granted to use, copy, create derivative works
 * and redistribute this software and such derivative works
 * for any purpose, so long as the name of The University of
 * Michigan is not used in any advertising or publicity
 * pertaining to the use of distribution of this software
 * without specific, written prior authorization.  If the
 * above copyright notice or any other identification of the
 * University of Michigan is included in any copy of any
 * portion of this software, then the disclaimer below must
 * also be included.
 *
 * THIS SOFTWARE IS PROVIDED AS IS, WITHOUT REPRESENTATION
 * FROM THE UNIVERSITY OF MICHIGAN AS TO ITS FITNESS FOR ANY
 * PURPOSE, AND WITHOUT WARRANTY BY THE UNIVERSITY OF
 * MICHIGAN OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING
 * WITHOUT LIMITATION THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
 * REGENTS OF THE UNIVERSITY OF MICHIGAN SHALL NOT BE LIABLE
 * FOR ANY DAMAGES, INCLUDING SPECIAL, INDIRECT, INCIDENTAL, OR
 * CONSEQUENTIAL DAMAGES, WITH RESPECT TO ANY CLAIM ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OF THE SOFTWARE, EVEN
 * IF IT HAS BEEN OR IS HEREAFTER ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGES.
 */

#include "config.h"

#ifdef HAVE_LUCID_CONTEXT_SUPPORT

/*
 * Newer versions of MIT and Heimdal have lucid context support.
 * We can use common code if it is supported.
 */

#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <krb5.h>
#include <gssapi/gssapi.h>
#ifndef OM_uint64
typedef uint64_t OM_uint64;
#endif
#include <gssapi/gssapi_krb5.h>

#ifdef _NEW_BUILD_
# include "lgss_utils.h"
#else
# include "gss_util.h"
# include "gss_oids.h"
# include "err_util.h"
#endif
#include "write_bytes.h"
#include "context.h"

extern OM_uint32 gss_export_lucid_sec_context(OM_uint32 *min_stat,
					      gss_ctx_id_t *ctx,
					      OM_uint32 version,
					      void **kctx);
extern OM_uint32 gss_free_lucid_sec_context(OM_uint32 *min_stat,
					    gss_ctx_id_t ctx,
					    void *kctx);

static int
write_lucid_keyblock(char **p, char *end, gss_krb5_lucid_key_t *key)
{
	gss_buffer_desc tmp;

	if (WRITE_BYTES(p, end, key->type)) return -1;
	tmp.length = key->length;
	tmp.value = key->data;
	if (write_buffer(p, end, &tmp)) return -1;
	return 0;
}

static int
prepare_krb5_rfc1964_buffer(gss_krb5_lucid_context_v1_t *lctx,
	gss_buffer_desc *buf)
{
	char *p, *end;
	static int constant_zero = 0;
	unsigned char fakeseed[16] = { 0 };
	uint32_t word_send_seq;
	gss_krb5_lucid_key_t enc_key;
	int i;
	char *skd, *dkd;
	gss_buffer_desc fakeoid;

	/*
	 * The new Kerberos interface to get the gss context
	 * does not include the seed or seed_init fields
	 * because we never really use them.  But for now,
	 * send down a fake buffer so we can use the same
	 * interface to the kernel.
	 */
	memset(&enc_key, 0, sizeof(enc_key));
	memset(&fakeoid, 0, sizeof(fakeoid));

	if (!(buf->value = calloc(1, MAX_CTX_LEN)))
		goto out_err;
	p = buf->value;
	end = buf->value + MAX_CTX_LEN;

	if (WRITE_BYTES(&p, end, lctx->initiate)) goto out_err;

	/* seed_init and seed not used by kernel anyway */
	if (WRITE_BYTES(&p, end, constant_zero)) goto out_err;
	if (write_bytes(&p, end, &fakeseed, 16)) goto out_err;

	if (WRITE_BYTES(&p, end, lctx->rfc1964_kd.sign_alg)) goto out_err;
	if (WRITE_BYTES(&p, end, lctx->rfc1964_kd.seal_alg)) goto out_err;
	if (WRITE_BYTES(&p, end, lctx->endtime)) goto out_err;
	word_send_seq = lctx->send_seq;	/* XXX send_seq is 64-bit */
	if (WRITE_BYTES(&p, end, word_send_seq)) goto out_err;
	if (write_oid(&p, end, &krb5oid)) goto out_err;

#ifdef HAVE_HEIMDAL
	/*
	 * The kernel gss code expects des-cbc-raw for all flavors of des.
	 * The keytype from MIT has this type, but Heimdal does not.
	 * Force the Heimdal keytype to 4 (des-cbc-raw).
	 * Note that the rfc1964 version only supports DES enctypes.
	 */
	if (lctx->rfc1964_kd.ctx_key.type != 4) {
		printerr(2, "%s: overriding heimdal keytype (%d => %d)\n",
			 __FUNCTION__, lctx->rfc1964_kd.ctx_key.type, 4);
		lctx->rfc1964_kd.ctx_key.type = 4;
	}
#endif
	printerr(2, "%s: serializing keys with enctype %d and length %d\n",
		 __FUNCTION__, lctx->rfc1964_kd.ctx_key.type,
		 lctx->rfc1964_kd.ctx_key.length);

	/* derive the encryption key and copy it into buffer */
	enc_key.type = lctx->rfc1964_kd.ctx_key.type;
	enc_key.length = lctx->rfc1964_kd.ctx_key.length;
	if ((enc_key.data = calloc(1, enc_key.length)) == NULL)
		goto out_err;
	skd = (char *) lctx->rfc1964_kd.ctx_key.data;
	dkd = (char *) enc_key.data;
	for (i = 0; i < enc_key.length; i++)
		dkd[i] = skd[i] ^ 0xf0;
	if (write_lucid_keyblock(&p, end, &enc_key)) {
		free(enc_key.data);
		goto out_err;
	}
	free(enc_key.data);

	if (write_lucid_keyblock(&p, end, &lctx->rfc1964_kd.ctx_key))
		goto out_err;

	buf->length = p - (char *)buf->value;
	return 0;
out_err:
	printerr(0, "ERROR: failed serializing krb5 context for kernel\n");
	if (buf->value) free(buf->value);
	buf->length = 0;
	if (enc_key.data) free(enc_key.data);
	return -1;
}

/* XXX Hack alert! XXX  Do NOT submit upstream! XXX */
/* XXX Hack alert! XXX  Do NOT submit upstream! XXX */

/* for 3DES */
#define KG_USAGE_SEAL 22
#define KG_USAGE_SIGN 23
#define KG_USAGE_SEQ  24

/* for rfc???? */
#define KG_USAGE_ACCEPTOR_SEAL  22
#define KG_USAGE_ACCEPTOR_SIGN  23
#define KG_USAGE_INITIATOR_SEAL 24
#define KG_USAGE_INITIATOR_SIGN 25

/* Lifted from mit src/lib/gssapi/krb5/gssapiP_krb5.h */
enum seal_alg {
  SEAL_ALG_NONE            = 0xffff,
  SEAL_ALG_DES             = 0x0000,
  SEAL_ALG_1               = 0x0001, /* not published */
  SEAL_ALG_MICROSOFT_RC4   = 0x0010, /* microsoft w2k;  */
  SEAL_ALG_DES3KD          = 0x0002
};

#define KEY_USAGE_SEED_ENCRYPTION	0xAA
#define KEY_USAGE_SEED_INTEGRITY	0x55
#define KEY_USAGE_SEED_CHECKSUM		0x99
#define K5CLENGTH 5

/* Flags for version 2 context flags */
#define KRB5_CTX_FLAG_INITIATOR		0x00000001
#define KRB5_CTX_FLAG_CFX		0x00000002
#define KRB5_CTX_FLAG_ACCEPTOR_SUBKEY	0x00000004

/* XXX Hack alert! XXX  Do NOT submit upstream! XXX */
/* XXX Hack alert! XXX  Do NOT submit upstream! XXX */
/*
 * We don't have "legal" access to these MIT-only
 * structures located in libk5crypto
 */
extern void krb5int_enc_arcfour;
extern void krb5int_enc_des3;
extern void krb5int_enc_aes128;
extern void krb5int_enc_aes256;

static void
key_lucid_to_krb5(const gss_krb5_lucid_key_t *lin, krb5_keyblock *kout)
{
	memset(kout, '\0', sizeof(kout));
#ifdef HAVE_KRB5
	kout->enctype = lin->type;
	kout->length = lin->length;
	kout->contents = lin->data;
#else
	kout->keytype = lin->type;
	kout->keyvalue.length = lin->length;
	kout->keyvalue.data = lin->data;
#endif
}

static void
key_krb5_to_lucid(const krb5_keyblock *kin, gss_krb5_lucid_key_t *lout)
{
	memset(lout, '\0', sizeof(lout));
#ifdef HAVE_KRB5
	lout->type = kin->enctype;
	lout->length = kin->length;
	lout->data = kin->contents;
#else
	lout->type = kin->keytype;
	lout->length = kin->keyvalue.length;
	memcpy(lout->data, kin->keyvalue.data, kin->keyvalue.length);
#endif
}

/* XXX Hack alert! XXX  Do NOT submit upstream! XXX */
/* XXX Hack alert! XXX  Do NOT submit upstream! XXX */
/* XXX Hack alert! XXX  Do NOT submit upstream! XXX */
/* XXX Hack alert! XXX  Do NOT submit upstream! XXX */
/*
 * Function to derive a new key from a given key and given constant data.
 */
static krb5_error_code
derive_key_lucid(const gss_krb5_lucid_key_t *in, gss_krb5_lucid_key_t *out,
		 int usage, char extra)
{
	krb5_error_code code;
	unsigned char constant_data[K5CLENGTH];
	krb5_data datain;
	int keylength;
	void *enc;
	krb5_keyblock kin, kout;  /* must send krb5_keyblock, not lucid! */
#if defined(HAVE_HEIMDAL) || HAVE_KRB5INT_DERIVE_KEY
	krb5_context kcontext;
#endif
#if HAVE_KRB5INT_DERIVE_KEY
	krb5_key key_in, key_out;
#endif
#ifdef HAVE_HEIMDAL
	krb5_keyblock *outkey;
#endif

	/*
	 * XXX Hack alert.  We don't have "legal" access to these
	 * values and structures located in libk5crypto
	 */
	switch (in->type) {
	case ENCTYPE_DES3_CBC_SHA1:
#ifdef HAVE_KRB5
	case ENCTYPE_DES3_CBC_RAW:
#endif
		keylength = 24;
#ifdef HAVE_KRB5
		enc = &krb5int_enc_des3;
#endif
		break;
	case ENCTYPE_AES128_CTS_HMAC_SHA1_96:
		keylength = 16;
#ifdef HAVE_KRB5
		enc = &krb5int_enc_aes128;
#endif
		break;
	case ENCTYPE_AES256_CTS_HMAC_SHA1_96:
		keylength = 32;
#ifdef HAVE_KRB5
		enc = &krb5int_enc_aes256;
#endif
		break;
	default:
		code = KRB5_BAD_ENCTYPE;
		goto out;
	}

	/* allocate memory for output key */
	if ((out->data = malloc(keylength)) == NULL) {
		code = ENOMEM;
		goto out;
	}
	out->length = keylength;
	out->type = in->type;

	/* Convert to correct format for call to krb5_derive_key */
	key_lucid_to_krb5(in, &kin);
	key_lucid_to_krb5(out, &kout);

	datain.data = (char *) constant_data;
	datain.length = K5CLENGTH;

	((char *)(datain.data))[0] = (usage>>24)&0xff;
	((char *)(datain.data))[1] = (usage>>16)&0xff;
	((char *)(datain.data))[2] = (usage>>8)&0xff;
	((char *)(datain.data))[3] = usage&0xff;

	((char *)(datain.data))[4] = (char) extra;

#ifdef HAVE_KRB5
#if HAVE_KRB5INT_DERIVE_KEY
	code = krb5_init_context(&kcontext);
	if (code) {
		free(out->data);
		out->data = NULL;
		goto out;
	}
	code = krb5_k_create_key(kcontext, &kin, &key_in);
	if (code) {
		free(out->data);
		out->data = NULL;
		goto out;
	}
	code = krb5_k_create_key(kcontext, &kout, &key_out);
	if (code) {
		free(out->data);
		out->data = NULL;
		goto out;
	}
	code = krb5int_derive_key(enc, key_in, &key_out, &datain,
				  DERIVE_RFC3961);
#else  /* !HAVE_KRB5INT_DERIVE_KEY */
	code = krb5_derive_key(enc, &kin, &kout, &datain);
#endif	/* HAVE_KRB5INT_DERIVE_KEY */
#else	/* !defined(HAVE_KRB5) */
	if ((code = krb5_init_context(&kcontext))) {
	}
	code = krb5_derive_key(kcontext, &kin, in->type, constant_data, K5CLENGTH, &outkey);
#endif	/* defined(HAVE_KRB5) */
	if (code) {
		free(out->data);
		out->data = NULL;
		goto out;
	}
#ifdef HAVE_KRB5
	key_krb5_to_lucid(&kout, out);
#if HAVE_KRB5INT_DERIVE_KEY
	krb5_free_context(kcontext);
#endif	/* HAVE_KRB5INT_DERIVE_KEY */
#else	/* !defined(HAVE_KRB5) */
	key_krb5_to_lucid(outkey, out);
	krb5_free_keyblock(kcontext, outkey);
	krb5_free_context(kcontext);
#endif	/* defined(HAVE_KRB5) */

  out:
	if (code)
		printerr(0, "ERROR: %s: returning error %d (%s)\n",
			 __FUNCTION__, code, error_message(code));
	return (code);
}


/*
 * Prepare a new-style buffer, as defined in rfc4121 (a.k.a. cfx),
 * to send to the kernel for newer encryption types -- or for DES3.
 *
 * The new format is:
 *
 *	u32 initiate;			( whether we are the initiator or not )
 *	s32 endtime;
 *	u32 flags;
 *	#define KRB5_CTX_FLAG_INITIATOR		0x00000001
 *	#define KRB5_CTX_FLAG_CFX		0x00000002
 *	#define KRB5_CTX_FLAG_ACCEPTOR_SUBKEY	0x00000004
 *	u64 seq_send;
 *	u32  enctype;			( encrption type of keys )
 *	u32  size_of_each_key;		( size of each key in bytes )
 *	u32  number_of_keys;		( N -- should always be 3 for now )
 *	keydata-1;                      ( Ke )
 *	keydata-2;                      ( Ki )
 *	keydata-3;                      ( Kc )
 *
 */
static int
prepare_krb5_rfc4121_buffer(gss_krb5_lucid_context_v1_t *lctx,
			    gss_buffer_desc *buf)
{
	static int constant_two = 2;
	char *p, *end;
	uint32_t v2_flags = 0;
	gss_krb5_lucid_key_t enc_key;
	gss_krb5_lucid_key_t derived_key;
	gss_buffer_desc fakeoid;
	uint32_t enctype;
	uint32_t keysize;
	uint32_t numkeys;

	memset(&enc_key, 0, sizeof(enc_key));
	memset(&fakeoid, 0, sizeof(fakeoid));

	if (!(buf->value = calloc(1, MAX_CTX_LEN)))
		goto out_err;
	p = buf->value;
	end = buf->value + MAX_CTX_LEN;

	/* Version 2 */
	if (WRITE_BYTES(&p, end, constant_two)) goto out_err;
	if (WRITE_BYTES(&p, end, lctx->endtime)) goto out_err;

	if (lctx->initiate)
		v2_flags |= KRB5_CTX_FLAG_INITIATOR;
	if (lctx->protocol != 0)
		v2_flags |= KRB5_CTX_FLAG_CFX;
	if (lctx->protocol != 0 && lctx->cfx_kd.have_acceptor_subkey == 1)
		v2_flags |= KRB5_CTX_FLAG_ACCEPTOR_SUBKEY;

	if (WRITE_BYTES(&p, end, v2_flags)) goto out_err;

	if (WRITE_BYTES(&p, end, lctx->send_seq)) goto out_err;

	/* Protocol 0 here implies DES3 or RC4 */
	printerr(3, "protocol %d\n", lctx->protocol);
	if (lctx->protocol == 0) {
		enctype = lctx->rfc1964_kd.ctx_key.type;
#ifdef HAVE_HEIMDAL
		/*
		 * The kernel gss code expects ENCTYPE_DES3_CBC_RAW (6) for
		 * 3des keys, but Heimdal key has ENCTYPE_DES3_CBC_SHA1 (16).
		 * Force the Heimdal enctype to 6.
		 */
		if (enctype == ENCTYPE_DES3_CBC_SHA1) {
			printerr(2, "%s: overriding heimdal keytype (%d => %d)\n",
				 __FUNCTION__, enctype, 6);

			enctype = 6;
		}
#endif
		keysize = lctx->rfc1964_kd.ctx_key.length;
		numkeys = 3;	/* XXX is always gonna be three? */
	} else {
		if (lctx->cfx_kd.have_acceptor_subkey) {
			enctype = lctx->cfx_kd.acceptor_subkey.type;
			keysize = lctx->cfx_kd.acceptor_subkey.length;
		} else {
			enctype = lctx->cfx_kd.ctx_key.type;
			keysize = lctx->cfx_kd.ctx_key.length;
		}
		numkeys = 3;
	}
	printerr(3, "serializing %d keys with enctype %d and size %d\n",
		 numkeys, enctype, keysize);
	if (WRITE_BYTES(&p, end, enctype)) goto out_err;
	if (WRITE_BYTES(&p, end, keysize)) goto out_err;
	if (WRITE_BYTES(&p, end, numkeys)) goto out_err;

	if (lctx->protocol == 0) {
		/* derive and send down: Ke, Ki, and Kc */
		/* Ke */
		if (write_bytes(&p, end, lctx->rfc1964_kd.ctx_key.data,
				lctx->rfc1964_kd.ctx_key.length))
			goto out_err;

		/* Ki */
		if (write_bytes(&p, end, lctx->rfc1964_kd.ctx_key.data,
				lctx->rfc1964_kd.ctx_key.length))
			goto out_err;

		/* Kc */
		/*
		 * RC4 is special, it dosen't need key derivation. Actually
		 * the Ke is based on plain text. Here we just let all three
		 * key identical, kernel will handle everything. --ericm
		 */
		if (lctx->rfc1964_kd.ctx_key.type == ENCTYPE_ARCFOUR_HMAC) {
			if (write_bytes(&p, end, lctx->rfc1964_kd.ctx_key.data,
					lctx->rfc1964_kd.ctx_key.length))
				goto out_err;
		} else {
			if (derive_key_lucid(&lctx->rfc1964_kd.ctx_key,
					&derived_key,
					KG_USAGE_SIGN, KEY_USAGE_SEED_CHECKSUM))
				goto out_err;
			if (write_bytes(&p, end, derived_key.data,
					derived_key.length))
				goto out_err;
			free(derived_key.data);
		}
	} else {
		gss_krb5_lucid_key_t *keyptr;
		uint32_t sign_usage, seal_usage;

		if (lctx->cfx_kd.have_acceptor_subkey)
			keyptr = &lctx->cfx_kd.acceptor_subkey;
		else
			keyptr = &lctx->cfx_kd.ctx_key;

#if 0
		if (lctx->initiate == 1) {
			sign_usage = KG_USAGE_INITIATOR_SIGN;
			seal_usage = KG_USAGE_INITIATOR_SEAL;
		} else {
			sign_usage = KG_USAGE_ACCEPTOR_SIGN;
			seal_usage = KG_USAGE_ACCEPTOR_SEAL;
		}
#else
		/* FIXME
		 * These are from rfc4142, but I don't understand: if we supply
		 * different 'usage' value for client & server, then the peers
		 * will have different derived keys. How could this work?
		 *
		 * Here we simply use old SIGN/SEAL values until we find the
		 * answer.  --ericm
		 * FIXME
		 */
		sign_usage = KG_USAGE_SIGN;
		seal_usage = KG_USAGE_SEAL;
#endif

		/* derive and send down: Ke, Ki, and Kc */

		/* Ke */
		if (derive_key_lucid(keyptr, &derived_key,
			       seal_usage, KEY_USAGE_SEED_ENCRYPTION))
			goto out_err;
		if (write_bytes(&p, end, derived_key.data,
				derived_key.length))
			goto out_err;
		free(derived_key.data);

		/* Ki */
		if (derive_key_lucid(keyptr, &derived_key,
			       seal_usage, KEY_USAGE_SEED_INTEGRITY))
			goto out_err;
		if (write_bytes(&p, end, derived_key.data,
				derived_key.length))
			goto out_err;
		free(derived_key.data);

		/* Kc */
		if (derive_key_lucid(keyptr, &derived_key,
			       sign_usage, KEY_USAGE_SEED_CHECKSUM))
			goto out_err;
		if (write_bytes(&p, end, derived_key.data,
				derived_key.length))
			goto out_err;
		free(derived_key.data);
	}

	buf->length = p - (char *)buf->value;
	return 0;

out_err:
	printerr(0, "ERROR: %s: failed serializing krb5 context for kernel\n",
		 __FUNCTION__);
	if (buf->value) {
		free(buf->value);
		buf->value = NULL;
	}
	buf->length = 0;
	if (enc_key.data) {
		free(enc_key.data);
		enc_key.data = NULL;
	}
	return -1;
}
int
serialize_krb5_ctx(gss_ctx_id_t ctx, gss_buffer_desc *buf)
{
	OM_uint32 maj_stat, min_stat;
	void *return_ctx = 0;
	OM_uint32 vers;
	gss_krb5_lucid_context_v1_t *lctx = 0;
	int retcode = 0;

	printerr(3, "lucid version!\n");
	maj_stat = gss_export_lucid_sec_context(&min_stat, &ctx,
						1, &return_ctx);
	if (maj_stat != GSS_S_COMPLETE) {
		pgsserr("gss_export_lucid_sec_context",
			maj_stat, min_stat, &krb5oid);
		goto out_err;
	}

	/* Check the version returned, we only support v1 right now */
	vers = ((gss_krb5_lucid_context_version_t *)return_ctx)->version;
	switch (vers) {
	case 1:
		lctx = (gss_krb5_lucid_context_v1_t *) return_ctx;
		break;
	default:
		printerr(0, "ERROR: unsupported lucid sec context version %d\n",
			vers);
		goto out_err;
		break;
	}

        /*
	 * Now lctx points to a lucid context that we can send down to kernel
	 *
	 * Note: we send down different information to the kernel depending
	 * on the protocol version and the enctyption type.
	 * For protocol version 0 with all enctypes besides DES3, we use
	 * the original format.  For protocol version != 0 or DES3, we
	 * send down the new style information.
	 */

	if (lctx->protocol == 0 && lctx->rfc1964_kd.ctx_key.type <= 4)
		retcode = prepare_krb5_rfc1964_buffer(lctx, buf);
	else
		retcode = prepare_krb5_rfc4121_buffer(lctx, buf);

	maj_stat = gss_free_lucid_sec_context(&min_stat, ctx, return_ctx);
	if (maj_stat != GSS_S_COMPLETE) {
		pgsserr("gss_export_lucid_sec_context",
			maj_stat, min_stat, &krb5oid);
		printerr(0, "WARN: failed to free lucid sec context\n");
	}

	if (retcode) {
		printerr(1, "%s: prepare_krb5_*_buffer failed (retcode = %d)\n",
			 __FUNCTION__, retcode);
		goto out_err;
	}

	return 0;

out_err:
	printerr(0, "ERROR: failed serializing krb5 context for kernel\n");
	return -1;
}



#endif /* HAVE_LUCID_CONTEXT_SUPPORT */
