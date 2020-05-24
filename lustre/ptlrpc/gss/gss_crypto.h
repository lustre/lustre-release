#ifndef PTLRPC_GSS_CRYPTO_H
#define PTLRPC_GSS_CRYPTO_H

#include <linux/scatterlist.h>

#include "gss_internal.h"

#include <crypto/skcipher.h>

/*
 * linux v4.19-rc2-66-gb350bee5ea0f
 * crypto: skcipher - Introduce crypto_sync_skcipher
 *
 * crypto_sync_skcipher will replace crypto_blkcipher so start using
 * crypto_sync_skcipher and provide wrappers for older kernels
 */
#ifdef SYNC_SKCIPHER_REQUEST_ON_STACK

#define crypto_skcipher_encrypt_iv(desc, dst, src, blocksize)		\
	crypto_skcipher_encrypt((desc))

#define crypto_skcipher_decrypt_iv(desc, dst, src, blocksize)		\
	crypto_skcipher_decrypt((desc))

#define skcipher_request_set_crypt_iv(d)

#else /* ! SYNC_SKCIPHER_REQUEST_ON_STACK */

#define	crypto_sync_skcipher		crypto_blkcipher

#define SYNC_SKCIPHER_REQUEST_ON_STACK(name, tfm)			\
	struct blkcipher_desc __##name##_obj, *name = (void *)&__##name##_obj

#define skcipher_request_set_sync_tfm(d, _tfm)				\
	do { (d)->tfm = _tfm; } while (0)

#define skcipher_request_set_callback(d, f, c, data)			\
	do { (d)->flags = f; } while (0)

#define skcipher_request_set_crypt(d, src, dst, cryptlen, iv)		\
	do { (d)->info = iv; } while (0)

#define skcipher_request_set_crypt_iv(d)				\
	do { (d)->info = crypto_blkcipher_crt((d)->tfm)->iv; } while (0)

#define crypto_sync_skcipher_blocksize(tfm)				\
	crypto_blkcipher_blocksize((tfm))

#define crypto_sync_skcipher_setkey(tfm, key, keylen)			\
	crypto_blkcipher_setkey((tfm), (key), (keylen))

#define crypto_alloc_sync_skcipher(name, type, mask)			\
	crypto_alloc_blkcipher((name), (type), (mask))

#define crypto_free_sync_skcipher(tfm)					\
	crypto_free_blkcipher((tfm))

#define crypto_sync_skcipher_ivsize(tfm)				\
	crypto_blkcipher_ivsize((tfm))

#define crypto_skcipher_encrypt_iv(desc, dst, src, len)			\
	crypto_blkcipher_encrypt_iv((desc), (dst), (src), (len))

#define crypto_skcipher_decrypt_iv(desc, dst, src, len)			\
	crypto_blkcipher_decrypt_iv((desc), (dst), (src), (len))

#define skcipher_request_zero(req) /* nop */

#endif /* SYNC_SKCIPHER_REQUEST_ON_STACK */

struct gss_keyblock {
	rawobj_t kb_key;
	struct crypto_sync_skcipher *kb_tfm;
};

int gss_keyblock_init(struct gss_keyblock *kb, const char *alg_name,
		      const int alg_mode);
void gss_keyblock_free(struct gss_keyblock *kb);
int gss_keyblock_dup(struct gss_keyblock *new, struct gss_keyblock *kb);
int gss_get_bytes(char **ptr, const char *end, void *res, size_t len);
int gss_get_rawobj(char **ptr, const char *end, rawobj_t *res);
int gss_get_keyblock(char **ptr, const char *end, struct gss_keyblock *kb,
		     __u32 keysize);
int gss_setup_sgtable(struct sg_table *sgt, struct scatterlist *prealloc_sg,
		      const void *buf, unsigned int buf_len);
void gss_teardown_sgtable(struct sg_table *sgt);
int gss_crypt_generic(struct crypto_sync_skcipher *tfm, int decrypt,
		      const void *iv, const void *in, void *out, size_t length);
int gss_digest_hash(struct ahash_request *req, rawobj_t *hdr,
		    int msgcnt, rawobj_t *msgs, int iovcnt, lnet_kiov_t *iovs);
int gss_digest_hash_compat(struct ahash_request *req,
			   rawobj_t *hdr, int msgcnt, rawobj_t *msgs,
			   int iovcnt, lnet_kiov_t *iovs);
int gss_add_padding(rawobj_t *msg, int msg_buflen, int blocksize);
int gss_crypt_rawobjs(struct crypto_sync_skcipher *tfm, __u8 *iv,
		      int inobj_cnt, rawobj_t *inobjs, rawobj_t *outobj,
		      int enc);

#endif /* PTLRPC_GSS_CRYPTO_H */
