#ifndef PTLRPC_GSS_CRYPTO_H
#define PTLRPC_GSS_CRYPTO_H

#include "gss_internal.h"

struct gss_keyblock {
	rawobj_t		 kb_key;
	struct crypto_blkcipher *kb_tfm;
};

int gss_keyblock_init(struct gss_keyblock *kb, char *alg_name,
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
int gss_crypt_generic(struct crypto_blkcipher *tfm, int decrypt, const void *iv,
		      const void *in, void *out, size_t length);
int gss_digest_hmac(struct crypto_hash *tfm, rawobj_t *key, rawobj_t *hdr,
		    int msgcnt, rawobj_t *msgs, int iovcnt, lnet_kiov_t *iovs,
		    rawobj_t *cksum);
int gss_digest_norm(struct crypto_hash *tfm, struct gss_keyblock *kb,
		    rawobj_t *hdr, int msgcnt, rawobj_t *msgs, int iovcnt,
		    lnet_kiov_t *iovs, rawobj_t *cksum);
int gss_add_padding(rawobj_t *msg, int msg_buflen, int blocksize);
int gss_crypt_rawobjs(struct crypto_blkcipher *tfm, __u8 *iv,
		      int inobj_cnt, rawobj_t *inobjs, rawobj_t *outobj,
		      int enc);

#endif /* PTLRPC_GSS_CRYPTO_H */
