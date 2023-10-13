/*
 * Modifications for Lustre
 *
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 2012, 2014, Intel Corporation.
 *
 * Author: Eric Mei <ericm@clusterfs.com>
 */

/*
 * Neil Brown <neilb@cse.unsw.edu.au>
 * J. Bruce Fields <bfields@umich.edu>
 * Andy Adamson <andros@umich.edu>
 * Dug Song <dugsong@monkey.org>
 *
 * RPCSEC_GSS server authentication.
 * This implements RPCSEC_GSS as defined in rfc2203 (rpcsec_gss) and rfc2078
 * (gssapi)
 *
 * The RPCSEC_GSS involves three stages:
 *  1/ context creation
 *  2/ data exchange
 *  3/ context destruction
 *
 * Context creation is handled largely by upcalls to user-space.
 *  In particular, GSS_Accept_sec_context is handled by an upcall
 * Data exchange is handled entirely within the kernel
 *  In particular, GSS_GetMIC, GSS_VerifyMIC, GSS_Seal, GSS_Unseal are in-kernel.
 * Context destruction is handled in-kernel
 *  GSS_Delete_sec_context is in-kernel
 *
 * Context creation is initiated by a RPCSEC_GSS_INIT request arriving.
 * The context handle and gss_token are used as a key into the rpcsec_init cache.
 * The content of this cache includes some of the outputs of GSS_Accept_sec_context,
 * being major_status, minor_status, context_handle, reply_token.
 * These are sent back to the client.
 * Sequence window management is handled by the kernel.  The window size if currently
 * a compile time constant.
 *
 * When user-space is happy that a context is established, it places an entry
 * in the rpcsec_context cache. The key for this cache is the context_handle.
 * The content includes:
 *   uid/gidlist - for determining access rights
 *   mechanism type
 *   mechanism specific information, such as a key
 *
 */

#define DEBUG_SUBSYSTEM S_SEC
#include <linux/types.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/sunrpc/cache.h>
#include <linux/binfmts.h>
#include <net/sock.h>
#include <linux/un.h>

#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_import.h>
#include <lustre_net.h>
#include <lustre_nodemap.h>
#include <lustre_sec.h>
#include <libcfs/linux/linux-hash.h>

#include "gss_err.h"
#include "gss_internal.h"
#include "gss_api.h"
#include "gss_crypto.h"

#ifndef HAVE_GET_EXPIRY_2ARGS
static inline int __get_expiry2(char **bpp, time64_t *rvp)
{
	*rvp = get_expiry(bpp);
	return *rvp ? 0 : -EINVAL;
}
#define get_expiry(ps, pt)	__get_expiry2((ps), (pt))
#endif

#define GSS_SVC_UPCALL_TIMEOUT  (20)

static DEFINE_SPINLOCK(__ctx_index_lock);
static __u64 __ctx_index;

unsigned int krb5_allow_old_client_csum;

__u64 gss_get_next_ctx_index(void)
{
	__u64 idx;

	spin_lock(&__ctx_index_lock);
	idx = __ctx_index++;
	spin_unlock(&__ctx_index_lock);

	return idx;
}

static inline unsigned long hash_mem(char *buf, int length, int bits)
{
	unsigned long hash = 0;
	unsigned long l = 0;
	int len = 0;
	unsigned char c;

	do {
		if (len == length) {
			c = (char) len;
			len = -1;
		} else
			c = *buf++;

		l = (l << 8) | c;
		len++;

		if ((len & (BITS_PER_LONG/8-1)) == 0)
			hash = cfs_hash_long(hash^l, BITS_PER_LONG);
	} while (len);

	return hash >> (BITS_PER_LONG - bits);
}

/* This is a little bit of a concern but we need to make our own hash64 function
 * as the one from the kernel seems to be buggy by returning a u32:
 * static __always_inline u32 hash_64_generic(u64 val, unsigned int bits)
 */
#if BITS_PER_LONG == 64
static __always_inline __u64 gss_hash_64(__u64 val, unsigned int bits)
{
	__u64 hash = val;
	/*  Sigh, gcc can't optimise this alone like it does for 32 bits. */
	__u64 n = hash;

	n <<= 18;
	hash -= n;
	n <<= 33;
	hash -= n;
	n <<= 3;
	hash += n;
	n <<= 3;
	hash -= n;
	n <<= 4;
	hash += n;
	n <<= 2;
	hash += n;

	/* High bits are more random, so use them. */
	return hash >> (64 - bits);
}

static inline unsigned long hash_mem_64(char *buf, int length, int bits)
{
	unsigned long hash = 0;
	unsigned long l = 0;
	int len = 0;
	unsigned char c;

	do {
		if (len == length) {
			c = (char) len;
			len = -1;
		} else
			c = *buf++;

		l = (l << 8) | c;
		len++;

		if ((len & (BITS_PER_LONG/8-1)) == 0)
			hash = gss_hash_64(hash^l, BITS_PER_LONG);
	} while (len);

	return hash >> (BITS_PER_LONG - bits);
}
#endif /* BITS_PER_LONG == 64 */

/****************************************
 * rpc sec init (rsi) cache		*
 ****************************************/

#define RSI_HASHBITS    (6)
#define RSI_HASHMAX     (1 << RSI_HASHBITS)
#define RSI_HASHMASK    (RSI_HASHMAX - 1)

static void rsi_entry_init(struct upcall_cache_entry *entry,
			   void *args)
{
	struct gss_rsi *rsi = &entry->u.rsi;
	struct gss_rsi *tmp = args;

	rsi->si_uc_entry = entry;
	rawobj_dup(&rsi->si_in_handle, &tmp->si_in_handle);
	rawobj_dup(&rsi->si_in_token, &tmp->si_in_token);
	rsi->si_out_handle = RAWOBJ_EMPTY;
	rsi->si_out_token = RAWOBJ_EMPTY;

	rsi->si_lustre_svc = tmp->si_lustre_svc;
	rsi->si_nid4 = tmp->si_nid4;
	memcpy(rsi->si_nm_name, tmp->si_nm_name, sizeof(tmp->si_nm_name));
}

static void __rsi_free(struct gss_rsi *rsi)
{
	rawobj_free(&rsi->si_in_handle);
	rawobj_free(&rsi->si_in_token);
	rawobj_free(&rsi->si_out_handle);
	rawobj_free(&rsi->si_out_token);
}

static void rsi_entry_free(struct upcall_cache *cache,
			   struct upcall_cache_entry *entry)
{
	struct gss_rsi *rsi = &entry->u.rsi;

	__rsi_free(rsi);
}

static inline int rsi_entry_hash(struct gss_rsi *rsi)
{
#if BITS_PER_LONG == 64
	return hash_mem_64((char *)rsi->si_in_handle.data,
			   rsi->si_in_handle.len, RSI_HASHBITS) ^
		hash_mem_64((char *)rsi->si_in_token.data,
			    rsi->si_in_token.len, RSI_HASHBITS);
#else
	return hash_mem((char *)rsi->si_in_handle.data, rsi->si_in_handle.len,
			RSI_HASHBITS) ^
		hash_mem((char *)rsi->si_in_token.data, rsi->si_in_token.len,
			 RSI_HASHBITS);
#endif
}

static inline int __rsi_entry_match(rawobj_t *h1, rawobj_t *h2,
				    rawobj_t *t1, rawobj_t *t2)
{
	return !(rawobj_equal(h1, h2) && rawobj_equal(t1, t2));
}

static inline int rsi_entry_match(struct gss_rsi *rsi, struct gss_rsi *tmp)
{
	return __rsi_entry_match(&rsi->si_in_handle, &tmp->si_in_handle,
				 &rsi->si_in_token, &tmp->si_in_token);
}

/* Returns 0 to tell this is a match */
static inline int rsi_upcall_compare(struct upcall_cache *cache,
				     struct upcall_cache_entry *entry,
				     __u64 key, void *args)
{
	struct gss_rsi *rsi1 = &entry->u.rsi;
	struct gss_rsi *rsi2 = args;

	return rsi_entry_match(rsi1, rsi2);
}

/* See handle_channel_request() userspace for where the upcall data is read */
static int rsi_do_upcall(struct upcall_cache *cache,
			 struct upcall_cache_entry *entry)
{
	int size, len, *blen;
	char *buffer, *bp, **bpp;
	char *argv[] = {
		[0] = cache->uc_upcall,
		[1] = "-c",
		[2] = cache->uc_name,
		[3] = "-r",
		[4] = NULL,
		[5] = NULL
	};
	char *envp[] = {
		[0] = "HOME=/",
		[1] = "PATH=/sbin:/usr/sbin",
		[2] = NULL
	};
	ktime_t start, end;
	struct gss_rsi *rsi = &entry->u.rsi;
	__u64 index = 0;
	int rc;

	ENTRY;
	CDEBUG(D_SEC, "rsi upcall '%s' on '%s'\n",
	       cache->uc_upcall, cache->uc_name);

	size = 24 + 1 + /* ue_key is uint64_t */
		12 + 1 + /* si_lustre_svc is __u32*/
		18 + 1 + /* si_nid4 is lnet_nid_t, hex with leading 0x */
		18 + 1 + /* index is __u64, hex with leading 0x */
		strlen(rsi->si_nm_name) + 1 +
		BASE64URL_CHARS(rsi->si_in_handle.len) + 1 +
		BASE64URL_CHARS(rsi->si_in_token.len) + 1 +
		1 + 1; /* eol */
	if (size > MAX_ARG_STRLEN)
		RETURN(-E2BIG);
	OBD_ALLOC_LARGE(buffer, size);
	if (!buffer)
		RETURN(-ENOMEM);

	bp = buffer;
	bpp = &bp;
	len = size;
	blen = &len;

	/* if in_handle is null, provide kernel suggestion */
	if (rsi->si_in_handle.len == 0)
		index = gss_get_next_ctx_index();

	/* entry->ue_key is put into args sent via upcall, so that it can be
	 * returned by userspace. This will help find cache entry at downcall,
	 * without unnecessary recomputation of the hash.
	 */
	gss_u64_write_string(bpp, blen, entry->ue_key);
	gss_u64_write_string(bpp, blen, rsi->si_lustre_svc);
	gss_u64_write_hex_string(bpp, blen, rsi->si_nid4);
	gss_u64_write_hex_string(bpp, blen, index);
	gss_string_write(bpp, blen, (char *) rsi->si_nm_name);
	gss_base64url_encode(bpp, blen, rsi->si_in_handle.data,
			     rsi->si_in_handle.len);
	gss_base64url_encode(bpp, blen, rsi->si_in_token.data,
			     rsi->si_in_token.len);
	(*bpp)[-1] = '\n';
	(*bpp)[0] = '\0';

	argv[4] = buffer;
	down_read(&cache->uc_upcall_rwsem);
	start = ktime_get();
	rc = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	end = ktime_get();
	up_read(&cache->uc_upcall_rwsem);
	if (rc < 0) {
		CERROR("%s: error invoking upcall %s %s (time %ldus): rc = %d\n",
		       cache->uc_name, argv[0], argv[2],
		       (long)ktime_us_delta(end, start), rc);
	} else {
		CDEBUG(D_SEC, "%s: invoked upcall %s %s (time %ldus)\n",
		       cache->uc_name, argv[0], argv[2],
		       (long)ktime_us_delta(end, start));
		rc = 0;
	}

	OBD_FREE_LARGE(buffer, size);
	RETURN(rc);
}

static inline int rsi_downcall_compare(struct upcall_cache *cache,
				       struct upcall_cache_entry *entry,
				       __u64 key, void *args)
{
	struct gss_rsi *rsi = &entry->u.rsi;
	struct rsi_downcall_data *sid = args;
	char *mesg = sid->sid_val;
	rawobj_t handle, token;
	char *p = mesg;
	int len;

	/* sid_val starts with handle and token */

	/* First, handle */
	len = gss_buffer_get(&mesg, &handle.len, &handle.data);
	sid->sid_offset = mesg - p;
	p = mesg;

	/* Second, token */
	len = gss_buffer_get(&mesg, &token.len, &token.data);
	sid->sid_offset += mesg - p;

	return __rsi_entry_match(&rsi->si_in_handle, &handle,
				 &rsi->si_in_token, &token);
}

static int rsi_parse_downcall(struct upcall_cache *cache,
			      struct upcall_cache_entry *entry,
			      void *args)
{
	struct gss_rsi *rsi = &entry->u.rsi;
	struct rsi_downcall_data *sid = args;
	int mlen = sid->sid_len;
	char *mesg = sid->sid_val + sid->sid_offset;
	char *buf = sid->sid_val;
	int status = -EINVAL;
	int len;

	ENTRY;

	if (mlen <= 0)
		goto out;

	rsi->si_major_status = sid->sid_maj_stat;
	rsi->si_minor_status = sid->sid_min_stat;

	/* in_handle and in_token have already been consumed in
	 * rsi_downcall_compare(). sid_offset gives next field.
	 */

	/* out_handle */
	len = gss_buffer_read(&mesg, buf, mlen);
	if (len < 0)
		goto out;
	if (rawobj_alloc(&rsi->si_out_handle, buf, len)) {
		status = -ENOMEM;
		goto out;
	}

	/* out_token */
	len = gss_buffer_read(&mesg, buf, mlen);
	if (len < 0)
		goto out;
	if (rawobj_alloc(&rsi->si_out_token, buf, len)) {
		status = -ENOMEM;
		goto out;
	}

	entry->ue_expire = 0;
	status = 0;

out:
	CDEBUG(D_OTHER, "rsi parse %p: %d\n", rsi, status);
	RETURN(status);
}

struct gss_rsi *rsi_entry_get(struct upcall_cache *cache, struct gss_rsi *rsi)
{
	struct upcall_cache_entry *entry;
	int hash = rsi_entry_hash(rsi);

	if (!cache)
		return ERR_PTR(-ENOENT);

	entry = upcall_cache_get_entry(cache, (__u64)hash, rsi);
	if (unlikely(!entry))
		return ERR_PTR(-ENOENT);
	if (IS_ERR(entry))
		return ERR_CAST(entry);

	return &entry->u.rsi;
}

void rsi_entry_put(struct upcall_cache *cache, struct gss_rsi *rsi)
{
	if (!cache || !rsi)
		return;

	upcall_cache_put_entry(cache, rsi->si_uc_entry);
}

void rsi_flush(struct upcall_cache *cache, int hash)
{
	if (hash < 0)
		upcall_cache_flush_idle(cache);
	else
		upcall_cache_flush_one(cache, (__u64)hash, NULL);
}

struct upcall_cache_ops rsi_upcall_cache_ops = {
	.init_entry	  = rsi_entry_init,
	.free_entry	  = rsi_entry_free,
	.upcall_compare	  = rsi_upcall_compare,
	.downcall_compare = rsi_downcall_compare,
	.do_upcall	  = rsi_do_upcall,
	.parse_downcall	  = rsi_parse_downcall,
};

struct upcall_cache *rsicache;

struct rsi {
	struct cache_head       h;
	__u32                   lustre_svc;
	lnet_nid_t		nid4; /* FIXME Support larger NID */
	char			nm_name[LUSTRE_NODEMAP_NAME_LENGTH + 1];
	wait_queue_head_t       waitq;
	rawobj_t                in_handle, in_token;
	rawobj_t                out_handle, out_token;
	int                     major_status, minor_status;
#ifdef HAVE_CACHE_HASH_SPINLOCK
	struct rcu_head		rcu_head;
#endif
};

#ifdef HAVE_CACHE_HEAD_HLIST
static struct hlist_head rsi_table[RSI_HASHMAX];
#else
static struct cache_head *rsi_table[RSI_HASHMAX];
#endif
static struct cache_detail rsi_cache;
static struct rsi *rsi_update(struct rsi *new, struct rsi *old);
static struct rsi *rsi_lookup(struct rsi *item);

#ifdef HAVE_CACHE_DETAIL_WRITERS
static inline int channel_users(struct cache_detail *cd)
{
	return atomic_read(&cd->writers);
}
#else
static inline int channel_users(struct cache_detail *cd)
{
	return atomic_read(&cd->readers);
}
#endif

static inline int rsi_hash(struct rsi *item)
{
        return hash_mem((char *)item->in_handle.data, item->in_handle.len,
                        RSI_HASHBITS) ^
               hash_mem((char *)item->in_token.data, item->in_token.len,
                        RSI_HASHBITS);
}

static inline int __rsi_match(struct rsi *item, struct rsi *tmp)
{
        return (rawobj_equal(&item->in_handle, &tmp->in_handle) &&
                rawobj_equal(&item->in_token, &tmp->in_token));
}

static void rsi_free(struct rsi *rsi)
{
        rawobj_free(&rsi->in_handle);
        rawobj_free(&rsi->in_token);
        rawobj_free(&rsi->out_handle);
        rawobj_free(&rsi->out_token);
}

/* See handle_channel_req() userspace for where the upcall data is read */
static void rsi_request(struct cache_detail *cd,
                        struct cache_head *h,
                        char **bpp, int *blen)
{
	struct rsi *rsi = container_of(h, struct rsi, h);
	__u64 index = 0;

	/* if in_handle is null, provide kernel suggestion */
	if (rsi->in_handle.len == 0)
		index = gss_get_next_ctx_index();

	qword_addhex(bpp, blen, (char *) &rsi->lustre_svc,
			sizeof(rsi->lustre_svc));
	qword_addhex(bpp, blen, (char *) &rsi->nid4, sizeof(rsi->nid4));
	qword_addhex(bpp, blen, (char *) &index, sizeof(index));
	qword_addhex(bpp, blen, (char *) rsi->nm_name,
		     strlen(rsi->nm_name) + 1);
	qword_addhex(bpp, blen, rsi->in_handle.data, rsi->in_handle.len);
	qword_addhex(bpp, blen, rsi->in_token.data, rsi->in_token.len);
	(*bpp)[-1] = '\n';
}

static inline void __rsi_init(struct rsi *new, struct rsi *item)
{
	new->out_handle = RAWOBJ_EMPTY;
	new->out_token = RAWOBJ_EMPTY;

	new->in_handle = item->in_handle;
	item->in_handle = RAWOBJ_EMPTY;
	new->in_token = item->in_token;
	item->in_token = RAWOBJ_EMPTY;

	new->lustre_svc = item->lustre_svc;
	new->nid4 = item->nid4;
	memcpy(new->nm_name, item->nm_name, sizeof(item->nm_name));
	init_waitqueue_head(&new->waitq);
}

static inline void __rsi_update(struct rsi *new, struct rsi *item)
{
        LASSERT(new->out_handle.len == 0);
        LASSERT(new->out_token.len == 0);

        new->out_handle = item->out_handle;
        item->out_handle = RAWOBJ_EMPTY;
        new->out_token = item->out_token;
        item->out_token = RAWOBJ_EMPTY;

        new->major_status = item->major_status;
        new->minor_status = item->minor_status;
}

#ifdef HAVE_CACHE_HASH_SPINLOCK
static void rsi_free_rcu(struct rcu_head *head)
{
	struct rsi *rsi = container_of(head, struct rsi, rcu_head);

#ifdef HAVE_CACHE_HEAD_HLIST
	LASSERT(hlist_unhashed(&rsi->h.cache_list));
#else
	LASSERT(rsi->h.next == NULL);
#endif
	rsi_free(rsi);
	OBD_FREE_PTR(rsi);
}

static void rsi_put(struct kref *ref)
{
	struct rsi *rsi = container_of(ref, struct rsi, h.ref);

	call_rcu(&rsi->rcu_head, rsi_free_rcu);
}
#else /* !HAVE_CACHE_HASH_SPINLOCK */
static void rsi_put(struct kref *ref)
{
	struct rsi *rsi = container_of(ref, struct rsi, h.ref);

#ifdef HAVE_CACHE_HEAD_HLIST
	LASSERT(hlist_unhashed(&rsi->h.cache_list));
#else
	LASSERT(rsi->h.next == NULL);
#endif
	rsi_free(rsi);
	OBD_FREE_PTR(rsi);
}
#endif /* HAVE_CACHE_HASH_SPINLOCK */

static int rsi_match(struct cache_head *a, struct cache_head *b)
{
        struct rsi *item = container_of(a, struct rsi, h);
        struct rsi *tmp = container_of(b, struct rsi, h);

        return __rsi_match(item, tmp);
}

static void rsi_init(struct cache_head *cnew, struct cache_head *citem)
{
        struct rsi *new = container_of(cnew, struct rsi, h);
        struct rsi *item = container_of(citem, struct rsi, h);

        __rsi_init(new, item);
}

static void update_rsi(struct cache_head *cnew, struct cache_head *citem)
{
        struct rsi *new = container_of(cnew, struct rsi, h);
        struct rsi *item = container_of(citem, struct rsi, h);

        __rsi_update(new, item);
}

static struct cache_head *rsi_alloc(void)
{
        struct rsi *rsi;

        OBD_ALLOC_PTR(rsi);
        if (rsi) 
                return &rsi->h;
        else
                return NULL;
}

static int rsi_parse(struct cache_detail *cd, char *mesg, int mlen)
{
	char *buf = mesg;
	int len;
	struct rsi rsii, *rsip = NULL;
	time64_t expiry;
	int status = -EINVAL;
	ENTRY;

	memset(&rsii, 0, sizeof(rsii));

	/* handle */
	len = qword_get(&mesg, buf, mlen);
	if (len < 0)
		goto out;
	if (rawobj_alloc(&rsii.in_handle, buf, len)) {
		status = -ENOMEM;
		goto out;
	}

	/* token */
	len = qword_get(&mesg, buf, mlen);
	if (len < 0)
		goto out;
	if (rawobj_alloc(&rsii.in_token, buf, len)) {
		status = -ENOMEM;
		goto out;
	}

	rsip = rsi_lookup(&rsii);
	if (!rsip)
		goto out;
	if (!test_bit(CACHE_PENDING, &rsip->h.flags)) {
		/* If this is not a pending request, it probably means
		 * someone wrote arbitrary data to the init channel.
		 * Directly return -EINVAL in this case.
		 */
		status = -EINVAL;
		goto out;
	}

	rsii.h.flags = 0;
	/* expiry */
	status = get_expiry(&mesg, &expiry);
	if (status)
		goto out;

	len = qword_get(&mesg, buf, mlen);
	if (len <= 0)
		goto out;

	/* major */
	status = kstrtoint(buf, 10, &rsii.major_status);
	if (status)
		goto out;

	/* minor */
	len = qword_get(&mesg, buf, mlen);
	if (len <= 0) {
		status = -EINVAL;
		goto out;
	}

	status = kstrtoint(buf, 10, &rsii.minor_status);
	if (status)
		goto out;

	/* out_handle */
	len = qword_get(&mesg, buf, mlen);
	if (len < 0)
		goto out;
	if (rawobj_alloc(&rsii.out_handle, buf, len)) {
		status = -ENOMEM;
		goto out;
	}

	/* out_token */
	len = qword_get(&mesg, buf, mlen);
	if (len < 0)
		goto out;
	if (rawobj_alloc(&rsii.out_token, buf, len)) {
		status = -ENOMEM;
		goto out;
	}

	rsii.h.expiry_time = expiry;
	rsip = rsi_update(&rsii, rsip);
	status = 0;
out:
	rsi_free(&rsii);
	if (rsip) {
		wake_up(&rsip->waitq);
		cache_put(&rsip->h, &rsi_cache);
	} else {
		status = -ENOMEM;
	}

	if (status)
		CERROR("rsi parse error %d\n", status);
	RETURN(status);
}

static struct cache_detail rsi_cache = {
	.hash_size	= RSI_HASHMAX,
	.hash_table	= rsi_table,
	.name		= "auth.sptlrpc.init",
	.cache_put	= rsi_put,
	.cache_request	= rsi_request,
	.cache_upcall	= sunrpc_cache_pipe_upcall,
	.cache_parse	= rsi_parse,
	.match		= rsi_match,
	.init		= rsi_init,
	.update		= update_rsi,
	.alloc		= rsi_alloc,
};

static struct rsi *rsi_lookup(struct rsi *item)
{
        struct cache_head *ch;
        int hash = rsi_hash(item);

        ch = sunrpc_cache_lookup(&rsi_cache, &item->h, hash);
        if (ch)
                return container_of(ch, struct rsi, h);
        else
                return NULL;
}

static struct rsi *rsi_update(struct rsi *new, struct rsi *old)
{
        struct cache_head *ch;
        int hash = rsi_hash(new);

        ch = sunrpc_cache_update(&rsi_cache, &new->h, &old->h, hash);
        if (ch)
                return container_of(ch, struct rsi, h);
        else
                return NULL;
}

/****************************************
 * rpc sec context (rsc) cache		*
 ****************************************/

#define RSC_HASHBITS    (10)
#define RSC_HASHMAX     (1 << RSC_HASHBITS)
#define RSC_HASHMASK    (RSC_HASHMAX - 1)

static void rsc_entry_init(struct upcall_cache_entry *entry,
			   void *args)
{
	struct gss_rsc *rsc = &entry->u.rsc;
	struct gss_rsc *tmp = args;

	rsc->sc_uc_entry = entry;
	rawobj_dup(&rsc->sc_handle, &tmp->sc_handle);

	rsc->sc_target = NULL;
	memset(&rsc->sc_ctx, 0, sizeof(rsc->sc_ctx));
	rsc->sc_ctx.gsc_rvs_hdl = RAWOBJ_EMPTY;

	memset(&rsc->sc_ctx.gsc_seqdata, 0, sizeof(rsc->sc_ctx.gsc_seqdata));
	spin_lock_init(&rsc->sc_ctx.gsc_seqdata.ssd_lock);
}

void __rsc_free(struct gss_rsc *rsc)
{
	rawobj_free(&rsc->sc_handle);
	rawobj_free(&rsc->sc_ctx.gsc_rvs_hdl);
	lgss_delete_sec_context(&rsc->sc_ctx.gsc_mechctx);
}

static void rsc_entry_free(struct upcall_cache *cache,
			   struct upcall_cache_entry *entry)
{
	struct gss_rsc *rsc = &entry->u.rsc;

	__rsc_free(rsc);
}

static inline int rsc_entry_hash(struct gss_rsc *rsc)
{
#if BITS_PER_LONG == 64
	return hash_mem_64((char *)rsc->sc_handle.data,
			   rsc->sc_handle.len, RSC_HASHBITS);
#else
	return hash_mem((char *)rsc->sc_handle.data,
			rsc->sc_handle.len, RSC_HASHBITS);
#endif
}

static inline int __rsc_entry_match(rawobj_t *h1, rawobj_t *h2)
{
	return !(rawobj_equal(h1, h2));
}

static inline int rsc_entry_match(struct gss_rsc *rsc, struct gss_rsc *tmp)
{
	return __rsc_entry_match(&rsc->sc_handle, &tmp->sc_handle);
}

/* Returns 0 to tell this is a match */
static inline int rsc_upcall_compare(struct upcall_cache *cache,
				     struct upcall_cache_entry *entry,
				     __u64 key, void *args)
{
	struct gss_rsc *rsc1 = &entry->u.rsc;
	struct gss_rsc *rsc2 = args;

	return rsc_entry_match(rsc1, rsc2);
}

/* rsc upcall is a no-op, we just need a valid entry */
static inline int rsc_do_upcall(struct upcall_cache *cache,
				struct upcall_cache_entry *entry)
{
	upcall_cache_update_entry(cache, entry,
				  ktime_get_seconds() + cache->uc_entry_expire,
				  0);
	return 0;
}

static inline int rsc_downcall_compare(struct upcall_cache *cache,
				       struct upcall_cache_entry *entry,
				       __u64 key, void *args)
{
	struct gss_rsc *rsc = &entry->u.rsc;
	struct rsc_downcall_data *scd = args;
	char *mesg = scd->scd_val;
	rawobj_t handle;
	int len;

	/* scd_val starts with handle */
	len = gss_buffer_get(&mesg, &handle.len, &handle.data);
	scd->scd_offset = mesg - scd->scd_val;

	return __rsc_entry_match(&rsc->sc_handle, &handle);
}

static int rsc_parse_downcall(struct upcall_cache *cache,
			      struct upcall_cache_entry *entry,
			      void *args)
{
	struct gss_api_mech *gm = NULL;
	struct gss_rsc *rsc = &entry->u.rsc;
	struct rsc_downcall_data *scd = args;
	int mlen = scd->scd_len;
	char *mesg = scd->scd_val + scd->scd_offset;
	char *buf = scd->scd_val;
	int status = -EINVAL;
	time64_t ctx_expiry;
	rawobj_t tmp_buf;
	int len;

	ENTRY;

	if (mlen <= 0)
		goto out;

	rsc->sc_ctx.gsc_remote = !!(scd->scd_flags & RSC_DATA_FLAG_REMOTE);
	rsc->sc_ctx.gsc_usr_root = !!(scd->scd_flags & RSC_DATA_FLAG_ROOT);
	rsc->sc_ctx.gsc_usr_mds = !!(scd->scd_flags & RSC_DATA_FLAG_MDS);
	rsc->sc_ctx.gsc_usr_oss = !!(scd->scd_flags & RSC_DATA_FLAG_OSS);
	rsc->sc_ctx.gsc_mapped_uid = scd->scd_mapped_uid;
	rsc->sc_ctx.gsc_uid = scd->scd_uid;

	rsc->sc_ctx.gsc_gid = scd->scd_gid;
	gm = lgss_name_to_mech(scd->scd_mechname);
	if (!gm) {
		status = -EOPNOTSUPP;
		goto out;
	}

	/* handle has already been consumed in rsc_downcall_compare().
	 * scd_offset gives next field.
	 */

	/* context token */
	len = gss_buffer_read(&mesg, buf, mlen);
	if (len < 0)
		goto out;
	tmp_buf.len = len;
	tmp_buf.data = (unsigned char *)buf;
	if (lgss_import_sec_context(&tmp_buf, gm,
				    &rsc->sc_ctx.gsc_mechctx))
		goto out;

	if (lgss_inquire_context(rsc->sc_ctx.gsc_mechctx, &ctx_expiry))
		goto out;

	/* ctx_expiry is the number of seconds since Jan 1 1970.
	 * We just want the number of seconds into the future.
	 */
	entry->ue_expire = ktime_get_seconds() +
		(ctx_expiry - ktime_get_real_seconds());
	status = 0;

out:
	if (gm)
		lgss_mech_put(gm);
	CDEBUG(D_OTHER, "rsc parse %p: %d\n", rsc, status);
	RETURN(status);
}

struct gss_rsc *rsc_entry_get(struct upcall_cache *cache, struct gss_rsc *rsc)
{
	struct upcall_cache_entry *entry;
	int hash = rsc_entry_hash(rsc);

	if (!cache)
		return ERR_PTR(-ENOENT);

	entry = upcall_cache_get_entry(cache, (__u64)hash, rsc);
	if (unlikely(!entry))
		return ERR_PTR(-ENOENT);
	if (IS_ERR(entry))
		return ERR_CAST(entry);

	return &entry->u.rsc;
}

void rsc_entry_put(struct upcall_cache *cache, struct gss_rsc *rsc)
{
	if (!cache || !rsc)
		return;

	upcall_cache_put_entry(cache, rsc->sc_uc_entry);
}

void rsc_flush(struct upcall_cache *cache, int hash)
{
	if (hash < 0)
		upcall_cache_flush_idle(cache);
	else
		upcall_cache_flush_one(cache, (__u64)hash, NULL);
}

struct upcall_cache_ops rsc_upcall_cache_ops = {
	.init_entry	  = rsc_entry_init,
	.free_entry	  = rsc_entry_free,
	.upcall_compare	  = rsc_upcall_compare,
	.downcall_compare = rsc_downcall_compare,
	.do_upcall	  = rsc_do_upcall,
	.parse_downcall	  = rsc_parse_downcall,
};

struct upcall_cache *rsccache;

struct rsc {
        struct cache_head       h;
        struct obd_device      *target;
        rawobj_t                handle;
        struct gss_svc_ctx      ctx;
#ifdef HAVE_CACHE_HASH_SPINLOCK
	struct rcu_head		rcu_head;
#endif
};

#ifdef HAVE_CACHE_HEAD_HLIST
static struct hlist_head rsc_table[RSC_HASHMAX];
#else
static struct cache_head *rsc_table[RSC_HASHMAX];
#endif
static struct cache_detail rsc_cache;
static struct rsc *rsc_update(struct rsc *new, struct rsc *old);
static struct rsc *rsc_lookup(struct rsc *item);

static void rsc_free(struct rsc *rsci)
{
        rawobj_free(&rsci->handle);
        rawobj_free(&rsci->ctx.gsc_rvs_hdl);
        lgss_delete_sec_context(&rsci->ctx.gsc_mechctx);
}

static inline int rsc_hash(struct rsc *rsci)
{
        return hash_mem((char *)rsci->handle.data,
                        rsci->handle.len, RSC_HASHBITS);
}

static inline int __rsc_match(struct rsc *new, struct rsc *tmp)
{
        return rawobj_equal(&new->handle, &tmp->handle);
}

static inline void __rsc_init(struct rsc *new, struct rsc *tmp)
{
        new->handle = tmp->handle;
        tmp->handle = RAWOBJ_EMPTY;

        new->target = NULL;
        memset(&new->ctx, 0, sizeof(new->ctx));
        new->ctx.gsc_rvs_hdl = RAWOBJ_EMPTY;
}

static inline void __rsc_update(struct rsc *new, struct rsc *tmp)
{
	new->ctx = tmp->ctx;
	memset(&tmp->ctx, 0, sizeof(tmp->ctx));
	tmp->ctx.gsc_rvs_hdl = RAWOBJ_EMPTY;
	tmp->ctx.gsc_mechctx = NULL;
	tmp->target = NULL;

	memset(&new->ctx.gsc_seqdata, 0, sizeof(new->ctx.gsc_seqdata));
	spin_lock_init(&new->ctx.gsc_seqdata.ssd_lock);
}

#ifdef HAVE_CACHE_HASH_SPINLOCK
static void rsc_free_rcu(struct rcu_head *head)
{
	struct rsc *rsci = container_of(head, struct rsc, rcu_head);

#ifdef HAVE_CACHE_HEAD_HLIST
	LASSERT(hlist_unhashed(&rsci->h.cache_list));
#else
	LASSERT(rsci->h.next == NULL);
#endif
	rawobj_free(&rsci->handle);
	OBD_FREE_PTR(rsci);
}

static void rsc_put(struct kref *ref)
{
	struct rsc *rsci = container_of(ref, struct rsc, h.ref);

	rawobj_free(&rsci->ctx.gsc_rvs_hdl);
	lgss_delete_sec_context(&rsci->ctx.gsc_mechctx);
	call_rcu(&rsci->rcu_head, rsc_free_rcu);
}
#else /* !HAVE_CACHE_HASH_SPINLOCK */
static void rsc_put(struct kref *ref)
{
	struct rsc *rsci = container_of(ref, struct rsc, h.ref);

#ifdef HAVE_CACHE_HEAD_HLIST
	LASSERT(hlist_unhashed(&rsci->h.cache_list));
#else
	LASSERT(rsci->h.next == NULL);
#endif
	rsc_free(rsci);
	OBD_FREE_PTR(rsci);
}
#endif /* HAVE_CACHE_HASH_SPINLOCK */

static int rsc_match(struct cache_head *a, struct cache_head *b)
{
        struct rsc *new = container_of(a, struct rsc, h);
        struct rsc *tmp = container_of(b, struct rsc, h);

        return __rsc_match(new, tmp);
}

static void rsc_init(struct cache_head *cnew, struct cache_head *ctmp)
{
        struct rsc *new = container_of(cnew, struct rsc, h);
        struct rsc *tmp = container_of(ctmp, struct rsc, h);

        __rsc_init(new, tmp);
}

static void update_rsc(struct cache_head *cnew, struct cache_head *ctmp)
{
        struct rsc *new = container_of(cnew, struct rsc, h);
        struct rsc *tmp = container_of(ctmp, struct rsc, h);

        __rsc_update(new, tmp);
}

static struct cache_head * rsc_alloc(void)
{
        struct rsc *rsc;

        OBD_ALLOC_PTR(rsc);
        if (rsc)
                return &rsc->h;
        else
                return NULL;
}

static int rsc_parse(struct cache_detail *cd, char *mesg, int mlen)
{
	char *buf = mesg;
	int len, rv, tmp_int;
	struct rsc rsci, *rscp = NULL;
	time64_t expiry;
	int status = -EINVAL;
	struct gss_api_mech *gm = NULL;

	memset(&rsci, 0, sizeof(rsci));

	/* context handle */
	len = qword_get(&mesg, buf, mlen);
	if (len < 0)
		goto out;

	status = -ENOMEM;
	if (rawobj_alloc(&rsci.handle, buf, len))
		goto out;

	rsci.h.flags = 0;
	/* expiry */
	status = get_expiry(&mesg, &expiry);
	if (status)
		goto out;

	status = -EINVAL;
	/* remote flag */
	rv = get_int(&mesg, &tmp_int);
	if (rv) {
		CERROR("fail to get remote flag\n");
		goto out;
	}
	rsci.ctx.gsc_remote = (tmp_int != 0);

	/* root user flag */
	rv = get_int(&mesg, &tmp_int);
	if (rv) {
		CERROR("fail to get root user flag\n");
		goto out;
	}
	rsci.ctx.gsc_usr_root = (tmp_int != 0);

	/* mds user flag */
	rv = get_int(&mesg, &tmp_int);
	if (rv) {
		CERROR("fail to get mds user flag\n");
		goto out;
	}
	rsci.ctx.gsc_usr_mds = (tmp_int != 0);

	/* oss user flag */
	rv = get_int(&mesg, &tmp_int);
	if (rv) {
		CERROR("fail to get oss user flag\n");
		goto out;
	}
	rsci.ctx.gsc_usr_oss = (tmp_int != 0);

	/* mapped uid */
	rv = get_int(&mesg, (int *) &rsci.ctx.gsc_mapped_uid);
	if (rv) {
		CERROR("fail to get mapped uid\n");
		goto out;
	}

	rscp = rsc_lookup(&rsci);
	if (!rscp)
		goto out;

	/* uid, or NEGATIVE */
	rv = get_int(&mesg, (int *) &rsci.ctx.gsc_uid);
	if (rv == -EINVAL)
		goto out;
	if (rv == -ENOENT) {
		CERROR("NOENT? set rsc entry negative\n");
		set_bit(CACHE_NEGATIVE, &rsci.h.flags);
	} else {
		rawobj_t tmp_buf;
		time64_t ctx_expiry;

		/* gid */
		if (get_int(&mesg, (int *) &rsci.ctx.gsc_gid))
			goto out;

		/* mech name */
		len = qword_get(&mesg, buf, mlen);
		if (len < 0)
			goto out;
		gm = lgss_name_to_mech(buf);
		status = -EOPNOTSUPP;
		if (!gm)
			goto out;

		status = -EINVAL;
		/* mech-specific data: */
		len = qword_get(&mesg, buf, mlen);
		if (len < 0)
			goto out;

		tmp_buf.len = len;
		tmp_buf.data = (unsigned char *)buf;
		if (lgss_import_sec_context(&tmp_buf, gm,
					    &rsci.ctx.gsc_mechctx))
			goto out;

		/* set to seconds since machine booted */
		expiry = ktime_get_seconds();

		/* currently the expiry time passed down from user-space
		 * is invalid, here we retrive it from mech.
		 */
		if (lgss_inquire_context(rsci.ctx.gsc_mechctx, &ctx_expiry)) {
			CERROR("unable to get expire time, drop it\n");
			goto out;
		}

		/* ctx_expiry is the number of seconds since Jan 1 1970.
		 * We want just the  number of seconds into the future.
		 */
		expiry += ctx_expiry - ktime_get_real_seconds();
	}

	rsci.h.expiry_time = expiry;
	rscp = rsc_update(&rsci, rscp);
	status = 0;
out:
	if (gm)
		lgss_mech_put(gm);
	rsc_free(&rsci);
	if (rscp)
		cache_put(&rscp->h, &rsc_cache);
	else
		status = -ENOMEM;

	if (status)
		CERROR("parse rsc error %d\n", status);
	return status;
}

static struct cache_detail rsc_cache = {
        .hash_size      = RSC_HASHMAX,
        .hash_table     = rsc_table,
        .name           = "auth.sptlrpc.context",
        .cache_put      = rsc_put,
        .cache_parse    = rsc_parse,
        .match          = rsc_match,
        .init           = rsc_init,
        .update         = update_rsc,
        .alloc          = rsc_alloc,
};

static struct rsc *rsc_lookup(struct rsc *item)
{
        struct cache_head *ch;
        int                hash = rsc_hash(item);

        ch = sunrpc_cache_lookup(&rsc_cache, &item->h, hash);
        if (ch)
                return container_of(ch, struct rsc, h);
        else
                return NULL;
}

static struct rsc *rsc_update(struct rsc *new, struct rsc *old)
{
        struct cache_head *ch;
        int                hash = rsc_hash(new);

        ch = sunrpc_cache_update(&rsc_cache, &new->h, &old->h, hash);
        if (ch)
                return container_of(ch, struct rsc, h);
        else
                return NULL;
}

#define COMPAT_RSC_PUT(item, cd)        cache_put((item), (cd))

/****************************************
 * rsc cache flush                      *
 ****************************************/

static struct gss_rsc *gss_svc_searchbyctx(rawobj_t *handle)
{
	struct gss_rsc rsc;
	struct gss_rsc *found;

	memset(&rsc, 0, sizeof(rsc));
	if (rawobj_dup(&rsc.sc_handle, handle))
		return NULL;

	found = rsc_entry_get(rsccache, &rsc);
	__rsc_free(&rsc);
	if (IS_ERR_OR_NULL(found))
		return found;
	if (!found->sc_ctx.gsc_mechctx) {
		rsc_entry_put(rsccache, found);
		return ERR_PTR(-ENOENT);
	}
	return found;
}

int gss_svc_upcall_install_rvs_ctx(struct obd_import *imp,
				   struct gss_sec *gsec,
				   struct gss_cli_ctx *gctx)
{
	struct gss_rsc rsc, *rscp = NULL;
	time64_t ctx_expiry;
	__u32 major;
	int rc;

	ENTRY;
	memset(&rsc, 0, sizeof(rsc));

	if (!imp || !imp->imp_obd) {
		CERROR("invalid imp, drop\n");
		RETURN(-EPROTO);
	}

	if (rawobj_alloc(&rsc.sc_handle, (char *)&gsec->gs_rvs_hdl,
			 sizeof(gsec->gs_rvs_hdl)))
		GOTO(out, rc = -ENOMEM);

	rscp = rsc_entry_get(rsccache, &rsc);
	__rsc_free(&rsc);
	if (IS_ERR_OR_NULL(rscp))
		GOTO(out, rc = -ENOMEM);

	major = lgss_copy_reverse_context(gctx->gc_mechctx,
					  &rscp->sc_ctx.gsc_mechctx);
	if (major != GSS_S_COMPLETE)
		GOTO(out, rc = -ENOMEM);

	if (lgss_inquire_context(rscp->sc_ctx.gsc_mechctx, &ctx_expiry)) {
		CERROR("%s: unable to get expire time, drop\n",
		       imp->imp_obd->obd_name);
		GOTO(out, rc = -EINVAL);
	}
	rscp->sc_uc_entry->ue_expire = ktime_get_seconds() +
		(ctx_expiry - ktime_get_real_seconds());

	switch (imp->imp_obd->u.cli.cl_sp_to) {
	case LUSTRE_SP_MDT:
		rscp->sc_ctx.gsc_usr_mds = 1;
		break;
	case LUSTRE_SP_OST:
		rscp->sc_ctx.gsc_usr_oss = 1;
		break;
	case LUSTRE_SP_CLI:
		rscp->sc_ctx.gsc_usr_root = 1;
		break;
	case LUSTRE_SP_MGS:
		/* by convention, all 3 set to 1 means MGS */
		rscp->sc_ctx.gsc_usr_mds = 1;
		rscp->sc_ctx.gsc_usr_oss = 1;
		rscp->sc_ctx.gsc_usr_root = 1;
		break;
	default:
		break;
	}

	rscp->sc_target = imp->imp_obd;
	rawobj_dup(&gctx->gc_svc_handle, &rscp->sc_handle);

	CDEBUG(D_SEC, "%s: create reverse svc ctx %p to %s: idx %#llx\n",
	       imp->imp_obd->obd_name, &rscp->sc_ctx, obd2cli_tgt(imp->imp_obd),
	       gsec->gs_rvs_hdl);
	rc = 0;
out:
	if (!IS_ERR_OR_NULL(rscp))
		rsc_entry_put(rsccache, rscp);
	if (rc)
		CERROR("%s: can't create reverse svc ctx idx %#llx: rc = %d\n",
		       imp->imp_obd->obd_name, gsec->gs_rvs_hdl, rc);
	RETURN(rc);
}

int gss_svc_upcall_expire_rvs_ctx(rawobj_t *handle)
{
	const time64_t expire = 20;
	struct gss_rsc *rscp;

	rscp = gss_svc_searchbyctx(handle);
	if (!IS_ERR_OR_NULL(rscp)) {
		CDEBUG(D_SEC,
		       "reverse svcctx %p (rsc %p) expire in %lld seconds\n",
		       &rscp->sc_ctx, rscp, expire);

		rscp->sc_uc_entry->ue_expire = ktime_get_seconds() + expire;
		rsc_entry_put(rsccache, rscp);
	}
	return 0;
}

int gss_svc_upcall_dup_handle(rawobj_t *handle, struct gss_svc_ctx *ctx)
{
	struct gss_rsc *rscp = container_of(ctx, struct gss_rsc, sc_ctx);

	return rawobj_dup(handle, &rscp->sc_handle);
}

int gss_svc_upcall_update_sequence(rawobj_t *handle, __u32 seq)
{
	struct gss_rsc *rscp;

	rscp = gss_svc_searchbyctx(handle);
	if (!IS_ERR_OR_NULL(rscp)) {
		CDEBUG(D_SEC, "reverse svcctx %p (rsc %p) update seq to %u\n",
		       &rscp->sc_ctx, rscp, seq + 1);

		rscp->sc_ctx.gsc_rvs_seq = seq + 1;
		rsc_entry_put(rsccache, rscp);
	}
	return 0;
}

int gss_svc_upcall_handle_init(struct ptlrpc_request *req,
			       struct gss_svc_reqctx *grctx,
			       struct gss_wire_ctx *gw,
			       struct obd_device *target,
			       __u32 lustre_svc,
			       rawobj_t *rvs_hdl,
			       rawobj_t *in_token)
{
	struct gss_rsi rsi = { 0 }, *rsip = NULL;
	struct ptlrpc_reply_state *rs;
	struct gss_rsc *rscp = NULL;
	int replen = sizeof(struct ptlrpc_body);
	struct gss_rep_header *rephdr;
	int rc, rc2;

	ENTRY;

	rsi.si_lustre_svc = lustre_svc;
	/* In case of MR, rq_peer is not the NID from which request is received,
	 * but primary NID of peer.
	 * So we need LNetPrimaryNID(rq_source) to match what the clients uses.
	 */
	LNetPrimaryNID(&req->rq_source.nid);
	rsi.si_nid4 = lnet_nid_to_nid4(&req->rq_source.nid);
	nodemap_test_nid(lnet_nid_to_nid4(&req->rq_peer.nid), rsi.si_nm_name,
			 sizeof(rsi.si_nm_name));

	/* Note that context handle is always 0 for for INIT. */
	rc2 = rawobj_dup(&rsi.si_in_handle, &gw->gw_handle);
	if (rc2) {
		CERROR("%s: failed to duplicate context handle: rc = %d\n",
		       target->obd_name, rc2);
		GOTO(out, rc = SECSVC_DROP);
	}

	rc2 = rawobj_dup(&rsi.si_in_token, in_token);
	if (rc2) {
		CERROR("%s: failed to duplicate token: rc = %d\n",
		       target->obd_name, rc2);
		rawobj_free(&rsi.si_in_handle);
		GOTO(out, rc = SECSVC_DROP);
	}

	rsip = rsi_entry_get(rsicache, &rsi);
	__rsi_free(&rsi);
	if (IS_ERR_OR_NULL(rsip)) {
		if (IS_ERR(rsip))
			rc2 = PTR_ERR(rsip);
		else
			rc2 = -EINVAL;
		CERROR("%s: failed to get entry from rsi cache (nid %s): rc = %d\n",
		       target->obd_name,
		       libcfs_nid2str(lnet_nid_to_nid4(&req->rq_source.nid)),
		       rc2);

		if (!gss_pack_err_notify(req, GSS_S_FAILURE, 0))
			rc = SECSVC_COMPLETE;
		else
			rc = SECSVC_DROP;

		GOTO(out, rc);
	}

	rscp = gss_svc_searchbyctx(&rsip->si_out_handle);
	if (IS_ERR_OR_NULL(rscp)) {
		/* gss mechanism returned major and minor code so we return
		 * those in error message */

		if (!gss_pack_err_notify(req, rsip->si_major_status,
					 rsip->si_minor_status))
			rc = SECSVC_COMPLETE;
		else
			rc = SECSVC_DROP;

		CERROR("%s: authentication failed: rc = %d\n",
		       target->obd_name, rc);
		GOTO(out, rc);
	} else {
		/* we need to take an extra ref on the cache entry,
		 * as a pointer to sc_ctx is stored in grctx
		 */
		upcall_cache_get_entry_raw(rscp->sc_uc_entry);
		grctx->src_ctx = &rscp->sc_ctx;
	}

	if (gw->gw_flags & LUSTRE_GSS_PACK_KCSUM) {
		grctx->src_ctx->gsc_mechctx->hash_func = gss_digest_hash;
	} else if (!strcmp(grctx->src_ctx->gsc_mechctx->mech_type->gm_name,
			   "krb5") &&
		   !krb5_allow_old_client_csum) {
		CWARN("%s: deny connection from '%s' due to missing 'krb_csum' feature, set 'sptlrpc.gss.krb5_allow_old_client_csum=1' to allow, but recommend client upgrade: rc = %d\n",
		      target->obd_name, libcfs_nidstr(&req->rq_peer.nid),
		      -EPROTO);
		GOTO(out, rc = SECSVC_DROP);
	} else {
		grctx->src_ctx->gsc_mechctx->hash_func =
			gss_digest_hash_compat;
	}

	if (rawobj_dup(&rscp->sc_ctx.gsc_rvs_hdl, rvs_hdl)) {
		CERROR("%s: failed duplicate reverse handle\n",
		       target->obd_name);
		GOTO(out, rc = SECSVC_DROP);
	}

	rscp->sc_target = target;

	CDEBUG(D_SEC, "%s: server create rsc %p(%u->%s)\n",
	       target->obd_name, rscp, rscp->sc_ctx.gsc_uid,
	       libcfs_nidstr(&req->rq_peer.nid));

	if (rsip->si_out_handle.len > PTLRPC_GSS_MAX_HANDLE_SIZE) {
		CERROR("%s: handle size %u too large\n",
		       target->obd_name, rsip->si_out_handle.len);
		GOTO(out, rc = SECSVC_DROP);
	}

	grctx->src_init = 1;
	grctx->src_reserve_len = round_up(rsip->si_out_token.len, 4);

	rc = lustre_pack_reply_v2(req, 1, &replen, NULL, 0);
	if (rc) {
		CERROR("%s: failed to pack reply: rc = %d\n",
		       target->obd_name, rc);
		GOTO(out, rc = SECSVC_DROP);
	}

	rs = req->rq_reply_state;
	LASSERT(rs->rs_repbuf->lm_bufcount == 3);
	LASSERT(rs->rs_repbuf->lm_buflens[0] >=
		sizeof(*rephdr) + rsip->si_out_handle.len);
	LASSERT(rs->rs_repbuf->lm_buflens[2] >= rsip->si_out_token.len);

	rephdr = lustre_msg_buf(rs->rs_repbuf, 0, 0);
	rephdr->gh_version = PTLRPC_GSS_VERSION;
	rephdr->gh_flags = 0;
	rephdr->gh_proc = PTLRPC_GSS_PROC_ERR;
	rephdr->gh_major = rsip->si_major_status;
	rephdr->gh_minor = rsip->si_minor_status;
	rephdr->gh_seqwin = GSS_SEQ_WIN;
	rephdr->gh_handle.len = rsip->si_out_handle.len;
	memcpy(rephdr->gh_handle.data, rsip->si_out_handle.data,
	       rsip->si_out_handle.len);

	memcpy(lustre_msg_buf(rs->rs_repbuf, 2, 0), rsip->si_out_token.data,
	       rsip->si_out_token.len);

	rs->rs_repdata_len = lustre_shrink_msg(rs->rs_repbuf, 2,
					       rsip->si_out_token.len, 0);

	rc = SECSVC_OK;

out:
	if (!IS_ERR_OR_NULL(rsip))
		rsi_entry_put(rsicache, rsip);
	if (!IS_ERR_OR_NULL(rscp)) {
		/* if anything went wrong, we don't keep the context too */
		if (rc != SECSVC_OK)
			UC_CACHE_SET_INVALID(rscp->sc_uc_entry);
		else
			CDEBUG(D_SEC, "%s: create rsc with idx %#llx\n",
			       target->obd_name,
			       gss_handle_to_u64(&rscp->sc_handle));

		rsc_entry_put(rsccache, rscp);
	}
	RETURN(rc);
}

struct gss_svc_ctx *gss_svc_upcall_get_ctx(struct ptlrpc_request *req,
					   struct gss_wire_ctx *gw)
{
	struct gss_rsc *rscp;

	rscp = gss_svc_searchbyctx(&gw->gw_handle);
	if (IS_ERR_OR_NULL(rscp)) {
		CWARN("Invalid gss ctx idx %#llx from %s\n",
		      gss_handle_to_u64(&gw->gw_handle),
		      libcfs_nidstr(&req->rq_peer.nid));
		return NULL;
	}

	return &rscp->sc_ctx;
}

void gss_svc_upcall_put_ctx(struct gss_svc_ctx *ctx)
{
	struct gss_rsc *rscp = container_of(ctx, struct gss_rsc, sc_ctx);

	rsc_entry_put(rsccache, rscp);
}

void gss_svc_upcall_destroy_ctx(struct gss_svc_ctx *ctx)
{
	struct gss_rsc *rscp = container_of(ctx, struct gss_rsc, sc_ctx);

	UC_CACHE_SET_INVALID(rscp->sc_uc_entry);
	rscp->sc_uc_entry->ue_expire = 1;
}

/* Wait for userspace daemon to open socket, approx 1.5 s.
 * If socket is not open, upcall requests might fail.
 */
static int check_gssd_socket(void)
{
	struct sockaddr_un *sun;
	struct socket *sock;
	int tries = 0;
	int err;

#ifdef HAVE_SOCK_CREATE_KERN_USE_NET
	err = sock_create_kern(current->nsproxy->net_ns,
			       AF_UNIX, SOCK_STREAM, 0, &sock);
#else
	err = sock_create_kern(AF_UNIX, SOCK_STREAM, 0, &sock);
#endif
	if (err < 0) {
		CDEBUG(D_SEC, "Failed to create socket: %d\n", err);
		return err;
	}

	OBD_ALLOC(sun, sizeof(*sun));
	if (!sun) {
		sock_release(sock);
		return -ENOMEM;
	}
	memset(sun, 0, sizeof(*sun));
	sun->sun_family = AF_UNIX;
	strncpy(sun->sun_path, GSS_SOCKET_PATH, sizeof(sun->sun_path));

	/* Try to connect to the socket */
	while (tries++ < 6) {
		err = kernel_connect(sock, (struct sockaddr *)sun,
				     sizeof(*sun), 0);
		if (!err)
			break;
		schedule_timeout_uninterruptible(cfs_time_seconds(1) / 4);
	}
	if (err < 0)
		CDEBUG(D_SEC, "Failed to connect to socket: %d\n", err);
	else
		kernel_sock_shutdown(sock, SHUT_RDWR);

	sock_release(sock);
	OBD_FREE(sun, sizeof(*sun));
	return err;
}

int __init gss_init_svc_upcall(void)
{
	int rc;

	/*
	 * this helps reducing context index confliction. after server reboot,
	 * conflicting request from clients might be filtered out by initial
	 * sequence number checking, thus no chance to sent error notification
	 * back to clients.
	 */
	get_random_bytes(&__ctx_index, sizeof(__ctx_index));

#ifdef HAVE_CACHE_HEAD_HLIST
	for (rc = 0; rc < rsi_cache.hash_size; rc++)
		INIT_HLIST_HEAD(&rsi_cache.hash_table[rc]);
#endif
	rc = cache_register_net(&rsi_cache, &init_net);
	if (rc != 0)
		return rc;

#ifdef HAVE_CACHE_HEAD_HLIST
	for (rc = 0; rc < rsc_cache.hash_size; rc++)
		INIT_HLIST_HEAD(&rsc_cache.hash_table[rc]);
#endif
	rc = cache_register_net(&rsc_cache, &init_net);
	if (rc != 0) {
		cache_unregister_net(&rsi_cache, &init_net);
		return rc;
	}

	rsicache = upcall_cache_init(RSI_CACHE_NAME, RSI_UPCALL_PATH,
				     UC_RSICACHE_HASH_SIZE,
				     3600, /* entry expire: 1 h */
				     30, /* acquire expire: 30 s */
				     false, /* can't replay acquire */
				     &rsi_upcall_cache_ops);
	if (IS_ERR(rsicache)) {
		rc = PTR_ERR(rsicache);
		rsicache = NULL;
		return rc;
	}
	rsccache = upcall_cache_init(RSC_CACHE_NAME, RSC_UPCALL_PATH,
				     UC_RSCCACHE_HASH_SIZE,
				     3600, /* replaced with one from mech */
				     100, /* arbitrary, not used */
				     false, /* can't replay acquire */
				     &rsc_upcall_cache_ops);
	if (IS_ERR(rsccache)) {
		upcall_cache_cleanup(rsicache);
		rsicache = NULL;
		rc = PTR_ERR(rsccache);
		rsccache = NULL;
		return rc;
	}

	if (check_gssd_socket())
		CDEBUG(D_SEC,
		       "Init channel not opened by lsvcgssd, GSS might not work on server side until daemon is active\n");

	return 0;
}

void gss_exit_svc_upcall(void)
{
	cache_purge(&rsi_cache);
	cache_unregister_net(&rsi_cache, &init_net);

	cache_purge(&rsc_cache);
	cache_unregister_net(&rsc_cache, &init_net);

	upcall_cache_cleanup(rsicache);
	upcall_cache_cleanup(rsccache);
}
