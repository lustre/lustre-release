/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc. <info@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * GS data structures.
 * See also lustre_idl.h for wire formats of requests.
 *
 */

#ifndef _LUSTRE_GS_H
#define _LUSTRE_GS_H

#define LUSTRE_GKS_NAME "gks"
#define LUSTRE_GKT_NAME "gkt"
#define LUSTRE_GKC_NAME "gkc"


/*define gsk type*/
#define NO_CRYPTO 0
#define GKS_TYPE  1
#define MKS_TYPE  2  

struct crypto_ops_item {
        struct crypto_helper_ops *cops;
        struct list_head clist;
        char   *ctype;
};

#define DECRYPT_DATA      0x00000001
#define ENCRYPT_DATA      0x00000002
struct lustre_key {
        struct crypto_key   lk_ck;
        atomic_t            lk_refcount;
        __u32               lk_key_type;
        __u32               lk_flags; 
};
 
static inline struct lustre_key *
lustre_key_get(struct lustre_key *lkey)
{
        if (lkey) { 
                atomic_inc(&lkey->lk_refcount);
        }
        return lkey;
}


static inline void
lustre_key_release(struct lustre_key *lkey)
{
        if (lkey && atomic_dec_and_test(&lkey->lk_refcount))
                kfree(lkey);
}

#define SET_CRYPTO_FLAGS(flags, type, offset, width)           \
do {                                                           \
        flags &= ~(((1 << width) - 1) << offset);              \
        flags |= (type & ((1 << width) - 1)) << offset;        \
} while(0)

#define CPT_TYPE_OFFSET 0
#define CPT_TYPE_WIDTH  2 
#define GKS_CRYPTO_TYPE 1
#define MKS_CRYPTO_TYPE 2

#define SET_CRYPTO_TYPE(flags, type)                           \
SET_CRYPTO_FLAGS(flags, type, CPT_TYPE_OFFSET, CPT_TYPE_WIDTH)

#define IS_GKS_TYPE(flags)                                      \
(((flags >> CPT_TYPE_OFFSET) & ((1 << CPT_TYPE_WIDTH) - 1)) == GKS_CRYPTO_TYPE)

#define IS_MKS_TYPE(flags)                                      \
(((flags >> CPT_TYPE_OFFSET) & ((1 << CPT_TYPE_WIDTH) - 1)) == MKS_CRYPTO_TYPE)

#define CPT_ENCRYPT_OFFSET 2 
#define CPT_ENCRYPT_WIDTH  1 
#define ENABLE_ENCRYPT_FLAG 1
#define DISABLE_ENCRYPT_FLAG 0 

#define ENABLE_ENCRYPT(flag) \
SET_CRYPTO_FLAGS(flag, ENABLE_ENCRYPT_FLAG, CPT_ENCRYPT_OFFSET, CPT_ENCRYPT_WIDTH)

#define DISABLE_ENCRYPT(flag) \
SET_CRYPTO_FLAGS(flag, DISABLE_ENCRYPT_FLAG, CPT_ENCRYPT_OFFSET, CPT_ENCRYPT_WIDTH)

#define IS_ENABLE_ENCRYPT(flags)                                 \
(((flags >> CPT_ENCRYPT_OFFSET) & ((1 << CPT_ENCRYPT_WIDTH) - 1)) \
                                == ENABLE_ENCRYPT_FLAG)

#define CPT_DECRYPT_OFFSET 3 
#define CPT_DECRYPT_WIDTH  1 
#define ENABLE_DECRYPT_FLAG 1
#define DISABLE_DECRYPT_FLAG 2

#define ENABLE_DECRYPT(flag) \
SET_CRYPTO_FLAGS(flag, ENABLE_DECRYPT_FLAG, CPT_DECRYPT_OFFSET, CPT_DECRYPT_WIDTH)

#define DISABLE_DECRYPT(flag) \
SET_CRYPTO_FLAGS(flag, DISABLE_DECRYPT_FLAG, CPT_DECRYPT_OFFSET, CPT_DECRYPT_WIDTH)

#define IS_ENABLE_DECRYPT(flags)                                 \
(((flags >> CPT_DECRYPT_OFFSET) & ((1 << CPT_DECRYPT_WIDTH) - 1)) \
                                == ENABLE_DECRYPT_FLAG)

#define CPT_DECRYPTED_OFFSET 4 
#define CPT_DECRYPTED_WIDTH  1 
#define DECRYPTED_FLAG 1
#define ENCRYPTED_FLAG 0 

#define SET_DECRYPTED(flag) \
SET_CRYPTO_FLAGS(flag, DECRYPTED_FLAG, CPT_DECRYPTED_OFFSET, CPT_DECRYPTED_WIDTH)

#define SET_UNDECRYPTED(flag) \
SET_CRYPTO_FLAGS(flag, ENCRYPTED_FLAG, CPT_DECRYPTED_OFFSET, CPT_DECRYPTED_WIDTH)

#define IS_DECRYPTED(flags) \
(((flags >> CPT_DECRYPTED_OFFSET) & ((1 << CPT_DECRYPTED_WIDTH) - 1)) \
                                == DECRYPTED_FLAG)



#define MD_KEY_MAGIC 0x19760218
struct crypto_key_md {
        struct crypto_key md_ck;
        __u32             md_magic;
};

struct key_parms {
        struct key_context *context;
        struct key_perm    *perm; 
        int                 context_size;
        int                 perm_size;
};

static inline int crypto_kcontext_size(int acl_count) 
{
       return (sizeof(struct key_context) + acl_count * 
               sizeof(struct posix_acl_entry));
}
static inline int crypto_kperm_size(int acl_count)
{
        return (sizeof(struct key_perm) + acl_count * 
                       sizeof(struct posix_acl_entry));
}
#endif /*LUSTRE_GS_H*/
