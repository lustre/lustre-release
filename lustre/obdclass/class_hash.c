/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2005 Cluster File Systems, Inc.
 *   Author: YuZhangyong <yzy@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org/
 *
 *   No redistribution or use is permitted outside of Cluster File Systems, Inc.
 *
 *   Implement a hash class for hash process in lustre system.
 */

#ifndef __KERNEL__
#include <liblustre.h>
#include <obd.h>
#endif

#include <obd_class.h>
#include <class_hash.h>
#include <lustre_export.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <lustre_quota.h>

int lustre_hash_init(struct lustre_class_hash_body **hash_body_new,
                     char *hashname, __u32 hashsize,
                     struct lustre_hash_operations *hash_operations)
{
        int i, n = 0;
        struct lustre_class_hash_body *hash_body = NULL;

        LASSERT(hashsize > 0);
        LASSERT(hash_operations != NULL);
        ENTRY;

        i = hashsize;
        while (i != 0) {
                if (i & 0x1)
                        n++;
                i >>= 1;
        }

        LASSERTF(n == 1, "hashsize %u isn't 2^n\n", hashsize);

        /* alloc space for hash_body */
        OBD_ALLOC(hash_body, sizeof(*hash_body));

        if (hash_body == NULL) {
                CERROR("Cannot alloc space for hash body, hashname = %s \n",
                        hashname);
                RETURN(-ENOMEM);
        }

        LASSERT(hashname != NULL &&
                strlen(hashname) <= sizeof(hash_body->hashname));
        strcpy(hash_body->hashname, hashname);
        hash_body->lchb_hash_max_size = hashsize;
        hash_body->lchb_hash_operations = hash_operations;

        /* alloc space for the hash tables */
        OBD_ALLOC(hash_body->lchb_hash_tables,
                  sizeof(*hash_body->lchb_hash_tables) * hash_body->lchb_hash_max_size);

        if (hash_body->lchb_hash_tables == NULL) {
                OBD_FREE(hash_body, sizeof(*hash_body));
                CERROR("Cannot alloc space for hashtables, hashname = %s \n",
                        hash_body->hashname);
                RETURN(-ENOMEM);
        }

        spin_lock_init(&hash_body->lchb_lock); /* initialize the body lock */

        for(i = 0 ; i < hash_body->lchb_hash_max_size; i++) {
                /* initial the bucket lock and list_head */
                INIT_HLIST_HEAD(&hash_body->lchb_hash_tables[i].lhb_head);
                spin_lock_init(&hash_body->lchb_hash_tables[i].lhb_lock);
        }
        *hash_body_new = hash_body;

        RETURN(0);
}
EXPORT_SYMBOL(lustre_hash_init);

void lustre_hash_exit(struct lustre_class_hash_body **new_hash_body)
{
        int i;
        struct lustre_class_hash_body *hash_body = NULL;
        ENTRY;

        hash_body = *new_hash_body;

        if (hash_body == NULL) {
                CWARN("hash body has been deleted\n");
                goto out_hash;
        }

        spin_lock(&hash_body->lchb_lock); /* lock the hash tables */

        if (hash_body->lchb_hash_tables == NULL ) {
                spin_unlock(&hash_body->lchb_lock);
                CWARN("hash tables has been deleted\n");
                goto out_hash;
        }

        for( i = 0; i < hash_body->lchb_hash_max_size; i++ ) {
                struct lustre_hash_bucket * bucket;
                struct hlist_node * actual_hnode, *pos;

                bucket = &hash_body->lchb_hash_tables[i];
                spin_lock(&bucket->lhb_lock); /* lock the bucket */
                hlist_for_each_safe(actual_hnode, pos, &(bucket->lhb_head)) {
                        lustre_hash_delitem_nolock(hash_body, i, actual_hnode);
                }
                spin_unlock(&bucket->lhb_lock);
        }

        /* free the hash_tables's memory space */
        OBD_FREE(hash_body->lchb_hash_tables,
                 sizeof(*hash_body->lchb_hash_tables) *
                 hash_body->lchb_hash_max_size);

        hash_body->lchb_hash_tables = NULL;

        spin_unlock(&hash_body->lchb_lock);

out_hash : 
        /* free the hash_body's memory space */
        if (hash_body != NULL) {
                OBD_FREE(hash_body, sizeof(*hash_body));
                *new_hash_body = NULL;
        }
        EXIT;
}
EXPORT_SYMBOL(lustre_hash_exit);

/*
 * only allow unique @key in hashtables, if the same @key has existed 
 * in hashtables, it will return with fails.
 */
int lustre_hash_additem_unique(struct lustre_class_hash_body *hash_body, 
                               void *key, struct hlist_node *actual_hnode)
{
        int hashent;
        struct lustre_hash_bucket *bucket = NULL;
        struct lustre_hash_operations *hop = hash_body->lchb_hash_operations;
        ENTRY;

        LASSERT(hlist_unhashed(actual_hnode));
        hashent = hop->lustre_hashfn(hash_body, key);

        /* get the hash-bucket and lock it */
        bucket = &hash_body->lchb_hash_tables[hashent];
        spin_lock(&bucket->lhb_lock);

        if ( (lustre_hash_getitem_in_bucket_nolock(hash_body, hashent, key)) != NULL) {
                /* the added-item exist in hashtables, so cannot add it again */
                spin_unlock(&bucket->lhb_lock);

                CWARN("Already found the key in hash [%s]\n", 
                      hash_body->hashname);
                RETURN(-EALREADY);
        }

        hlist_add_head(actual_hnode, &(bucket->lhb_head));

#ifdef LUSTRE_HASH_DEBUG
        /* hash distribute debug */
        hash_body->lchb_hash_tables[hashent].lhb_item_count++; 
        CDEBUG(D_INFO, "hashname[%s] bucket[%d] has [%d] hashitem\n", 
                        hash_body->hashname, hashent, 
                        hash_body->lchb_hash_tables[hashent].lhb_item_count);
#endif  
        hop->lustre_hash_object_refcount_get(actual_hnode); 

        spin_unlock(&bucket->lhb_lock);

        RETURN(0);
}
EXPORT_SYMBOL(lustre_hash_additem_unique);

/*
 * only allow unique @key in hashtables, if the same @key has existed 
 * in hashtables, it will return with fails.
 */
void* lustre_hash_findadd_unique(struct lustre_class_hash_body *hash_body, 
                                     void *key, struct hlist_node *actual_hnode)
{
        int hashent;
        struct lustre_hash_bucket *bucket = NULL;
        struct lustre_hash_operations *hop = hash_body->lchb_hash_operations;
        struct hlist_node * hash_item_hnode = NULL;
        void *obj;
        ENTRY;

        LASSERT(hlist_unhashed(actual_hnode));
        hashent = hop->lustre_hashfn(hash_body, key);

        /* get the hash-bucket and lock it */
        bucket = &hash_body->lchb_hash_tables[hashent];
        spin_lock(&bucket->lhb_lock);

        hash_item_hnode = lustre_hash_getitem_in_bucket_nolock(hash_body,
                                                               hashent, key);
        if ( hash_item_hnode != NULL) {
                /* the added-item exist in hashtables, so cannot add it again */
                obj = hop->lustre_hash_object_refcount_get(hash_item_hnode);
                spin_unlock(&bucket->lhb_lock);
                RETURN(obj);
        }

        hlist_add_head(actual_hnode, &(bucket->lhb_head));

#ifdef LUSTRE_HASH_DEBUG
        /* hash distribute debug */
        hash_body->lchb_hash_tables[hashent].lhb_item_count++; 
        CDEBUG(D_INFO, "hashname[%s] bucket[%d] has [%d] hashitem\n", 
                        hash_body->hashname, hashent, 
                        hash_body->lchb_hash_tables[hashent].lhb_item_count);
#endif
        obj = hop->lustre_hash_object_refcount_get(actual_hnode);

        spin_unlock(&bucket->lhb_lock);

        RETURN(obj);
}
EXPORT_SYMBOL(lustre_hash_findadd_unique);

/*
 * this version of additem, it allow multi same @key <key, value> in hashtables. 
 * in this additem version, we don't need to check if exist same @key in hash 
 * tables, we only add it to related hashbucket.
 * example: maybe same nid will be related to multi difference export
 */
int lustre_hash_additem(struct lustre_class_hash_body *hash_body, void *key, 
                         struct hlist_node *actual_hnode)
{
        int hashent;
        struct lustre_hash_bucket *bucket = NULL;
        struct lustre_hash_operations *hop = hash_body->lchb_hash_operations;
        ENTRY;

        LASSERT(hlist_unhashed(actual_hnode));

        hashent = hop->lustre_hashfn(hash_body, key);

        /* get the hashbucket and lock it */
        bucket = &hash_body->lchb_hash_tables[hashent];
        spin_lock(&bucket->lhb_lock);

        hlist_add_head(actual_hnode, &(bucket->lhb_head));

#ifdef LUSTRE_HASH_DEBUG
        /* hash distribute debug */
        hash_body->lchb_hash_tables[hashent].lhb_item_count++; 
        CDEBUG(D_INFO, "hashname[%s] bucket[%d] has [%d] hashitem\n", 
                        hash_body->hashname, hashent, 
                        hash_body->lchb_hash_tables[hashent].lhb_item_count);
#endif  
        hop->lustre_hash_object_refcount_get(actual_hnode); 

        spin_unlock(&bucket->lhb_lock);

        RETURN(0);
}
EXPORT_SYMBOL(lustre_hash_additem);


/*
 * this version of delitem will delete a hashitem with given @key, 
 * we need to search the <@key, @value> in hashbucket with @key, 
 * if match, the hashitem will be delete. 
 * we have a no-search version of delitem, it will directly delete a hashitem, 
 * doesn't need to search it in hashtables, so it is a O(1) delete.
 */
int lustre_hash_delitem_by_key(struct lustre_class_hash_body *hash_body, 
                               void *key)
{
        int hashent ;
        struct hlist_node * hash_item;
        struct lustre_hash_bucket *bucket = NULL;
        struct lustre_hash_operations *hop = hash_body->lchb_hash_operations;
        int retval = 0;
        ENTRY;

        hashent = hop->lustre_hashfn(hash_body, key);

        /* first, lock the hashbucket */
        bucket = &hash_body->lchb_hash_tables[hashent];
        spin_lock(&bucket->lhb_lock);

        /* get the hash_item from hash_bucket */
        hash_item = lustre_hash_getitem_in_bucket_nolock(hash_body, hashent, 
                                                         key);

        if (hash_item == NULL) {
                spin_unlock(&bucket->lhb_lock);
                RETURN(-ENOENT);
        }

        /* call delitem_nolock() to delete the hash_item */
        retval = lustre_hash_delitem_nolock(hash_body, hashent, hash_item);

        spin_unlock(&bucket->lhb_lock);

        RETURN(retval);
}
EXPORT_SYMBOL(lustre_hash_delitem_by_key);

/*
 * the O(1) version of delete hash item, 
 * it will directly delete the hashitem with given @hash_item,
 * the parameter @key used to get the relation hash bucket and lock it.
 */
int lustre_hash_delitem(struct lustre_class_hash_body *hash_body, 
                        void *key, struct hlist_node * hash_item)
{  
        int hashent = 0;
        int retval = 0;
        struct lustre_hash_bucket *bucket = NULL;
        struct lustre_hash_operations *hop = hash_body->lchb_hash_operations;
        ENTRY;

        hashent = hop->lustre_hashfn(hash_body, key);

        bucket = &hash_body->lchb_hash_tables[hashent];
        spin_lock(&bucket->lhb_lock);

        /* call delitem_nolock() to delete the hash_item */
        retval = lustre_hash_delitem_nolock(hash_body, hashent, hash_item);

        spin_unlock(&bucket->lhb_lock);

        RETURN(retval);
}
EXPORT_SYMBOL(lustre_hash_delitem);

void lustre_hash_bucket_iterate(struct lustre_class_hash_body *hash_body,
                                void *key, hash_item_iterate_cb func, void *data)
{
        int hashent, find = 0;
        struct lustre_hash_bucket *bucket = NULL;
        struct hlist_node *hash_item_node = NULL;
        struct lustre_hash_operations *hop = hash_body->lchb_hash_operations;
        struct obd_export *tmp = NULL;

        ENTRY;

        hashent = hop->lustre_hashfn(hash_body, key);
        bucket = &hash_body->lchb_hash_tables[hashent];

        spin_lock(&bucket->lhb_lock);
        hlist_for_each(hash_item_node, &(bucket->lhb_head)) {
                find = hop->lustre_hash_key_compare(key, hash_item_node);
                if (find) {
                        tmp = hop->lustre_hash_object_refcount_get(hash_item_node);
                        func(tmp, data);
                        hop->lustre_hash_object_refcount_put(hash_item_node);
                }
        }
        spin_unlock(&bucket->lhb_lock);
}
EXPORT_SYMBOL(lustre_hash_bucket_iterate);

void lustre_hash_iterate_all(struct lustre_class_hash_body *hash_body,
                            hash_item_iterate_cb func, void *data)
{
        int i;
        struct lustre_hash_operations *hop = hash_body->lchb_hash_operations;
        ENTRY;

        for( i = 0; i < hash_body->lchb_hash_max_size; i++ ) {
                struct lustre_hash_bucket * bucket;
                struct hlist_node * actual_hnode, *pos;
                void *obj;

                bucket = &hash_body->lchb_hash_tables[i];
#ifdef LUSTRE_HASH_DEBUG
                CDEBUG(D_INFO, "idx %d - bucket %p\n", i, bucket);
#endif
                spin_lock(&bucket->lhb_lock); /* lock the bucket */
                hlist_for_each_safe(actual_hnode, pos, &(bucket->lhb_head)) {
                        obj = hop->lustre_hash_object_refcount_get(actual_hnode);
                        func(obj, data);
                        hop->lustre_hash_object_refcount_put(actual_hnode);
                }
                spin_unlock(&bucket->lhb_lock);
        }
        EXIT;
}
EXPORT_SYMBOL(lustre_hash_iterate_all);


void * lustre_hash_get_object_by_key(struct lustre_class_hash_body *hash_body,
                                     void *key)
{
        int hashent ;
        struct hlist_node * hash_item_hnode = NULL;
        void * obj_value = NULL;
        struct lustre_hash_bucket *bucket = NULL;
        struct lustre_hash_operations * hop = hash_body->lchb_hash_operations;
        ENTRY;

        /* get the hash value from the given item */
        hashent = hop->lustre_hashfn(hash_body, key);

        bucket = &hash_body->lchb_hash_tables[hashent];
        spin_lock(&bucket->lhb_lock); /* lock the bucket */

        hash_item_hnode = lustre_hash_getitem_in_bucket_nolock(hash_body, 
                                                               hashent, key);

        if (hash_item_hnode == NULL) {
                spin_unlock(&bucket->lhb_lock); /* lock the bucket */
                RETURN(NULL);
        }

        obj_value = hop->lustre_hash_object_refcount_get(hash_item_hnode);
        spin_unlock(&bucket->lhb_lock); /* lock the bucket */

        RETURN(obj_value);
}
EXPORT_SYMBOL(lustre_hash_get_object_by_key);

/* string hashing using djb2 hash algorithm */
__u32 djb2_hashfn(struct lustre_class_hash_body *hash_body,  void* key, 
                  size_t size)
{
        __u32 hash = 5381;
        int i;
        char *ptr = key;

        LASSERT(key != NULL);

        for (i=0; i<size; i++) 
                hash = hash * 33 + ptr[i];

        hash &= (hash_body->lchb_hash_max_size - 1);

        RETURN(hash);
}

/*
 * define (uuid <-> export) hash operations and function define
 */

/* define the uuid hash operations */
struct lustre_hash_operations uuid_hash_operations = {
        .lustre_hashfn = uuid_hashfn,
        .lustre_hash_key_compare = uuid_hash_key_compare,
        .lustre_hash_object_refcount_get = uuid_export_refcount_get,
        .lustre_hash_object_refcount_put = uuid_export_refcount_put,
};

__u32 uuid_hashfn(struct lustre_class_hash_body *hash_body,  void * key)
{
        struct obd_uuid * uuid_key = key;

        return djb2_hashfn(hash_body, uuid_key->uuid, sizeof(uuid_key->uuid));
}

/* Note, it is impossible to find an export that is in failed state with
 * this function */
int uuid_hash_key_compare(void *key, struct hlist_node *compared_hnode)
{
        struct obd_export *export = NULL;
        struct obd_uuid *uuid_key = NULL, *compared_uuid = NULL;

        LASSERT( key != NULL);

        uuid_key = (struct obd_uuid*)key;

        export = hlist_entry(compared_hnode, struct obd_export, exp_uuid_hash);

        compared_uuid = &export->exp_client_uuid;

        RETURN(obd_uuid_equals(uuid_key, compared_uuid) &&
               !export->exp_failed);
}

void * uuid_export_refcount_get(struct hlist_node * actual_hnode)
{
        struct obd_export *export = NULL;

        LASSERT(actual_hnode != NULL);

        export = hlist_entry(actual_hnode, struct obd_export, exp_uuid_hash);

        LASSERT(export != NULL);

        class_export_get(export);

        RETURN(export);
}

void uuid_export_refcount_put(struct hlist_node * actual_hnode)
{
        struct obd_export *export = NULL;

        LASSERT(actual_hnode != NULL);

        export = hlist_entry(actual_hnode, struct obd_export, exp_uuid_hash);

        LASSERT(export != NULL);

        class_export_put(export);
}

/*
 * define (nid <-> export) hash operations and function define
 */

/* define the nid hash operations */
struct lustre_hash_operations nid_hash_operations = {
        .lustre_hashfn = nid_hashfn,
        .lustre_hash_key_compare = nid_hash_key_compare,
        .lustre_hash_object_refcount_get = nid_export_refcount_get,
        .lustre_hash_object_refcount_put = nid_export_refcount_put,
};

__u32 nid_hashfn(struct lustre_class_hash_body *hash_body,  void * key)
{
        return djb2_hashfn(hash_body, key, sizeof(lnet_nid_t));
}

/* Note, it is impossible to find an export that is in failed state with
 * this function */
int nid_hash_key_compare(void *key, struct hlist_node *compared_hnode)
{
        struct obd_export *export = NULL;
        lnet_nid_t *nid_key = NULL;

        LASSERT( key != NULL);

        nid_key = (lnet_nid_t*)key;

        export = hlist_entry(compared_hnode, struct obd_export, exp_nid_hash);

        return (export->exp_connection->c_peer.nid == *nid_key &&
                !export->exp_failed);
}

void *nid_export_refcount_get(struct hlist_node *actual_hnode)
{
        struct obd_export *export = NULL;

        LASSERT(actual_hnode != NULL);

        export = hlist_entry(actual_hnode, struct obd_export, exp_nid_hash);

        LASSERT(export != NULL);

        class_export_get(export);

        RETURN(export);
}

void nid_export_refcount_put(struct hlist_node *actual_hnode)
{
        struct obd_export *export = NULL;

        LASSERT(actual_hnode != NULL);

        export = hlist_entry(actual_hnode, struct obd_export, exp_nid_hash);

        LASSERT(export != NULL);

        class_export_put(export);
}

/*
 * define (net_peer <-> connection) hash operations and function define
 */

/* define the conn hash operations */
struct lustre_hash_operations conn_hash_operations = {
        .lustre_hashfn = conn_hashfn,
        .lustre_hash_key_compare = conn_hash_key_compare,
        .lustre_hash_object_refcount_get = conn_refcount_get,
        .lustre_hash_object_refcount_put = conn_refcount_put,
};
EXPORT_SYMBOL(conn_hash_operations);

__u32 conn_hashfn(struct lustre_class_hash_body *hash_body,  void * key)
{
        return djb2_hashfn(hash_body, key, sizeof(lnet_process_id_t));
}

int conn_hash_key_compare(void *key, struct hlist_node *compared_hnode)
{
        struct ptlrpc_connection *c = NULL;
        lnet_process_id_t *conn_key = NULL;

        LASSERT( key != NULL);

        conn_key = (lnet_process_id_t*)key;

        c = hlist_entry(compared_hnode, struct ptlrpc_connection, c_hash);

        return (conn_key->nid == c->c_peer.nid &&
                conn_key->pid == c->c_peer.pid);
}

void *conn_refcount_get(struct hlist_node *actual_hnode)
{
        struct ptlrpc_connection *c = NULL;

        LASSERT(actual_hnode != NULL);

        c = hlist_entry(actual_hnode, struct ptlrpc_connection, c_hash);

        LASSERT(c != NULL);

        atomic_inc(&c->c_refcount);

        RETURN(c);
}

void conn_refcount_put(struct hlist_node *actual_hnode)
{
        struct ptlrpc_connection *c = NULL;

        LASSERT(actual_hnode != NULL);

        c = hlist_entry(actual_hnode, struct ptlrpc_connection, c_hash);

        LASSERT(c != NULL);

        atomic_dec(&c->c_refcount);
}

/*******************************************************************************/
/* ( nid<>nidstats ) hash operations define */

struct lustre_hash_operations nid_stat_hash_operations = {
        .lustre_hashfn = nid_hashfn,
        .lustre_hash_key_compare = nidstats_hash_key_compare,
        .lustre_hash_object_refcount_get = nidstats_refcount_get,
        .lustre_hash_object_refcount_put = nidstats_refcount_put,
};
EXPORT_SYMBOL(nid_stat_hash_operations);

int nidstats_hash_key_compare(void *key, struct hlist_node * compared_hnode)
{
        struct nid_stat *data;
        lnet_nid_t *nid_key;

        LASSERT( key != NULL);

        nid_key = (lnet_nid_t*)key;
        data = hlist_entry(compared_hnode, struct nid_stat, nid_hash);

        return (data->nid == *nid_key);
}

void* nidstats_refcount_get(struct hlist_node * actual_hnode)
{
        struct nid_stat *data;

        data = hlist_entry(actual_hnode, struct nid_stat, nid_hash);
        data->nid_exp_ref_count++;

        RETURN(data);
}

void nidstats_refcount_put(struct hlist_node * actual_hnode)
{
        struct nid_stat *data;

        data = hlist_entry(actual_hnode, struct nid_stat, nid_hash);
        data->nid_exp_ref_count--;
        EXIT;
}

/*******************************************************************************/

#ifdef __KERNEL__
/*
 * define ( lqs <-> qctxt ) hash operations and function define
 */

/* define the conn hash operations */
struct lustre_hash_operations lqs_hash_operations = {
        .lustre_hashfn = lqs_hashfn,
        .lustre_hash_key_compare = lqs_hash_key_compare,
        .lustre_hash_object_refcount_get = lqs_refcount_get,
        .lustre_hash_object_refcount_put = lqs_refcount_put,
};
EXPORT_SYMBOL(lqs_hash_operations);

/* string hashing using djb2 hash algorithm */
__u32 lqs_hashfn(struct lustre_class_hash_body *hash_body,  void * key)
{
        struct quota_adjust_qunit *lqs_key = NULL;
        __u32 hash;

        LASSERT(key != NULL);

        lqs_key = (struct quota_adjust_qunit *)key;

        hash = QAQ_IS_GRP(lqs_key) ? 5381 : 5387;
        hash *= lqs_key->qaq_id;

        hash &= (hash_body->lchb_hash_max_size - 1);

        RETURN(hash);
}

int lqs_hash_key_compare(void *key, struct hlist_node *compared_hnode)
{
        struct quota_adjust_qunit *lqs_key = NULL;
        struct lustre_qunit_size *q = NULL;
        int retval = 0;

        LASSERT( key != NULL);

        lqs_key = (struct quota_adjust_qunit *)key;

        q = hlist_entry(compared_hnode, struct lustre_qunit_size, lqs_hash);

        spin_lock(&q->lqs_lock);
        if (lqs_key->qaq_id == q->lqs_id && QAQ_IS_GRP(lqs_key) == LQS_IS_GRP(q))
                 retval = 1;
        spin_unlock(&q->lqs_lock);

        return retval;
}

void * lqs_refcount_get(struct hlist_node * actual_hnode)
{
        struct lustre_qunit_size *q = NULL;

        LASSERT(actual_hnode != NULL);

        q = hlist_entry(actual_hnode, struct lustre_qunit_size, lqs_hash);

        LASSERT(q != NULL);

        lqs_getref(q);

        RETURN(q);
}

void lqs_refcount_put(struct hlist_node * actual_hnode)
{
        struct lustre_qunit_size *q = NULL;

        LASSERT(actual_hnode != NULL);

        q = hlist_entry(actual_hnode, struct lustre_qunit_size, lqs_hash);

        LASSERT(q != NULL);

        lqs_putref(q);
}
#endif
