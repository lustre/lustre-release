/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * obd/ldlm/resource.c
 *
 * Copyright (C) 2002  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * by Cluster File Systems, Inc.
 */

#define EXPORT_SYMTAB

#include <linux/version.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/unistd.h>

#define DEBUG_SUBSYSTEM S_LDLM

#include <linux/obd_support.h>
#include <linux/obd_class.h>

#include <linux/lustre_dlm.h>

static kmem_cache_t *ldlm_resource_slab;
static kmem_cache_t *ldlm_lock_slab;

struct ldlm_namespace *ldlm_namespace_find(struct obd_device *obddev, __u32 id)
{
	struct list_head *tmp;
	struct ldlm_namespace *res;

	res = NULL;
	list_for_each(tmp, &obddev->u.ldlm.ldlm_namespaces) { 
		struct ldlm_namespace *chk;
		chk = list_entry(tmp, struct ldlm_namespace, ns_link);
		
		if ( chk->ns_id == id ) {
			res = chk;
			break;
		}
	}
	return res;
}

static void res_hash_init(struct ldlm_namespace *name_space)
{
	struct list_head *res_hash;
	struct list_head *bucket;

	OBD_ALLOC(res_hash, sizeof(struct list_head) * RES_HASH_SIZE);
	if (!res_hash)
		BUG();

	for (bucket = res_hash + RES_HASH_SIZE-1 ; bucket >= res_hash ;
	     bucket--) {
		INIT_LIST_HEAD(bucket);
	}

	name_space->ns_hash = res_hash;
}

struct ldlm_namespace *ldlm_namespace_new(struct obd_device *obddev, __u32 id)
{
	struct ldlm_namespace *ns;

	if (ldlm_namespace_find(obddev, id))
		BUG();

	OBD_ALLOC(ns, sizeof(*ns));
	if (!ns)
		BUG();

	ns->ns_id = id;
	INIT_LIST_HEAD(&ns->ns_root_list);
	list_add(&ns->ns_link, &obddev->u.ldlm.ldlm_namespaces);

	res_hash_init(ns); 
	return ns;
}

__u32 ldlm_hash_fn(struct ldlm_resource *parent, __u32 *name)
{
	__u32 hash = 0;
	int i;

	for (i = 0; i < RES_NAME_SIZE; i++) {
		hash += name[i];
	}

	hash += (__u32)((unsigned long)parent >> 4);

	return (hash & RES_HASH_MASK);
}

struct ldlm_resource *ldlm_resource_find(struct ldlm_namespace *ns,
					 struct ldlm_resource *parent,
					 __u32 *name)
{
	struct list_head *bucket;
	struct list_head *tmp = bucket;
	struct ldlm_resource *res;

	if (ns->ns_hash == NULL)
		BUG();
	bucket = ns->ns_hash + ldlm_hash_fn(parent, name);

	res = NULL;
	list_for_each(tmp, bucket) {
		struct ldlm_resource *chk;
		chk = list_entry(tmp, struct ldlm_resource, lr_hash);

		if (memcmp(chk->lr_name, name, RES_NAME_SIZE * sizeof(__u32))){
			res = chk;
			break;
		}
	}
			
	return res;
}

struct ldlm_resource *ldlm_resource_new(void)
{
	struct ldlm_resource *res;

	res = kmem_cache_alloc(ldlm_resource_slab, SLAB_KERNEL);
	if (res == NULL)
		BUG();
	memset(res, 0, sizeof(*res));

	INIT_LIST_HEAD(&res->lr_children);
	INIT_LIST_HEAD(&res->lr_granted);
	INIT_LIST_HEAD(&res->lr_converting);
	INIT_LIST_HEAD(&res->lr_waiting);

	return res;
}

struct ldlm_resource *ldlm_resource_add(struct obd_device *obddev, __u32 id,
					struct ldlm_resource *parent,
					__u32 *name)
{
	struct ldlm_namespace *ns;
	struct list_head *bucket;
	struct ldlm_resource *res;

	ns = ldlm_namespace_find(obddev, id);
	if (ns == NULL || ns->ns_hash == NULL)
		BUG();

	bucket = ns->ns_hash + ldlm_hash_fn(parent, name);

	if (ldlm_resource_find(ns, parent, name) != NULL)
		BUG();

	res = ldlm_resource_new();
	if (!res)
		BUG();

	memcpy(res->lr_name, name, RES_NAME_SIZE * sizeof(__u32));
	list_add(&res->lr_hash, bucket);
	if (parent == NULL) {
		res->lr_parent = res;
		list_add(&res->lr_rootlink, &ns->ns_root_list);
	} else {
		res->lr_parent = parent;
		list_add(&res->lr_childof, &parent->lr_children);
	}

	return res;
}

static int ldlm_obd_setup(struct obd_device *obddev, obd_count len, void *data)
{
	INIT_LIST_HEAD(&obddev->u.ldlm.ldlm_namespaces);

	return 0;
}

struct obd_ops ldlm_obd_ops = {
	o_setup:       ldlm_obd_setup,
        o_connect:     gen_connect,
        o_disconnect:  gen_disconnect,
};

static int __init ldlm_init(void)
{
        int rc = obd_register_type(&ldlm_obd_ops, OBD_LDLM_DEVICENAME);
	if (rc != 0)
		return rc;

	ldlm_resource_slab = kmem_cache_create("ldlm_resources",
					       sizeof(struct ldlm_resource), 0,
					       SLAB_HWCACHE_ALIGN, NULL, NULL);
	if (ldlm_resource_slab == NULL)
		return -ENOMEM;

	ldlm_lock_slab = kmem_cache_create("ldlm_locks",
					   sizeof(struct ldlm_lock), 0,
					   SLAB_HWCACHE_ALIGN, NULL, NULL);
	if (ldlm_lock_slab == NULL) {
		kmem_cache_destroy(ldlm_resource_slab);
		return -ENOMEM;
	}

	return 0;
}

static void __exit ldlm_exit(void)
{
        obd_unregister_type(OBD_LDLM_DEVICENAME);
	kmem_cache_destroy(ldlm_resource_slab);
	kmem_cache_destroy(ldlm_lock_slab);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Lock Management Module v0.1");
MODULE_LICENSE("GPL"); 

module_init(ldlm_init);
module_exit(ldlm_exit);
