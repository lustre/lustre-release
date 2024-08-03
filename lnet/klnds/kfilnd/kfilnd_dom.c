// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2022 Hewlett Packard Enterprise Development LP
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * kfilnd domain and fabric implementation.
 */

#include "kfilnd_dom.h"
#include "kfilnd_tn.h"

/* Global list of allocated KFI LND fabrics. */
static LIST_HEAD(fab_list);
static DEFINE_MUTEX(fab_list_lock);

/**
 * kfilnd_dom_free() - Free a KFI LND domain.
 * @dom: KFI LND domain to be freed.
 */
static void kfilnd_dom_free(struct kref *kref)
{
	struct kfilnd_dom *dom;

	if (!kref)
		return;

	dom = container_of(kref, struct kfilnd_dom, cnt);

	mutex_lock(&dom->fab->dom_list_lock);
	list_del(&dom->entry);
	mutex_unlock(&dom->fab->dom_list_lock);

	kfi_close(&dom->domain->fid);
	LIBCFS_FREE(dom, sizeof(*dom));
}

/**
 * kfilnd_dom_alloc() - Allocate a new KFI LND domain.
 * @dom_info: KFI info structure used to allocate the KFI LND domain.
 * @fab: KFI LND fabric used by the domain.
 *
 * A KFI LND domain (and the underlying KFI domain) provides access to a
 * specific NIC on a fabric. The same KFI LND domain can be used to allocate
 * different KFI LND devices.
 *
 * Return: On success, valid pointer. Else, negative errno pointer.
 */
static struct kfilnd_dom *kfilnd_dom_alloc(struct kfi_info *dom_info,
					   struct kfilnd_fab *fab)
{
	int rc;
	struct kfilnd_dom *dom;

	if (!dom_info || !fab) {
		rc = -EINVAL;
		goto err;
	}

	LIBCFS_ALLOC_GFP(dom, sizeof(*dom), GFP_KERNEL);
	if (!dom) {
		rc = -ENOMEM;
		goto err;
	}

	INIT_LIST_HEAD(&dom->dev_list);
	spin_lock_init(&dom->lock);
	dom->fab = fab;
	kref_init(&dom->cnt);

	rc = kfi_domain(fab->fabric, dom_info, &dom->domain, dom);
	if (rc) {
		CERROR("Failed to create KFI domain: rc=%d\n", rc);
		goto err_free_dom;
	}

	mutex_lock(&fab->dom_list_lock);
	list_add_tail(&dom->entry, &fab->dom_list);
	mutex_unlock(&fab->dom_list_lock);

	return dom;

err_free_dom:
	LIBCFS_FREE(dom, sizeof(*dom));
err:
	return ERR_PTR(rc);
}

/**
 * kfilnd_dom_reuse() - Attempt to reuse an already allocated domain.
 * @node: Node string used to limit domains to.
 * @service: Service string used to limit domains to.
 * @hints: Hints used to allocate KFI info structures.
 * @fab: Fabric used to limit domains to.
 *
 * Return: On success (matching domain is found), valid pointer is returned.
 * Else, NULL.
 */
struct kfilnd_dom *kfilnd_dom_reuse(const char *node, const char *service,
				    struct kfi_info *hints,
				    struct kfilnd_fab *fab)
{
	struct kfilnd_dom *dom;
	struct kfi_info *info;
	int rc;

	if (!node || !service || !hints || !fab)
		return NULL;

	/* Update the hints domain attribute with an already allocated domain to
	 * see if domains can be reused.
	 */
	hints->fabric_attr->fabric = fab->fabric;

	mutex_lock(&fab->dom_list_lock);
	list_for_each_entry(dom, &fab->dom_list, entry) {
		hints->domain_attr->domain = dom->domain;

		rc = kfi_getinfo(0, node, service, KFI_SOURCE, hints, &info);
		if (!rc) {
			kref_get(&dom->cnt);

			mutex_unlock(&fab->dom_list_lock);

			kfi_freeinfo(info);

			return dom;
		}
	}
	mutex_unlock(&fab->dom_list_lock);

	hints->domain_attr->domain = NULL;

	return NULL;
}

/**
 * kfilnd_fab_free() - Free KFI LND fabric.
 */
static void kfilnd_fab_free(struct kref *kref)
{
	struct kfilnd_fab *fab;

	if (!kref)
		return;

	fab = container_of(kref, struct kfilnd_fab, cnt);

	mutex_lock(&fab_list_lock);
	list_del(&fab->entry);
	mutex_unlock(&fab_list_lock);

	kfi_close(&fab->fabric->fid);
	LIBCFS_FREE(fab, sizeof(*fab));
}

/**
 * kfilnd_fab_alloc() - Allocate a new KFI LND fabric.
 * @attr: KFI fabric attributes used to allocate the underlying KFI fabric.
 *
 * A KFI LND fabric (and the underlying KFI fabric) providers access to NICs on
 * the same fabric. The underlying KFI fabric should be shared between all NICs
 * (KFI domains) on the same fabric.
 *
 * Return: On success, valid pointer. Else, negative errno pointer.
 */
static struct kfilnd_fab *kfilnd_fab_alloc(struct kfi_fabric_attr *attr)
{
	int rc;
	struct kfilnd_fab *fab;

	if (!attr) {
		rc = -EINVAL;
		goto err;
	}

	LIBCFS_ALLOC_GFP(fab, sizeof(*fab), GFP_KERNEL);
	if (!fab) {
		rc = -ENOMEM;
		goto err;
	}

	INIT_LIST_HEAD(&fab->dom_list);
	mutex_init(&fab->dom_list_lock);
	kref_init(&fab->cnt);

	rc = kfi_fabric(attr, &fab->fabric, fab);
	if (rc) {
		CERROR("Failed to allocate KFI fabric: rc=%d\n", rc);
		goto err_free_fab;
	}

	mutex_lock(&fab_list_lock);
	list_add_tail(&fab->entry, &fab_list);
	mutex_unlock(&fab_list_lock);

	return fab;

err_free_fab:
	LIBCFS_FREE(fab, sizeof(*fab));
err:
	return ERR_PTR(rc);
}

/**
 * kfilnd_fab_reuse() - Attempt to reuse an already allocated fabric.
 * @node: Node string used to limit fabrics to.
 * @service: Service string used to limit fabrics to.
 * @hints: Hints used to allocate KFI info structures.
 *
 * Return: On success (matching fabric is found), valid pointer is returned.
 * Else, NULL.
 */
struct kfilnd_fab *kfilnd_fab_reuse(const char *node, const char *service,
				    struct kfi_info *hints)
{
	struct kfilnd_fab *fab;
	struct kfi_info *info;
	int rc;

	if (!node || !service || !hints)
		return NULL;

	/* Update the hints fabric attribute with an already allocated fabric to
	 * see if fabrics can be reused.
	 */
	mutex_lock(&fab_list_lock);
	list_for_each_entry(fab, &fab_list, entry) {
		hints->fabric_attr->fabric = fab->fabric;

		rc = kfi_getinfo(0, node, service, KFI_SOURCE, hints, &info);
		if (!rc) {
			kref_get(&fab->cnt);

			mutex_unlock(&fab_list_lock);

			kfi_freeinfo(info);

			return fab;
		}
	}
	mutex_unlock(&fab_list_lock);

	hints->fabric_attr->fabric = NULL;

	return NULL;
}

/**
 * kfi_domain_put() - Put a KFI LND domain reference.
 */
void kfilnd_dom_put(struct kfilnd_dom *dom)
{
	struct kfilnd_fab *fab;

	if (!dom)
		return;

	fab = dom->fab;

	kref_put(&dom->cnt, kfilnd_dom_free);

	kref_put(&fab->cnt, kfilnd_fab_free);
}

/**
 * kfilnd_dom_get() - Get a KFI LND domain.
 * @ni: LNet NI used to define the KFI LND domain address.
 * @node: Node string which can be passed into kfi_getinfo().
 * @dev_info: KFI info structure which should be used to allocate a KFI LND
 * device using this domain.
 *
 * On success, a KFI info structure is returned to the user in addition to a KFI
 * LND domain. Callers should free the KFI info structure once done using it.
 *
 * Return: On success, dev_info is set to a valid KFI info structure and a valid
 * KFI LND domain is returned. Else, negative errno pointer is returned.
 */
struct kfilnd_dom *kfilnd_dom_get(struct lnet_ni *ni, const char *node,
				  struct kfi_info **dev_info)
{
	int rc;
	struct kfi_info *hints;
	struct kfi_info *info;
	struct kfi_info *hints_tmp;
	struct kfi_info *info_tmp;
	struct kfilnd_fab *fab;
	struct kfilnd_dom *dom;
	struct kfi_cxi_fabric_ops *fab_ops;
	char *service;

	if (!ni || !dev_info) {
		rc = -EINVAL;
		goto err;
	}

	service = kasprintf(GFP_KERNEL, "%u", ntohs(ni->ni_nid.nid_num));
	if (!service) {
		rc = -ENOMEM;
		goto err;
	}

	hints = kfi_allocinfo();
	if (!hints) {
		rc = -ENOMEM;
		goto err_free_service;
	}

	hints->caps = KFI_MSG | KFI_RMA | KFI_SEND | KFI_RECV | KFI_READ |
		KFI_WRITE | KFI_REMOTE_READ | KFI_REMOTE_WRITE |
		KFI_MULTI_RECV | KFI_REMOTE_COMM | KFI_NAMED_RX_CTX |
		KFI_TAGGED | KFI_TAGGED_RMA | KFI_DIRECTED_RECV;
	hints->fabric_attr->prov_version =
		KFI_VERSION(ni->ni_lnd_tunables.lnd_tun_u.lnd_kfi.lnd_prov_major_version,
			    ni->ni_lnd_tunables.lnd_tun_u.lnd_kfi.lnd_prov_minor_version);
	hints->domain_attr->mr_iov_limit = 256; /* 1 MiB LNet message */
	hints->domain_attr->mr_key_size = sizeof(int);
	hints->domain_attr->resource_mgmt = KFI_RM_DISABLED;
	hints->domain_attr->tclass =
		ni->ni_lnd_tunables.lnd_tun_u.lnd_kfi.lnd_traffic_class;
	hints->ep_attr->max_msg_size = LNET_MAX_PAYLOAD;
	hints->rx_attr->op_flags = KFI_COMPLETION | KFI_MULTI_RECV;
	hints->rx_attr->iov_limit = 256; /* 1 MiB LNet message */
	hints->tx_attr->op_flags = KFI_COMPLETION;
	hints->tx_attr->iov_limit = 256; /* 1 MiB LNet message */
	hints->tx_attr->rma_iov_limit = 256; /* 1 MiB LNet message */
	hints->tx_attr->tclass =
		ni->ni_lnd_tunables.lnd_tun_u.lnd_kfi.lnd_traffic_class;
	hints->ep_attr->auth_key =
		(void *)&ni->ni_lnd_tunables.lnd_tun_u.lnd_kfi.lnd_auth_key;
	hints->ep_attr->auth_key_size =
		sizeof(ni->ni_lnd_tunables.lnd_tun_u.lnd_kfi.lnd_auth_key);

	/* Check if dynamic resource allocation is supported.
	 * Set dynamic resource alloc hints if it is.
	 *
	 * Need to check if op is supported since due to a bug can't
	 * simply set ctx_cnts greater than 1 (default value) if it isn't.
	 */
	hints_tmp = kfi_dupinfo(hints);
	if (hints_tmp) {
		rc = kfi_getinfo(0, node, service, KFI_SOURCE, hints_tmp,
				 &info_tmp);
		if (!rc) {
			fab = kfilnd_fab_alloc(info_tmp->fabric_attr);
			if (!IS_ERR(fab)) {
				rc = kfi_open_ops(&fab->fabric->fid,
					KFI_CXI_FAB_OPS_1, 0, (void **)&fab_ops,
					NULL);
				if (!rc) {
					/* Set dynamic resource alloc hints */
					hints->domain_attr->cq_cnt = ni->ni_ncpts * 2;
					hints->domain_attr->tx_ctx_cnt = ni->ni_ncpts;
					hints->domain_attr->rx_ctx_cnt = ni->ni_ncpts;
					hints->rx_attr->size =
						ni->ni_net->net_tunables.lct_max_tx_credits +
						immediate_rx_buf_count;
				}
				kref_put(&fab->cnt, kfilnd_fab_free);
			}
			kfi_freeinfo(info_tmp);
		}
		kfi_freeinfo(hints_tmp);
	}

	/* Check to see if any KFI LND fabrics/domains can be reused. */
	fab = kfilnd_fab_reuse(node, service, hints);
	dom = kfilnd_dom_reuse(node, service, hints, fab);

	if (fab)
		hints->fabric_attr->fabric = fab->fabric;
	if (dom)
		hints->domain_attr->domain = dom->domain;

	/* Allocate the official KFI info structure to be used for KFI LND
	 * device allocation.
	 */
	rc = kfi_getinfo(0, node, service, KFI_SOURCE, hints, &info);

	/* Authorization key information is now stored in the returned kfi_info
	 * structure. Since kfi_freeinfo() will try to free the auth_key pointer
	 * and this memory is owned as part of the LNet NI, need to zero this
	 * information in the hints to prevent LNet NI corruption.
	 */
	hints->ep_attr->auth_key = NULL;
	hints->ep_attr->auth_key_size = 0;

	kfi_freeinfo(hints);
	kfree(service);
	node = NULL;
	service = NULL;

	if (rc)
		goto err_free_service;

	/* Allocate a new KFI LND fabric and domain if necessary. */
	if (!fab) {
		fab = kfilnd_fab_alloc(info->fabric_attr);
		if (IS_ERR(fab)) {
			rc = PTR_ERR(fab);
			goto err_free_info;
		}
	}

	if (!dom) {
		/* Enable dynamic resource allocation if operation supported */
		rc = kfi_open_ops(&fab->fabric->fid, KFI_CXI_FAB_OPS_1, 0,
				  (void **)&fab_ops, NULL);
		if (!rc) {
			rc = fab_ops->enable_dynamic_rsrc_alloc(&fab->fabric->fid, true);
			if (!rc)
				CDEBUG(D_NET, "Enabled dynamic resource allocation for KFI domain\n");
		}
		dom = kfilnd_dom_alloc(info, fab);
		if (IS_ERR(dom)) {
			rc = PTR_ERR(dom);
			goto err_put_fab;
		}
	}

	*dev_info = info;

	return dom;

err_put_fab:
	kref_put(&fab->cnt, kfilnd_fab_free);
err_free_info:
	kfi_freeinfo(info);
err_free_service:
	kfree(service);
err:
	return ERR_PTR(rc);
}
