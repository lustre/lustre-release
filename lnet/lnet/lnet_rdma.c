// SPDX-License-Identifier: GPL-2.0

/* This file is part of Lustre, http://www.lustre.org/ */

#include <linux/lnet/lnet_rdma.h>
#include <linux/libcfs/libcfs.h>
#include <lustre_compat.h>

/* MAX / MIN conflict */
#include <linux/lnet/lib-lnet.h>

#ifdef HAVE_IS_PCI_P2PDMA_PAGE
#include <linux/pci.h>
#include <linux/memremap.h>
#include <linux/pci-p2pdma.h>
#endif

#define NVFS_HOLD_TIME_MS 1000

#define ERROR_PRINT_DEADLINE 3600

static atomic_t nvfs_shutdown = ATOMIC_INIT(1);
static struct nvfs_dma_rw_ops *nvfs_ops;
static struct percpu_counter nvfs_n_ops;

static inline long nvfs_count_ops(void)
{
	return percpu_counter_sum(&nvfs_n_ops);
}

static struct nvfs_dma_rw_ops *nvfs_get_ops(void)
{
	if (!nvfs_ops || atomic_read(&nvfs_shutdown))
		return NULL;

	percpu_counter_inc(&nvfs_n_ops);

	return nvfs_ops;
}

static inline void nvfs_put_ops(void)
{
	percpu_counter_dec(&nvfs_n_ops);
}

static inline bool nvfs_check_feature_set(struct nvfs_dma_rw_ops *ops)
{
	bool supported = true;
	static time64_t last_printed;

	if (unlikely(!NVIDIA_FS_CHECK_FT_SGLIST_PREP(ops))) {
		if ((ktime_get_seconds() - last_printed) > ERROR_PRINT_DEADLINE)
			CDEBUG(D_CONSOLE,
			       "NVFS sg list preparation callback missing\n");
		supported = false;
	}
	if (unlikely(!NVIDIA_FS_CHECK_FT_SGLIST_DMA(ops))) {
		if ((ktime_get_seconds() - last_printed) > ERROR_PRINT_DEADLINE)
			CDEBUG(D_CONSOLE,
			       "NVFS DMA mapping callbacks missing\n");
		supported = false;
	}
	if (unlikely(!NVIDIA_FS_CHECK_FT_GPU_PAGE(ops))) {
		if ((ktime_get_seconds() - last_printed) > ERROR_PRINT_DEADLINE)
			CDEBUG(D_CONSOLE,
			       "NVFS page identification callback missing\n");
		supported = false;
	}
	if (unlikely(!NVIDIA_FS_CHECK_FT_DEVICE_PRIORITY(ops))) {
		if ((ktime_get_seconds() - last_printed) > ERROR_PRINT_DEADLINE)
			CDEBUG(D_CONSOLE,
			       "NVFS device priority callback not missing\n");
		supported = false;
	}

	if (unlikely(!supported &&
		     ((ktime_get_seconds() - last_printed) > ERROR_PRINT_DEADLINE)))
		last_printed = ktime_get_seconds();
	else if (supported)
		last_printed = 0;

	return supported;
}

int REGISTER_FUNC(struct nvfs_dma_rw_ops *ops)
{
	if (!ops || !nvfs_check_feature_set(ops))
		return -EINVAL;

	nvfs_ops = ops;
	(void)percpu_counter_init(&nvfs_n_ops, 0, GFP_KERNEL);
	atomic_set(&nvfs_shutdown, 0);
	CDEBUG(D_NET, "registering nvfs %p\n", ops);
	return 0;
}
EXPORT_SYMBOL_GPL(REGISTER_FUNC);

void UNREGISTER_FUNC(void)
{
	(void)atomic_cmpxchg(&nvfs_shutdown, 0, 1);
	do {
		CDEBUG(D_NET, "Attempting to de-register nvfs: %ld\n",
		       nvfs_count_ops());
		msleep(NVFS_HOLD_TIME_MS);
	} while (nvfs_count_ops());
	nvfs_ops = NULL;
	percpu_counter_destroy(&nvfs_n_ops);
}
EXPORT_SYMBOL_GPL(UNREGISTER_FUNC);

unsigned int
lnet_get_dev_prio(struct device *dev, struct lnet_device_id *dev_id)
{
	unsigned int dev_prio = UINT_MAX;
	struct nvfs_dma_rw_ops *nvfs_ops;

	if (!dev || !dev_id || dev_id->ldi_type == LNET_DEV_TYPE_NONE)
		return dev_prio;

#ifdef HAVE_IS_PCI_P2PDMA_PAGE
	if (dev_id->ldi_type == LNET_DEV_TYPE_P2P) {
		int p2p_dist;

		p2p_dist = pci_p2pdma_distance(to_pci_dev(dev_id->ldi_p2pdev),
					       dev, false);
		if (p2p_dist < 0)
			return UINT_MAX;
		return p2p_dist;
	}
#endif

	if (dev_id->ldi_type == LNET_DEV_TYPE_GPU) {
		nvfs_ops = nvfs_get_ops();
		if (!nvfs_ops)
			return dev_prio;

		dev_prio = nvfs_ops->nvfs_device_priority(dev,
							  dev_id->ldi_gpu_idx);
		nvfs_put_ops();
	}

	return dev_prio;
}
EXPORT_SYMBOL(lnet_get_dev_prio);

#ifdef HAVE_IS_PCI_P2PDMA_PAGE

#ifndef HAVE_PAGE_PGMAP
#define page_pgmap(page) ((page)->pgmap)
#endif
static inline struct device *lnet_get_p2p_dev(struct page *page)
{
	struct dev_pagemap *pgmap = page_pgmap(page);

#ifdef HAVE_P2PDMA_PROVIDER
	struct {
		struct dev_pagemap pgmap;
		struct p2pdma_provider *mem;
	} *p2p = container_of(pgmap, typeof(*p2p), pgmap);
	return p2p->mem->owner;
#elif KERNEL_VERSION(6, 7, 0) <= LINUX_VERSION_CODE
	struct {
		struct pci_dev *provider;
		u64 bus_offset;
		struct dev_pagemap pgmap;
	} *p2p = container_of(pgmap, typeof(*p2p), pgmap);
	return &p2p->provider->dev;
#else
	struct {
		struct dev_pagemap pgmap;
		struct pci_dev *provider;
		u64 bus_offset;
	} *p2p = container_of(pgmap, typeof(*p2p), pgmap);
	return &p2p->provider->dev;
#endif
}
#endif /* HAVE_IS_PCI_P2PDMA_PAGE */

void lnet_get_device_id(struct page *page, struct lnet_device_id *id)
{
	struct nvfs_dma_rw_ops *nvfs_ops;
	unsigned int idx;

	id->ldi_type = LNET_DEV_TYPE_NONE;

	if (!page)
		return;

#ifdef HAVE_IS_PCI_P2PDMA_PAGE
	if (is_pci_p2pdma_page(page)) {
		id->ldi_type = LNET_DEV_TYPE_P2P;
		id->ldi_p2pdev = lnet_get_p2p_dev(page);
		return;
	}
#endif

	nvfs_ops = nvfs_get_ops();
	if (!nvfs_ops)
		return;

	idx = nvfs_ops->nvfs_gpu_index(page);

	if (idx != UINT_MAX) {
		id->ldi_type = LNET_DEV_TYPE_GPU;
		id->ldi_gpu_idx = idx;
	}

	nvfs_put_ops();
}

int lnet_rdma_map_sg_attrs(struct device *dev, struct scatterlist *sg,
			   int nents, enum dma_data_direction direction)
{
	struct nvfs_dma_rw_ops *nvfs_ops = nvfs_get_ops();

	if (nvfs_ops) {
		int count;

		count = nvfs_ops->nvfs_dma_map_sg_attrs(dev,
				sg, nents, direction,
				DMA_ATTR_NO_WARN);

		if (unlikely((count == NVFS_IO_ERR))) {
			nvfs_put_ops();
			return -EIO;
		}

		if (unlikely(count == NVFS_CPU_REQ))
			nvfs_put_ops();
		else
			return count;
	}

	return 0;
}
EXPORT_SYMBOL(lnet_rdma_map_sg_attrs);

int lnet_rdma_unmap_sg(struct device *dev,
		       struct scatterlist *sg, int nents,
		       enum dma_data_direction direction)
{
	struct nvfs_dma_rw_ops *nvfs_ops = nvfs_get_ops();

	if (nvfs_ops) {
		int count;

		count = nvfs_ops->nvfs_dma_unmap_sg(dev, sg,
						    nents, direction);

		/* drop the count we got by calling nvfs_get_ops() */
		nvfs_put_ops();

		if (count) {
			nvfs_put_ops();
			return count;
		}
	}

	return 0;
}
EXPORT_SYMBOL(lnet_rdma_unmap_sg);

bool
lnet_is_rdma_only_page(struct page *page)
{
	bool is_gpu_page = false;
	struct nvfs_dma_rw_ops *nvfs_ops;

	LASSERT(page != NULL);

	if (lustre_is_p2prdma_page(page))
		return true;

	nvfs_ops = nvfs_get_ops();
	if (nvfs_ops != NULL) {
		is_gpu_page = nvfs_ops->nvfs_is_gpu_page(page);
		nvfs_put_ops();
	}
	return is_gpu_page;
}
EXPORT_SYMBOL(lnet_is_rdma_only_page);
