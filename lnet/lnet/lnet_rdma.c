#include <lnet/lnet_rdma.h>
#include <libcfs/libcfs.h>
#include <lnet/lib-lnet.h>

#define ERROR_PRINT_DEADLINE 3600

atomic_t nvfs_shutdown = ATOMIC_INIT(1);
struct nvfs_dma_rw_ops *nvfs_ops = NULL;
struct percpu_counter nvfs_n_ops;

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
EXPORT_SYMBOL(REGISTER_FUNC);

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
EXPORT_SYMBOL(UNREGISTER_FUNC);

unsigned int
lnet_get_dev_prio(struct device *dev, unsigned int dev_idx)
{
	unsigned int dev_prio = UINT_MAX;
	struct nvfs_dma_rw_ops *nvfs_ops;

	if (!dev)
		return dev_prio;

	nvfs_ops = nvfs_get_ops();
	if (!nvfs_ops)
		return dev_prio;

	dev_prio = nvfs_ops->nvfs_device_priority (dev, dev_idx);

	nvfs_put_ops();
	return dev_prio;
}
EXPORT_SYMBOL(lnet_get_dev_prio);

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
	bool found = false;
	struct nvfs_dma_rw_ops *nvfs_ops;

	if (!page)
		return found;

	nvfs_ops = nvfs_get_ops();
	if (!nvfs_ops)
		return found;

	if (!nvfs_ops->nvfs_is_gpu_page(page))
		goto out;

	found = true;

out:
	nvfs_put_ops();
	return found;
}
EXPORT_SYMBOL(lnet_is_rdma_only_page);

unsigned int
lnet_get_dev_idx(struct page *page)
{
	unsigned int dev_idx = UINT_MAX;
	struct nvfs_dma_rw_ops *nvfs_ops;

	nvfs_ops = nvfs_get_ops();
	if (!nvfs_ops)
		return dev_idx;

	dev_idx = nvfs_ops->nvfs_gpu_index(page);

	nvfs_put_ops();
	return dev_idx;
}
EXPORT_SYMBOL(lnet_get_dev_idx);

