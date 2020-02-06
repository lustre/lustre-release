#ifndef LUSTRE_NVFS_H
#define LUSTRE_NVFS_H

#include <linux/types.h>
#include <linux/delay.h>
#include <linux/blkdev.h>
#include <linux/cpumask.h>
#include <linux/scatterlist.h>
#include <linux/percpu-defs.h>
#include <linux/dma-direction.h>
#include <linux/dma-mapping.h>

#define REGSTR2(x) x##_register_nvfs_dma_ops
#define REGSTR(x)  REGSTR2(x)

#define UNREGSTR2(x) x##_unregister_nvfs_dma_ops
#define UNREGSTR(x)  UNREGSTR2(x)

#define MODULE_PREFIX lustre_v1

#define REGISTER_FUNC REGSTR(MODULE_PREFIX)
#define UNREGISTER_FUNC UNREGSTR(MODULE_PREFIX)

#define NVFS_IO_ERR			-1
#define NVFS_CPU_REQ			-2

#define NVFS_HOLD_TIME_MS 1000

struct nvfs_dma_rw_ops {
	unsigned long long ft_bmap; /* feature bitmap */

	int (*nvfs_blk_rq_map_sg) (struct request_queue *q,
				   struct request *req,
				   struct scatterlist *sglist);

	int (*nvfs_dma_map_sg_attrs) (struct device *device,
				      struct scatterlist *sglist,
			              int nents,
				      enum dma_data_direction dma_dir,
				      unsigned long attrs);

	int (*nvfs_dma_unmap_sg)  (struct device *device,
				   struct scatterlist *sglist,
				   int nents,
				   enum dma_data_direction dma_dir);
	bool (*nvfs_is_gpu_page) (struct page *);
	unsigned int (*nvfs_gpu_index) (struct page *page);
	unsigned int (*nvfs_device_priority) (struct device *dev, unsigned int dev_index);
};

/* feature list for dma_ops, values indicate bit pos */
enum ft_bits {
	nvfs_ft_prep_sglist         = 1ULL << 0,
	nvfs_ft_map_sglist          = 1ULL << 1,
	nvfs_ft_is_gpu_page         = 1ULL << 2,
	nvfs_ft_device_priority     = 1ULL << 3,
};

/* check features for use in registration with vendor drivers */
#define NVIDIA_FS_CHECK_FT_SGLIST_PREP(ops) \
	((ops)->ft_bmap & nvfs_ft_prep_sglist)
#define NVIDIA_FS_CHECK_FT_SGLIST_DMA(ops) \
	((ops)->ft_bmap & nvfs_ft_map_sglist)
#define NVIDIA_FS_CHECK_FT_GPU_PAGE(ops) \
	((ops)->ft_bmap & nvfs_ft_is_gpu_page)
#define NVIDIA_FS_CHECK_FT_DEVICE_PRIORITY(ops) \
	((ops)->ft_bmap & nvfs_ft_device_priority)

int REGISTER_FUNC (struct nvfs_dma_rw_ops *ops);

void UNREGISTER_FUNC (void);

unsigned int lnet_get_dev_prio(struct device *dev,
			       unsigned int dev_idx);
int lnet_rdma_map_sg_attrs(struct device *dev, struct scatterlist *sg,
			   int nents, enum dma_data_direction direction);
int lnet_rdma_unmap_sg(struct device *dev,
		       struct scatterlist *sg, int nents,
		       enum dma_data_direction direction);
bool lnet_is_rdma_only_page(struct page *page);
unsigned int lnet_get_dev_idx(struct page *page);

/* DMA_ATTR_NO_WARN was added to kernel v4.8-11962-ga9a62c9 */
#ifndef DMA_ATTR_NO_WARN
#define DMA_ATTR_NO_WARN 0
#endif

#endif /* LUSTRE_NVFS_H */

