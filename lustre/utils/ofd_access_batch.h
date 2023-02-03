#ifndef _OFD_ACCESS_BATCH_H_
#define _OFD_ACCESS_BATCH_H_
#include <pthread.h>
#include <sys/types.h>
#include <linux/types.h>
#include <libcfs/util/list.h>

struct lu_fid;
struct alr_batch;

struct alr_batch *alr_batch_create(unsigned int shift);
void alr_batch_destroy(struct alr_batch *alrb);
int alr_batch_add(struct alr_batch *alrb, const char *obd_name,
		const struct lu_fid *pfid, time_t time, __u64 begin, __u64 end,
		__u32 size, __u32 segment_count, __u32 flags);
int alr_batch_print(struct alr_batch *alrb, FILE *file,
		    pthread_mutex_t *file_mutex, int fraction);

/*
 * The code is inspired by the kernel list implementation. Hence, this has
 * a weird param order to be consistent with the kernel list_replace_init().
 */
static inline void list_replace_init(struct list_head *old_node,
				     struct list_head *new_node)
{
	list_add(new_node, old_node);
	list_del_init(old_node);
}

#endif /* _OFD_ACCESS_BATCH_H_ */
