#ifndef _OFD_ACCESS_BATCH_H_
#define _OFD_ACCESS_BATCH_H_
#include <pthread.h>
#include <sys/types.h>
#include <linux/types.h>
#include <libcfs/util/list.h>
#include <errno.h>

extern FILE *debug_file;
extern FILE *trace_file;

#define DEBUG(fmt, args...)						\
	do {								\
		if (debug_file != NULL)					\
			fprintf(debug_file, "DEBUG %s:%d: "fmt,		\
				__func__, __LINE__, ##args);		\
	} while (0)

#define TRACE(fmt, args...)						\
	do {								\
		if (trace_file != NULL)					\
			fprintf(trace_file, "TRACE "fmt, ##args);	\
	} while (0)

#define DEBUG_D(x) DEBUG("%s = %"PRIdMAX"\n", #x, (intmax_t)x)
#define DEBUG_P(x) DEBUG("%s = %p\n", #x, x)
#define DEBUG_S(x) DEBUG("%s = '%s'\n", #x, x)
#define DEBUG_U(x) DEBUG("%s = %"PRIuMAX"\n", #x, (uintmax_t)x)

#define ERROR(fmt, args...) \
	fprintf(stderr, "%s: "fmt, program_invocation_short_name, ##args)

#define FATAL(fmt, args...)			\
	do {					\
		ERROR("FATAL: "fmt, ##args);	\
		exit(EXIT_FAILURE);		\
	} while (0)

struct lu_fid;
struct alr_batch;
extern unsigned long keepalive_interval;

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
