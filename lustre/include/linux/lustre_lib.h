#ifndef _LUSTRE_LIB_H
#define _LUSTRE_LIB_H

#include <asm/types.h>

#ifndef __KERNEL__
# include <string.h>
#endif

#undef MIN
#define MIN(a,b) (((a)<(b)) ? (a): (b))
#undef MAX
#define MAX(a,b) (((a)>(b)) ? (a): (b))
#define MKSTR(ptr) ((ptr))? (ptr) : ""

static inline int size_round (int val)
{
	return (val + 3) & (~0x3);
}

static inline size_t round_strlen(char *fset)
{
	return size_round(strlen(fset) + 1);
}

#ifdef __KERNEL__
static inline char *strdup(char *str)
{
	char *tmp = kmalloc(strlen(str) + 1, GFP_KERNEL);
	if (tmp)
		memcpy(tmp, str, strlen(str) + 1);
		
	return NULL;
}
#endif

#ifdef __KERNEL__
# define NTOH__u32(var) le32_to_cpu(var)
# define NTOH__u64(var) le64_to_cpu(var)
# define HTON__u32(var) cpu_to_le32(var)
# define HTON__u64(var) cpu_to_le64(var)
#else
# include <glib.h>
# define NTOH__u32(var) GUINT32_FROM_LE(var)
# define NTOH__u64(var) GUINT64_FROM_LE(var)
# define HTON__u32(var) GUINT32_TO_LE(var)
# define HTON__u64(var) GUINT64_TO_LE(var)
#endif

/* 
 * copy sizeof(type) bytes from pointer to var and move ptr forward.
 * return EFAULT if pointer goes beyond end
 */
#define UNLOGV(var,type,ptr,end)                \
do {                                            \
        var = *(type *)ptr;                     \
        ptr += sizeof(type);                    \
        if (ptr > end )                         \
                return -EFAULT;                 \
} while (0)

/* the following two macros convert to little endian */
/* type MUST be __u32 or __u64 */
#define LUNLOGV(var,type,ptr,end)               \
do {                                            \
        var = NTOH##type(*(type *)ptr);         \
        ptr += sizeof(type);                    \
        if (ptr > end )                         \
                return -EFAULT;                 \
} while (0)

/* now log values */
#define LOGV(var,type,ptr)                      \
do {                                            \
        *((type *)ptr) = var;                   \
        ptr += sizeof(type);                    \
} while (0)

/* and in network order */
#define LLOGV(var,type,ptr)                     \
do {                                            \
        *((type *)ptr) = HTON##type(var);       \
        ptr += sizeof(type);                    \
} while (0)


/* 
 * set var to point at (type *)ptr, move ptr forward with sizeof(type)
 * return from function with EFAULT if ptr goes beyond end
 */
#define UNLOGP(var,type,ptr,end)                \
do {                                            \
        var = (type *)ptr;                      \
        ptr += sizeof(type);                    \
        if (ptr > end )                         \
                return -EFAULT;                 \
} while (0)

#define LOGP(var,type,ptr)                      \
do {                                            \
        memcpy(ptr, var, sizeof(type));         \
        ptr += sizeof(type);                    \
} while (0)

/* 
 * set var to point at (char *)ptr, move ptr forward by size_round(len);
 * return from function with EFAULT if ptr goes beyond end
 */
#define UNLOGL(var,type,len,ptr,end)            \
do {                                            \
        var = (type *)ptr;                      \
        ptr += size_round(len * sizeof(type));  \
        if (ptr > end )                         \
                return -EFAULT;                 \
} while (0)


#define LOGL(var,len,ptr)                               \
do {                                                    \
        memcpy((char *)ptr, (const char *)var, len);    \
        ptr += size_round(len);                         \
} while (0)

#endif /* _LUSTRE_LIB_H */
