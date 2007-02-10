#ifndef __LIBCFS_DARWIN_UTILS_H__
#define __LIBCFS_DARWIN_UTILS_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#include <sys/random.h> 

#ifdef __KERNEL__
inline int isspace(char c);
char *strpbrk(const char *cs, const char *ct);
char * strsep(char **s, const char *ct);
size_t strnlen(const char * s, size_t count);
char * strstr(const char *in, const char *str);
char * strrchr(const char *p, int ch);
char * ul2dstr(unsigned long address, char *buf, int len);

#define simple_strtol(a1, a2, a3)               strtol(a1, a2, a3)
#define simple_strtoul(a1, a2, a3)              strtoul(a1, a2, a3)
#define simple_strtoll(a1, a2, a3)              strtoq(a1, a2, a3)
#define simple_strtoull(a1, a2, a3)             strtouq(a1, a2, a3)

#define test_bit(i, a)                          isset(a, i)
#define set_bit(i, a)                           setbit(a, i)
#define clear_bit(i, a)                         clrbit(a, i)

#define get_random_bytes(buf, len)              read_random(buf, len)

#endif  /* __KERNEL__ */

#ifndef min_t
#define min_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#endif
#ifndef max_t
#define max_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })
#endif

#define do_div(n,base)                          \
	({                                      \
	 __u64 __n = (n);                       \
	 __u32 __base = (base);                 \
	 __u32 __mod;                           \
						\
	 __mod = __n % __base;                  \
	 n = __n / __base;                      \
	 __mod;                                 \
	 })

#define NIPQUAD(addr)			\
	((unsigned char *)&addr)[0],	\
	((unsigned char *)&addr)[1],	\
	((unsigned char *)&addr)[2],	\
	((unsigned char *)&addr)[3]

#define HIPQUAD NIPQUAD

#ifndef LIST_CIRCLE
#define LIST_CIRCLE(elm, field)                                 \
	do {                                                    \
		(elm)->field.le_prev = &(elm)->field.le_next;   \
	} while (0)
#endif

#endif /* __XNU_UTILS_H__ */
