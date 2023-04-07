#ifndef _LIBCFS_FORTIFY_STRING_H
#define _LIBCFS_FORTIFY_STRING_H

#ifdef HAVE_LINUX_FORTIFY_STRING_HEADER
#include <linux/fortify-string.h>

/*
 * Linux v5.11-11104-ga28a6e860c6c introduces fortify-string.h
 * where an unsafe_memcpy is provided in Linux v5.18-rc5-1405-g43213daed6d6
 *
 * This following is excerpted from the Linux v6.1 fortified memcpy()
 * which resolves some corner cases, one of which is triggered in lustre
 */
#ifndef unsafe_memcpy

#include <linux/bug.h>
#include <linux/const.h>
#include <linux/limits.h>

#ifndef __RENAME
#define __RENAME(x) __asm__(#x)
#endif

void fortify_panic(const char *name) __noreturn __cold;
void __read_overflow(void) __compiletime_error("detected read beyond size of object (1st parameter)");
void __read_overflow2(void) __compiletime_error("detected read beyond size of object (2nd parameter)");
void __read_overflow2_field(size_t avail, size_t wanted) __compiletime_warning("detected read beyond size of field (2nd parameter); maybe use struct_group()?");
void __write_overflow(void) __compiletime_error("detected write beyond size of object (1st parameter)");
void __write_overflow_field(size_t avail, size_t wanted) __compiletime_warning("detected write beyond size of field (1st parameter); maybe use struct_group()?");

#define __compiletime_strlen(p)					\
({								\
	char *__p = (char *)(p);				\
	size_t __ret = SIZE_MAX;				\
	size_t __p_size = __member_size(p);			\
	if (__p_size != SIZE_MAX &&				\
	    __builtin_constant_p(*__p)) {			\
		size_t __p_len = __p_size - 1;			\
		if (__builtin_constant_p(__p[__p_len]) &&	\
		    __p[__p_len] == '\0')			\
			__ret = __builtin_strlen(__p);		\
	}							\
	__ret;							\
})

#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
extern void *__underlying_memchr(const void *p, int c, __kernel_size_t size) __RENAME(memchr);
extern int __underlying_memcmp(const void *p, const void *q, __kernel_size_t size) __RENAME(memcmp);
extern void *__underlying_memcpy(void *p, const void *q, __kernel_size_t size) __RENAME(memcpy);
extern void *__underlying_memmove(void *p, const void *q, __kernel_size_t size) __RENAME(memmove);
extern void *__underlying_memset(void *p, int c, __kernel_size_t size) __RENAME(memset);
extern char *__underlying_strcat(char *p, const char *q) __RENAME(strcat);
extern char *__underlying_strcpy(char *p, const char *q) __RENAME(strcpy);
extern __kernel_size_t __underlying_strlen(const char *p) __RENAME(strlen);
extern char *__underlying_strncat(char *p, const char *q, __kernel_size_t count) __RENAME(strncat);
extern char *__underlying_strncpy(char *p, const char *q, __kernel_size_t size) __RENAME(strncpy);
#else

#if defined(__SANITIZE_MEMORY__)
/*
 * For KMSAN builds all memcpy/memset/memmove calls should be replaced by the
 * corresponding __msan_XXX functions.
 */
#include <linux/kmsan_string.h>
#define __underlying_memcpy	__msan_memcpy
#define __underlying_memmove	__msan_memmove
#define __underlying_memset	__msan_memset
#else
#define __underlying_memcpy	__builtin_memcpy
#define __underlying_memmove	__builtin_memmove
#define __underlying_memset	__builtin_memset
#endif

#define __underlying_memchr	__builtin_memchr
#define __underlying_memcmp	__builtin_memcmp
#define __underlying_strcat	__builtin_strcat
#define __underlying_strcpy	__builtin_strcpy
#define __underlying_strlen	__builtin_strlen
#define __underlying_strncat	__builtin_strncat
#define __underlying_strncpy	__builtin_strncpy
#endif

/**
 * unsafe_memcpy - memcpy implementation with no FORTIFY bounds checking
 *
 * @dst: Destination memory address to write to
 * @src: Source memory address to read from
 * @bytes: How many bytes to write to @dst from @src
 * @justification: Free-form text or comment describing why the use is needed
 *
 * This should be used for corner cases where the compiler cannot do the
 * right thing, or during transitions between APIs, etc. It should be used
 * very rarely, and includes a place for justification detailing where bounds
 * checking has happened, and why existing solutions cannot be employed.
 */
#define unsafe_memcpy(dst, src, bytes, justification)		\
	__underlying_memcpy(dst, src, bytes)

/*
 * Clang's use of __builtin_*object_size() within inlines needs hinting via
 * __pass_*object_size(). The preference is to only ever use type 1 (member
 * size, rather than struct size), but there remain some stragglers using
 * type 0 that will be converted in the future.
 */
#define POS			__pass_object_size(1)
#define POS0			__pass_object_size(0)
#define __struct_size(p)	__builtin_object_size(p, 0)
#define __member_size(p)	__builtin_object_size(p, 1)

#define __compiletime_lessthan(bounds, length)	(	\
	__builtin_constant_p((bounds) < (length)) &&	\
	(bounds) < (length)				\
)


/*
 * To make sure the compiler can enforce protection against buffer overflows,
 * memcpy(), memmove(), and memset() must not be used beyond individual
 * struct members. If you need to copy across multiple members, please use
 * struct_group() to create a named mirror of an anonymous struct union.
 * (e.g. see struct sk_buff.) Read overflow checking is currently only
 * done when a write overflow is also present, or when building with W=1.
 *
 * Mitigation coverage matrix
 *					Bounds checking at:
 *					+-------+-------+-------+-------+
 *					| Compile time  |   Run time    |
 * memcpy() argument sizes:		| write | read  | write | read  |
 *        dest     source   length      +-------+-------+-------+-------+
 * memcpy(known,   known,   constant)	|   y   |   y   |  n/a  |  n/a  |
 * memcpy(known,   unknown, constant)	|   y   |   n   |  n/a  |   V   |
 * memcpy(known,   known,   dynamic)	|   n   |   n   |   B   |   B   |
 * memcpy(known,   unknown, dynamic)	|   n   |   n   |   B   |   V   |
 * memcpy(unknown, known,   constant)	|   n   |   y   |   V   |  n/a  |
 * memcpy(unknown, unknown, constant)	|   n   |   n   |   V   |   V   |
 * memcpy(unknown, known,   dynamic)	|   n   |   n   |   V   |   B   |
 * memcpy(unknown, unknown, dynamic)	|   n   |   n   |   V   |   V   |
 *					+-------+-------+-------+-------+
 *
 * y = perform deterministic compile-time bounds checking
 * n = cannot perform deterministic compile-time bounds checking
 * n/a = no run-time bounds checking needed since compile-time deterministic
 * B = can perform run-time bounds checking (currently unimplemented)
 * V = vulnerable to run-time overflow (will need refactoring to solve)
 *
 */
extern __always_inline __gnu_inline
bool fortify_memcpy_chk(__kernel_size_t size,
					 const size_t p_size,
					 const size_t q_size,
					 const size_t p_size_field,
					 const size_t q_size_field,
					 const char *func)
{
	if (__builtin_constant_p(size)) {
		/*
		 * Length argument is a constant expression, so we
		 * can perform compile-time bounds checking where
		 * buffer sizes are also known at compile time.
		 */

		/* Error when size is larger than enclosing struct. */
		if (__compiletime_lessthan(p_size_field, p_size) &&
		    __compiletime_lessthan(p_size, size))
			__write_overflow();
		if (__compiletime_lessthan(q_size_field, q_size) &&
		    __compiletime_lessthan(q_size, size))
			__read_overflow2();

		/* Warn when write size argument larger than dest field. */
		if (__compiletime_lessthan(p_size_field, size))
			__write_overflow_field(p_size_field, size);
		/*
		 * Warn for source field over-read when building with W=1
		 * or when an over-write happened, so both can be fixed at
		 * the same time.
		 */
		if ((IS_ENABLED(KBUILD_EXTRA_WARN1) ||
		     __compiletime_lessthan(p_size_field, size)) &&
		    __compiletime_lessthan(q_size_field, size))
			__read_overflow2_field(q_size_field, size);
	}
	/*
	 * At this point, length argument may not be a constant expression,
	 * so run-time bounds checking can be done where buffer sizes are
	 * known. (This is not an "else" because the above checks may only
	 * be compile-time warnings, and we want to still warn for run-time
	 * overflows.)
	 */

	/*
	 * Always stop accesses beyond the struct that contains the
	 * field, when the buffer's remaining size is known.
	 * (The SIZE_MAX test is to optimize away checks where the buffer
	 * lengths are unknown.)
	 */
	if ((p_size != SIZE_MAX && p_size < size) ||
	    (q_size != SIZE_MAX && q_size < size))
		fortify_panic(func);

	/*
	 * Warn when writing beyond destination field size.
	 *
	 * We must ignore p_size_field == 0 for existing 0-element
	 * fake flexible arrays, until they are all converted to
	 * proper flexible arrays.
	 *
	 * The implementation of __builtin_*object_size() behaves
	 * like sizeof() when not directly referencing a flexible
	 * array member, which means there will be many bounds checks
	 * that will appear at run-time, without a way for them to be
	 * detected at compile-time (as can be done when the destination
	 * is specifically the flexible array member).
	 * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=101832
	 */
	if (p_size_field != 0 && p_size_field != SIZE_MAX &&
	    p_size != p_size_field && p_size_field < size)
		return true;

	return false;
}

#define __fortify_memcpy_chk(p, q, size, p_size, q_size,		\
			     p_size_field, q_size_field, op) ({		\
	const size_t __fortify_size = (size_t)(size);			\
	const size_t __p_size = (p_size);				\
	const size_t __q_size = (q_size);				\
	const size_t __p_size_field = (p_size_field);			\
	const size_t __q_size_field = (q_size_field);			\
	WARN_ONCE(fortify_memcpy_chk(__fortify_size, __p_size,		\
				     __q_size, __p_size_field,		\
				     __q_size_field, #op),		\
		  #op ": detected field-spanning write (size %zu) of single %s (size %zu)\n", \
		  __fortify_size,					\
		  "field \"" #p "\" at " __FILE__ ":" __stringify(__LINE__), \
		  __p_size_field);					\
	__underlying_##op(p, q, __fortify_size);			\
})

/*
 * Notes about compile-time buffer size detection:
 *
 * With these types...
 *
 *	struct middle {
 *		u16 a;
 *		u8 middle_buf[16];
 *		int b;
 *	};
 *	struct end {
 *		u16 a;
 *		u8 end_buf[16];
 *	};
 *	struct flex {
 *		int a;
 *		u8 flex_buf[];
 *	};
 *
 *	void func(TYPE *ptr) { ... }
 *
 * Cases where destination size cannot be currently detected:
 * - the size of ptr's object (seemingly by design, gcc & clang fail):
 *	__builtin_object_size(ptr, 1) == SIZE_MAX
 * - the size of flexible arrays in ptr's obj (by design, dynamic size):
 *	__builtin_object_size(ptr->flex_buf, 1) == SIZE_MAX
 * - the size of ANY array at the end of ptr's obj (gcc and clang bug):
 *	__builtin_object_size(ptr->end_buf, 1) == SIZE_MAX
 *	https://gcc.gnu.org/bugzilla/show_bug.cgi?id=101836
 *
 * Cases where destination size is currently detected:
 * - the size of non-array members within ptr's object:
 *	__builtin_object_size(ptr->a, 1) == 2
 * - the size of non-flexible-array in the middle of ptr's obj:
 *	__builtin_object_size(ptr->middle_buf, 1) == 16
 *
 */

/*
 * __struct_size() vs __member_size() must be captured here to avoid
 * evaluating argument side-effects further into the macro layers.
 */
#define memcpy(p, q, s)  __fortify_memcpy_chk(p, q, s,			\
		__struct_size(p), __struct_size(q),			\
		__member_size(p), __member_size(q),			\
		memcpy)

#endif /* HAVE_LINUX_FORTIFY_STRING_HEADER */
#endif /* unsafe_memcpy */

/* a catch all to ensure an unsafe_memcpy() exists */
#ifndef unsafe_memcpy
#define unsafe_memcpy(dst, src, bytes, justification)		\
	memcpy(dst, src, bytes)
#endif

#endif /* _LIBCFS_FORTIFY_STRING_H */
