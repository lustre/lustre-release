/*
 * Try to be a little smarter about which kernel are we currently running
 */

#ifndef __rh_config_h__
#define __rh_config_h__

/*
 * First, get the version string for the running kernel from
 * /boot/kernel.h - initscripts should create it for us
 */

#include "/boot/kernel.h"

#if defined(__BOOT_KERNEL_SMP) && (__BOOT_KERNEL_SMP == 1)
#define __module__smp
#endif /* __BOOT_KERNEL_SMP */

#if defined(__BOOT_KERNEL_BOOT) && (__BOOT_KERNEL_BOOT == 1)
#define __module__BOOT
#endif /* __BOOT_KERNEL_BOOT */

#if defined(__BOOT_KERNEL_BOOTSMP) && (__BOOT_KERNEL_BOOTSMP == 1)
#define __module__BOOTsmp
#endif /* __BOOT_KERNEL_BOOTSMP */

#if defined(__BOOT_KERNEL_ENTERPRISE) && (__BOOT_KERNEL_ENTERPRISE == 1)
#define __module__enterprise
#endif /* __BOOT_KERNEL_ENTERPRISE */

#if defined(__BOOT_KERNEL_BIGMEM) && (__BOOT_KERNEL_BIGMEM == 1)
#define __module__bigmem
#endif /* __BOOT_KERNEL_BIGMEM */

#if defined(__BOOT_KERNEL_DEBUG) && (__BOOT_KERNEL_DEBUG == 1)
#define __module__debug
#endif /* __BOOT_KERNEL_DEBUG */

#if !defined(__module__smp) && !defined(__module__BOOT) && !defined(__module__BOOTsmp) && !defined(__module__enterprise) && !defined(__module__bigmem) && !defined(__module__debug)
#define __module__up
#endif /* default (BOOT_KERNEL_UP) */

#ifdef __i386__
# if defined(__MODULE_KERNEL_i586) && (__MODULE_KERNEL_i586 == 1)
#  define __module__i586
#  ifdef __module__up
#   define __module__i586_up
#  endif
#  ifdef __module__smp
#   define __module__i586_smp
#  endif
#  ifdef __module__BOOT
#   define __module__i586_BOOT
#  endif
#  ifdef __module__BOOTsmp
#   define __module__i586_BOOTsmp
#  endif
#  ifdef __module__enterprise
#   define __module__i586_enterprise
#  endif
#  ifdef __module__debug
#   define __module_i586_debug
#  endif
# elif defined(__MODULE_KERNEL_i686) && (__MODULE_KERNEL_i686 == 1)
#  define __module__i686
#  ifdef __module__up
#   define __module__i686_up
#  endif
#  ifdef __module__smp
#   define __module__i686_smp
#  endif
#  ifdef __module__BOOT
#   define __module__i686_BOOT
#  endif
#  ifdef __module__BOOTsmp
#   define __module__i686_BOOTsmp
#  endif
#  ifdef __module__enterprise
#   define __module__i686_enterprise
#  endif
#  ifdef __module__bigmem
#   define __module__i686_bigmem
#  endif
#  ifdef __module__debug
#   define __module_i686_debug
#  endif
# elif defined(__MODULE_KERNEL_athlon) && (__MODULE_KERNEL_athlon == 1)
#  define __module__athlon
#  ifdef __module__up
#   define __module__athlon_up
#  endif
#  ifdef __module__smp
#   define __module__athlon_smp
#  endif
#  ifdef __module__BOOT
#   define __module__athlon_BOOT
#  endif
#  ifdef __module__BOOTsmp
#   define __module__athlon_BOOTsmp
#  endif
#  ifdef __module__enterprise
#   define __module__athlon_enterprise
#  endif
#  ifdef __module__bigmem
#   define __module__athlon_bigmem
#  endif
#  ifdef __module__debug
#   define __module__athlon_debug
#  endif
# else
#  define __module__i386
#  ifdef __module__up
#   define __module__i386_up
#  endif
#  ifdef __module__smp
#   define __module__i386_smp
#  endif
#  ifdef __module__BOOT
#   define __module__i386_BOOT
#  endif
#  ifdef __module__BOOTsmp
#   define __module__i386_BOOTsmp
#  endif
#  ifdef __module__enterprise
#   define __module__i386_enterprise
#  endif
#  ifdef __module__debug
#   define __module__i386_debug
#  endif
# endif
#endif

#ifdef __sparc__
# ifdef __arch64__
#  define __module__sparc64
#  ifdef __module__up
#   define __module__sparc64_up
#  endif
#  ifdef __module__smp
#   define __module__sparc64_smp
#  endif
#  ifdef __module__BOOT
#   define __module__sparc64_BOOT
#  endif
#  ifdef __module__BOOTsmp
#   define __module__sparc64_BOOTsmp
#  endif
#  ifdef __module__enterprise
#   define __module__sparc64_enterprise
#  endif
#  ifdef __module__debug
#   define __module__sparc64_debug
#  endif
# else
#  define __module__sparc
#  ifdef __module__up
#   define __module__sparc_up
#  endif
#  ifdef __module__smp
#   define __module__sparc_smp
#  endif
#  ifdef __module__BOOT
#   define __module__sparc_BOOT
#  endif
#  ifdef __module__BOOTsmp
#   define __module__sparc_BOOTsmp
#  endif
#  ifdef __module__enterprise
#   define __module__sparc_enterprise
#  endif
#  ifdef __module__debug
#   define __module__sparc_debug
#  endif
# endif
#endif

#ifdef __alpha__
# define __module__alpha
# ifdef __module__up
#  define __module__alpha_up
# endif
# ifdef __module__smp
#  define __module__alpha_smp
# endif
# ifdef __module__BOOT
#  define __module__alpha_BOOT
# endif
# ifdef __module__BOOTsmp
#  define __module__alpha_BOOTsmp
# endif
# ifdef __module__enterprise
#  define __module__alpha_enterprise
# endif
# ifdef __module__debug
#  define __module__alpha_debug
# endif
#endif

#ifdef __ia64__
# define __module__ia64
# ifdef __module__up
#  define __module__ia64_up
# endif
# ifdef __module__smp
#  define __module__ia64_smp
# endif
# ifdef __module__BOOT
#  define __module__ia64_BOOT
# endif
# ifdef __module__BOOTsmp
#  define __module__ia64_BOOTsmp
# endif
# ifdef __module__enterprise
#  define __module__ia64_enterprise
# endif
# ifdef __module__debug
#  define __module__ia64_debug
# endif
#endif

#if defined(__module__smp) || defined(__module__BOOTsmp) || defined(__module__enterprise) || defined(__module__bigmem)
#define _ver_str(x) smp_ ## x
#else
#define _ver_str(x) x
#endif

#define RED_HAT_LINUX_KERNEL 1

#endif /* __rh_config_h__ */
