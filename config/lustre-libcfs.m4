# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

#
# LIBCFS_CONFIG_CDEBUG
#
# whether to enable various libcfs debugs (CDEBUG, ENTRY/EXIT, LASSERT, etc.)
#
AC_DEFUN([LIBCFS_CONFIG_CDEBUG], [
AC_MSG_CHECKING([whether to enable CDEBUG, CWARN])
AC_ARG_ENABLE([libcfs_cdebug],
	AS_HELP_STRING([--disable-libcfs-cdebug],
		[disable libcfs CDEBUG, CWARN]),
	[], [enable_libcfs_cdebug="yes"])
AC_MSG_RESULT([$enable_libcfs_cdebug])
AS_IF([test "x$enable_libcfs_cdebug" = xyes], [
	AC_DEFINE(CDEBUG_ENABLED, 1, [enable libcfs CDEBUG, CWARN])
	AC_SUBST(ENABLE_LIBCFS_CDEBUG, yes)
], [
	AC_SUBST(ENABLE_LIBCFS_CDEBUG, no)
])

AC_MSG_CHECKING([whether to enable ENTRY/EXIT])
AC_ARG_ENABLE([libcfs_trace],
	AS_HELP_STRING([--disable-libcfs-trace],
		[disable libcfs ENTRY/EXIT]),
	[], [enable_libcfs_trace="yes"])
AC_MSG_RESULT([$enable_libcfs_trace])
AS_IF([test "x$enable_libcfs_trace" = xyes], [
	AC_DEFINE(CDEBUG_ENTRY_EXIT, 1, [enable libcfs ENTRY/EXIT])
	AC_SUBST(ENABLE_LIBCFS_TRACE, yes)
], [
	AC_SUBST(ENABLE_LIBCFS_TRACE, no)
])

AC_MSG_CHECKING([whether to enable LASSERT, LASSERTF])
AC_ARG_ENABLE([libcfs_assert],
	AS_HELP_STRING([--disable-libcfs-assert],
		[disable libcfs LASSERT, LASSERTF]),
	[], [enable_libcfs_assert="yes"])
AC_MSG_RESULT([$enable_libcfs_assert])
AS_IF([test x$enable_libcfs_assert = xyes], [
	AC_DEFINE(LIBCFS_DEBUG, 1, [enable libcfs LASSERT, LASSERTF])
	AC_SUBST(ENABLE_LIBCFS_ASSERT, yes)
], [
	AC_SUBST(ENABLE_LIBCFS_ASSERT, no)
])
]) # LIBCFS_CONFIG_CDEBUG

#
# LIBCFS_CONFIG_PANIC_DUMPLOG
#
# check if tunable panic_dumplog is wanted
#
AC_DEFUN([LIBCFS_CONFIG_PANIC_DUMPLOG], [
AC_MSG_CHECKING([whether to use tunable 'panic_dumplog' support])
AC_ARG_ENABLE([panic_dumplog],
	AS_HELP_STRING([--enable-panic_dumplog],
		[enable panic_dumplog]),
	[], [enable_panic_dumplog="no"])
AC_MSG_RESULT([$enable_panic_dumplog])
AS_IF([test "x$enable_panic_dumplog" = xyes], [
	AC_DEFINE(LNET_DUMP_ON_PANIC, 1, [use dumplog on panic])
	AC_SUBST(ENABLE_PANIC_DUMPLOG, yes)
], [
	AC_SUBST(ENABLE_PANIC_DUMPLOG, no)
])
]) # LIBCFS_CONFIG_PANIC_DUMPLOG

#
# LIBCFS_KOBJ_TYPE_DEFAULT_GROUPS
#
# Linux commit v5.1-rc3-29-gaa30f47cf666
#    kobject: Add support for default attribute groups to kobj_type
# Linux commit v5.18-rc1-2-gcdb4f26a63c3
#    kobject: kobj_type: remove default_attrs
#
AC_DEFUN([LIBCFS_SRC_KOBJ_TYPE_DEFAULT_GROUPS],[
	LB2_LINUX_TEST_SRC([kobj_type_default_groups], [
		#include <linux/kobject.h>
	],[
		struct kobj_type *kobj_type = NULL;
		void *has = kobj_type->default_groups;
		(void) has;
	])
])
AC_DEFUN([LIBCFS_KOBJ_TYPE_DEFAULT_GROUPS],[
	LB2_MSG_LINUX_TEST_RESULT([if struct kobj_type have 'default_groups' member],
	[kobj_type_default_groups], [
		AC_DEFINE(HAVE_KOBJ_TYPE_DEFAULT_GROUPS, 1,
			[struct kobj_type has 'default_groups' member])
	])
]) # LIBCFS_KOBJ_TYPE_DEFAULT_GROUPS

#
# LIBCFS_LOOKUP_USER_KEY
#
# kernel 5.3 commit 3cf5d076fb4d48979f382bc9452765bf8b79e740
# signal: Remove task parameter from force_sig
#
AC_DEFUN([LIBCFS_SRC_LOOKUP_USER_KEY], [
	LB2_LINUX_TEST_SRC([lookup_user_key_exported], [
		#include <linux/key.h>
		#include <linux/keyctl.h>
	],[
		lookup_user_key(KEY_SPEC_USER_KEYRING, 0, 0);
	],[-Werror])
])
AC_DEFUN([LIBCFS_LOOKUP_USER_KEY], [
	LB2_MSG_LINUX_TEST_RESULT([if lookup_user_key() is available],
	[lookup_user_key_exported], [
		AC_DEFINE(HAVE_LOOKUP_USER_KEY, 1,
			[lookup_user_key() is available])
	])
]) # LIBCFS_LOOKUP_USER_KEY

#
# LIBCFS_CACHE_DETAIL_WRITERS
#
# kernel v5.3-rc2-1-g64a38e840ce5
# SUNRPC: Track writers of the 'channel' file to improve cache_listeners_exist
#
AC_DEFUN([LIBCFS_SRC_CACHE_DETAIL_WRITERS], [
	LB2_LINUX_TEST_SRC([cache_detail_writers_atomic], [
		#include <linux/sunrpc/cache.h>

		static struct cache_detail rsi_cache;
	],[
		atomic_set(&rsi_cache.writers, 0);
	],[-Werror])
])
AC_DEFUN([LIBCFS_CACHE_DETAIL_WRITERS], [
	LB2_MSG_LINUX_TEST_RESULT([if struct cache_detail has writers],
	[cache_detail_writers_atomic], [
		AC_DEFINE(HAVE_CACHE_DETAIL_WRITERS, 1,
			[struct cache_detail has writers])
	])
]) # LIBCFS_CACHE_DETAIL_WRITERS

#
# LIBCFS_GENL_DUMPIT_INFO
#
# kernel v5.4-rc1 commit bf813b0afeae2f012f0e527a526c1b78ca21ad82
# expanded struct genl_dumpit_info to include struct genl_family.
#
# kernel v6.5-rc5 commit 5c670a010de46 moved genl_family from
# struct genl_dumpit_info to struct genl_info.
#
# Note RHEL8 while earlier than 5.4 does have family info in
# struct genl_dumpit_info
#
AC_DEFUN([LIBCFS_SRC_GENL_DUMPIT_INFO], [
	LB2_LINUX_TEST_SRC([genl_dumpit_info], [
		#include <net/genetlink.h>
	],[
		static struct genl_dumpit_info info;

		info.family = NULL;
	],[-Werror])
])
AC_DEFUN([LIBCFS_GENL_DUMPIT_INFO], [
	LB2_MSG_LINUX_TEST_RESULT([if struct genl_dumpit_info has family field],
	[genl_dumpit_info], [
		AC_DEFINE(HAVE_GENL_DUMPIT_INFO, 1,
			[struct genl_dumpit_info has family field])
	])
]) # LIBCFS_GENL_DUMPIT_INFO

#
# LIBCFS_KALLSYMS_LOOKUP
#
# kernel v5.6-11591-g0bd476e6c671
# kallsyms: unexport kallsyms_lookup_name() and kallsyms_on_each_symbol()
AC_DEFUN([LIBCFS_KALLSYMS_LOOKUP], [
LB_CHECK_EXPORT([kallsyms_lookup_name], [kernel/kallsyms.c],
	[AC_DEFINE(HAVE_KALLSYMS_LOOKUP_NAME, 1,
		[kallsyms_lookup_name is exported by kernel])])
]) # LIBCFS_KALLSYMS_LOOKUP

#
# v5.5-8862-gd56c0d45f0e2
# proc: decouple proc from VFS with "struct proc_ops"
#
AC_DEFUN([LIBCFS_SRC_HAVE_PROC_OPS], [
	LB2_LINUX_TEST_SRC([proc_ops], [
		#include <linux/proc_fs.h>

		static struct proc_ops *my_proc;
	],[
		my_proc->proc_lseek = NULL;
	],[-Werror])
]) # LIBCFS_SRC_HAVE_PROC_OPS
AC_DEFUN([LIBCFS_HAVE_PROC_OPS], [
	LB2_MSG_LINUX_TEST_RESULT([if struct proc_ops exists],
	[proc_ops], [
		AC_DEFINE(HAVE_PROC_OPS, 1,
			[struct proc_ops exists])
	])
]) # LIBCFS_HAVE_PROC_OPS

#
# LIBCFS_TCP_SOCK_SET_QUICKACK
# kernel v5.7-rc6-2504-gddd061b8daed
#   tcp: add tcp_sock_set_quickack
#
AC_DEFUN([LIBCFS_SRC_TCP_SOCK_SET_QUICKACK], [
	LB2_LINUX_TEST_SRC([tcp_sock_set_quickack_exists], [
		#include <linux/tcp.h>
	],[
		tcp_sock_set_quickack(NULL, 0);
	],[-Werror])
])
AC_DEFUN([LIBCFS_TCP_SOCK_SET_QUICKACK], [
	LB2_MSG_LINUX_TEST_RESULT([if 'tcp_sock_set_quickack()' exists],
	[tcp_sock_set_quickack_exists], [
		AC_DEFINE(HAVE_TCP_SOCK_SET_QUICKACK, 1,
			['tcp_sock_set_quickack()' exists])
	])
]) # LIBCFS_TCP_SOCK_SET_QUICKACK

#
# LIBCFS_TCP_SOCK_SET_KEEPINTVL
# v5.7-rc6-2508-gd41ecaac903c
# tcp: add tcp_sock_set_keepintvl
#
AC_DEFUN([LIBCFS_SRC_TCP_SOCK_SET_KEEPINTVL], [
	LB2_LINUX_TEST_SRC([tcp_sock_set_keepintvl_exists], [
		#include <linux/tcp.h>
	],[
		tcp_sock_set_keepintvl(NULL, 0);
	],[-Werror])
])
AC_DEFUN([LIBCFS_TCP_SOCK_SET_KEEPINTVL], [
	LB2_MSG_LINUX_TEST_RESULT([if 'tcp_sock_set_keepintvl()' exists],
	[tcp_sock_set_keepintvl_exists], [
		AC_DEFINE(HAVE_TCP_SOCK_SET_KEEPINTVL, 1,
			['tcp_sock_set_keepintvl()' exists])
	])
]) # LIBCFS_TCP_SOCK_SET_KEEPINTVL

#
# LIBCFS_TCP_SOCK_SET_KEEPCNT
# v5.7-rc6-2509-g480aeb9639d6
# tcp: add tcp_sock_set_keepcnt
#
AC_DEFUN([LIBCFS_SRC_TCP_SOCK_SET_KEEPCNT], [
	LB2_LINUX_TEST_SRC([tcp_sock_set_keepcnt_exists], [
		#include <linux/tcp.h>
	],[
		tcp_sock_set_keepcnt(NULL, 0);
	],[-Werror])
])
AC_DEFUN([LIBCFS_TCP_SOCK_SET_KEEPCNT], [
	LB2_MSG_LINUX_TEST_RESULT([if 'tcp_sock_set_keepcnt()' exists],
	[tcp_sock_set_keepcnt_exists], [
		AC_DEFINE(HAVE_TCP_SOCK_SET_KEEPCNT, 1,
			['tcp_sock_set_keepcnt()' exists])
	])
]) # LIBCFS_TCP_SOCK_SET_KEEPCNT

#
# LIBCFS_IP6_SET_PREF
#
# kernel v5.8-rc1~165^2~71^2~3 commit 18d5ad62327576cbb1e5b9938a59d63ac0c15832
# ipv6: add ip6_sock_set_addr_preferences
#
AC_DEFUN([LIBCFS_SRC_IP6_SET_PREF], [
	LB2_LINUX_TEST_SRC([ip6_set_pref_test], [
		#include <net/ipv6.h>
	],[
		ip6_sock_set_addr_preferences(NULL, 0);
	],[-Werror])
])
AC_DEFUN([LIBCFS_IP6_SET_PREF], [
	LB2_MSG_LINUX_TEST_RESULT([if ip6_sock_set_addr_preferences() exists],
	[ip6_set_pref_test], [
		AC_DEFINE(HAVE_IP6_SET_PREF, 1,
			[if ip6_sock_set_addr_preferences exists])
	])
]) # LIBCFS_IP6_SET_PREF

#
# LIBCFS_IP_SET_TOS
#
# kernel v5.8-rc1~165^2~71^2~3 commit 6ebf71bab9fb476fc8132be4c12b88201278f0ca
# ipv4: add ip_sock_set_tos
#
AC_DEFUN([LIBCFS_SRC_IP_SET_TOS], [
	LB2_LINUX_TEST_SRC([ip_set_tos_test], [
		#include <net/ip.h>
	],[
		ip_sock_set_tos(NULL, 0);
	],[-Werror])
])
AC_DEFUN([LIBCFS_IP_SET_TOS], [
	LB2_MSG_LINUX_TEST_RESULT([if ip_sock_set_tos() exists],
	[ip_set_tos_test], [
		AC_DEFINE(HAVE_IP_SET_TOS, 1,
			[if ip_sock_set_tos exists])
	])
]) # LIBCFS_IP_SET_TOS

#
# LIBCFS_VMALLOC_2ARGS
#
# kernel v5.8-rc1~201^2~19
# mm: remove the pgprot argument to __vmalloc
AC_DEFUN([LIBCFS_SRC_VMALLOC_2ARGS], [
	LB2_LINUX_TEST_SRC([vmalloc_2args], [
		#include <linux/vmalloc.h>
	],[
		__vmalloc(0, 0);
	],[])
])
AC_DEFUN([LIBCFS_VMALLOC_2ARGS], [
	LB2_MSG_LINUX_TEST_RESULT([if __vmalloc has 2 args],
	[vmalloc_2args], [
		AC_DEFINE(HAVE_VMALLOC_2ARGS, 1,
			[__vmalloc only takes 2 args.])
	])
]) # LIBCFS_VMALLOC_2ARGS

#
# LIBCFS_HAVE_NR_UNSTABLE_NFS
#
# kernel v5.8-rc1~201^2~75
# mm/writeback: discard NR_UNSTABLE_NFS, use NR_WRITEBACK instead
#
AC_DEFUN([LIBCFS_SRC_HAVE_NR_UNSTABLE_NFS], [
	LB2_LINUX_TEST_SRC([nr_unstable_nfs_exists], [
		#include <linux/mm.h>

		int i;
	],[
		i = NR_UNSTABLE_NFS;
	],[-Werror])
])
AC_DEFUN([LIBCFS_HAVE_NR_UNSTABLE_NFS], [
	LB2_MSG_LINUX_TEST_RESULT([if NR_UNSTABLE_NFS still in use],
	[nr_unstable_nfs_exists], [
		AC_DEFINE(HAVE_NR_UNSTABLE_NFS, 1,
			[NR_UNSTABLE_NFS is still in use.])
	])
]) # LIBCFS_HAVE_NR_UNSTABLE_NFS

#
# LIBCFS_NR_UNSTABLE_NFS_DEPRECATED
#
# SLES15 still defines NR_UNSTABLE_NFS, but DEPRECATED it
#
AC_DEFUN([LIBCFS_NR_UNSTABLE_NFS_DEPRECATED], [
	AC_MSG_CHECKING([if NR_UNSTABLE_NFS is defined but DEPRECATED])
	AS_IF([grep -q -E "NFS unstable pages - DEPRECATED DO NOT USE" "$LINUX/include/linux/mmzone.h" 2>/dev/null], [
		AC_DEFINE([HAVE_NR_UNSTABLE_NFS_DEPRECATED], 1,
			  [NR_UNSTABLE_NFS is defined but deprecated])
		AC_MSG_RESULT(yes)
	],[
		AC_MSG_RESULT(no)
	])
]) # LIBCFS_NR_UNSTABLE_NFS_DEPRECATED

#
# LIBCFS_HAVE_MMAP_LOCK
#
# kernel v5.8-rc1~83^2~24
# mmap locking API: rename mmap_sem to mmap_lock
#
AC_DEFUN([LIBCFS_SRC_HAVE_MMAP_LOCK], [
	LB2_LINUX_TEST_SRC([mmap_write_lock], [
		#include <linux/mm.h>
	],[
		mmap_write_lock(NULL);
	],[])
])
AC_DEFUN([LIBCFS_HAVE_MMAP_LOCK], [
	LB2_MSG_LINUX_TEST_RESULT([if mmap_lock API is available],
	[mmap_write_lock], [
		AC_DEFINE(HAVE_MMAP_LOCK, 1,
			[mmap_lock API is available.])
	])
]) # LIBCFS_HAVE_MMAP_LOCK

#
# LIBCFS_KERNEL_SETSOCKOPT
#
# kernel v5.8-rc1~165^2~59^2
# net: remove kernel_setsockopt
AC_DEFUN([LIBCFS_SRC_KERNEL_SETSOCKOPT], [
	LB2_LINUX_TEST_SRC([kernel_setsockopt_exists], [
		#include <linux/net.h>
	],[
		kernel_setsockopt(NULL, 0, 0, NULL, 0);
	],[-Werror])
])
AC_DEFUN([LIBCFS_KERNEL_SETSOCKOPT], [
	LB2_MSG_LINUX_TEST_RESULT([if kernel_setsockopt still in use],
	[kernel_setsockopt_exists], [
	AC_DEFINE(HAVE_KERNEL_SETSOCKOPT, 1,
		[kernel_setsockopt still in use])
	])
]) # LIBCFS_KERNEL_SETSOCKOPT

#
# LIBCFS_USER_UID_KEYRING
#
# kernel 5.2 commit 0f44e4d976f9 removed uid_keyring
# from the user_struct struct
#
AC_DEFUN([LIBCFS_SRC_USER_UID_KEYRING], [
	LB2_LINUX_TEST_SRC([user_uid_keyring_exists], [
		#include <linux/sched/user.h>
	],[
		((struct user_struct *)0)->uid_keyring = NULL;
	],[-Werror])
])
AC_DEFUN([LIBCFS_USER_UID_KEYRING], [
	AC_MSG_CHECKING([if uid_keyring exists])
	LB2_LINUX_TEST_RESULT([user_uid_keyring_exists], [
		AC_DEFINE(HAVE_USER_UID_KEYRING, 1,
			[uid_keyring exists])
	])
]) # LIBCFS_USER_UID_KEYRING

#
# LIBCFS_KEY_NEED_UNLINK
#
# kernel 5.8 commit 8c0637e950d68933a67f7438f779d79b049b5e5c
# keys: Make the KEY_NEED_* perms an enum rather than a mask
#
AC_DEFUN([LIBCFS_SRC_KEY_NEED_UNLINK], [
	LB2_LINUX_TEST_SRC([key_need_unlink_exists], [
		#include <linux/key.h>
		#include <linux/keyctl.h>
	],[
		lookup_user_key(0, 0, KEY_NEED_UNLINK);
	],[-Werror])
])
AC_DEFUN([LIBCFS_KEY_NEED_UNLINK], [
	LB2_MSG_LINUX_TEST_RESULT([if KEY_NEED_UNLINK exists],
	[key_need_unlink_exists], [
		AC_DEFINE(HAVE_KEY_NEED_UNLINK, 1,
			[KEY_NEED_UNLINK exists])
	])
]) # LIBCFS_KEY_NEED_UNLINK

#
# LIBCFS_SEC_RELEASE_SECCTX
#
# kernel linux-hwe-5.8 (5.8.0-22.23~20.04.1)
# LSM: Use lsmcontext in security_release_secctx
AC_DEFUN([LIBCFS_SRC_SEC_RELEASE_SECCTX], [
	LB2_LINUX_TEST_SRC([security_release_secctx_1arg], [
		#include <linux/security.h>
	],[
		security_release_secctx(NULL);
	],[])
])
AC_DEFUN([LIBCFS_SEC_RELEASE_SECCTX], [
	LB2_MSG_LINUX_TEST_RESULT([if security_release_secctx has 1 arg],
	[security_release_secctx_1arg], [
		AC_DEFINE(HAVE_SEC_RELEASE_SECCTX_1ARG, 1,
			[security_release_secctx has 1 arg.])
	])
]) # LIBCFS_SEC_RELEASE_SECCTX

#
# LIBCFS_HAVE_KMAP_LOCAL
#
# Linux commit v5.10-rc2-80-gf3ba3c710ac5
#   mm/highmem: Provide kmap_local*
#
AC_DEFUN([LIBCFS_SRC_HAVE_KMAP_LOCAL], [
	LB2_LINUX_TEST_SRC([kmap_local_page], [
		#include <linux/highmem.h>
	],[
		struct page *pg = NULL;
		void *kaddr = kmap_local_page(pg);

		kunmap_local(kaddr);
	],[-Werror])
])
AC_DEFUN([LIBCFS_HAVE_KMAP_LOCAL], [
	LB2_MSG_LINUX_TEST_RESULT([if 'kmap_local*' are available],
	[kmap_local_page], [
		AC_DEFINE(HAVE_KMAP_LOCAL, 1,
			[kmap_local_* functions are available])
	],[
		## Map kmap_local_page to kmap_atomic for older kernels
		AC_DEFINE([kmap_local_page(p)], [kmap_atomic(p)],
			  [need kmap_local_page map to atomic])
		AC_DEFINE([kunmap_local(kaddr)], [kunmap_atomic((kaddr))],
			  [need kunmap_local map to atomic])
	])
]) # LIBCFS_HAVE_KMAP_LOCAL

#
# LIBCFS_HAVE_KFREE_SENSITIVE
#
# kernel v5.10-rc1~3
# mm: remove kzfree() compatibility definition
#
AC_DEFUN([LIBCFS_SRC_HAVE_KFREE_SENSITIVE], [
	LB2_LINUX_TEST_SRC([kfree_sensitive_exists], [
		#include <linux/slab.h>
	],[
		kfree_sensitive(NULL);
	], [-Werror])
])
AC_DEFUN([LIBCFS_HAVE_KFREE_SENSITIVE], [
	LB2_MSG_LINUX_TEST_RESULT([if kfree_sensitive() is available],
	[kfree_sensitive_exists], [
		AC_DEFINE(HAVE_KFREE_SENSITIVE, 1,
			[kfree_sensitive() is available.])
	])
]) # LIBCFS_HAVE_KFREE_SENSITIVE

#
# LIBCFS_HAVE_CRYPTO_SHA2_HEADER
#
# Kernel v5.10-rc1-114-ga24d22b225ce
# crypto: sha - split sha.h into sha1.h and sha2.h
#
AC_DEFUN([LIBCFS_SRC_HAVE_CRYPTO_SHA2_HEADER], [
	LB2_CHECK_LINUX_HEADER_SRC([crypto/sha2.h], [-Werror])
])
AC_DEFUN([LIBCFS_HAVE_CRYPTO_SHA2_HEADER], [
	LB2_CHECK_LINUX_HEADER_RESULT([crypto/sha2.h], [
		AC_DEFINE(HAVE_CRYPTO_SHA2_HEADER, 1,
			[crypto/sha2.h is present])
	])
]) # LIBCFS_HAVE_CRYPTO_SHA2_HEADER

#
# LIBCFS_HAVE_LIST_CMP_FUNC_T
#
# kernel 5.10.70 commit 4f0f586bf0c898233d8f316f471a21db2abd522d
# treewide: Change list_sort to use const pointers
AC_DEFUN([LIBCFS_SRC_HAVE_LIST_CMP_FUNC_T], [
	LB2_LINUX_TEST_SRC([list_cmp_func_t_exists], [
		#include <linux/list_sort.h>
	],[
		list_cmp_func_t cmp;
		(void)cmp;
	], [-Werror])
])
AC_DEFUN([LIBCFS_HAVE_LIST_CMP_FUNC_T], [
	LB2_MSG_LINUX_TEST_RESULT([if list_cmp_func_t type is defined],
	[list_cmp_func_t_exists], [
		AC_DEFINE(HAVE_LIST_CMP_FUNC_T, 1,
			[list_cmp_func_t type is defined])
	])
]) # LIBCFS_HAVE_LIST_CMP_FUNC_T

#
# LIBCFS_NLA_STRLCPY
#
# Kernel version 5.10-rc3 commit 872f690341948b502c93318f806d821c56772c42
# replaced nla_strlcpy() with nla_strscpy().
#
AC_DEFUN([LIBCFS_SRC_NLA_STRLCPY], [
	LB2_LINUX_TEST_SRC([nla_strlcpy], [
		#include <net/netlink.h>
	],[
		if (nla_strlcpy(NULL, NULL, 0) == 0)
			return -EINVAL;
	])
])
AC_DEFUN([LIBCFS_NLA_STRLCPY], [
	LB2_MSG_LINUX_TEST_RESULT([if 'nla_strlcpy()' still exists],
	[nla_strlcpy], [
		AC_DEFINE(HAVE_NLA_STRLCPY, 1,
			['nla_strlcpy' is available])
	])
]) # LIBCFS_NLA_STRLCPY

#
# LIBCFS_RB_FIND
#
# Kernel v5.11-20-g2d24dd5798d0
#   rbtree: Add generic add and find helpers
#
AC_DEFUN([LIBCFS_SRC_RB_FIND], [
	LB2_LINUX_TEST_SRC([rb_find], [
		#include <linux/rbtree.h>
		static int cmp(const void *key, const struct rb_node *node)
		{
			return 0;
		}
	],[
		void *key = NULL;
		struct rb_root *tree = NULL;
		struct rb_node *node __maybe_unused = rb_find(key, tree, cmp);
	])
])
AC_DEFUN([LIBCFS_RB_FIND], [
	LB2_MSG_LINUX_TEST_RESULT([if 'rb_find()' is available],
	[rb_find], [
		AC_DEFINE(HAVE_RB_FIND, 1,
			['rb_find()' is available])
	])
]) # LIBCFS_RB_FIND

#
# LIBCFS_LINUX_FORTIFY_STRING_HEADER
#
# Linux v5.11-11104-ga28a6e860c6c
#  string.h: move fortified functions definitions in a dedicated header.
#
AC_DEFUN([LIBCFS_SRC_LINUX_FORTIFY_STRING_HEADER],[
	LB2_LINUX_TEST_SRC([linux_fortify_string_header], [
		#include <linux/fortify-string.h>
	],[
	],[])
])
AC_DEFUN([LIBCFS_LINUX_FORTIFY_STRING_HEADER],[
	LB2_MSG_LINUX_TEST_RESULT([if linux/fortify-string.h header available],
	[linux_fortify_string_header], [
		AC_DEFINE(HAVE_LINUX_FORTIFY_STRING_HEADER, 1,
			[linux/fortify-string.h header available])
	])
]) # LIBCFS_LINUX_FORTIFY_STRING_HEADER

#
# LIBCFS_HAVE_CIPHER_HEADER
#
# Kernel 5.12 commit 0eb76ba29d16df2951d37c54ca279c4e5630b071
# crypto: remove cipher routines from public crypto API
#
AC_DEFUN([LIBCFS_SRC_HAVE_CIPHER_HEADER], [
	LB2_CHECK_LINUX_HEADER_SRC([crypto/internal/cipher.h], [-Werror])
])
AC_DEFUN([LIBCFS_HAVE_CIPHER_HEADER], [
	LB2_CHECK_LINUX_HEADER_RESULT([crypto/internal/cipher.h], [
		AC_DEFINE(HAVE_CIPHER_H, 1,
			[crypto/internal/cipher.h is present])
	])
]) # LIBCFS_HAVE_CIPHER_HEADER

#
# LIBCFS_HAVE_TASK_RUNNING
#
# Kernel 5.13-rc6 commit b03fbd4ff24c5f075e58eb19261d5f8b3e40d
# introduced task_is_running() macro.
#
AC_DEFUN([LIBCFS_SRC_HAVE_TASK_IS_RUNNING], [
	LB2_LINUX_TEST_SRC([task_is_running], [
		#include <linux/sched.h>
	],[
		if (task_is_running(current))
			schedule();
	], [-Werror])
])
AC_DEFUN([LIBCFS_HAVE_TASK_IS_RUNNING], [
	LB2_MSG_LINUX_TEST_RESULT([if task_is_running() is defined],
	[task_is_running], [
		AC_DEFINE(HAVE_TASK_IS_RUNNING, 1,
			[task_is_running() is defined])
	])
]) # LIBCFS_HAVE_TASK_IS_RUNNING

#
# LIBCFS_LINUX_STDARG_HEADER
#
# Kernel 5.14-rc5 commit c0891ac15f0428ffa81b2e818d416bdf3cb74ab6
# isystem: ship and use stdarg.h
#
AC_DEFUN([LIBCFS_SRC_LINUX_STDARG_HEADER], [
	LB2_CHECK_LINUX_HEADER_SRC([linux/stdarg.h], [-Werror])
])
AC_DEFUN([LIBCFS_LINUX_STDARG_HEADER], [
	LB2_CHECK_LINUX_HEADER_RESULT([linux/stdarg.h], [
		AC_DEFINE(HAVE_LINUX_STDARG_HEADER, 1,
			[linux/stdarg.h is present])
	])
]) # LIBCFS_LINUX_STDARG_HEADER

#
# LIBCFS_HAVE_PANIC_NOTIFIER_HEADER
#
# Kernel 5.14 commit f39650de687e35766572ac89dbcd16a5911e2f0a
# kernel.h: split out panic and oops helpers
#
AC_DEFUN([LIBCFS_SRC_HAVE_PANIC_NOTIFIER_HEADER], [
	LB2_CHECK_LINUX_HEADER_SRC([linux/panic_notifier.h], [-Werror])
])
AC_DEFUN([LIBCFS_HAVE_PANIC_NOTIFIER_HEADER], [
	LB2_CHECK_LINUX_HEADER_RESULT([linux/panic_notifier.h], [
		AC_DEFINE(HAVE_PANIC_NOTIFIER_H, 1,
			[linux/panic_notifier.h is present])
	])
]) # LIBCFS_HAVE_PANIC_NOTIFIER_HEADER

#
# LIBCFS_PARAM_SET_UINT_MINMAX
#
# Kernel 5.15-rc1 commit 2a14c9ae15a38148484a128b84bff7e9ffd90d68
# moved param_set_uint_minmax to common code
#
AC_DEFUN([LIBCFS_SRC_PARAM_SET_UINT_MINMAX],[
	LB2_LINUX_TEST_SRC([param_set_uint_minmax], [
		#include <linux/moduleparam.h>
	],[
		param_set_uint_minmax(NULL, NULL, 0, 0);
	], [])
])
AC_DEFUN([LIBCFS_PARAM_SET_UINT_MINMAX],[
	LB2_MSG_LINUX_TEST_RESULT([if function 'param_set_uint_minmax' exist],
	[param_set_uint_minmax], [
		AC_DEFINE(HAVE_PARAM_SET_UINT_MINMAX, 1,
			['param_set_uint_minmax' is available])
	])
]) # LIBCFS_PARAM_SET_UINT_MINMAX

#
# LIBCFS_LINUX_BLK_INTEGRITY_HEADER
#
# Kernel 5.15-rc6 commit fe45e630a1035aea94c29016f2598bbde149bbe3
# block: move integrity handling out of <linux/blkdev.h>
#
AC_DEFUN([LIBCFS_SRC_LINUX_BLK_INTEGRITY_HEADER], [
	LB2_CHECK_LINUX_HEADER_SRC([linux/blk-integrity.h], [-Werror])
])
AC_DEFUN([LIBCFS_LINUX_BLK_INTEGRITY_HEADER], [
	LB2_CHECK_LINUX_HEADER_RESULT([linux/blk-integrity.h], [
		AC_DEFINE(HAVE_LINUX_BLK_INTEGRITY_HEADER, 1,
			[linux/blk-integrity.h is present])
	])
]) # LIBCFS_LINUX_BLK_INTEGRITY_HEADER

#
# LIBCFS_PDE_DATA_EXISTS
#
# Linux commit v5.16-11573-g6dfbbae14a7b
#    introduce pde_data()
# Linux commit v5.16-11574-g359745d78351
#    remove PDE_DATA()
#
AC_DEFUN([LIBCFS_SRC_PDE_DATA_EXISTS],[
	LB2_LINUX_TEST_SRC([pde_data], [
		#include <linux/proc_fs.h>
	],[
		struct inode *inode = NULL;
		void *data =pde_data(inode);
		(void)data;
	],[])
])
AC_DEFUN([LIBCFS_PDE_DATA_EXISTS],[
	LB2_MSG_LINUX_TEST_RESULT([if function 'pde_data' exist],
	[pde_data], [
		AC_DEFINE(HAVE_pde_data, 1, [function pde_data() available])
	],[
		AC_DEFINE(pde_data(inode), PDE_DATA(inode),
			  [function pde_data() unavailable])
	])
]) # LIBCFS_PDE_DATA_EXISTS

#
# LIBCFS_BIO_ALLOC_WITH_BDEV
#
# Linux commit v5.17-rc2-21-g07888c665b40
#   block: pass a block_device and opf to bio_alloc
#
AC_DEFUN([LIBCFS_SRC_BIO_ALLOC_WITH_BDEV],[
	LB2_LINUX_TEST_SRC([bio_alloc_with_bdev], [
		#include <linux/bio.h>
	],[
		struct block_device *bdev = NULL;
		unsigned short nr_vecs = 1;
		gfp_t gfp = GFP_KERNEL;
		struct bio *bio = bio_alloc(bdev, nr_vecs, REQ_OP_WRITE, gfp);
		(void) bio;
	],[])
])
AC_DEFUN([LIBCFS_BIO_ALLOC_WITH_BDEV],[
	LB2_MSG_LINUX_TEST_RESULT([if bio_alloc() takes a struct block_device],
	[bio_alloc_with_bdev], [
		AC_DEFINE(HAVE_BIO_ALLOC_WITH_BDEV, 1,
			[bio_alloc() takes a struct block_device])
	])
]) # LIBCFS_BIO_ALLOC_WITH_BDEV

#
# LIBCFS_TIMER_DELETE_SYNC
#
# Linux commit v6.1-rc1-7-g9a5a30568697
#   timers: Get rid of del_singleshot_timer_sync()
# Linux commit v6.1-rc1-11-g9b13df3fb64e
#   timers: Rename del_timer_sync() to timer_delete_sync()
#
AC_DEFUN([LIBCFS_SRC_TIMER_DELETE_SYNC],[
	LB2_LINUX_TEST_SRC([timer_delete_sync], [
		#include <linux/timer.h>
	],[
		struct timer_list *timer = NULL;
		(void)timer_delete_sync(timer);
	],[])
])
AC_DEFUN([LIBCFS_TIMER_DELETE_SYNC],[
	LB2_MSG_LINUX_TEST_RESULT([if timer_delete_sync() is available],
	[timer_delete_sync], [
		AC_DEFINE(HAVE_TIMER_DELETE_SYNC, 1,
			[timer_delete_sync() is available])
	],[
		AC_DEFINE(timer_delete_sync(t), del_timer_sync(t),
			[timer_delete_sync() not is available])
	])
]) # LIBCFS_TIMER_DELETE_SYNC

#
# LIBCFS_TIMER_DELETE_SYNC
#
# Linux commit v6.1-rc1-12-gbb663f0f3c39
#   timers: Rename del_timer() to timer_delete()
#
AC_DEFUN([LIBCFS_SRC_TIMER_DELETE],[
	LB2_LINUX_TEST_SRC([timer_delete], [
		#include <linux/timer.h>
	],[
		struct timer_list *timer = NULL;
		(void)timer_delete(timer);
	],[])
])
AC_DEFUN([LIBCFS_TIMER_DELETE],[
	LB2_MSG_LINUX_TEST_RESULT([if timer_delete() is available],
	[timer_delete], [
		AC_DEFINE(HAVE_TIMER_DELETE, 1,
			[timer_delete() is available])
	],[
		AC_DEFINE(timer_delete(t), del_timer(t),
			[timer_delete() not is available])
	])
]) # LIBCFS_TIMER_DELETE

#
# LIBCFS_CONSTIFY_CTR_TABLE
#
# Linux commit v6.10-12269-g78eb4ea25cd5
#   sysctl: treewide: constify the ctl_table argument of proc_handlers
#
AC_DEFUN([LIBCFS_SRC_CONSTIFY_CTR_TABLE],[
	LB2_LINUX_TEST_SRC([constify_struct_ctl_table], [
		#include <linux/sysctl.h>

		static int handler(const struct ctl_table *table, int write,
				   void __user *buf, size_t *lenp, loff_t *ppos)
		{
			return 0;
		}
	],[
		static struct ctl_table ctl_tbl __attribute__ ((unused)) = {
			.proc_handler	= &handler,
		};
	],[-Werror])
])
AC_DEFUN([LIBCFS_CONSTIFY_CTR_TABLE],[
	LB2_MSG_LINUX_TEST_RESULT(
	[if struct ctl_table argument to proc_handler() is const],
	[constify_struct_ctl_table], [
		AC_DEFINE(HAVE_CONST_CTR_TABLE, 1,
			[struct ctl_table argument to proc_handler() is const])
	])
]) # LIBCFS_CONSTIFY_CTR_TABLE

#
# LIBCFS_BLK_INTEGRITY_NOVERIFY
#
# Linux commit v6.10-rc3-25-g9f4aa46f2a74
#   block: invert the BLK_INTEGRITY_{GENERATE,VERIFY} flags
#
AC_DEFUN([LIBCFS_SRC_BLK_INTEGRITY_NOVERIFY], [
	LB2_LINUX_TEST_SRC([blk_integrity_noverify], [
		#include <linux/blk-integrity.h>
	],[
		int flag __attribute__ ((unused)) = BLK_INTEGRITY_NOVERIFY;
	],[-Werror])
])
AC_DEFUN([LIBCFS_BLK_INTEGRITY_NOVERIFY], [
	LB2_MSG_LINUX_TEST_RESULT([if BLK_INTEGRITY_NOVERIFY is available],
	[blk_integrity_noverify], [
		AC_DEFINE(HAVE_BLK_INTEGRITY_NOVERIFY, 1,
			[BLK_INTEGRITY_NOVERIFY is available])
	])
]) # LIBCFS_BLK_INTEGRITY_NOVERIFY

#
# LIBCFS_LINUX_BIO_INTEGRITY_HEADER
#
# Linux commit v6.10-rc6-157-gda042a365515
#   block: split integrity support out of bio.h
#
AC_DEFUN([LIBCFS_SRC_LINUX_BIO_INTEGRITY_HEADER], [
	LB2_CHECK_LINUX_HEADER_SRC([linux/bio-integrity.h], [-Werror])
])
AC_DEFUN([LIBCFS_LINUX_BIO_INTEGRITY_HEADER], [
	LB2_CHECK_LINUX_HEADER_RESULT([linux/bio-integrity.h], [
		AC_DEFINE(HAVE_LINUX_BIO_INTEGRITY_HEADER, 1,
			[linux/bio-integrity.h is present])
	])
]) # LIBCFS_LINUX_BIO_INTEGRITY_HEADER

dnl #
dnl # Generate and compile all of the kernel API test cases to determine
dnl # which interfaces are available.  By invoking the kernel build system
dnl # only once the compilation can be done in parallel significantly
dnl # speeding up the process.
dnl #
AC_DEFUN([LIBCFS_PROG_LINUX_SRC], [
	# 5.2
	LIBCFS_SRC_KOBJ_TYPE_DEFAULT_GROUPS
	LIBCFS_SRC_USER_UID_KEYRING
	# 5.3
	LIBCFS_SRC_LOOKUP_USER_KEY
	LIBCFS_SRC_CACHE_DETAIL_WRITERS
	# 5.4
	LIBCFS_SRC_GENL_DUMPIT_INFO
	# 5.6
	LIBCFS_SRC_HAVE_PROC_OPS
	# 5.7
	LIBCFS_SRC_TCP_SOCK_SET_QUICKACK
	LIBCFS_SRC_TCP_SOCK_SET_KEEPINTVL
	LIBCFS_SRC_TCP_SOCK_SET_KEEPCNT
	# 5.8
	LIBCFS_SRC_IP6_SET_PREF
	LIBCFS_SRC_IP_SET_TOS
	LIBCFS_SRC_VMALLOC_2ARGS
	LIBCFS_SRC_HAVE_NR_UNSTABLE_NFS
	LIBCFS_SRC_KERNEL_SETSOCKOPT
	LIBCFS_SRC_KEY_NEED_UNLINK
	LIBCFS_SRC_SEC_RELEASE_SECCTX
	# 5.10
	LIBCFS_SRC_HAVE_KMAP_LOCAL
	LIBCFS_SRC_HAVE_KFREE_SENSITIVE
	LIBCFS_SRC_HAVE_CRYPTO_SHA2_HEADER
	LIBCFS_SRC_HAVE_LIST_CMP_FUNC_T
	LIBCFS_SRC_NLA_STRLCPY
	# 5.12
	LIBCFS_SRC_RB_FIND
	LIBCFS_SRC_LINUX_FORTIFY_STRING_HEADER
	LIBCFS_SRC_HAVE_CIPHER_HEADER
	# 5.13
	LIBCFS_SRC_HAVE_TASK_IS_RUNNING
	# 5.14
	LIBCFS_SRC_LINUX_STDARG_HEADER
	LIBCFS_SRC_HAVE_PANIC_NOTIFIER_HEADER
	# 5.15
	LIBCFS_SRC_PARAM_SET_UINT_MINMAX
	# 5.17
	LIBCFS_SRC_PDE_DATA_EXISTS
	LIBCFS_SRC_BIO_ALLOC_WITH_BDEV
	# 6.2
	LIBCFS_SRC_TIMER_DELETE_SYNC
	LIBCFS_SRC_TIMER_DELETE
	# 6.11
	LIBCFS_SRC_CONSTIFY_CTR_TABLE
	LIBCFS_SRC_BLK_INTEGRITY_NOVERIFY
])

dnl #
dnl # Check results of kernel interface tests.
dnl #
AC_DEFUN([LIBCFS_PROG_LINUX_RESULTS], [
	# 5.2
	LIBCFS_KOBJ_TYPE_DEFAULT_GROUPS
	LIBCFS_USER_UID_KEYRING
	# 5.3
	LIBCFS_LOOKUP_USER_KEY
	LIBCFS_CACHE_DETAIL_WRITERS
	# 5.4
	LIBCFS_GENL_DUMPIT_INFO
	# 5.6
	LIBCFS_HAVE_PROC_OPS
	# 5.7
	LIBCFS_TCP_SOCK_SET_QUICKACK
	LIBCFS_TCP_SOCK_SET_KEEPINTVL
	LIBCFS_TCP_SOCK_SET_KEEPCNT
	# 5.8
	LIBCFS_IP6_SET_PREF
	LIBCFS_IP_SET_TOS
	LIBCFS_VMALLOC_2ARGS
	LIBCFS_HAVE_NR_UNSTABLE_NFS
	LIBCFS_NR_UNSTABLE_NFS_DEPRECATED
	LIBCFS_KERNEL_SETSOCKOPT
	LIBCFS_KEY_NEED_UNLINK
	LIBCFS_SEC_RELEASE_SECCTX
	# 5.10
	LIBCFS_HAVE_KMAP_LOCAL
	LIBCFS_HAVE_KFREE_SENSITIVE
	LIBCFS_HAVE_CRYPTO_SHA2_HEADER
	LIBCFS_HAVE_LIST_CMP_FUNC_T
	LIBCFS_NLA_STRLCPY
	# 5.12
	LIBCFS_RB_FIND
	LIBCFS_LINUX_FORTIFY_STRING_HEADER
	LIBCFS_HAVE_CIPHER_HEADER
	# 5.13
	LIBCFS_HAVE_TASK_IS_RUNNING
	# 5.14
	LIBCFS_LINUX_STDARG_HEADER
	LIBCFS_HAVE_PANIC_NOTIFIER_HEADER
	# 5.15
	LIBCFS_PARAM_SET_UINT_MINMAX
	# 5.17
	LIBCFS_PDE_DATA_EXISTS
	LIBCFS_BIO_ALLOC_WITH_BDEV
	# 6.2
	LIBCFS_TIMER_DELETE_SYNC
	LIBCFS_TIMER_DELETE
	# 6.11
	LIBCFS_CONSTIFY_CTR_TABLE
	LIBCFS_BLK_INTEGRITY_NOVERIFY
])

#
# LIBCFS_PROG_LINUX
#
# LibCFS linux kernel checks
#
AC_DEFUN([LIBCFS_PROG_LINUX], [
AC_MSG_NOTICE([LibCFS kernel checks
==============================================================================])
LIBCFS_CONFIG_PANIC_DUMPLOG

# 5.7 - Export Check
LIBCFS_KALLSYMS_LOOKUP
]) # LIBCFS_PROG_LINUX

#
# LIBCFS_PATH_DEFAULTS
#
# default paths for installed files
#
AC_DEFUN([LIBCFS_PATH_DEFAULTS], [
]) # LIBCFS_PATH_DEFAULTS

#
# LIBCFS_CONFIGURE
#
# other configure checks
#
AC_DEFUN([LIBCFS_CONFIGURE], [
AC_MSG_NOTICE([LibCFS core checks
==============================================================================])

# libcfs/libcfs/util/nidstrings.c
AC_CHECK_HEADERS([netdb.h asm/types.h endian.h])

# --------  Check for required packages  --------------

AC_MSG_NOTICE([LibCFS required packages checks
==============================================================================])

AC_MSG_CHECKING([whether to enable readline support])
AC_ARG_ENABLE(readline,
	AS_HELP_STRING([--disable-readline],
		[disable readline support]),
	[], [enable_readline="yes"])
AC_MSG_RESULT([$enable_readline])

LIBREADLINE=""
AS_IF([test "x$enable_readline" = xyes], [
	AC_CHECK_LIB([readline], [readline], [
		LIBREADLINE="-lreadline"
		AC_DEFINE(HAVE_LIBREADLINE, 1,
			[readline library is available])
	])

	AC_SUBST(ENABLE_READLINE, yes)
], [
	AC_SUBST(ENABLE_READLINE, no)
])
AC_SUBST(LIBREADLINE)

AC_MSG_CHECKING([whether to use libpthread for libcfs library])
AC_ARG_ENABLE([libpthread],
	AS_HELP_STRING([--disable-libpthread],
		[disable libpthread]),
	[], [enable_libpthread="yes"])
AC_MSG_RESULT([$enable_libpthread])

PTHREAD_LIBS=""
AS_IF([test "x$enable_libpthread" = xyes], [
	AC_CHECK_LIB([pthread], [pthread_create], [
		PTHREAD_LIBS="-lpthread"
		AC_DEFINE([HAVE_LIBPTHREAD], 1,
			[use libpthread for libcfs library])
	])

	AC_SUBST(ENABLE_LIBPTHREAD, yes)
], [
	AC_SUBST(ENABLE_LIBPTHREAD, no)
	AC_MSG_WARN([Using libpthread for libcfs library is disabled explicitly])
])
AC_SUBST(PTHREAD_LIBS)
]) # LIBCFS_CONFIGURE

#
# LIBCFS_CONFIG_FILES
#
# files that should be generated with AC_OUTPUT
#
AC_DEFUN([LIBCFS_CONFIG_FILES], [
AC_CONFIG_FILES([
libcfs/Makefile
libcfs/autoMakefile
libcfs/libcfs/Makefile
libcfs/libcfs/autoMakefile
])
]) # LIBCFS_CONFIG_FILES
