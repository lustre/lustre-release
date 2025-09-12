/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2025 Whamcloud
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Generic capabilities manipulation functions.
 *
 */

#ifndef __LIBCFS_CAPS_H__
#define __LIBCFS_CAPS_H__

static inline const char *libcfs_cap2str(int cap)
{
	/* We don't allow using all capabilities, but the fields must exist.
	 * The supported capabilities are CAP_FS_SET and CAP_NFSD_SET, plus
	 * CAP_SYS_ADMIN for a bunch of HSM operations (that should be fixed).
	 */
	static const char *const capability_names[] = {
		"cap_chown",			/*  0 */
		"cap_dac_override",		/*  1 */
		"cap_dac_read_search",		/*  2 */
		"cap_fowner",			/*  3 */
		"cap_fsetid",			/*  4 */
		NULL,				/*  5 */
		NULL,				/*  6 */
		NULL,				/*  7 */
		NULL,				/*  8 */
		"cap_linux_immutable",		/*  9 */
		NULL,				/* 10 */
		NULL,				/* 11 */
		NULL,				/* 12 */
		NULL,				/* 13 */
		NULL,				/* 14 */
		NULL,				/* 15 */
		NULL,				/* 16 */
		NULL,				/* 17 */
		NULL,				/* 18 */
		NULL,				/* 19 */
		NULL,				/* 20 */
		/* we should use more precise capabilities than this */
		"cap_sys_admin",		/* 21 */
		NULL,				/* 22 */
		NULL,				/* 23 */
		"cap_sys_resource",		/* 24 */
		NULL,				/* 25 */
		NULL,				/* 26 */
		"cap_mknod",			/* 27 */
		NULL,				/* 28 */
		NULL,				/* 29 */
		NULL,				/* 30 */
		NULL,				/* 31 */
		"cap_mac_override",		/* 32 */
	};

	if (cap >= ARRAY_SIZE(capability_names))
		return NULL;

	return capability_names[cap];
}

/* convert a capability into an integer to print or manage more easily */
static inline u64 libcfs_cap2num(kernel_cap_t cap)
{
#ifdef CAP_FOR_EACH_U32
	/* kernels before v6.2-13111-gf122a08b197d had a more complex
	 * kernel_cap_t structure with an array of __u32 values, but this
	 * was then fixed to have a single __u64 value.  There are accessor
	 * functions for the old kernel_cap_t but since that is now dead code
	 * it isn't worthwhile to jump through hoops for compatibility for it.
	 */
	return ((u64)cap.cap[1] << 32) | cap.cap[0];
#else
	return cap.val;
#endif
}

/* convert an integer into a capabilityt */
static inline kernel_cap_t libcfs_num2cap(u64 num)
{
	kernel_cap_t cap;

#ifdef CAP_FOR_EACH_U32
	cap.cap[0] = num;
	cap.cap[1] = (num >> 32);
#else
	cap.val = num;
#endif

	return cap;
}

#endif
