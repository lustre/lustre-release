/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */
#ifndef _LUSTRE_COMPAT_LINUX_TIME64_H
#define _LUSTRE_COMPAT_LINUX_TIME64_H

#include <linux/ktime.h>
#include <linux/time64.h>

/*
 * KTIME_SEC_MIN was added in Linux 5.15 along with the fix for a bug
 * in timespec64_to_ns() where negative tv_sec was cast to unsigned,
 * causing it to exceed KTIME_SEC_MAX and return KTIME_MAX incorrectly.
 * Define missing constants and provide a fixed timespec64_to_ns() for
 * kernels older than 5.15.
 * See: https://elixir.bootlin.com/linux/v5.14/source/include/linux/time64.h#L125
 */
#ifndef KTIME_SEC_MIN
#ifndef KTIME_MIN
#define KTIME_MIN		(-KTIME_MAX - 1)
#endif
#define KTIME_SEC_MAX		(KTIME_MAX / NSEC_PER_SEC)
#define KTIME_SEC_MIN		(KTIME_MIN / NSEC_PER_SEC)

static inline s64 lu_timespec64_to_ns(const struct timespec64 *ts)
{
	if (ts->tv_sec >= KTIME_SEC_MAX)
		return KTIME_MAX;

	if (ts->tv_sec <= KTIME_SEC_MIN)
		return KTIME_MIN;

	return ((s64)ts->tv_sec * NSEC_PER_SEC) + ts->tv_nsec;
}
#undef timespec64_to_ns
#define timespec64_to_ns(ts)	lu_timespec64_to_ns(ts)
#endif /* !KTIME_SEC_MIN */

#endif /* _LUSTRE_COMPAT_LINUX_TIME64_H */
