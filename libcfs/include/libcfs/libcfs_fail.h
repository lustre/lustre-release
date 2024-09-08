/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef _LIBCFS_FAIL_H
#define _LIBCFS_FAIL_H

extern unsigned long cfs_fail_loc;
extern unsigned int cfs_fail_val;
extern int cfs_fail_err;

extern wait_queue_head_t cfs_race_waitq;
extern int cfs_race_state;

int __cfs_fail_check_set(__u32 id, __u32 value, int set);
int __cfs_fail_timeout_set(const char *file, const char *func, int line,
			   __u32 id, __u32 value, int ms, int set);

enum {
	CFS_FAIL_LOC_NOSET = 0,
	CFS_FAIL_LOC_ORSET = 1,
	CFS_FAIL_LOC_RESET = 2,
	CFS_FAIL_LOC_VALUE = 3
};

/*
 * Failure ranges:
 *	"0x0100 - 0x3fff" for Lustre
 *	"0xe000 - 0xefff" for LNet
 *	"0xf000 - 0xffff" for LNDs
 */

/* Failure injection control */
#define CFS_FAIL_MASK_SYS    0x0000FF00
#define CFS_FAIL_MASK_LOC   (0x000000FF | CFS_FAIL_MASK_SYS)

#define CFS_FAILED_BIT       30
/* CFS_FAILED is 0x40000000 */
#define CFS_FAILED          BIT(CFS_FAILED_BIT)

#define CFS_FAIL_ONCE_BIT    31
/* CFS_FAIL_ONCE is 0x80000000 */
#define CFS_FAIL_ONCE       BIT(CFS_FAIL_ONCE_BIT)

/* The following flags aren't made to be combined */
#define CFS_FAIL_SKIP        0x20000000 /* skip N times then fail */
#define CFS_FAIL_SOME        0x10000000 /* only fail N times */
#define CFS_FAIL_RAND        0x08000000 /* fail 1/N of the times */
#define CFS_FAIL_USR1        0x04000000 /* user flag */

/* CFS_FAULT may be combined with any one of the above flags. */
#define CFS_FAULT	     0x02000000 /* match any CFS_FAULT_CHECK */

static inline bool CFS_FAIL_PRECHECK(__u32 id)
{
	return unlikely(cfs_fail_loc != 0 &&
	      ((cfs_fail_loc & CFS_FAIL_MASK_LOC) == (id & CFS_FAIL_MASK_LOC) ||
	       (cfs_fail_loc & id & CFS_FAULT)));
}

#define UNLIKELY_CHECK_SET(id, value, set, quiet)			\
	(unlikely(cfs_fail_check_set_loc(__FILE__, __func__, __LINE__,	\
					 id, value, set, quiet)))

static inline int cfs_fail_check_set_loc(const char *file, const char *func,
					 int line, __u32 id, __u32 value,
					 int set, int quiet)
{
	int ret = 0;

	if (CFS_FAIL_PRECHECK(id)) {
		/* set failed_once before the CFS_FAILED flag is set below */
		unsigned long failed_once = cfs_fail_loc & CFS_FAILED;

		ret = __cfs_fail_check_set(id, value, set);
		if (ret)
			CDEBUG_LIMIT_LOC(file, func, line,
					 (quiet && failed_once) ?
						D_INFO : D_CONSOLE,
					 "*** cfs_fail_loc=%x, val=%u***\n",
					 id, value);
	}

	return ret;
}

/*
 * If id hit cfs_fail_loc, return 1, otherwise return 0
 */
#define CFS_FAIL_CHECK(id) \
	UNLIKELY_CHECK_SET(id, cfs_fail_val, CFS_FAIL_LOC_NOSET, 0)
#define CFS_FAIL_CHECK_QUIET(id) \
	UNLIKELY_CHECK_SET(id, cfs_fail_val, CFS_FAIL_LOC_NOSET, 1)

/*
 * If id hit cfs_fail_loc and cfs_fail_val == (-1 or value) return 1,
 * otherwise return 0
 */
#define CFS_FAIL_CHECK_VALUE(id, value) \
	UNLIKELY_CHECK_SET(id, value, CFS_FAIL_LOC_VALUE, 0)
#define CFS_FAIL_CHECK_VALUE_QUIET(id, value) \
	UNLIKELY_CHECK_SET(id, value, CFS_FAIL_LOC_VALUE, 1)

/*
 * If id hit cfs_fail_loc, cfs_fail_loc |= value and return 1,
 * otherwise return 0
 */
#define CFS_FAIL_CHECK_ORSET(id, value) \
	UNLIKELY_CHECK_SET(id, value, CFS_FAIL_LOC_ORSET, 0)
#define CFS_FAIL_CHECK_ORSET_QUIET(id, value) \
	UNLIKELY_CHECK_SET(id, value, CFS_FAIL_LOC_ORSET, 1)

/*
 * If id hit cfs_fail_loc, cfs_fail_loc = value and return 1,
 * otherwise return 0
 */
#define CFS_FAIL_CHECK_RESET(id, value) \
	UNLIKELY_CHECK_SET(id, value, CFS_FAIL_LOC_RESET, 0)
#define CFS_FAIL_CHECK_RESET_QUIET(id, value) \
	UNLIKELY_CHECK_SET(id, value, CFS_FAIL_LOC_RESET, 1)

#define UNLIKELY_TIMEOUT_SET(id, value, ms, set) \
	(unlikely(cfs_fail_timeout_set_loc(__FILE__, __func__, __LINE__, \
					   id, value, ms, set)))

static inline int cfs_fail_timeout_set_loc(const char *file, const char *func,
					   int line, __u32 id, __u32 value,
					   int ms, int set)
{
	if (CFS_FAIL_PRECHECK(id))
		return __cfs_fail_timeout_set(file, func, line, id, value, ms,
					      set);
	return 0;
}

/* If id hit cfs_fail_loc, sleep for seconds or milliseconds */
#define CFS_FAIL_TIMEOUT(id, secs) \
	UNLIKELY_TIMEOUT_SET(id, cfs_fail_val, (secs)*1000, CFS_FAIL_LOC_NOSET)
#define CFS_FAIL_TIMEOUT_MS(id, ms) \
	UNLIKELY_TIMEOUT_SET(id, cfs_fail_val, ms, CFS_FAIL_LOC_NOSET)

/*
 * If id hit cfs_fail_loc, cfs_fail_loc |= value and
 * sleep seconds or milliseconds
 */
#define CFS_FAIL_TIMEOUT_ORSET(id, value, secs) \
	UNLIKELY_TIMEOUT_SET(id, value, (secs) * 1000, CFS_FAIL_LOC_ORSET)

#define CFS_FAIL_TIMEOUT_RESET(id, value, secs) \
	UNLIKELY_TIMEOUT_SET(id, value, (secs) * 1000, CFS_FAIL_LOC_RESET)

#define CFS_FAIL_TIMEOUT_MS_ORSET(id, value, ms) \
	UNLIKELY_TIMEOUT_SET(id, value, ms, CFS_FAIL_LOC_ORSET)
#define CFS_FAULT_CHECK(id)			\
	CFS_FAIL_CHECK(CFS_FAULT | (id))

/*
 * The idea here is to synchronise two threads to force a race. The
 * first thread that calls this with a matching fail_loc is put to
 * sleep. The next thread that calls with the same fail_loc wakes up
 * the first and continues.
 */
static inline void cfs_race_loc(const char *file, const char *func, int line,
				__u32 id)
{
	if (CFS_FAIL_PRECHECK(id)) {
		if (unlikely(__cfs_fail_check_set(id, 0, CFS_FAIL_LOC_NOSET))) {
			int rc;
			cfs_race_state = 0;
			CDEBUG_LIMIT_LOC(file, func, line, D_ERROR,
					 "cfs_race id %x sleeping\n", id);
			/*
			 * XXX: don't wait forever as there is no guarantee
			 * that this branch is executed first. for testing
			 * purposes this construction works good enough
			 */
			rc = wait_event_interruptible_timeout(cfs_race_waitq,
						      cfs_race_state != 0,
						      cfs_time_seconds(5));
			CDEBUG_LIMIT_LOC(file, func, line, D_ERROR,
					 "cfs_fail_race id %x awake: rc=%d\n",
					 id, rc);
		} else {
			CDEBUG_LIMIT_LOC(file, func, line, D_ERROR,
					 "cfs_fail_race id %x waking\n", id);
			cfs_race_state = 1;
			wake_up(&cfs_race_waitq);
		}
	}
}
#define CFS_RACE(id) cfs_race_loc(__FILE__, __func__, __LINE__, id)

/**
 * Wait on race.
 *
 * The first thread that calls this with a matching fail_loc is put to sleep,
 * but subseqent callers of this won't sleep. Until another thread that calls
 * cfs_race_wakeup(), the first thread will be woken up and continue.
 */
static inline void cfs_race_wait_loc(const char *file, const char *func,
				     int line, __u32 id)
{
	if (CFS_FAIL_PRECHECK(id)) {
		if (unlikely(__cfs_fail_check_set(id, 0, CFS_FAIL_LOC_NOSET))) {
			int rc;

			cfs_race_state = 0;
			CDEBUG_LIMIT_LOC(file, func, line, D_ERROR,
					 "cfs_race id %x sleeping\n", id);
			rc = wait_event_interruptible(cfs_race_waitq,
						      cfs_race_state != 0);
			CDEBUG_LIMIT_LOC(file, func, line, D_ERROR,
					 "cfs_fail_race id %x awake: rc=%d\n",
					 id, rc);
		}
	}
}
#define CFS_RACE_WAIT(id) cfs_race_wait_loc(__FILE__, __func__, __LINE__, id)

/**
 * Wake up the thread that is waiting on the matching fail_loc.
 */
static inline void cfs_race_wakeup_loc(const char *file, const char *func,
				       int line, __u32 id)
{
	if (CFS_FAIL_PRECHECK(id)) {
		if (likely(!__cfs_fail_check_set(id, 0, CFS_FAIL_LOC_NOSET))) {
			CDEBUG_LIMIT_LOC(file, func, line, D_ERROR,
					 "cfs_fail_race id %x waking\n", id);
			cfs_race_state = 1;
			wake_up(&cfs_race_waitq);
		}
	}
}
#define CFS_RACE_WAKEUP(id) cfs_race_wakeup_loc(__FILE__, __func__, __LINE__,id)

#endif /* _LIBCFS_FAIL_H */
