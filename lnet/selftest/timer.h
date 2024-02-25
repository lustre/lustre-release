// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Isaac Huang <isaac@clusterfs.com>
 */

#ifndef __SELFTEST_TIMER_H__
#define __SELFTEST_TIMER_H__

struct stt_timer {
	struct list_head	stt_list;
	time64_t		stt_expires;
	void			(*stt_func)(void *);
	void			*stt_data;
};

void stt_add_timer(struct stt_timer *timer);
int stt_del_timer(struct stt_timer *timer);
int stt_startup(void);
void stt_shutdown(void);

#endif /* __SELFTEST_TIMER_H__ */
