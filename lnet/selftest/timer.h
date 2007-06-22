/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *   Author: Isaac Huang <isaac@clusterfs.com>
 *
 */
#ifndef __SELFTEST_TIMER_H__
#define __SELFTEST_TIMER_H__

typedef struct {
        struct list_head  stt_list;
        cfs_time_t        stt_expires;
        void            (*stt_func) (void *);
        void             *stt_data;
} stt_timer_t;

void stt_add_timer (stt_timer_t *timer);
int stt_del_timer (stt_timer_t *timer);
int stt_startup (void);
void stt_shutdown (void);

#endif /* __SELFTEST_TIMER_H__ */
