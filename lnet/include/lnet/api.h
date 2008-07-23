/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef __LNET_API_H__
#define __LNET_API_H__

#include <lnet/types.h>

int LNetInit(void);
void LNetFini(void);

int LNetNIInit(lnet_pid_t requested_pid);
int LNetNIFini(void);

int LNetGetId(unsigned int index, lnet_process_id_t *id);
int LNetDist(lnet_nid_t nid, lnet_nid_t *srcnid, __u32 *order);
int LNetCtl(unsigned int cmd, void *arg);
void LNetSnprintHandle (char *str, int str_len, lnet_handle_any_t handle);

/*
 * Portals
 */
int LNetSetLazyPortal(int portal);
int LNetClearLazyPortal(int portal);

/*
 * Match entries
 */
int LNetMEAttach(unsigned int      portal,
		 lnet_process_id_t match_id_in, 
		 __u64             match_bits_in,
		 __u64             ignore_bits_in, 
		 lnet_unlink_t     unlink_in,
		 lnet_ins_pos_t    pos_in, 
		 lnet_handle_me_t *handle_out);

int LNetMEInsert(lnet_handle_me_t  current_in, 
		 lnet_process_id_t match_id_in,
		 __u64             match_bits_in, 
		 __u64             ignore_bits_in,
		 lnet_unlink_t     unlink_in, 
		 lnet_ins_pos_t    position_in,
		 lnet_handle_me_t *handle_out);

int LNetMEUnlink(lnet_handle_me_t current_in);

/*
 * Memory descriptors
 */
int LNetMDAttach(lnet_handle_me_t  current_in, 
		 lnet_md_t         md_in,
		 lnet_unlink_t     unlink_in, 
		 lnet_handle_md_t *handle_out);

int LNetMDBind(lnet_md_t         md_in,
	       lnet_unlink_t     unlink_in, 
	       lnet_handle_md_t *handle_out);

int LNetMDUnlink(lnet_handle_md_t md_in);

/*
 * Event queues
 */
int LNetEQAlloc(unsigned int       count_in,
		lnet_eq_handler_t  handler,
		lnet_handle_eq_t  *handle_out);

int LNetEQFree(lnet_handle_eq_t eventq_in);

int LNetEQGet(lnet_handle_eq_t  eventq_in, 
	      lnet_event_t     *event_out);


int LNetEQWait(lnet_handle_eq_t  eventq_in, 
	       lnet_event_t     *event_out);

int LNetEQPoll(lnet_handle_eq_t *eventqs_in, 
	       int               neq_in, 
	       int               timeout_ms,
	       lnet_event_t     *event_out, 
	       int              *which_eq_out);

/*
 * Data movement
 */
int LNetPut(lnet_nid_t        self,
	    lnet_handle_md_t  md_in, 
	    lnet_ack_req_t    ack_req_in,
	    lnet_process_id_t target_in, 
	    unsigned int      portal_in,
	    __u64             match_bits_in,
	    unsigned int      offset_in, 
	    __u64             hdr_data_in);

int LNetGet(lnet_nid_t        self,
	    lnet_handle_md_t  md_in, 
	    lnet_process_id_t target_in,
	    unsigned int      portal_in, 
	    __u64             match_bits_in, 
	    unsigned int      offset_in);


int LNetSetAsync(lnet_process_id_t id, int nasync);

#ifndef __KERNEL__
/* Temporary workaround to allow uOSS and test programs force server
 * mode in userspace. See comments near ln_server_mode_flag in
 * lnet/lib-types.h */

void lnet_server_mode();
#endif        

#endif
