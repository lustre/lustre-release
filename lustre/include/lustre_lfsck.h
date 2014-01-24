/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2013, Intel Corporation.
 */
/*
 * lustre/include/lustre_lfsck.h
 *
 * Lustre LFSCK exported functions.
 *
 * Author: Fan, Yong <fan.yong@intel.com>
 */

#ifndef _LUSTRE_LFSCK_H
# define _LUSTRE_LFSCK_H

#include <lustre/lustre_lfsck_user.h>
#include <lustre_dlm.h>
#include <lu_object.h>
#include <dt_object.h>

/**
 * status machine:
 *
 * 					LS_INIT
 * 					   |
 * 				     (lfsck|start)
 * 					   |
 *					   v
 *				   LS_SCANNING_PHASE1
 *					|	^
 *					|	:
 *					| (lfsck:restart)
 *					|	:
 *					v	:
 *	-----------------------------------------------------------------
 *	|		    |^		|^	   |^	      |^ 	|^
 *	|		    |:		|:	   |:	      |:	|:
 *	v		    v:		v:	   v:	      v: 	v:
 * LS_SCANNING_PHASE2	LS_FAILED  LS_STOPPED  LS_PAUSED LS_CRASHED LS_PARTIAL
 *			  (CO_)       (CO_)	 (CO_)
 *	|	^	    ^:		^:	   ^:	      ^:	^:
 *	|	:	    |:		|:	   |:	      |:	|:
 *	| (lfsck:restart)   |:		|:	   |:	      |:	|:
 *	v	:	    |v		|v	   |v	      |v	|v
 *	-----------------------------------------------------------------
 *	    |
 *	    v
 *    LS_COMPLETED
 */
enum lfsck_status {
	/* The lfsck file is new created, for new MDT, upgrading from old disk,
	 * or re-creating the lfsck file manually. */
	LS_INIT			= 0,

	/* The first-step system scanning. */
	LS_SCANNING_PHASE1	= 1,

	/* The second-step system scanning. */
	LS_SCANNING_PHASE2	= 2,

	/* The LFSCK processing has completed for all objects. */
	LS_COMPLETED		= 3,

	/* The LFSCK exited automatically for failure, will not auto restart. */
	LS_FAILED		= 4,

	/* The LFSCK is stopped manually, will not auto restart. */
	LS_STOPPED		= 5,

	/* LFSCK is paused automatically when umount,
	 * will be restarted automatically when remount. */
	LS_PAUSED		= 6,

	/* System crashed during the LFSCK,
	 * will be restarted automatically after recovery. */
	LS_CRASHED		= 7,

	/* Some OST/MDT failed during the LFSCK, or not join the LFSCK. */
	LS_PARTIAL		= 8,

	/* The LFSCK is failed because its controller is failed. */
	LS_CO_FAILED		= 9,

	/* The LFSCK is stopped because its controller is stopped. */
	LS_CO_STOPPED		= 10,

	/* The LFSCK is paused because its controller is paused. */
	LS_CO_PAUSED		= 11,

	LS_MAX
};

struct lfsck_start_param {
	struct lfsck_start	*lsp_start;
	struct ldlm_namespace	*lsp_namespace;
};

enum lfsck_events {
	LE_LASTID_REBUILDING	= 1,
	LE_LASTID_REBUILT	= 2,
	LE_PHASE1_DONE		= 3,
	LE_PHASE2_DONE		= 4,
	LE_START		= 5,
	LE_STOP 		= 6,
};

typedef int (*lfsck_out_notify)(const struct lu_env *env, void *data,
				enum lfsck_events event);

int lfsck_register(const struct lu_env *env, struct dt_device *key,
		   struct dt_device *next, lfsck_out_notify notify,
		   void *notify_data, bool master);
void lfsck_degister(const struct lu_env *env, struct dt_device *key);

int lfsck_add_target(const struct lu_env *env, struct dt_device *key,
		     struct dt_device *tgt, struct obd_export *exp,
		     __u32 index, bool for_ost);
void lfsck_del_target(const struct lu_env *env, struct dt_device *key,
		      struct dt_device *tgt, __u32 index, bool for_ost);

int lfsck_start(const struct lu_env *env, struct dt_device *key,
		struct lfsck_start_param *lsp);
int lfsck_stop(const struct lu_env *env, struct dt_device *key,
	       bool pause);

int lfsck_get_speed(struct dt_device *key, void *buf, int len);
int lfsck_set_speed(struct dt_device *key, int val);
int lfsck_get_windows(struct dt_device *key, void *buf, int len);
int lfsck_set_windows(struct dt_device *key, int val);

int lfsck_dump(struct dt_device *key, void *buf, int len, enum lfsck_type type);

#endif /* _LUSTRE_LFSCK_H */
