#ifndef _OBD_ECHO_H
#define _OBD_ECHO_H
/*
 * Copyright (C) 2001  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

#define OBD_ECHO_DEVICENAME "obdecho"
#define OBD_ECHO_CLIENT_DEVICENAME "echo_client"

struct ec_object
{
	struct list_head       eco_obj_chain;
	struct list_head       eco_lockhandles;
	struct obd_device     *eco_device;
	int                    eco_refcount;
	int                    eco_deleted;
	obd_id                 eco_id;
	struct lov_stripe_md  *eco_lsm;
};

struct ec_open_object
{
	struct list_head       ecoo_exp_chain;
	struct ec_object      *ecoo_object;
	struct obdo            ecoo_oa;
};

struct ec_lockhandle
{
	struct list_head       eclh_obj_chain;
	struct lustre_handle   eclh_handle;
};

struct ec_lock
{
	struct list_head       ecl_exp_chain;
	struct lustre_handle   ecl_handle;
	struct ldlm_extent     ecl_extent;
	__u32                  ecl_mode;
	struct ec_object      *ecl_object;
	__u64                  ecl_cookie;
};

#endif
