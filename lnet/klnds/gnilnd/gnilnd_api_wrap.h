/*
 * Copyright (C) 2009-2012 Cray, Inc.
 *
 *   Author: Nic Henke <nic@cray.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
#ifndef _GNILND_API_WRAP_H
#define _GNILND_API_WRAP_H

/* LNet is allocated failure locations 0xe000 to 0xffff */

/* GNILND has 0xf0XX */
#define CFS_FAIL_GNI			0xf000
#define CFS_FAIL_GNI_PHYS_MAP		0xf001
#define CFS_FAIL_GNI_VIRT_MAP		0xf002
#define CFS_FAIL_GNI_GET_UNMAP		0xf003
#define CFS_FAIL_GNI_PUT_UNMAP		0xf004
#define CFS_FAIL_GNI_MAP_TX		0xf005
#define CFS_FAIL_GNI_SMSG_SEND		0xf006
#define CFS_FAIL_GNI_CLOSE_SEND		0xf007
#define CFS_FAIL_GNI_CDM_CREATE		0xf008
#define CFS_FAIL_GNI_CDM_DESTROY	0xf009
#define CFS_FAIL_GNI_CDM_ATTACH		0xf00a
#define CFS_FAIL_GNI_CQ_CREATE		0xf00b
#define CFS_FAIL_GNI_CQ_DESTROY		0xf00c
#define CFS_FAIL_GNI_EP_BIND		0xf00d
#define CFS_FAIL_GNI_EP_UNBIND		0xf00e
#define CFS_FAIL_GNI_EP_SET_EVDATA	0xf00f
#define CFS_FAIL_GNI_SMSG_INIT		0xf010
#define CFS_FAIL_GNI_SMSG_RELEASE	0xf011
#define CFS_FAIL_GNI_POST_RDMA		0xf012
#define CFS_FAIL_GNI_GET_COMPLETED	0xf013
#define CFS_FAIL_GNI_EP_DESTROY		0xf015
#define CFS_FAIL_GNI_VIRT_UNMAP		0xf016
#define CFS_FAIL_GNI_MDD_RELEASE	0xf017
#define CFS_FAIL_GNI_NOOP_SEND		0xf018
#define CFS_FAIL_GNI_ERR_SUBSCRIBE	0xf01a
#define CFS_FAIL_GNI_QUIESCE_RACE	0xf01b
#define CFS_FAIL_GNI_DG_TERMINATE	0xf01c
#define CFS_FAIL_GNI_REG_QUIESCE	0xf01d
#define CFS_FAIL_GNI_IN_QUIESCE		0xf01e
#define CFS_FAIL_GNI_DELAY_RDMA		0xf01f
#define CFS_FAIL_GNI_SR_DOWN_RACE	0xf020
#define CFS_FAIL_GNI_ALLOC_TX		0xf021
#define CFS_FAIL_GNI_FMABLK_AVAIL	0xf022
#define CFS_FAIL_GNI_EP_CREATE		0xf023
#define CFS_FAIL_GNI_CQ_GET_EVENT	0xf024
#define CFS_FAIL_GNI_PROBE		0xf025
#define CFS_FAIL_GNI_EP_TEST		0xf026
#define CFS_FAIL_GNI_CONNREQ_DROP	0xf027
#define CFS_FAIL_GNI_CONNREQ_PROTO	0xf028
#define CFS_FAIL_GNI_CONND_PILEUP	0xf029
#define CFS_FAIL_GNI_PHYS_SETUP		0xf02a
#define CFS_FAIL_GNI_FIND_TARGET	0xf02b
#define CFS_FAIL_GNI_WC_DGRAM_FREE	0xf02c
#define CFS_FAIL_GNI_DROP_CLOSING	0xf02d
#define CFS_FAIL_GNI_RX_CLOSE_CLOSING	0xf02e
#define CFS_FAIL_GNI_RX_CLOSE_CLOSED	0xf02f
#define CFS_FAIL_GNI_EP_POST		0xf030
#define CFS_FAIL_GNI_PACK_SRCNID	0xf031
#define CFS_FAIL_GNI_PACK_DSTNID	0xf032
#define CFS_FAIL_GNI_PROBE_WAIT		0xf033
#define CFS_FAIL_GNI_SMSG_CKSUM1	0xf034
#define CFS_FAIL_GNI_SMSG_CKSUM2	0xf035
#define CFS_FAIL_GNI_SMSG_CKSUM3	0xf036
#define CFS_FAIL_GNI_DROP_DESTROY_EP	0xf037
#define CFS_FAIL_GNI_SMSG_GETNEXT	0xf038
#define CFS_FAIL_GNI_FINISH_PURG	0xf039
#define CFS_FAIL_GNI_PURG_REL_DELAY	0xf03a
#define CFS_FAIL_GNI_DONT_NOTIFY	0xf03b
#define CFS_FAIL_GNI_VIRT_SMALL_MAP	0xf03c
#define CFS_FAIL_GNI_DELAY_RDMAQ	0xf03d
#define CFS_FAIL_GNI_PAUSE_SHUTDOWN	0xf03e
#define CFS_FAIL_GNI_PAUSE_DGRAM_COMP	0xf03f
#define CFS_FAIL_GNI_NET_LOOKUP		0xf040
#define CFS_FAIL_GNI_RECV_TIMEOUT	0xf041
#define CFS_FAIL_GNI_SEND_TIMEOUT	0xf042
#define CFS_FAIL_GNI_ONLY_NOOP		0xf043
#define CFS_FAIL_GNI_FINISH_PURG2	0xf044
#define CFS_FAIL_GNI_RACE_RESET		0xf045
#define CFS_FAIL_GNI_GNP_CONNECTING1	0xf046
#define CFS_FAIL_GNI_GNP_CONNECTING2	0xf047
#define CFS_FAIL_GNI_GNP_CONNECTING3	0xf048
#define CFS_FAIL_GNI_SCHEDULE_COMPLETE	0xf049
#define CFS_FAIL_GNI_PUT_ACK_AGAIN	0xf050
#define CFS_FAIL_GNI_GET_REQ_AGAIN	0xf051
#define CFS_FAIL_GNI_SCHED_DEADLINE	0xf052
#define CFS_FAIL_GNI_DGRAM_DEADLINE	0xf053
#define CFS_FAIL_GNI_DGRAM_DROP_TX	0xf054
#define CFS_FAIL_GNI_RDMA_CQ_ERROR	0xf055

/* helper macros */
extern void
_kgnilnd_api_rc_lbug(const char *rcstr, int rc, struct libcfs_debug_msg_data *data,
			const char *fmt, ...)
	__attribute__ ((format (printf, 4, 5)));

#define kgnilnd_api_rc_lbug(msgdata, rc, fmt, a...)				\
do {										\
	CFS_CHECK_STACK(msgdata, D_ERROR, NULL);				\
	/* we don't mask this - it is always at D_ERROR */			\
	_kgnilnd_api_rc_lbug(kgnilnd_api_rc2str(rc), (rc), msgdata, fmt, ##a);	\
} while (0)

#define DO_RETCODE(x) case x: return #x;
static inline const char *
kgnilnd_api_rc2str(gni_return_t rrc)
{

	switch (rrc) {
		DO_RETCODE(GNI_RC_SUCCESS)
		DO_RETCODE(GNI_RC_NOT_DONE);
		DO_RETCODE(GNI_RC_INVALID_PARAM);
		DO_RETCODE(GNI_RC_ERROR_RESOURCE);
		DO_RETCODE(GNI_RC_TIMEOUT);
		DO_RETCODE(GNI_RC_PERMISSION_ERROR);
		DO_RETCODE(GNI_RC_DESCRIPTOR_ERROR);
		DO_RETCODE(GNI_RC_ALIGNMENT_ERROR);
		DO_RETCODE(GNI_RC_INVALID_STATE);
		DO_RETCODE(GNI_RC_NO_MATCH);
		DO_RETCODE(GNI_RC_SIZE_ERROR);
		DO_RETCODE(GNI_RC_TRANSACTION_ERROR);
		DO_RETCODE(GNI_RC_ILLEGAL_OP);
		DO_RETCODE(GNI_RC_ERROR_NOMEM);
	}
	LBUG();
}
#undef DO_RETCODE

/* log an error and LBUG for unhandled rc from gni api function
 * the fmt should be something like:
 *  gni_api_call(arg1, arg2, arg3)
 */

/* apick_fn and apick_fmt should be defined for each site */
#undef apick_fn
#undef apick_fmt

#define GNILND_API_RC_LBUG(args...)						\
do {										\
	LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, D_ERROR, NULL);			\
	kgnilnd_api_rc_lbug(&msgdata, rrc, apick_fn"("apick_fmt")", ##args);	\
} while (0)

#define GNILND_API_SWBUG(args...)                                               \
do {                                                                            \
	CERROR("likely SOFTWARE BUG "apick_fn"("apick_fmt") rc %s\n",           \
		 ##args, kgnilnd_api_rc2str(rrc));                              \
} while (0)

#define GNILND_API_EINVAL(args...)                                              \
do {                                                                            \
	CERROR("invalid parameter to "apick_fn"("apick_fmt") rc %s\n",          \
		 ##args, kgnilnd_api_rc2str(rrc));                              \
} while (0)

#define GNILND_API_RESOURCE(args...)                                            \
do {                                                                            \
	CERROR("no resources for "apick_fn"("apick_fmt") rc %s\n",              \
		##args, kgnilnd_api_rc2str(rrc));                               \
} while (0)

#define GNILND_API_BUSY(args...)                                                \
do {                                                                            \
	CERROR("resources busy for "apick_fn"("apick_fmt") rc %s\n",            \
		##args, kgnilnd_api_rc2str(rrc));                               \
} while (0)

#undef DEBUG_SMSG_CREDITS
#ifdef DEBUG_SMSG_CREDITS
#define CRAY_CONFIG_GHAL_GEMINI
#include <gni_priv.h>
#define GNIDBG_SMSG_CREDS(level, conn)                                        \
do {                                                                          \
	gni_ep_smsg_mbox_t *smsg = conn->gnc_ephandle->smsg;                  \
	CDEBUG(level, "SMSGDBG: conn %p mcred %d/%d bcred %d/%d "             \
		"s_seq %d/%d/%d r_seq %d/%d/%d retr %d\n",                    \
		conn, smsg->mbox_credits, smsg->back_mbox_credits,            \
		smsg->buffer_credits, smsg->back_buffer_credits,              \
		smsg->s_seqno, smsg->s_seqno_back_mbox_credits,               \
		smsg->s_seqno_back_buffer_credits, smsg->r_seqno,             \
		smsg->r_seqno_back_mbox_credits,                              \
		smsg->r_seqno_back_buffer_credits, smsg->retransmit_count);   \
} while (0)
#else
#define GNIDBG_SMSG_CREDS(level, conn) do {} while(0)
#endif

/* these are all wrappers around gni_XXX functions.
 * This allows us to handle all the return codes and api checks without
 * dirtying up the logic code */

/* TODO: RETURN wrapper that translates integer to GNI API RC string */

#define apick_fn "kgnilnd_cdm_create"
#define apick_fmt "%u, %u, %u, %u, 0x%p"
static inline gni_return_t kgnilnd_cdm_create(
		IN uint32_t		inst_id,
		IN uint8_t		ptag,
		IN uint32_t		cookie,
		IN uint32_t		modes,
		OUT gni_cdm_handle_t	*cdm_hndl
		)
{
	gni_return_t rrc;

	/* Error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_CDM_CREATE)) {
		rrc = cfs_fail_val ? cfs_fail_val : GNI_RC_INVALID_PARAM;
	} else {
		rrc = gni_cdm_create(inst_id, ptag, cookie, modes, cdm_hndl);
	}

	switch (rrc)  {
	case GNI_RC_SUCCESS:
		break;
	case GNI_RC_ERROR_RESOURCE:
	case GNI_RC_INVALID_PARAM:
		/* Try to bail gracefully */
		GNILND_API_SWBUG(
			inst_id, ptag, cookie, modes, cdm_hndl);
		break;
	default:
		GNILND_API_RC_LBUG(
			inst_id, ptag, cookie, modes, cdm_hndl);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}

#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_cdm_attach"
#define apick_fmt "0x%p, %u, 0x%p, 0x%p"
static inline gni_return_t kgnilnd_cdm_attach(
		IN gni_cdm_handle_t	cdm_hndl,
		IN uint32_t		device_id,
		OUT uint32_t		*local_addr,
		OUT gni_nic_handle_t	*nic_hndl
		)
{
	gni_return_t rrc;

	/* Error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_CDM_ATTACH)) {
		rrc = cfs_fail_val ? cfs_fail_val : GNI_RC_INVALID_PARAM;
	} else {
		rrc = gni_cdm_attach(cdm_hndl, device_id, local_addr, nic_hndl);
	}

	switch (rrc)  {
	case GNI_RC_SUCCESS:
		break;
	case GNI_RC_NO_MATCH:
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			cdm_hndl, device_id, local_addr, nic_hndl);
		break;
	case GNI_RC_ERROR_RESOURCE:
	case GNI_RC_INVALID_STATE:
		GNILND_API_RESOURCE(
			cdm_hndl, device_id, local_addr, nic_hndl);
		break;
	default:
		GNILND_API_RC_LBUG(
			cdm_hndl, device_id, local_addr, nic_hndl);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fmt
#undef apick_fn

#define apick_fn "kgnilnd_cdm_destroy"
#define apick_fmt "0x%p"
static inline gni_return_t kgnilnd_cdm_destroy(
		IN gni_cdm_handle_t     cdm_hndl
		)
{
	gni_return_t rrc;

	/* Error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_CQ_DESTROY)) {
		rrc = cfs_fail_val ? cfs_fail_val : GNI_RC_INVALID_PARAM;
	} else {
		rrc = gni_cdm_destroy(
			cdm_hndl);
	}

	switch (rrc)  {
	case GNI_RC_SUCCESS:
		break;
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			cdm_hndl);
		break;
	default:
		GNILND_API_RC_LBUG(
			cdm_hndl);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_subscribe_errors"
#define apick_fmt "0x%p,%x,%u,0x%p,0x%p,0x%p"
static inline gni_return_t kgnilnd_subscribe_errors(
		IN gni_nic_handle_t  nic_handle,
		IN gni_error_mask_t  mask,
		IN uint32_t          EEQ_size,
		IN void              (*EQ_new_event)(gni_err_handle_t),
		IN void              (*app_crit_err)(gni_err_handle_t),
		OUT gni_err_handle_t *err_handle
		)
{
	gni_return_t rrc;

	/* Error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_ERR_SUBSCRIBE)) {
		rrc = cfs_fail_val ? cfs_fail_val : GNI_RC_INVALID_PARAM;
	} else {
		rrc = gni_subscribe_errors(
			nic_handle, mask, EEQ_size, EQ_new_event, app_crit_err,
			err_handle);
	}

	switch (rrc)  {
	case GNI_RC_SUCCESS:
		break;
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			nic_handle, mask, EEQ_size, EQ_new_event, app_crit_err,
			err_handle);
		break;
	case GNI_RC_ERROR_RESOURCE:
		GNILND_API_RESOURCE(
			nic_handle, mask, EEQ_size, EQ_new_event, app_crit_err,
			err_handle);
		break;
	default:
		GNILND_API_RC_LBUG(
			nic_handle, mask, EEQ_size, EQ_new_event, app_crit_err,
			err_handle);
		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_release_errors"
#define apick_fmt "0x%p"
static inline gni_return_t kgnilnd_release_errors(
		IN gni_err_handle_t err_handle
		)
{
	gni_return_t rrc;

	rrc = gni_release_errors(
			err_handle);

	switch (rrc)  {
	case GNI_RC_SUCCESS:
		break;
	case GNI_RC_INVALID_PARAM:
	case GNI_RC_NOT_DONE:
		GNILND_API_SWBUG(
			err_handle);
		break;
	default:
		GNILND_API_RC_LBUG(
			err_handle);
		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_set_quiesce_callback"
#define apick_fmt "0x%p,0x%p"
static inline gni_return_t kgnilnd_set_quiesce_callback(
		IN gni_nic_handle_t  nic_handle,
		IN void              (*qsce_func)(gni_nic_handle_t, uint64_t msecs)
		)
{
	gni_return_t rrc;

	/* Error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_REG_QUIESCE)) {
		rrc = cfs_fail_val ? cfs_fail_val : GNI_RC_INVALID_PARAM;
	} else {
		rrc = gni_set_quiesce_callback(
			nic_handle, qsce_func);
	}

	switch (rrc)  {
	case GNI_RC_SUCCESS:
		break;
	case GNI_RC_INVALID_STATE:
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			nic_handle, qsce_func);
		break;
	default:
		GNILND_API_RC_LBUG(
			nic_handle, qsce_func);
		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_get_quiesce_status"
#define apick_fmt "0x%p"
static inline gni_return_t kgnilnd_get_quiesce_status(
		IN gni_nic_handle_t  nic_handle
		)
{
	uint32_t rrc;

	/* this has weird RC -
	 * 0 - quiesce not in progress
	 * 1 - quiesce is turned on
	*/

	/* Error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_IN_QUIESCE)) {
		rrc = 1;
	} else {
		rrc = gni_get_quiesce_status(
			nic_handle);
	}

	switch (rrc)  {
	case 1:
	case 0:
		break;
	default:
		GNILND_API_RC_LBUG(
			nic_handle);
		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_cq_create"
#define apick_fmt "0x%p, %u, %u, 0x%p, %#llx, 0x%p"
static inline gni_return_t kgnilnd_cq_create(
		IN gni_nic_handle_t	nic_hndl,
		IN uint32_t		entry_count,
		IN uint32_t		delay_index,
		IN gni_cq_event_hndlr_f *event_handler,
		IN uint64_t		usr_event_data,
		OUT gni_cq_handle_t	*cq_hndl
		)
{
	gni_return_t rrc;

	/* Error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_CQ_CREATE)) {
		rrc = cfs_fail_val ? cfs_fail_val : GNI_RC_INVALID_PARAM;
	} else {
		rrc = gni_cq_create(
		       nic_hndl, entry_count, delay_index, event_handler,
			usr_event_data, cq_hndl);
	}

	switch (rrc)  {
	case GNI_RC_SUCCESS:
		break;
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			nic_hndl, entry_count, delay_index, event_handler,
			usr_event_data, cq_hndl);
		break;
	case GNI_RC_ERROR_RESOURCE:
		GNILND_API_RESOURCE(
			nic_hndl, entry_count, delay_index, event_handler,
			usr_event_data, cq_hndl);
		break;
	default:
		GNILND_API_RC_LBUG(
			nic_hndl, entry_count, delay_index, event_handler,
			usr_event_data, cq_hndl);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_cq_destroy"
#define apick_fmt "0x%p"
static inline gni_return_t kgnilnd_cq_destroy(
		IN gni_cq_handle_t cq_hndl
		)
{
	gni_return_t rrc;

	/* Error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_CQ_DESTROY)) {
		rrc = cfs_fail_val ? cfs_fail_val : GNI_RC_INVALID_PARAM;
	} else {

		rrc = gni_cq_destroy(
			cq_hndl);
	}

	switch (rrc)  {
	case GNI_RC_SUCCESS:
		break;
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			cq_hndl);
		break;
	case GNI_RC_ERROR_RESOURCE:
		GNILND_API_BUSY(
			cq_hndl);
		break;
	default:
		GNILND_API_RC_LBUG(
			cq_hndl);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_cq_get_event"
#define apick_fmt "0x%p, 0x%p"
static inline gni_return_t kgnilnd_cq_get_event(
		IN gni_cq_handle_t cq_hndl,
		OUT gni_cq_entry_t *event_data
		)
{
	gni_return_t rrc;

	/* no error injection - CQs are touchy about the data.
	 * where appropriate, we'll do this on the CQs that should be able to
	 * handle the various errors */
	rrc = gni_cq_get_event(
			cq_hndl, event_data);

	switch (rrc)  {
	case GNI_RC_SUCCESS:
	case GNI_RC_NOT_DONE:
	case GNI_RC_TRANSACTION_ERROR:
		break;
	case GNI_RC_ERROR_RESOURCE:
		LASSERTF(GNI_CQ_OVERRUN(*event_data),
			 "kgni returned ERROR_RESOURCE but cq_hndl 0x%p is not "
			 "overrun\n", cq_hndl);
		break;
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			cq_hndl, event_data);
		break;
	default:
		GNILND_API_RC_LBUG(
			cq_hndl, event_data);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	return rrc;
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_smsg_init"
#define apick_fmt "0x%p, 0x%p, 0x%p"
static inline gni_return_t kgnilnd_smsg_init(
		IN gni_ep_handle_t      ep_hndl,
		IN gni_smsg_attr_t      *local_smsg_attr,
		IN gni_smsg_attr_t      *remote_smsg_attr
		)
{
	gni_return_t rrc;

	/* Error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_SMSG_INIT)) {
		rrc = cfs_fail_val ? cfs_fail_val : GNI_RC_ERROR_RESOURCE;
	} else {
		rrc = gni_smsg_init(
			ep_hndl, local_smsg_attr, remote_smsg_attr);
	}

	switch (rrc)  {
	/* both of these are OK, upper SW needs to handle */
	case GNI_RC_SUCCESS:
	case GNI_RC_NOT_DONE:
		break;
	case GNI_RC_INVALID_PARAM:
	case GNI_RC_INVALID_STATE:
		GNILND_API_SWBUG(
			ep_hndl, local_smsg_attr, remote_smsg_attr);
		break;
	case GNI_RC_ERROR_RESOURCE:
		GNILND_API_RESOURCE(
			ep_hndl, local_smsg_attr, remote_smsg_attr);
		break;
	default:
		GNILND_API_RC_LBUG(
			ep_hndl, local_smsg_attr, remote_smsg_attr);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_smsg_send"
#define apick_fmt "0x%p, 0x%p, %d, 0x%p, %u %u"
static inline gni_return_t kgnilnd_smsg_send(
		IN gni_ep_handle_t      ep_hndl,
		IN void                 *header,
		IN uint32_t             header_length,
		IN void                 *data,
		IN uint32_t             data_length,
		IN uint32_t             msg_id
		)
{
	gni_return_t rrc;

	/* Error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_SMSG_SEND)) {
		if (cfs_fail_loc & CFS_FAIL_RAND) {
			rrc = GNI_RC_NOT_DONE;
		} else {
			rrc = cfs_fail_val ? cfs_fail_val : GNI_RC_NOT_DONE;
		}
	} else {
		rrc = gni_smsg_send(
			ep_hndl, header, header_length, data, data_length, msg_id);
	}

	switch (rrc)  {
	/* both of these are OK, upper SW needs to handle */
	case GNI_RC_SUCCESS:
	case GNI_RC_NOT_DONE:
		break;
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			ep_hndl, header, header_length, data, data_length, msg_id);
		break;
	case GNI_RC_ERROR_RESOURCE:
		GNILND_API_RESOURCE(
			ep_hndl, header, header_length, data, data_length, msg_id);
		break;
	default:
		GNILND_API_RC_LBUG(
			ep_hndl, header, header_length, data, data_length, msg_id);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_smsg_getnext"
#define apick_fmt "0x%p,0x%p"
static inline gni_return_t kgnilnd_smsg_getnext(
		IN gni_ep_handle_t      ep_hndl,
		OUT void                **header
		)
{
	gni_return_t rrc;

	/* Error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_SMSG_RELEASE)) {
		rrc = cfs_fail_val ? cfs_fail_val : GNI_RC_NOT_DONE;
	} else {
		rrc = gni_smsg_getnext(
			ep_hndl, header);
	}

	switch (rrc)  {
	/* both of these are OK, upper SW needs to handle */
	case GNI_RC_SUCCESS:
	case GNI_RC_NOT_DONE:
	case GNI_RC_INVALID_STATE:
		break;
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			ep_hndl, header);
		break;
	default:
		GNILND_API_RC_LBUG(
			ep_hndl, header);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_smsg_release"
#define apick_fmt "0x%p"
static inline gni_return_t kgnilnd_smsg_release(
		IN gni_ep_handle_t      ep_hndl
		)
{
	gni_return_t rrc;

	/* Error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_SMSG_RELEASE)) {
		rrc = cfs_fail_val ? cfs_fail_val : GNI_RC_INVALID_PARAM;
	} else {
		rrc = gni_smsg_release(
			ep_hndl);
	}

	switch (rrc)  {
	/* both of these are OK, upper SW needs to handle */
	case GNI_RC_SUCCESS:
	case GNI_RC_NOT_DONE:
		break;
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			ep_hndl);
		break;
	default:
		GNILND_API_RC_LBUG(
			ep_hndl);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_ep_create"
#define apick_fmt "0x%p, 0x%p, 0x%p"
static inline gni_return_t kgnilnd_ep_create(
		IN gni_nic_handle_t     nic_hndl,
		IN gni_cq_handle_t      src_cq_hndl,
		OUT gni_ep_handle_t     *ep_hndl
		)
{
	gni_return_t rrc;

	/* error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_EP_CREATE)) {
		rrc = cfs_fail_val ? cfs_fail_val : GNI_RC_ERROR_NOMEM;
	} else {
		rrc = gni_ep_create(
			nic_hndl, src_cq_hndl, ep_hndl);
	}

	switch (rrc)  {
	case GNI_RC_SUCCESS:
		break;
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			nic_hndl, src_cq_hndl, ep_hndl);
		break;
	case GNI_RC_ERROR_NOMEM:
		GNILND_API_RESOURCE(
			nic_hndl, src_cq_hndl, ep_hndl);
		break;
	default:
		GNILND_API_RC_LBUG(
			nic_hndl, src_cq_hndl, ep_hndl);

		/* lbug never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_ep_bind"
#define apick_fmt "0x%p, %x, %x"
static inline gni_return_t kgnilnd_ep_bind(
		IN gni_ep_handle_t      ep_hndl,
		IN uint32_t             remote_addr,
		IN uint32_t             remote_id
		)
{
	gni_return_t rrc;

	/* error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_EP_BIND)) {
		rrc = cfs_fail_val ? cfs_fail_val : GNI_RC_NOT_DONE;
	} else {
		rrc = gni_ep_bind(
			ep_hndl, remote_addr, remote_id);
	}

	switch (rrc)  {
	/* both of these are ok, upper sw needs to handle */
	case GNI_RC_SUCCESS:
	case GNI_RC_NOT_DONE:
		break;
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			ep_hndl, remote_addr, remote_id);
		break;
	default:
		GNILND_API_RC_LBUG(
			ep_hndl, remote_addr, remote_id);

		/* lbug never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_ep_set_eventdata"
#define apick_fmt "0x%p, %x, %x"
static inline gni_return_t kgnilnd_ep_set_eventdata(
		IN gni_ep_handle_t      ep_hndl,
		IN uint32_t             local_event,
		IN uint32_t             remote_event
		)
{
	gni_return_t rrc;

	/* Error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_EP_SET_EVDATA)) {
		rrc = cfs_fail_val ? cfs_fail_val : GNI_RC_INVALID_PARAM;
	} else {
		rrc = gni_ep_set_eventdata(
			ep_hndl, local_event, remote_event);
	}

	switch (rrc)  {
	case GNI_RC_SUCCESS:
		break;
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			ep_hndl, local_event, remote_event);
		break;
	default:
		GNILND_API_RC_LBUG(
			ep_hndl, local_event, remote_event);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_ep_unbind"
#define apick_fmt "0x%p"
static inline gni_return_t kgnilnd_ep_unbind(
		IN gni_ep_handle_t      ep_hndl
		)
{
	gni_return_t rrc;

	/* Error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_EP_UNBIND)) {
		rrc = cfs_fail_val ? cfs_fail_val : GNI_RC_NOT_DONE;
	} else {
		rrc = gni_ep_unbind(
			ep_hndl);
	}

	switch (rrc)  {
	/* both of these are OK, upper SW needs to handle */
	case GNI_RC_NOT_DONE:
	case GNI_RC_SUCCESS:
		break;
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			ep_hndl);
		break;
	default:
		GNILND_API_RC_LBUG(
			ep_hndl);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_ep_destroy"
#define apick_fmt "0x%p"
static inline gni_return_t kgnilnd_ep_destroy(
		IN gni_ep_handle_t      ep_hndl
		)
{
	gni_return_t rrc;

	/* Error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_EP_DESTROY)) {
		rrc = cfs_fail_val ? cfs_fail_val : GNI_RC_NOT_DONE;
	} else {
		rrc = gni_ep_destroy(
			ep_hndl);
	}

	switch (rrc)  {
	case GNI_RC_SUCCESS:
		break;
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			ep_hndl);
		break;
	default:
		GNILND_API_RC_LBUG(
			ep_hndl);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_ep_postdata_w_id"
#define apick_fmt "0x%p, 0x%p, %d, 0x%p, %d, %llu"
static inline gni_return_t kgnilnd_ep_postdata_w_id(
		IN gni_ep_handle_t ep_hndl,
		IN void            *in_data,
		IN uint16_t        data_len,
		IN void            *out_buf,
		IN uint16_t        buf_size,
		IN uint64_t        datagram_id
		)
{
	gni_return_t rrc;

	/* Error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_EP_POST)) {
		rrc = cfs_fail_val ? cfs_fail_val : GNI_RC_SIZE_ERROR;
	} else {
		rrc = gni_ep_postdata_w_id(
			ep_hndl, in_data, data_len, out_buf, buf_size,
			datagram_id);
	}

	switch (rrc)  {
	case GNI_RC_SUCCESS:
	case GNI_RC_ERROR_NOMEM:
	case GNI_RC_ERROR_RESOURCE:
		break;
	case GNI_RC_INVALID_PARAM:
	case GNI_RC_SIZE_ERROR:
		GNILND_API_SWBUG(
			ep_hndl, in_data, data_len, out_buf, buf_size,
			datagram_id);
		break;
	default:
		GNILND_API_RC_LBUG(
			ep_hndl, in_data, data_len, out_buf, buf_size,
			datagram_id);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_ep_postdata_test_by_id"
#define apick_fmt "0x%p, %llu, 0x%p, 0x%p, 0x%p"
static inline gni_return_t kgnilnd_ep_postdata_test_by_id(
		IN gni_ep_handle_t      ep_hndl,
		IN uint64_t             datagram_id,
		OUT gni_post_state_t    *post_state,
		OUT uint32_t            *remote_addr,
		OUT uint32_t            *remote_id
		)
{
	gni_return_t rrc;

	/* Error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_EP_TEST)) {
		rrc = cfs_fail_val ? cfs_fail_val : GNI_RC_ERROR_NOMEM;
	} else {
		rrc = gni_ep_postdata_test_by_id(
			ep_hndl, datagram_id, post_state, remote_addr,
			remote_id);

		/* we want to lie, but we need to do the actual work first
		 * so we don't keep getting the event saying a dgram is ready */
		if (rrc == GNI_RC_SUCCESS && CFS_FAIL_CHECK(CFS_FAIL_GNI_DG_TERMINATE)) {
			/* don't use fail_val, allows us to do FAIL_SOME */
			*post_state = GNI_POST_TERMINATED;
		}
	}

	switch (rrc)  {
	case GNI_RC_SUCCESS:
	case GNI_RC_NO_MATCH:
		break;
	case GNI_RC_SIZE_ERROR:
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			ep_hndl, datagram_id, post_state, remote_addr,
			remote_id);
		break;
	case GNI_RC_ERROR_NOMEM:
		GNILND_API_RESOURCE(
			ep_hndl, datagram_id, post_state, remote_addr,
			remote_id);
		break;
	default:
		GNILND_API_RC_LBUG(
			ep_hndl, datagram_id, post_state, remote_addr,
			remote_id);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_ep_postdata_cancel_by_id"
#define apick_fmt "0x%p, %llu"
static inline gni_return_t kgnilnd_ep_postdata_cancel_by_id(
		IN gni_ep_handle_t      ep_hndl,
		IN uint64_t             datagram_id
		)
{
	gni_return_t rrc;

	/* no error injection as the only thing we'd do is LBUG */

	rrc = gni_ep_postdata_cancel_by_id(
		ep_hndl, datagram_id);

	switch (rrc)  {
	case GNI_RC_SUCCESS:
	case GNI_RC_NO_MATCH:
		break;
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			ep_hndl, datagram_id);
		break;
	default:
		GNILND_API_RC_LBUG(
			ep_hndl, datagram_id);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_postdata_probe_by_id"
#define apick_fmt "0x%p, 0x%p"
static inline gni_return_t kgnilnd_postdata_probe_by_id(
		IN gni_nic_handle_t    nic_hndl,
		OUT uint64_t          *datagram_id
		)
{
	gni_return_t rrc;

	/* Error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_PROBE)) {
		rrc = cfs_fail_val ? cfs_fail_val : GNI_RC_NO_MATCH;
	} else {
		rrc = gni_postdata_probe_by_id(
			nic_hndl, datagram_id);
	}

	switch (rrc)  {
	case GNI_RC_SUCCESS:
	case GNI_RC_NO_MATCH:
		break;
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			nic_hndl, datagram_id);
		break;
	default:
		GNILND_API_RC_LBUG(
			nic_hndl, datagram_id);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_postdata_probe_wait_by_id"
#define apick_fmt "0x%p, %d, 0x%p"
static inline gni_return_t kgnilnd_postdata_probe_wait_by_id(
		IN gni_nic_handle_t nic_hndl,
		IN uint32_t         timeout,
		OUT uint64_t        *datagram_id
		)
{
	gni_return_t rrc;

	/* Error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_PROBE_WAIT)) {
		rrc = cfs_fail_val ? cfs_fail_val : GNI_RC_TIMEOUT;
	} else {
		rrc = gni_postdata_probe_wait_by_id(
			nic_hndl, timeout, datagram_id);
	}

	switch (rrc)  {
	case GNI_RC_SUCCESS:
	case GNI_RC_TIMEOUT:
		break;
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			nic_hndl, timeout, datagram_id);
		break;
	default:
		GNILND_API_RC_LBUG(
			nic_hndl, timeout, datagram_id);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_post_rdma"
#define apick_fmt "0x%p, 0x%p"
static inline gni_return_t kgnilnd_post_rdma(
		IN gni_ep_handle_t               ep_hndl,
		IN gni_post_descriptor_t        *post_descr
		)
{
	gni_return_t rrc;

	/* Error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_POST_RDMA)) {
		rrc = cfs_fail_val ? cfs_fail_val : GNI_RC_INVALID_PARAM;
	} else {
		rrc = gni_post_rdma(
			ep_hndl, post_descr);
	}

	switch (rrc)  {
	case GNI_RC_SUCCESS:
		break;
	case GNI_RC_ALIGNMENT_ERROR:
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			ep_hndl, post_descr);
		break;
	case GNI_RC_ERROR_RESOURCE:
		CDEBUG(D_NET, "no resources for kgnilnd_post_rdma (0x%p, 0x%p)"
			" rc %s\n", ep_hndl, post_descr,
			kgnilnd_api_rc2str(rrc));
		break;
	default:
		GNILND_API_RC_LBUG(
			ep_hndl, post_descr);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_get_completed"
#define apick_fmt "0x%p,%#llx,0x%p"
static inline gni_return_t kgnilnd_get_completed(
		IN gni_cq_handle_t              cq_hndl,
		IN gni_cq_entry_t               event_data,
		OUT gni_post_descriptor_t       **post_descr
		)
{
	gni_return_t rrc;


	rrc = gni_get_completed(cq_hndl, event_data, post_descr);

	switch (rrc)  {
	case GNI_RC_TRANSACTION_ERROR:
	case GNI_RC_SUCCESS:
		break;
	case GNI_RC_DESCRIPTOR_ERROR:
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(cq_hndl, event_data, post_descr);
		break;
	default:
		GNILND_API_RC_LBUG(cq_hndl, event_data, post_descr);
		/* LBUG never returns, but just for style and consistency */
		break;
	}

	/* Error injection - we need a valid desc, so let kgni give us one
	 * - then we lie  */
	if (rrc == GNI_RC_SUCCESS &&
	    (CFS_FAIL_CHECK(CFS_FAIL_GNI_GET_COMPLETED))) {
		/* We only trigger TRANSACTION_ERROR for now */
		gni_post_descriptor_t *desc;
		rrc = GNI_RC_TRANSACTION_ERROR;
		desc = *post_descr;
		desc->status = rrc;
		/* recoverable decision made from cfs_fail_val in
		 *  kgnilnd_cq_error_str and
		 *  kgnilnd_cq_error_recoverable */
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_cq_error_str"
#define apick_fmt "%#llx,0x%p,%d"
static inline gni_return_t kgnilnd_cq_error_str(
		IN gni_cq_entry_t       entry,
		IN void                *buffer,
		IN uint32_t             len
		)
{
	gni_return_t rrc;

	/* Error injection - set string if we injected a
	 *  TRANSACTION_ERROR earlier */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_GET_COMPLETED)) {
		/* if we just set persistent error, we can't ever
		 * break in via ssh to clear, so use a count > 10 to indicate fatal */
		sprintf(buffer, "INJECT:%s", cfs_fail_val > 10 ?
			"FATAL" : "RECOVERABLE");
		rrc = GNI_RC_SUCCESS;
	} else {
		rrc = gni_cq_error_str(
			entry, buffer, len);
	}

	switch (rrc)  {
	case GNI_RC_SUCCESS:
		break;
	case GNI_RC_SIZE_ERROR:
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			entry, buffer, len);
		/* give them something to use */
		snprintf(buffer, len, "UNDEF:UNDEF");
		break;
	default:
		GNILND_API_RC_LBUG(
			entry, buffer, len);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_cq_error_recoverable"
#define apick_fmt "%#llx,0x%p"
static inline gni_return_t kgnilnd_cq_error_recoverable(
		IN gni_cq_entry_t       entry,
		IN uint32_t            *recoverable
		)
{
	gni_return_t rrc;

	/* Error injection - set string if we injected a
	 *  TRANSACTION_ERROR earlier */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_GET_COMPLETED)) {
		*recoverable = cfs_fail_val > 10 ? 0 : 1;
		rrc = GNI_RC_SUCCESS;
	} else {
		rrc = gni_cq_error_recoverable(
			entry, recoverable);
	}

	switch (rrc)  {
	case GNI_RC_SUCCESS:
		break;
	case GNI_RC_INVALID_STATE:
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			entry, recoverable);
		*recoverable = 0;
		break;
	default:
		GNILND_API_RC_LBUG(
			entry, recoverable);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_mem_register_segments"
#define apick_fmt "0x%p,0x%p,%u,0x%p,%x,0x%p"
static inline gni_return_t
kgnilnd_mem_register_segments(
		IN gni_nic_handle_t     nic_hndl,
		IN gni_mem_segment_t    *mem_segments,
		IN uint32_t             segments_cnt,
		IN gni_cq_handle_t      dst_cq_hndl,
		IN uint32_t             flags,
		OUT gni_mem_handle_t    *mem_hndl
		)
{
	gni_return_t rrc;

	/* Error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_PHYS_MAP)) {
		rrc = GNI_RC_ERROR_RESOURCE;
	} else {
		rrc = gni_mem_register_segments(
			nic_hndl, mem_segments, segments_cnt,
			dst_cq_hndl, flags, mem_hndl);
	}

	switch (rrc)  {
	case GNI_RC_SUCCESS:
	case GNI_RC_ERROR_RESOURCE:
		break;
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			nic_hndl, mem_segments, segments_cnt,
			dst_cq_hndl, flags, mem_hndl);
		break;
	default:
		GNILND_API_RC_LBUG(
			nic_hndl, mem_segments, segments_cnt,
			dst_cq_hndl, flags, mem_hndl);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_mem_register"
#define apick_fmt "0x%p,%#llx,%#llx0x%p,%u,0x%p"
static inline gni_return_t kgnilnd_mem_register(
		IN gni_nic_handle_t     nic_hndl,
		IN uint64_t             address,
		IN uint64_t             length,
		IN gni_cq_handle_t      dst_cq_hndl,
		IN uint32_t             flags,
		OUT gni_mem_handle_t    *mem_hndl
		)
{
	gni_return_t rrc;

	/* Error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_VIRT_MAP)) {
		rrc = GNI_RC_ERROR_RESOURCE;
	} else if (CFS_FAIL_CHECK(CFS_FAIL_GNI_VIRT_SMALL_MAP) &&
		   length <= *kgnilnd_tunables.kgn_max_immediate) {
		rrc = GNI_RC_INVALID_PARAM;
	} else {
		rrc = gni_mem_register(
			nic_hndl, address, length,
			dst_cq_hndl, flags, mem_hndl);
	}

	/* gni_mem_register may return GNI_RC_ERROR_NOMEM under memory
	 * pressure but the upper layers only know about resource errors
	 */
	if (rrc == GNI_RC_ERROR_NOMEM) {
		rrc = GNI_RC_ERROR_RESOURCE;
	}

	switch (rrc)  {
	case GNI_RC_SUCCESS:
	case GNI_RC_ERROR_RESOURCE:
		break;
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			nic_hndl, address, length,
			dst_cq_hndl, flags, mem_hndl);
		break;
	default:
		GNILND_API_RC_LBUG(
			nic_hndl, address, length,
			dst_cq_hndl, flags, mem_hndl);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_mem_deregister"
#define apick_fmt "0x%p,0x%p,%d"
static inline gni_return_t kgnilnd_mem_deregister(
		IN gni_nic_handle_t     nic_hndl,
		IN gni_mem_handle_t     *mem_hndl,
		IN int                  hold_timeout
		)
{
	gni_return_t rrc;

	/* Error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_VIRT_UNMAP)) {
		rrc = cfs_fail_val ? cfs_fail_val : GNI_RC_INVALID_PARAM;
	} else {
		rrc = gni_mem_deregister(
			nic_hndl, mem_hndl, hold_timeout);
	}

	switch (rrc)  {
	case GNI_RC_SUCCESS:
		break;
	case GNI_RC_INVALID_PARAM:
		GNILND_API_SWBUG(
			nic_hndl, mem_hndl, hold_timeout);
		break;
	default:
		GNILND_API_RC_LBUG(
			nic_hndl, mem_hndl, hold_timeout);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#define apick_fn "kgnilnd_mem_mdd_release"
#define apick_fmt "0x%p,0x%p"
static inline gni_return_t kgnilnd_mem_mdd_release(
		IN gni_nic_handle_t     nic_hndl,
		IN gni_mem_handle_t     *mem_hndl
		)
{
	gni_return_t rrc;

	/* Error injection */
	if (CFS_FAIL_CHECK(CFS_FAIL_GNI_MDD_RELEASE)) {
		rrc = cfs_fail_val ? cfs_fail_val : GNI_RC_NO_MATCH;
	} else {
		rrc = gni_mem_mdd_release(
			nic_hndl, mem_hndl);
	}

	switch (rrc)  {
	case GNI_RC_SUCCESS:
	case GNI_RC_NO_MATCH:
		break;
	default:
		GNILND_API_RC_LBUG(
			nic_hndl, mem_hndl);

		/* LBUG never returns, but just for style and consistency */
		break;
	}
	RETURN(rrc);
}
#undef apick_fn
#undef apick_fmt

#endif /* _GNILND_API_WRAP_H */
