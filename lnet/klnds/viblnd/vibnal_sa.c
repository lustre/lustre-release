/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004 Cluster File Systems, Inc.
 *   Author: Frank Zago <fzago@systemfabricworks.com>
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

#include "vibnal.h"

/*--------------------------------------------------------------------------*/

struct sa_request *alloc_sa_request(void)
{
        struct sa_request *request;
        gsi_dtgrm_t *dtgrm;
        vv_return_t retval;

        PORTAL_ALLOC(request, sizeof(*request));
        if (request == NULL)
                return NULL;
        
        retval = gsi_dtgrm_pool_get(kibnal_data.gsi_pool_handle, &dtgrm);
        if (retval) {
                CERROR("cannot get a datagram: %d\n", retval);
                PORTAL_FREE(request, sizeof(*request));
                return NULL;
        }

        memset(request, 0, sizeof(*request));

        request->dtgrm_req = dtgrm;
        request->retry = GSI_RETRY;    /* retry the request up to 10 times */

        return request;
}

void free_sa_request(struct sa_request *request)
{
        if (request) {
                if (request->dtgrm_req) {
                        gsi_dtgrm_pool_put(request->dtgrm_req);	
                }

                if (request->dtgrm_resp) {
                        gsi_dtgrm_pool_put(request->dtgrm_resp);
                }

                PORTAL_FREE(request, sizeof(*request));
        }
}

/*--------------------------------------------------------------------------*/

static void complete_sa_request(struct sa_request *request)
{
	if (request->callback) {
		request->callback(request);
	} else {
		complete(&request->signal);
	}
}

static void
sa_request_timeout_handler(unsigned long context)
{
	struct sa_request *request = (struct sa_request *)context;
	int ret;
	vv_return_t retval;

	if (request->retry--) {
		/* Resend */

		CDEBUG(D_NET, "timer expired for MAD TID "LPX64" - retrying (%d retry left)\n", request->mad->hdr.transact_id, request->retry);
		retval = gsi_post_send_dtgrm(kibnal_data.gsi_handle, request->dtgrm_req);
		if (retval) {
			CERROR("gsi_post_send_dtgrm failed: %d\n", retval);
			ret = -EIO;
		} else {

			/* restart the timer */
			request->timer.expires = jiffies + (HZ * GSI_TIMEOUT);
			add_timer(&request->timer);
			
			ret = 0;
		}
	} else {
		CDEBUG(D_NET, "timer expired for MAD TID "LPX64" - no more retry\n", request->mad->hdr.transact_id);
		ret = ETIMEDOUT;
	}

	if (ret) {
		request->status = ret;
		complete_sa_request(request);
	}
}

/*--------------------------------------------------------------------------*/

/* Send a SA request */
int vibnal_start_sa_request(struct sa_request *request)
{
	int ret;
	vv_return_t vv_stat;
	int retval;

	CDEBUG (D_NET, "querying SA\n");

	/* Put the request on the pending list and get a transaction ID. */
	down(&kibnal_data.gsi_mutex);

	list_add_tail(&request->list, &kibnal_data.gsi_pending);

	up(&kibnal_data.gsi_mutex);

	retval = gsi_post_send_dtgrm(kibnal_data.gsi_handle, request->dtgrm_req);
	if (retval) {
		CERROR("gsi_post_send_dtgrm failed: %d\n", retval);
		return -EIO;
	}

	/* TODO: This might create a race condition if the response has
	 * already been received. */
	init_timer(&request->timer);
	request->timer.expires = jiffies + (HZ * GSI_TIMEOUT);
	request->timer.data = (unsigned long)request;
	request->timer.function = sa_request_timeout_handler;
	add_timer(&request->timer);

	CDEBUG(D_NET, "Posted MAD with TID= "LPX64"\n", request->mad->hdr.transact_id);
	return 0;
}

/* Received a MAD */
void
vibnal_mad_received_cb(gsi_class_handle_t handle, void *context, gsi_dtgrm_t *dtgrm)
{
	sa_mad_v2_t *mad = (sa_mad_v2_t *) dtgrm->mad;
	ib_service_record_v2_t *sr = (ib_service_record_v2_t *) mad->payload;
	struct list_head *this;
	struct sa_request *request;

	CDEBUG(D_NET, "Received new MAD\n");

	/* Validate the MAD */
	if (mad->hdr.base_ver != MAD_IB_BASE_VERSION ||
		mad->hdr.class != MAD_CLASS_SUBN_ADM ||
        mad->hdr.class_ver != 2) {
		CDEBUG(D_NET, "ignoring MAD (base_ver=%x, class=%x, class_ver=%x)\n",
			   mad->hdr.base_ver, mad->hdr.class, mad->hdr.class_ver);
		return;
	}

	/* We don't care about queries, only about responses */
	if (mad->hdr.m.ms.r != 1) {
		CDEBUG(D_NET, "ignoring MAD (response=%d)\n", mad->hdr.m.ms.r);
		return;
	}

	/* We only care about service records and path records. */
	if (mad->hdr.attrib_id != SA_SERVICE_RECORD &&
		mad->hdr.attrib_id != SA_PATH_RECORD) {
		CDEBUG(D_NET, "ignoring MAD (attrib_id=%x)\n", mad->hdr.attrib_id);
		return;
	}

	/* Find the MAD request in our list */
	request = NULL;

	down(&kibnal_data.gsi_mutex);

	list_for_each(this, &kibnal_data.gsi_pending) {
		struct sa_request *_request = list_entry(this, struct sa_request, list);

		CDEBUG(D_NET, "Comparing pending MAD TID "LPX64" with incoming MAD TID "LPX64"\n",
			   _request->mad->hdr.transact_id, mad->hdr.transact_id);

		if (_request->mad->hdr.transact_id == mad->hdr.transact_id) {
			CDEBUG(D_NET, "TIDs match\n");
			request = _request;
			break;
		}
	}

	if (request == NULL) {
		up(&kibnal_data.gsi_mutex);
		CDEBUG(D_NET, "ignoring MAD (TID = "LPX64"\n", mad->hdr.transact_id);
		return;
	}

	up(&kibnal_data.gsi_mutex);

	/* Stop the timer and remove the request from the pending list of requests. */
	del_timer_sync(&request->timer);

	down(&kibnal_data.gsi_mutex);

	list_del(&request->list);

	up(&kibnal_data.gsi_mutex);

	request->dtgrm_resp = dtgrm;

	/* Depending on the response, update the status. This is not exact
	 * because a non-zero status is not always an error, but that
	 * should be good enough right now. */
	/* TODO: fix. */
	if (mad->hdr.u.ns.status.raw16) {
		CDEBUG(D_NET, "MAD response has bad status: %x\n", mad->hdr.u.ns.status.raw16);
		request->status = -EIO;
	} else {
		request->status = 0;
	}

	CDEBUG(D_NET, "incoming MAD successfully processed (status is %d)\n", request->status);

	complete_sa_request(request);
}

/* MAD send completion */
void
vibnal_mad_sent_cb(gsi_class_handle_t handle, void *context, gsi_dtgrm_t * dtgrm)
{
	sa_mad_v2_t *mad = (sa_mad_v2_t *) dtgrm->mad;
	
	/* Don't do anything. We might have to resend the datagram later. */
	CDEBUG(D_NET, "Datagram with TID "LPX64" sent.\n", mad->hdr.transact_id);
}

/* 
 * method is SUBN_ADM_SET, SUBN_ADM_GET, SUBN_ADM_DELETE. Tables not supported.
 * nid is the nid to advertize/query/unadvertize
 * Note: dgid is in network order.
 */
static void fill_pathrecord_request(struct sa_request *request, vv_gid_t dgid)
{
        gsi_dtgrm_t *dtgrm = request->dtgrm_req;
        sa_mad_v2_t *mad = (sa_mad_v2_t *) dtgrm->mad;
        ib_path_record_v2_t *path = (ib_path_record_v2_t *) mad->payload;

        memset(mad, 0, MAD_BLOCK_SIZE);

        request->mad = mad;

        dtgrm->rlid = kibnal_data.kib_port_attr.port_sma_address_info.sm_lid;
        dtgrm->sl = kibnal_data.kib_port_attr.port_sma_address_info.service_level;

        mad->hdr.base_ver = MAD_IB_BASE_VERSION;
        mad->hdr.class = MAD_CLASS_SUBN_ADM;
        mad->hdr.class_ver = 2;
        mad->hdr.m.ms.method = SUBN_ADM_GET;
		mad->hdr.attrib_id = SA_PATH_RECORD; /* something(?) will swap that field */
		mad->hdr.attrib_modifier = 0xFFFFFFFF; /* and that one too? */

		/* Note: the transaction ID is set by the Voltaire stack if it is 0. */

        /* TODO: these harcoded value to something better */
        mad->payload_len = cpu_to_be32(0x40 /*header size*/ + 0x35 /* PathRecord size */);

        mad->component_mask = cpu_to_be64(
									 (1 << 2) | /* DGID      */
									 (1 << 3) | /* SGID      */
									 (1 << 12)| /* numb_paths*/
									 (1 << 13)  /* P_key     */
									 );

		path->pkey = cpu_to_be16(kibnal_data.kib_port_pkey);
		path->sgid = kibnal_data.kib_port_gid;
		gid_swap(&path->sgid);
		path->dgid = dgid;		/* already in network order */
		path->numb_path = 1;
}

/* 
 * Do a path record query
 * If callback is NULL, the function is synchronous (and context is ignored).
 * Note: dgid is in network order.
 */
/* TODO: passing a request is a bit of a hack, but since this function
 * is called under interrupt, we cannot allocate memory here :(. */
int kibnal_pathrecord_op(struct sa_request *request, vv_gid_t dgid, sa_request_cb_t callback, void *context)
{
        int ret;

        LASSERT (kibnal_data.kib_nid != PTL_NID_ANY);

        fill_pathrecord_request(request, dgid);

        if (callback) {
                request->callback = callback;
                request->context = context;
        } else {
                init_completion(&request->signal);
        }

        ret = vibnal_start_sa_request(request);
        if (ret) {
                CERROR("vibnal_send_sa failed: %d\n", ret);
                free_sa_request(request);
        } else {
                if (callback) {
                        /* Return. The callback will have to free the SA request. */
                        ret = 0;
                } else {
                        wait_for_completion(&request->signal);

                        ret = request->status;

                        if (ret != 0) {
                                CERROR ("Error %d in querying a path record\n", ret);
                        }
                        
                        free_sa_request(request);
                }
        }

        return ret;
}
