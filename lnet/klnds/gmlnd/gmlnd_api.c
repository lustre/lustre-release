/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2003 Los Alamos National Laboratory (LANL)
 *
 *   This file is part of Lustre, http://www.lustre.org/
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
 */

/*
 *	Implements the API NAL functions
 */

#include "gmnal.h"



gmnal_data_t	*global_nal_data = NULL;
#define         GLOBAL_NID_STR_LEN      16
char            global_nid_str[GLOBAL_NID_STR_LEN] = {0};
ptl_handle_ni_t kgmnal_ni;

extern int gmnal_cmd(struct portals_cfg *pcfg, void *private);

/*
 *      Write the global nid /proc/sys/gmnal/globalnid
 */
#define GMNAL_SYSCTL    201
#define GMNAL_SYSCTL_GLOBALNID  1

static ctl_table gmnal_sysctl_table[] = {
        {GMNAL_SYSCTL_GLOBALNID, "globalnid",
         global_nid_str, GLOBAL_NID_STR_LEN,
         0444, NULL, &proc_dostring},
        { 0 }
};


static ctl_table gmnalnal_top_sysctl_table[] = {
        {GMNAL_SYSCTL, "gmnal", NULL, 0, 0555, gmnal_sysctl_table},
        { 0 }
};

/*
 *	gmnal_api_shutdown
 *      nal_refct == 0 => called on last matching PtlNIFini()
 *	Close down this interface and free any resources associated with it
 *	nal_t	nal	our nal to shutdown
 */
void
gmnal_api_shutdown(nal_t *nal)
{
	gmnal_data_t	*nal_data;
	lib_nal_t	*libnal;

        if (nal->nal_refct != 0) {
                /* This module got the first ref */
                PORTAL_MODULE_UNUSE;
                return;
        }

        LASSERT(nal == global_nal_data->nal);
        libnal = (lib_nal_t *)nal->nal_data;
        nal_data = (gmnal_data_t *)libnal->libnal_data;
        LASSERT(nal_data == global_nal_data);
	CDEBUG(D_TRACE, "gmnal_api_shutdown: nal_data [%p]\n", nal_data);

        /* Stop portals calling our ioctl handler */
        libcfs_nal_cmd_unregister(GMNAL);

        /* XXX for shutdown "under fire" we probably need to set a shutdown
         * flag so when lib calls us we fail immediately and dont queue any
         * more work but our threads can still call into lib OK.  THEN
         * shutdown our threads, THEN lib_fini() */
        lib_fini(libnal);

	gmnal_stop_rxthread(nal_data);
	gmnal_stop_ctthread(nal_data);
	gmnal_free_txd(nal_data);
	gmnal_free_srxd(nal_data);
	spin_lock(&nal_data->gm_lock);
	gm_close(nal_data->gm_port);
	gm_finalize();
	spin_unlock(&nal_data->gm_lock);
        if (nal_data->sysctl)
                unregister_sysctl_table (nal_data->sysctl);
        /* Don't free 'nal'; it's a static struct */
	PORTAL_FREE(nal_data, sizeof(gmnal_data_t));
	PORTAL_FREE(libnal, sizeof(lib_nal_t));

        global_nal_data = NULL;
}


int
gmnal_api_startup(nal_t *nal, ptl_pid_t requested_pid,
                  ptl_ni_limits_t *requested_limits,
                  ptl_ni_limits_t *actual_limits)
{

	lib_nal_t	*libnal = NULL;
	gmnal_data_t	*nal_data = NULL;
	gmnal_srxd_t	*srxd = NULL;
	gm_status_t	gm_status;
	unsigned int	local_nid = 0, global_nid = 0;
        ptl_process_id_t process_id;

        if (nal->nal_refct != 0) {
                if (actual_limits != NULL) {
                        libnal = (lib_nal_t *)nal->nal_data;
                        *actual_limits = libnal->libnal_ni.ni_actual_limits;
                }
                PORTAL_MODULE_USE;
                return (PTL_OK);
        }

        /* Called on first PtlNIInit() */

	CDEBUG(D_TRACE, "startup\n");

        LASSERT(global_nal_data == NULL);

	PORTAL_ALLOC(nal_data, sizeof(gmnal_data_t));
	if (!nal_data) {
		CERROR("can't get memory\n");
		return(PTL_NO_SPACE);
	}	
	memset(nal_data, 0, sizeof(gmnal_data_t));
	/*
 	 *	set the small message buffer size 
	 */

	CDEBUG(D_INFO, "Allocd and reset nal_data[%p]\n", nal_data);
	CDEBUG(D_INFO, "small_msg_size is [%d]\n", nal_data->small_msg_size);

	PORTAL_ALLOC(libnal, sizeof(lib_nal_t));
	if (!libnal) {
		PORTAL_FREE(nal_data, sizeof(gmnal_data_t));
		return(PTL_NO_SPACE);
	}

	memset(libnal, 0, sizeof(lib_nal_t));
        libnal->libnal_send = gmnal_cb_send;
        libnal->libnal_send_pages = gmnal_cb_send_pages;
        libnal->libnal_recv = gmnal_cb_recv;
        libnal->libnal_recv_pages = gmnal_cb_recv_pages;
        libnal->libnal_map = NULL;
        libnal->libnal_unmap = NULL;
        libnal->libnal_dist = gmnal_cb_dist;
        libnal->libnal_data = NULL;

	CDEBUG(D_INFO, "Allocd and reset libnal[%p]\n", libnal);

	/*
	 *	String them all together
	 */
	libnal->libnal_data = (void*)nal_data;
	nal_data->nal = nal;
	nal_data->libnal = libnal;

	spin_lock_init(&nal_data->gm_lock);


	/*
	 *	initialise the interface,
	 */
	CDEBUG(D_INFO, "Calling gm_init\n");
	if (gm_init() != GM_SUCCESS) {
		CERROR("call to gm_init failed\n");
		PORTAL_FREE(nal_data, sizeof(gmnal_data_t));	
		PORTAL_FREE(libnal, sizeof(lib_nal_t));
		return(PTL_FAIL);
	}


	CDEBUG(D_NET, "Calling gm_open with port [%d], "
	       "name [%s], version [%d]\n", gm_port_id,
	       "gmnal", GM_API_VERSION);

	spin_lock(&nal_data->gm_lock);
	gm_status = gm_open(&nal_data->gm_port, 0, gm_port_id, "gmnal",
			    GM_API_VERSION);
	spin_unlock(&nal_data->gm_lock);

	CDEBUG(D_INFO, "gm_open returned [%d]\n", gm_status);
	if (gm_status == GM_SUCCESS) {
		CDEBUG(D_INFO,"gm_open succeeded port[%p]\n",nal_data->gm_port);
	} else {
		switch(gm_status) {
		case(GM_INVALID_PARAMETER):
			CERROR("gm_open Failure. Invalid Parameter\n");
			break;
		case(GM_BUSY):
			CERROR("gm_open Failure. GM Busy\n");
			break;
		case(GM_NO_SUCH_DEVICE):
			CERROR("gm_open Failure. No such device\n");
			break;
		case(GM_INCOMPATIBLE_LIB_AND_DRIVER):
			CERROR("gm_open Failure. Incompatile lib and driver\n");
			break;
		case(GM_OUT_OF_MEMORY):
			CERROR("gm_open Failure. Out of Memory\n");
			break;
		default:
			CERROR("gm_open Failure. Unknow error code [%d]\n",
                               gm_status);
			break;
		}	
		spin_lock(&nal_data->gm_lock);
		gm_finalize();
		spin_unlock(&nal_data->gm_lock);
		PORTAL_FREE(nal_data, sizeof(gmnal_data_t));	
		PORTAL_FREE(libnal, sizeof(lib_nal_t));
		return(PTL_FAIL);
	}

	nal_data->small_msg_size = gmnal_small_msg_size;
	nal_data->small_msg_gmsize =
			gm_min_size_for_length(gmnal_small_msg_size);

	if (gmnal_alloc_srxd(nal_data) != GMNAL_STATUS_OK) {
		CERROR("Failed to allocate small rx descriptors\n");
		gmnal_free_txd(nal_data);
		spin_lock(&nal_data->gm_lock);
		gm_close(nal_data->gm_port);
		gm_finalize();
		spin_unlock(&nal_data->gm_lock);
		PORTAL_FREE(nal_data, sizeof(gmnal_data_t));	
		PORTAL_FREE(libnal, sizeof(lib_nal_t));
		return(PTL_FAIL);
	}


	/*
 	 *	Hang out a bunch of small receive buffers
	 *	In fact hang them all out
	 */
	while((srxd = gmnal_get_srxd(nal_data, 0))) {
		CDEBUG(D_NET, "giving [%p] to gm_provide_recvive_buffer\n", 
		       srxd->buffer);
		spin_lock(&nal_data->gm_lock);
		gm_provide_receive_buffer_with_tag(nal_data->gm_port, 
						   srxd->buffer, srxd->gmsize, 
						   GM_LOW_PRIORITY, 0);
		spin_unlock(&nal_data->gm_lock);
	}
	
	/*
	 *	Allocate pools of small tx buffers and descriptors
	 */
	if (gmnal_alloc_txd(nal_data) != GMNAL_STATUS_OK) {
		CERROR("Failed to allocate small tx descriptors\n");
		spin_lock(&nal_data->gm_lock);
		gm_close(nal_data->gm_port);
		gm_finalize();
		spin_unlock(&nal_data->gm_lock);
		PORTAL_FREE(nal_data, sizeof(gmnal_data_t));	
		PORTAL_FREE(libnal, sizeof(lib_nal_t));
		return(PTL_FAIL);
	}

	/*
	 *	Initialise the portals library
	 */
	CDEBUG(D_NET, "Getting node id\n");
	spin_lock(&nal_data->gm_lock);
	gm_status = gm_get_node_id(nal_data->gm_port, &local_nid);
	spin_unlock(&nal_data->gm_lock);
	if (gm_status != GM_SUCCESS) {
		gmnal_stop_rxthread(nal_data);
		gmnal_stop_ctthread(nal_data);
		CERROR("can't determine node id\n");
		gmnal_free_txd(nal_data);
		gmnal_free_srxd(nal_data);
		spin_lock(&nal_data->gm_lock);
		gm_close(nal_data->gm_port);
		gm_finalize();
		spin_unlock(&nal_data->gm_lock);
		PORTAL_FREE(nal_data, sizeof(gmnal_data_t));	
		PORTAL_FREE(libnal, sizeof(lib_nal_t));
		return(PTL_FAIL);
	}

	nal_data->gm_local_nid = local_nid;
	CDEBUG(D_INFO, "Local node id is [%u]\n", local_nid);

	spin_lock(&nal_data->gm_lock);
	gm_status = gm_node_id_to_global_id(nal_data->gm_port, local_nid, 
					    &global_nid);
	spin_unlock(&nal_data->gm_lock);
	if (gm_status != GM_SUCCESS) {
		CERROR("failed to obtain global id\n");
		gmnal_stop_rxthread(nal_data);
		gmnal_stop_ctthread(nal_data);
		gmnal_free_txd(nal_data);
		gmnal_free_srxd(nal_data);
		spin_lock(&nal_data->gm_lock);
		gm_close(nal_data->gm_port);
		gm_finalize();
		spin_unlock(&nal_data->gm_lock);
		PORTAL_FREE(nal_data, sizeof(gmnal_data_t));	
		PORTAL_FREE(libnal, sizeof(lib_nal_t));
		return(PTL_FAIL);
	}
	CDEBUG(D_INFO, "Global node id is [%u]\n", global_nid);
	nal_data->gm_global_nid = global_nid;
        snprintf(global_nid_str, GLOBAL_NID_STR_LEN, "%u", global_nid);

/*
	pid = gm_getpid();
*/
        process_id.pid = requested_pid;
        process_id.nid = global_nid;

	CDEBUG(D_INFO, "portals_pid is [%u]\n", process_id.pid);
	CDEBUG(D_INFO, "portals_nid is ["LPU64"]\n", process_id.nid);

	CDEBUG(D_PORTALS, "calling lib_init\n");
	if (lib_init(libnal, nal, process_id,
                     requested_limits, actual_limits) != PTL_OK) {
		CERROR("lib_init failed\n");
		gmnal_stop_rxthread(nal_data);
		gmnal_stop_ctthread(nal_data);
		gmnal_free_txd(nal_data);
		gmnal_free_srxd(nal_data);
		spin_lock(&nal_data->gm_lock);
		gm_close(nal_data->gm_port);
		gm_finalize();
		spin_unlock(&nal_data->gm_lock);
		PORTAL_FREE(nal_data, sizeof(gmnal_data_t));
		PORTAL_FREE(libnal, sizeof(lib_nal_t));
		return(PTL_FAIL);
	}

	/*
	 * Now that we have initialised the portals library, start receive threads,
	 * we do this to avoid processing messages before we can parse them
	 */
	gmnal_start_kernel_threads(nal_data);

	while (nal_data->rxthread_flag != GMNAL_RXTHREADS_STARTED) {
		gmnal_yield(1);
		CDEBUG(D_INFO, "Waiting for receive thread signs of life\n");
	}

	CDEBUG(D_INFO, "receive thread seems to have started\n");

	if (libcfs_nal_cmd_register(GMNAL, &gmnal_cmd, libnal->libnal_data) != 0) {
		CDEBUG(D_INFO, "libcfs_nal_cmd_register failed\n");

                /* XXX these cleanup cases should be restructured to
                 * minimise duplication... */
                lib_fini(libnal);
                
		gmnal_stop_rxthread(nal_data);
		gmnal_stop_ctthread(nal_data);
		gmnal_free_txd(nal_data);
		gmnal_free_srxd(nal_data);
		spin_lock(&nal_data->gm_lock);
		gm_close(nal_data->gm_port);
		gm_finalize();
		spin_unlock(&nal_data->gm_lock);
		PORTAL_FREE(nal_data, sizeof(gmnal_data_t));	
		PORTAL_FREE(libnal, sizeof(lib_nal_t));
		return(PTL_FAIL);
        }

        /* might be better to initialise this at module load rather than in
         * NAL startup */
        nal_data->sysctl = NULL;
        nal_data->sysctl = register_sysctl_table (gmnalnal_top_sysctl_table, 0);

	CDEBUG(D_INFO, "gmnal_init finished\n");

	global_nal_data = libnal->libnal_data;

	return(PTL_OK);
}

nal_t the_gm_nal;

/* 
 *        Called when module loaded
 */
int gmnal_init(void)
{
        int    rc;

	CDEBUG(D_INFO, "reset nal[%p]\n", &the_gm_nal);

        the_gm_nal = (nal_t) {
                .nal_ni_init = gmnal_api_startup,
                .nal_ni_fini = gmnal_api_shutdown,
                .nal_data = NULL,
        };

        rc = ptl_register_nal(GMNAL, &the_gm_nal);
        if (rc != PTL_OK)
                CERROR("Can't register GMNAL: %d\n", rc);
        rc = PtlNIInit(GMNAL, LUSTRE_SRV_PTL_PID, NULL, NULL, &kgmnal_ni);
        if (rc != PTL_OK && rc != PTL_IFACE_DUP) {
                ptl_unregister_nal(GMNAL);
                return (-ENODEV);
        }

        return (rc);
}


/*
 *	Called when module removed
 */
void gmnal_fini()
{
	CDEBUG(D_TRACE, "gmnal_fini\n");

        PtlNIFini(kgmnal_ni);

        ptl_unregister_nal(GMNAL);
        LASSERT(global_nal_data == NULL);
}
