#ifndef __LNET_API_H__
#define __LNET_API_H__

#include "build_check.h"

#include <lnet/types.h>

int LNetInit(int *);

void LNetFini(void);

int LNetNIInit(lnet_interface_t  interface, 
		    lnet_pid_t        requested_pid,
		    lnet_ni_limits_t *desired_limits, 
		    lnet_ni_limits_t *actual_limits,
		    lnet_handle_ni_t *interface_out);

int LNetNIInitialized(lnet_interface_t);

int LNetNIFini(lnet_handle_ni_t interface_in);

int LNetGetId(lnet_handle_ni_t   ni_handle, 
		   lnet_process_id_t *id);

int LNetGetUid(lnet_handle_ni_t  ni_handle, 
		    lnet_uid_t       *uid);

/*
 * Network interfaces
 */
int LNetNIStatus(lnet_handle_ni_t  interface_in,
		      int   register_in,
		      lnet_sr_value_t  *status_out);

int LNetNIDist(lnet_handle_ni_t   interface_in, 
		    lnet_process_id_t  process_in,
		    unsigned long    *distance_out);

int LNetNIHandle(lnet_handle_any_t handle_in, 
		      lnet_handle_ni_t *interface_out);

/* 
 * LNetFailNid
 *
 * Not an official Portals 3 API call.  It provides a way of calling
 * network-specific functions 
 */
int LNetNICtl(lnet_handle_ni_t interface, unsigned int cmd, void *arg);

/*
 * LNetSnprintHandle: 
 *
 * This is not an official Portals 3 API call.  It is provided
 * so that an application can print an opaque handle.
 */
void LNetSnprintHandle (char *str, int str_len, lnet_handle_any_t handle);

/*
 * Match entries
 */
int LNetMEAttach(lnet_handle_ni_t  interface_in, 
		      lnet_pt_index_t   index_in,
		      lnet_process_id_t match_id_in, 
		      lnet_match_bits_t match_bits_in,
		      lnet_match_bits_t ignore_bits_in, 
		      lnet_unlink_t     unlink_in,
		      lnet_ins_pos_t    pos_in, 
		      lnet_handle_me_t *handle_out);

int LNetMEInsert(lnet_handle_me_t  current_in, 
		      lnet_process_id_t match_id_in,
		      lnet_match_bits_t match_bits_in, 
		      lnet_match_bits_t ignore_bits_in,
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

int LNetMDBind(lnet_handle_ni_t  ni_in, 
		    lnet_md_t         md_in,
		    lnet_unlink_t     unlink_in, 
		    lnet_handle_md_t *handle_out);

int LNetMDUnlink(lnet_handle_md_t md_in);

/*
 * Event queues
 */
int LNetEQAlloc(lnet_handle_ni_t   ni_in, 
		     lnet_size_t        count_in,
		     lnet_eq_handler_t  handler,
		     lnet_handle_eq_t  *handle_out);

int LNetEQFree(lnet_handle_eq_t eventq_in);

int LNetEQGet(lnet_handle_eq_t  eventq_in, 
		   lnet_event_t     *event_out);


int LNetEQWait(lnet_handle_eq_t  eventq_in, 
		    lnet_event_t     *event_out);

int LNetEQPoll(lnet_handle_eq_t *eventqs_in, 
		    int              neq_in, 
		    int              timeout_ms,
		    lnet_event_t     *event_out, 
		    int             *which_eq_out);

/*
 * Access Control Table
 */
int LNetACEntry(lnet_handle_ni_t  ni_in, 
		     lnet_ac_index_t   index_in,
		     lnet_process_id_t match_id_in, 
		     lnet_pt_index_t   portal_in);


/*
 * Data movement
 */
int LNetPut(lnet_handle_md_t  md_in, 
		 lnet_ack_req_t    ack_req_in,
		 lnet_process_id_t target_in, 
		 lnet_pt_index_t   portal_in,
		 lnet_ac_index_t   cookie_in, 
		 lnet_match_bits_t match_bits_in,
		 lnet_size_t       offset_in, 
		 lnet_hdr_data_t   hdr_data_in);

int LNetGet(lnet_handle_md_t  md_in, 
		 lnet_process_id_t target_in,
		 lnet_pt_index_t   portal_in, 
		 lnet_ac_index_t   cookie_in,
		 lnet_match_bits_t match_bits_in, 
		 lnet_size_t       offset_in);


#endif
