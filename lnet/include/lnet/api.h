#ifndef P30_API_H
#define P30_API_H

#include "build_check.h"

#include <portals/types.h>

ptl_err_t LNetInit(int *);

void LNetFini(void);

ptl_err_t LNetNIInit(ptl_interface_t  interface, 
		    ptl_pid_t        requested_pid,
		    ptl_ni_limits_t *desired_limits, 
		    ptl_ni_limits_t *actual_limits,
		    ptl_handle_ni_t *interface_out);

ptl_err_t LNetNIInitialized(ptl_interface_t);

ptl_err_t LNetNIFini(ptl_handle_ni_t interface_in);

ptl_err_t LNetGetId(ptl_handle_ni_t   ni_handle, 
		   ptl_process_id_t *id);

ptl_err_t LNetGetUid(ptl_handle_ni_t  ni_handle, 
		    ptl_uid_t       *uid);

/*
 * Network interfaces
 */
ptl_err_t LNetNIStatus(ptl_handle_ni_t  interface_in,
		      ptl_sr_index_t   register_in,
		      ptl_sr_value_t  *status_out);

ptl_err_t LNetNIDist(ptl_handle_ni_t   interface_in, 
		    ptl_process_id_t  process_in,
		    unsigned long    *distance_out);

ptl_err_t LNetNIHandle(ptl_handle_any_t handle_in, 
		      ptl_handle_ni_t *interface_out);

/* 
 * LNetFailNid
 *
 * Not an official Portals 3 API call.  It provides a way of calling
 * network-specific functions 
 */
int LNetNICtl(ptl_handle_ni_t interface, unsigned int cmd, void *arg);

/*
 * LNetSnprintHandle: 
 *
 * This is not an official Portals 3 API call.  It is provided
 * so that an application can print an opaque handle.
 */
void LNetSnprintHandle (char *str, int str_len, ptl_handle_any_t handle);

/*
 * Match entries
 */
ptl_err_t LNetMEAttach(ptl_handle_ni_t  interface_in, 
		      ptl_pt_index_t   index_in,
		      ptl_process_id_t match_id_in, 
		      ptl_match_bits_t match_bits_in,
		      ptl_match_bits_t ignore_bits_in, 
		      ptl_unlink_t     unlink_in,
		      ptl_ins_pos_t    pos_in, 
		      ptl_handle_me_t *handle_out);

ptl_err_t LNetMEInsert(ptl_handle_me_t  current_in, 
		      ptl_process_id_t match_id_in,
		      ptl_match_bits_t match_bits_in, 
		      ptl_match_bits_t ignore_bits_in,
		      ptl_unlink_t     unlink_in, 
		      ptl_ins_pos_t    position_in,
		      ptl_handle_me_t *handle_out);

ptl_err_t LNetMEUnlink(ptl_handle_me_t current_in);

/*
 * Memory descriptors
 */
ptl_err_t LNetMDAttach(ptl_handle_me_t  current_in, 
		      ptl_md_t         md_in,
		      ptl_unlink_t     unlink_in, 
		      ptl_handle_md_t *handle_out);

ptl_err_t LNetMDBind(ptl_handle_ni_t  ni_in, 
		    ptl_md_t         md_in,
		    ptl_unlink_t     unlink_in, 
		    ptl_handle_md_t *handle_out);

ptl_err_t LNetMDUnlink(ptl_handle_md_t md_in);

/*
 * Event queues
 */
ptl_err_t LNetEQAlloc(ptl_handle_ni_t   ni_in, 
		     ptl_size_t        count_in,
		     ptl_eq_handler_t  handler,
		     ptl_handle_eq_t  *handle_out);

ptl_err_t LNetEQFree(ptl_handle_eq_t eventq_in);

ptl_err_t LNetEQGet(ptl_handle_eq_t  eventq_in, 
		   ptl_event_t     *event_out);


ptl_err_t LNetEQWait(ptl_handle_eq_t  eventq_in, 
		    ptl_event_t     *event_out);

ptl_err_t LNetEQPoll(ptl_handle_eq_t *eventqs_in, 
		    int              neq_in, 
		    int              timeout_ms,
		    ptl_event_t     *event_out, 
		    int             *which_eq_out);

/*
 * Access Control Table
 */
ptl_err_t LNetACEntry(ptl_handle_ni_t  ni_in, 
		     ptl_ac_index_t   index_in,
		     ptl_process_id_t match_id_in, 
		     ptl_pt_index_t   portal_in);


/*
 * Data movement
 */
ptl_err_t LNetPut(ptl_handle_md_t  md_in, 
		 ptl_ack_req_t    ack_req_in,
		 ptl_process_id_t target_in, 
		 ptl_pt_index_t   portal_in,
		 ptl_ac_index_t   cookie_in, 
		 ptl_match_bits_t match_bits_in,
		 ptl_size_t       offset_in, 
		 ptl_hdr_data_t   hdr_data_in);

ptl_err_t LNetGet(ptl_handle_md_t  md_in, 
		 ptl_process_id_t target_in,
		 ptl_pt_index_t   portal_in, 
		 ptl_ac_index_t   cookie_in,
		 ptl_match_bits_t match_bits_in, 
		 ptl_size_t       offset_in);


#endif
