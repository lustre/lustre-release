#ifndef P30_API_H
#define P30_API_H

#include <portals/types.h>

#ifndef PTL_NO_WRAP
int PtlInit(void);
int PtlInitialized(void);
void PtlFini(void);

int PtlNIInit(ptl_interface_t interface, ptl_pt_index_t ptl_size_in,
              ptl_ac_index_t acl_size_in, ptl_pid_t requested_pid,
              ptl_handle_ni_t * interface_out);

int PtlNIInitialized(ptl_interface_t);

int PtlNIFini(ptl_handle_ni_t interface_in);

#endif

int PtlGetId(ptl_handle_ni_t ni_handle, ptl_process_id_t *id);


/*
 * Network interfaces
 */

#ifndef PTL_NO_WRAP
int PtlNIBarrier(ptl_handle_ni_t interface_in);
#endif

int PtlNIStatus(ptl_handle_ni_t interface_in, ptl_sr_index_t register_in,
                ptl_sr_value_t * status_out);

int PtlNIDist(ptl_handle_ni_t interface_in, ptl_process_id_t process_in,
              unsigned long *distance_out);

#ifndef PTL_NO_WRAP
int PtlNIHandle(ptl_handle_any_t handle_in, ptl_handle_ni_t * interface_out);
#endif


/*
 * PtlNIDebug: 
 *
 * This is not an official Portals 3 API call.  It is provided
 * by the reference implementation to allow the maintainers an
 * easy way to turn on and off debugging information in the
 * library.  Do not use it in code that is not intended for use
 * with any version other than the portable reference library.
 */
unsigned int PtlNIDebug(ptl_handle_ni_t ni, unsigned int mask_in);

/* 
 * PtlNIFailNid
 *
 * Not an official Portals 3 API call.  It provides a way of simulating
 * communications failures to all (nid == PTL_NID_ANY), or specific peers
 * (via multiple calls), either until further notice (threshold == -1), or
 * for a specific number of messages.  Passing a threshold of zero, "heals"
 * the given peer.
 */
int PtlFailNid (ptl_handle_ni_t ni, ptl_nid_t nid, unsigned int threshold);


/*
 * Match entries
 */

int PtlMEAttach(ptl_handle_ni_t interface_in, ptl_pt_index_t index_in,
                ptl_process_id_t match_id_in, ptl_match_bits_t match_bits_in,
                ptl_match_bits_t ignore_bits_in, ptl_unlink_t unlink_in,
                ptl_ins_pos_t pos_in, ptl_handle_me_t * handle_out);

int PtlMEInsert(ptl_handle_me_t current_in, ptl_process_id_t match_id_in,
                ptl_match_bits_t match_bits_in, ptl_match_bits_t ignore_bits_in,
                ptl_unlink_t unlink_in, ptl_ins_pos_t position_in,
                ptl_handle_me_t * handle_out);

int PtlMEUnlink(ptl_handle_me_t current_in);

int PtlMEUnlinkList(ptl_handle_me_t current_in);

int PtlTblDump(ptl_handle_ni_t ni, int index_in);
int PtlMEDump(ptl_handle_me_t current_in);



/*
 * Memory descriptors
 */

#ifndef PTL_NO_WRAP
int PtlMDAttach(ptl_handle_me_t current_in, ptl_md_t md_in,
                ptl_unlink_t unlink_in, ptl_handle_md_t * handle_out);

int PtlMDBind(ptl_handle_ni_t ni_in, ptl_md_t md_in,
              ptl_handle_md_t * handle_out);

int PtlMDUnlink(ptl_handle_md_t md_in);

int PtlMDUpdate(ptl_handle_md_t md_in, ptl_md_t * old_inout,
                ptl_md_t * new_inout, ptl_handle_eq_t testq_in);

#endif

/* These should not be called by users */
int PtlMDUpdate_internal(ptl_handle_md_t md_in, ptl_md_t * old_inout,
                         ptl_md_t * new_inout, ptl_handle_eq_t testq_in,
                         ptl_seq_t sequence_in);




/*
 * Event queues
 */
#ifndef PTL_NO_WRAP

/* These should be called by users */
int PtlEQAlloc(ptl_handle_ni_t ni_in, ptl_size_t count_in,
               int (*callback) (ptl_event_t * event),
               ptl_handle_eq_t * handle_out);
int PtlEQFree(ptl_handle_eq_t eventq_in);

int PtlEQCount(ptl_handle_eq_t eventq_in, ptl_size_t * count_out);

int PtlEQGet(ptl_handle_eq_t eventq_in, ptl_event_t * event_out);


int PtlEQWait(ptl_handle_eq_t eventq_in, ptl_event_t * event_out);

int PtlEQWait_timeout(ptl_handle_eq_t eventq_in, ptl_event_t * event_out,
                      int timeout);
#endif

/*
 * Access Control Table
 */
int PtlACEntry(ptl_handle_ni_t ni_in, ptl_ac_index_t index_in,
               ptl_process_id_t match_id_in, ptl_pt_index_t portal_in);


/*
 * Data movement
 */

int PtlPut(ptl_handle_md_t md_in, ptl_ack_req_t ack_req_in,
           ptl_process_id_t target_in, ptl_pt_index_t portal_in,
           ptl_ac_index_t cookie_in, ptl_match_bits_t match_bits_in,
           ptl_size_t offset_in, ptl_hdr_data_t hdr_data_in);

int PtlGet(ptl_handle_md_t md_in, ptl_process_id_t target_in,
           ptl_pt_index_t portal_in, ptl_ac_index_t cookie_in,
           ptl_match_bits_t match_bits_in, ptl_size_t offset_in);



#endif
