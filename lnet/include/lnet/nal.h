#ifndef _NAL_H_
#define _NAL_H_

#include "build_check.h"

/*
 * p30/nal.h
 *
 * The API side NAL declarations
 */

#include <portals/types.h>

typedef struct nal_t nal_t;

struct nal_t {
	/* common interface state */
	int              nal_refct;
        ptl_handle_ni_t  nal_handle;

	/* NAL-private data */
	void            *nal_data;

	/* NAL API implementation 
	 * NB only nal_ni_init needs to be set when the NAL registers itself */
	int (*nal_ni_init) (nal_t *nal, ptl_pid_t requested_pid,
			    ptl_ni_limits_t *req, ptl_ni_limits_t *actual);
	
	void (*nal_ni_fini) (nal_t *nal);

	int (*nal_get_id) (nal_t *nal, ptl_process_id_t *id);
	int (*nal_ni_status) (nal_t *nal, ptl_sr_index_t register, ptl_sr_value_t *status);
	int (*nal_ni_dist) (nal_t *nal, ptl_process_id_t *id, unsigned long *distance);
	int (*nal_fail_nid) (nal_t *nal, ptl_nid_t nid, unsigned int threshold);
	int (*nal_loopback) (nal_t *nal, int set, int *enabled);

	int (*nal_me_attach) (nal_t *nal, ptl_pt_index_t portal,
			      ptl_process_id_t match_id, 
			      ptl_match_bits_t match_bits, ptl_match_bits_t ignore_bits,
			      ptl_unlink_t unlink, ptl_ins_pos_t pos, 
			      ptl_handle_me_t *handle);
	int (*nal_me_insert) (nal_t *nal, ptl_handle_me_t *me,
			      ptl_process_id_t match_id, 
			      ptl_match_bits_t match_bits, ptl_match_bits_t ignore_bits,
			      ptl_unlink_t unlink, ptl_ins_pos_t pos, 
			      ptl_handle_me_t *handle);
	int (*nal_me_unlink) (nal_t *nal, ptl_handle_me_t *me);
	
	int (*nal_md_attach) (nal_t *nal, ptl_handle_me_t *me,
			      ptl_md_t *md, ptl_unlink_t unlink, 
			      ptl_handle_md_t *handle);
	int (*nal_md_bind) (nal_t *nal, 
			    ptl_md_t *md, ptl_unlink_t unlink, 
			    ptl_handle_md_t *handle);
	int (*nal_md_unlink) (nal_t *nal, ptl_handle_md_t *md);
	int (*nal_md_update) (nal_t *nal, ptl_handle_md_t *md,
			      ptl_md_t *old_md, ptl_md_t *new_md,
			      ptl_handle_eq_t *testq);

	int (*nal_eq_alloc) (nal_t *nal, ptl_size_t count,
			     ptl_eq_handler_t handler,
			     ptl_handle_eq_t *handle);
	int (*nal_eq_free) (nal_t *nal, ptl_handle_eq_t *eq);
	int (*nal_eq_poll) (nal_t *nal, 
			    ptl_handle_eq_t *eqs, int neqs, int timeout,
			    ptl_event_t *event, int *which);

	int (*nal_ace_entry) (nal_t *nal, ptl_ac_index_t index,
			      ptl_process_id_t match_id, ptl_pt_index_t portal);
	
	int (*nal_put) (nal_t *nal, ptl_handle_md_t *md, ptl_ack_req_t ack,
			ptl_process_id_t *target, ptl_pt_index_t portal,
			ptl_ac_index_t ac, ptl_match_bits_t match,
			ptl_size_t offset, ptl_hdr_data_t hdr_data);
	int (*nal_get) (nal_t *nal, ptl_handle_md_t *md,
			ptl_process_id_t *target, ptl_pt_index_t portal,
			ptl_ac_index_t ac, ptl_match_bits_t match,
			ptl_size_t offset);
};

extern nal_t *ptl_hndl2nal(ptl_handle_any_t *any);

#ifdef __KERNEL__
extern int ptl_register_nal(ptl_interface_t interface, nal_t *nal);
extern void ptl_unregister_nal(ptl_interface_t interface);
#endif

#endif
