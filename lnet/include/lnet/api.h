#ifndef __LNET_API_H__
#define __LNET_API_H__

#include <lnet/types.h>

int LNetInit(void);
void LNetFini(void);

int LNetNIInit(lnet_pid_t requested_pid);
int LNetNIFini(void);

int LNetGetId(unsigned int index, lnet_process_id_t *id);
int LNetDist(lnet_nid_t nid, lnet_nid_t *srcnid, int *order);
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
