#ifndef _LIB_NAL_H_
#define _LIB_NAL_H_

/*
 * nal.h
 *
 * Library side headers that define the abstraction layer's
 * responsibilities and interfaces
 */

#include <portals/lib-types.h>

struct nal_cb_t {
	/*
	 * Per interface portal table, access control table
	 * and NAL private data field;
	 */
	lib_ni_t ni;
	void *nal_data;
	/*
	 * send: Sends a preformatted header and payload data to a
	 * specified remote process. The payload is scattered over 'niov'
	 * fragments described by iov, starting at 'offset' for 'mlen'
	 * bytes.  
	 * NB the NAL may NOT overwrite iov.  
	 * PTL_OK on success => NAL has committed to send and will call
	 * lib_finalize on completion
	 */
	ptl_err_t (*cb_send) (nal_cb_t * nal, void *private, lib_msg_t * cookie, 
			      ptl_hdr_t * hdr, int type, ptl_nid_t nid, ptl_pid_t pid, 
			      unsigned int niov, struct iovec *iov, 
			      size_t offset, size_t mlen);

	/* as send, but with a set of page fragments (NULL if not supported) */
	ptl_err_t (*cb_send_pages) (nal_cb_t * nal, void *private, lib_msg_t * cookie, 
				    ptl_hdr_t * hdr, int type, ptl_nid_t nid, ptl_pid_t pid, 
				    unsigned int niov, ptl_kiov_t *iov, 
				    size_t offset, size_t mlen);
	/*
	 * recv: Receives an incoming message from a remote process.  The
	 * payload is to be received into the scattered buffer of 'niov'
	 * fragments described by iov, starting at 'offset' for 'mlen'
	 * bytes.  Payload bytes after 'mlen' up to 'rlen' are to be
	 * discarded.  
	 * NB the NAL may NOT overwrite iov.
	 * PTL_OK on success => NAL has committed to receive and will call
	 * lib_finalize on completion
	 */
	ptl_err_t (*cb_recv) (nal_cb_t * nal, void *private, lib_msg_t * cookie,
			      unsigned int niov, struct iovec *iov, 
			      size_t offset, size_t mlen, size_t rlen);

	/* as recv, but with a set of page fragments (NULL if not supported) */
	ptl_err_t (*cb_recv_pages) (nal_cb_t * nal, void *private, lib_msg_t * cookie,
				    unsigned int niov, ptl_kiov_t *iov, 
				    size_t offset, size_t mlen, size_t rlen);
	/*
	 * read: Reads a block of data from a specified user address
	 */
	ptl_err_t (*cb_read) (nal_cb_t * nal, void *private, void *dst_addr,
			      user_ptr src_addr, size_t len);

	/*
	 * write: Writes a block of data into a specified user address
	 */
	ptl_err_t (*cb_write) (nal_cb_t * nal, void *private, user_ptr dsr_addr,
			       void *src_addr, size_t len);

	/*
	 * callback: Calls an event callback
	 * NULL => lib calls eq's callback (if any) directly.
	 */
	void (*cb_callback) (nal_cb_t * nal, void *private, lib_eq_t *eq,
			     ptl_event_t *ev);

	/*
	 *  malloc: Acquire a block of memory in a system independent
	 * fashion.
	 */
	void *(*cb_malloc) (nal_cb_t * nal, size_t len);

	void (*cb_free) (nal_cb_t * nal, void *buf, size_t len);

	/*
	 * (un)map: Tell the NAL about some memory it will access.
	 * *addrkey passed to cb_unmap() is what cb_map() set it to.
	 * type of *iov depends on options.
	 * Set to NULL if not required.
	 */
	ptl_err_t (*cb_map) (nal_cb_t * nal, unsigned int niov, struct iovec *iov, 
			     void **addrkey);
	void (*cb_unmap) (nal_cb_t * nal, unsigned int niov, struct iovec *iov, 
			  void **addrkey);

	/* as (un)map, but with a set of page fragments */
	ptl_err_t (*cb_map_pages) (nal_cb_t * nal, unsigned int niov, ptl_kiov_t *iov, 
				   void **addrkey);
	void (*cb_unmap_pages) (nal_cb_t * nal, unsigned int niov, ptl_kiov_t *iov, 
			  void **addrkey);

	void (*cb_printf) (nal_cb_t * nal, const char *fmt, ...);

	/* Turn interrupts off (begin of protected area) */
	void (*cb_cli) (nal_cb_t * nal, unsigned long *flags);

	/* Turn interrupts on (end of protected area) */
	void (*cb_sti) (nal_cb_t * nal, unsigned long *flags);

	/*
	 * Calculate a network "distance" to given node
	 */
	int (*cb_dist) (nal_cb_t * nal, ptl_nid_t nid, unsigned long *dist);
};

#endif
