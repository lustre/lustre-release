#ifndef __LINUX_OBD_PSDEV_H
#define __LINUX_OBD_PSDEV_H

#define OBD_PSDEV_MAJOR 120

#define ISLENTO (current->pid == psdev_vcomm.vc_pid)

/* communication pending & processing queues */
struct vcomm {
	unsigned int	    vc_seq;
	struct wait_queue  *vc_waitq;     /* Lento wait queue */
	struct list_head    vc_pending;
	struct list_head    vc_processing;
	int                 vc_inuse;
	int                 vc_pid;       /* Lento's pid */
};

extern void obd_psdev_detach(int unit);
extern int  init_obd_psdev(void);
struct vcomm psdev_vcomm;

/* messages between presto filesystem in kernel and Venus */
extern int presto_hard;
extern unsigned long presto_timeout;

#define REQ_READ   1
#define REQ_WRITE  2
#define REQ_ASYNC  4

struct upc_req {
	struct list_head   rq_chain;
	caddr_t	           rq_data;
	u_short	           rq_flags;
	u_short            rq_read_size;  /* Size is at most 5000 bytes */
	u_short	           rq_rep_size;
	u_short	           rq_opcode;  /* copied from data to save lookup */
	int		   rq_unique;
	struct wait_queue  *rq_sleep;   /* process' wait queue */
	unsigned long      rq_posttime;
};

#endif /* __LINUX_OBD_PSDEV_H */
