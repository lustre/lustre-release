#ifndef _LUSTRE_MDS_H
#define _LUSTRE_MDS_H

#include <linux/obd_support.h>


struct mds_run_ctxt { 
	struct vfsmount *pwdmnt;
	struct dentry   *pwd;
	mm_segment_t     fs;
};

#define MDS_UNMOUNT 1
#define LUSTRE_MDS_NAME "mds"

struct mds_obd {
	char *mds_fstype;
	struct task_struct *mds_thread;
	wait_queue_head_t mds_waitq;
	wait_queue_head_t mds_done_waitq;
	struct timer_list *mds_timer;
	int mds_interval; 
	int mds_flags;
	struct list_head mds_reqs;
        struct super_block * mds_sb;
	struct vfsmount *mds_vfsmnt;
	struct mds_run_ctxt  mds_ctxt;
	spinlock_t mds_lock;
	__u64 mds_lastino;
	struct file_operations *mds_fop; 
	struct inode_operations *mds_iop;
	struct address_space_operations *mds_aops;
};

#define MDS_GETATTR   1
#define MDS_SETATTR  2
#define MDS_OPEN     3
#define MDS_CREATE   4
#define MDS_LINK     5
#define MDS_SYMLINK  6
#define MDS_MKNOD    7
#define MDS_MKDIR    8
#define MDS_UNLINK   9
#define MDS_RMDIR   10
#define MDS_RENAME  11

struct mds_request { 
	struct list_head *rq_list;
	struct mds_obd *rq_obd;
	int rq_status;

	char *rq_reqbuf;
	int rq_reqlen;
	struct mds_req_hdr *rq_reqhdr;
	struct mds_req *rq_req;

	char *rq_repbuf;
	int rq_replen;
	struct mds_rep_hdr *rq_rephdr;
	struct mds_rep *rq_rep;

	wait_queue_head_t rq_wait_for_mds_rep;
};


/* mds/mds_pack.c */
int mds_pack_req(char *name, int namelen, char *tgt, int tgtlen, struct mds_req_hdr **hdr, struct mds_req **req, int *len, char **buf);
int mds_unpack_req(char *buf, int len, struct mds_req_hdr **hdr, struct mds_req **req);
int mds_pack_rep(char *name, int namelen, char *tgt, int tgtlen, struct mds_rep_hdr **hdr, struct mds_rep **rep, int *len, char **buf);
int mds_unpack_rep(char *buf, int len, struct mds_rep_hdr **hdr, struct mds_rep **rep);


#endif


