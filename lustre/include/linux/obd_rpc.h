#ifndef __OBD_RPC_H
#define __OBD_RPC_H

#define OBD_TGT_VERSION  001

#define OBD_TGT_TCP  0x1
#define OBD_TGT_INTR 0x2
#define OBD_TGT_SOFT 0x4




/* error codes */

enum obd_stat {
 OBD_OK = 0,
 OBDERR_PERM = 1, 
 OBDERR_NOENT = 2,
 OBDERR_IO = 5,
 OBDERR_NXIO = 6,
 OBDERR_ACCESS = 13,
 OBDERR_EXIST = 17,
 OBDERR_XDEV = 18, 
 OBDERR_NODEV = 19,
 OBDERR_INVAL = 22,
 OBDERR_FBIG = 27,
 OBDERR_NOSPC = 28,
 OBDERR_ROFS = 30,
 OBDERR_OPNOTSUPP = 45,
 OBDERR_DQUOT = 69
};



#define OBD_PROGRAM		100003
#define OBD_VERSION		2
#define OBDPROC_NULL		0
#define OBDPROC_GETATTR		1
#define OBDPROC_SETATTR		2
#define OBDPROC_ROOT		3
#define OBDPROC_LOOKUP		4
#define OBDPROC_READLINK	5
#define OBDPROC_READ		6
#define OBDPROC_WRITECACHE	7
#define OBDPROC_WRITE		8
#define OBDPROC_CREATE		9
#define OBDPROC_REMOVE		10
#define OBDPROC_RENAME		11
#define OBDPROC_LINK		12
#define OBDPROC_SYMLINK		13
#define OBDPROC_MKDIR		14



extern struct rpc_program obd_program;






struct obd_target {
	struct sockaddr_in tgt_addr;
	int tgt_flags;
	int tgt_timeo;
	int tgt_retrans;
	int tgt_hostnamelen;
	char tgt_hostname[0];
	
};


struct rpc_obd {
	struct rpc_clnt *	client;		/* RPC client handle */
	struct sockaddr_in     addr;
	int			flags;		/* various flags */
	int			rsize;		/* read size */
	int			wsize;		/* write size */
	unsigned int	 	bsize;		/* server block size */
	char *			hostname;	/* remote hostname */
};


#endif
