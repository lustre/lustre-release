/*
 * Based on cfs.h from Coda, but revamped for increased simplicity.
 * Linux modifications by Peter Braam, Aug 1996
 * Rewritten for InterMezzo
 */

#ifndef _PRESTO_HEADER_
#define _PRESTO_HEADER_


/* upcall.c */
#define SYNCHRONOUS 0
#define ASYNCHRONOUS 1

int lento_permit(ino_t ino);
int lento_opendir(ino_t ino, int async);
int lento_open(ino_t ino);
int lento_journal(char *page);



/*
 * Kernel <--> Lento communications.
 */

/* downcalls */
#define LENTO_PERMIT    1
#define LENTO_JOURNAL   2
#define LENTO_OPENDIR	3
#define LENTO_OPEN	4
#define LENTO_SIGNAL    5

/* upcalls */
#define PRESTO_RELEASE_JOURNAL 51
#define PRESTO_MARK            52

#define LENTO_DOWNCALL(opcode) (opcode <= PRESTO_MARK && opcode >= PRESTO_RELEASE_JOURNAL)

/*         Lento <-> Presto  RPC arguments       */
struct lento_up_hdr {
	unsigned int opcode;
	unsigned int unique;	/* Keep multiple outstanding msgs distinct */
	u_short pid;		/* Common to all */
	u_short uid;
};

/* This structure _must_ sit at the beginning of the buffer */
struct lento_down_hdr {
    unsigned int opcode;
    unsigned int unique;	
    unsigned int result;
};

/* lento_permit: */
struct lento_permit_in {
	struct lento_up_hdr uh;
	ino_t ino;
};
struct lento_permit_out {
    struct lento_down_hdr dh;
};


/* lento_opendir: */
struct lento_opendir_in {
	struct lento_up_hdr uh;
	ino_t ino;
	int   async;
};
struct lento_opendir_out {
    struct lento_down_hdr dh;
};


/* lento_open: */
struct lento_open_in {
    struct lento_up_hdr uh;
    ino_t ino;
};
struct lento_open_out {
    struct lento_down_hdr dh;
};

/* lento_mark_dentry */
struct lento_mark_dentry {  
	struct lento_down_hdr dh;
	int    and_flag;
	int    or_flag;
	char   path[0];
};

/* NB: every struct below begins with an up_hdr */
union up_args {
    struct lento_up_hdr uh;		
    struct lento_permit_in lento_permit;
    struct lento_open_in lento_open;
    struct lento_opendir_in lento_opendir;
};

union down_args {
    struct lento_down_hdr dh;
    struct lento_permit_out lento_permit;
    struct lento_open_out lento_open;
    struct lento_opendir_out lento_opendir;
};    

union lento_downcalls {
	struct lento_down_hdr        dch;
	struct lento_mark_dentry     mark;
};

int lento_upcall(int read_size, int *rep_size, 
		 union up_args *buffer, int async);
#endif 

