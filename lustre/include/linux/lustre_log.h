#ifndef _LUSTRE_LOG_H
#define _LUSTRE_LOG_H

#include <linux/lustre_lite.h>
#include <linux/lustre_idl.h>
#include <linux/obd.h>

/* generic infrastructure for managing a collection of logs. 
   These logs are used for: 

   - orphan recovery: OST adds record on create
   - mtime/size consistency: the OST adds a record on first write
   - open/unlinked objects: OST adds a record on destroy

   - mds unlink log: the MDS adds an entry upon delete

   - raid1 replication log between OST's
   - MDS replication logs
*/

/* catalog of log objects */

/* WARNING: adjust size records! */ 
#define LLOG_SIZE     (64 << 10)  
#define LLOG_REC_SIZE (1 << 5)
#define LLOG_ENTRY_COUNT 

struct llog_logid { 
        __u64           llh_oid;
        __u64           llh_bootcount;
};

struct llog_loglist_header { 
        struct llog_logid  llh_current;
        char               llh_bitmap[8192];
        struct llog_logid  llh_logs[0];
};


/* header structure of each log */

/* bitmap of allocated entries is based on minimum entry size of 16
   bytes with a log file size of 64K that is 16K entries, ie. 16K bits
   in the bitmap or a 2kb bitmap */

struct llog_header {
        __u32                 llh_bitmap[1024];
        __u64                 llh_lastrec; 
        struct llog_trans_rec llh_records[0];
};

struct llog_handle { 
        struct file *llh_file;
        struct llog_header *llh_hdr;
        struct llog_logid llh_id; 
};

/* cookie to find a log entry back */
struct llog_cookie { 
        struct llog_logid llc_id; 
        __u64             llc_recno;
};

/* OST records for 
   - orphans
   - size adjustments
   - open unlinked files
*/

struct llog_trans_rec { 
        __u64             tr_op;
        struct ll_fid     tr_fid;
        obd_id            tr_oid;
};


/* exported api prototypes */
int llog_add_record(struct llog_handle **, void *recbuf, int reclen,
                    struct llog_cookie *cookie);
int llog_clear_records(int count, struct llog_cookie **cookies);
int llog_clear_record(struct llog_handle *handle, __u32 recno);
int llog_delete(struct llog_logid *id);

/* internal api */
int llog_id2handle(struct 

#endif

