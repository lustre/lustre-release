#ifndef __LUSTRE_COMMIT_CONFD_H 
#define __LUSTRE_COMMIT_CONFD_H 

#include <lustre/lustre_log.h>

/*  a commit record that will be sent to an OST for OST trans record cleaning
 *  or pulled down from the OST for cleaning on the MDS 
 */
struct llog_commit_data { 
        struct llcd_entry; /* connect this data to the import */
        struct obd_uuid llcd_uuid; /* which node to go to */
        struct llog_cookie llcd_cookie; 
}; 

/* the thread data that collects local commits and makes rpc's */
struct llog_commit_confirm_daeamon { 
        struct list_head llcconf_list;   /* list of imports with commits */
        spinlock_t       llcconf_lock;
        int              llcconf_flags;
        int              llcconf_highwater;
        int              llcconf_lowwater;
};

#endif
