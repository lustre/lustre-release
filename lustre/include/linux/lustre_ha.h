#ifndef _LUSTRE_HA_H
#define _LUSTRE_HA_H

#define MGR_STOPPING   1
#define MGR_RUNNING    2
#define MGR_STOPPED    4
#define MGR_KILLED     8
#define MGR_EVENT      16
#define MGR_WORKING    32
#define MGR_SIGNAL     64

struct lustre_ha_mgr {
        __u32               mgr_flags; 
        struct task_struct *mgr_thread;
        wait_queue_head_t   mgr_waitq;
        wait_queue_head_t   mgr_ctl_waitq;
        spinlock_t          mgr_lock;
        time_t              mgr_waketime;
        struct list_head    mgr_connections_lh;  /* connections managed by the mgr */
        struct list_head    mgr_troubled_lh;  /* connections in trouble */
};

struct lustre_ha_thread { 
        char                 *name;
        struct lustre_ha_mgr *mgr; 
        struct obd_device    *dev;
}; 

int llite_ha_cleanup(struct lustre_ha_mgr *mgr);
struct lustre_ha_mgr *llite_ha_setup(void);
void llite_ha_conn_fail(struct ptlrpc_client *cli);
void llite_ha_conn_manage(struct lustre_ha_mgr *mgr, struct ptlrpc_client *cli);


#endif
