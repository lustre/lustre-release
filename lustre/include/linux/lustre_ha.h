
#define MGR_STOPPING   1
#define MGR_RUNNING    2
#define MGR_STOPPED    4
#define MGR_KILLED     8
#define MGR_EVENT      16
#define MGR_RECOVERING 32
#define MGR_SIGNAL     64

struct lustre_ha_mgr {
        __u32               mgr_flags; 
        struct task_struct *mgr_thread;
        wait_queue_head_t   mgr_waitq;
        wait_queue_head_t   mgr_ctl_waitq;
        spinlock_t          mgr_lock;
};

struct lustre_ha_thread { 
        char                 *name;
        struct lustre_ha_mgr *mgr; 
        struct obd_device    *dev;
}; 
