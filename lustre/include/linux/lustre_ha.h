#ifndef _LUSTRE_HA_H
#define _LUSTRE_HA_H

#define MGR_STOPPING   1
#define MGR_RUNNING    2
#define MGR_STOPPED    4
#define MGR_KILLED     8
#define MGR_EVENT      16
#define MGR_WORKING    32
#define MGR_SIGNAL     64

#define LUSTRE_HA_NAME "ptlrpc"

#define CONNMGR_CONNECT 1

extern struct connmgr_obd *ptlrpc_connmgr;

struct connmgr_thread { 
        struct connmgr_obd *mgr;
        char *name;
};


struct connmgr_body { 
        __u32 generation;
};

int connmgr_connect(struct connmgr_obd *mgr, struct ptlrpc_connection *cn);
void connmgr_cli_fail(struct ptlrpc_client *cli);
void connmgr_cli_manage(struct connmgr_obd *mgr, struct ptlrpc_client *cli);

#endif
