/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=4:tabstop=4:
 *
 * Copyright (C) 2004 Cluster File Systems, Inc.
 *
 * This file is part of Lustre, http://www.lustre.org.
 *
 * Lustre is free software; you can redistribute it and/or modify it under the
 * terms of version 2 of the GNU General Public License as published by the
 * Free Software Foundation.
 *
 * Lustre is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along
 * with Lustre; if not, write to the Free Software Foundation, Inc., 675 Mass
 * Ave, Cambridge, MA 02139, USA.
 *
 * Implementation of portable time API for Winnt (kernel and user-level).
 *
 */

#ifndef __LIBCFS_WINNT_TCPIP_H__
#define __LIBCFS_WINNT_TCPIP_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif


#ifdef __KERNEL__

//
//  ks definitions
//

// iovec is defined in libcfs: winnt_prim.h 
// lnetkiov_t is defined in lnet/types.h

typedef struct socket ksock_tconn_t;
typedef struct socket cfs_socket_t;

// completion notification callback routine

typedef VOID (*ksock_schedule_cb)(struct socket*, int, void *, ulong_ptr);

/* completion routine to update tx structure for async sending */
typedef PVOID (*ksock_update_tx)(struct socket*, PVOID tx, ulong_ptr);

//
// tdinal definitions
//


#if TDI_LIBCFS_DBG
#define KsPrint(X)     KsPrintf X
#else
#define KsPrint(X)
#endif


//
// Socket Addresses Related ...
//

#define	    INADDR_ANY		    (ULONG)0x00000000
#define     INADDR_LOOPBACK     (ULONG)0x7f000001
#define	    INADDR_BROADCAST	(ULONG)0xffffffff
#define	    INADDR_NONE		    (ULONG)0xffffffff

/*
 *  TCP / IP options
 */

#define     SOL_TCP             6
#define     SOL_UDP		        17


#define TL_INSTANCE             0

#define TCP_SOCKET_NODELAY      1 //  disabling "Nagle"
#define TCP_SOCKET_KEEPALIVE    2
#define TCP_SOCKET_OOBINLINE    3
#define TCP_SOCKET_BSDURGENT    4
#define TCP_SOCKET_ATMARK       5
#define TCP_SOCKET_WINDOW       6


/* Flags we can use with send/ and recv. 
   Added those for 1003.1g not all are supported yet
 */
 
#define MSG_OOB 	    1
#define MSG_PEEK        2
#define MSG_DONTROUTE   4
#define MSG_TRYHARD     4       /* Synonym for MSG_DONTROUTE for DECnet */
#define MSG_CTRUNC      8
#define MSG_PROBE       0x10	/* Do not send. Only probe path f.e. for MTU */
#define MSG_TRUNC       0x20
#define MSG_DONTWAIT    0x40	/* Nonblocking io		 */
#define MSG_EOR         0x80	/* End of record */
#define MSG_WAITALL     0x100	/* Wait for a full request */
#define MSG_FIN         0x200
#define MSG_SYN	        0x400
#define MSG_CONFIRM     0x800	/* Confirm path validity */
#define MSG_RST         0x1000
#define MSG_ERRQUEUE    0x2000	/* Fetch message from error queue */
#define MSG_NOSIGNAL    0x4000	/* Do not generate SIGPIPE */
#define MSG_MORE        0x8000	/* Sender will send more */

#define MSG_EOF         MSG_FIN


//
// Maximum TRANSPORT_ADDRESS Length
//
// it must >= FIELD_OFFSET(TRANSPORT_ADDRESS, Address->Address)
//            + TDI_ADDRESS_LENGTH_IP
//
// I define it a little large and 16 bytes aligned to avoid possible overflow.
//

#define MAX_ADDRESS_LENGTH              (0x30)


//
// Maximum Listers Children Sockets
//

#define MAX_CHILD_LISTENERS             (4)

//
// Maximum EA Information Length
//

#define EA_MAX_LENGTH                   ( sizeof(FILE_FULL_EA_INFORMATION) - 1 + \
                                          TDI_TRANSPORT_ADDRESS_LENGTH + 1 + \
                                          MAX_ADDRESS_LENGTH )


#define UDP_DEVICE_NAME L"\\Device\\Udp"
#define TCP_DEVICE_NAME L"\\Device\\Tcp"


/*
 * TSDU definitions
 */

#define TDINAL_TSDU_DEFAULT_SIZE  (0x10000)

#define KS_TSDU_MAGIC       'KSTD'

#define KS_TSDU_ATTACHED    0x00000001  // Attached to the socket receive tsdu list

typedef struct _KS_TSDU {

    ULONG               Magic;
    ULONG               Flags;

    struct list_head    Link;

    ULONG               TotalLength;    // Total size of KS_TSDU

    ULONG               StartOffset;    // Start offset of the first Tsdu unit
    ULONG               LastOffset;     // End offset of the last Tsdu unit

/*
    union {
        KS_TSDU_DAT[];
        KS_TSDU_BUF[];
        KS_TSDU_MDL[];
    }
*/

} KS_TSDU, *PKS_TSDU;

#define TSDU_TYPE_BUF   ((USHORT)0x5401)
#define TSDU_TYPE_DAT   ((USHORT)0x5402)
#define TSDU_TYPE_MDL   ((USHORT)0x5403)

#define KS_TSDU_BUF_RECEIVING       0x0001
typedef struct _KS_TSDU_BUF {

    USHORT              TsduType;
    USHORT              TsduFlags;

    ULONG               DataLength;
    ULONG               StartOffset;

    PVOID               UserBuffer;

} KS_TSDU_BUF, *PKS_TSDU_BUF;

#define KS_TSDU_DAT_RECEIVING       0x0001

typedef struct _KS_TSDU_DAT {

    USHORT              TsduType;
    USHORT              TsduFlags;

    ULONG               DataLength;
    ULONG               StartOffset;

    ULONG               TotalLength;

    UCHAR               Data[1];

} KS_TSDU_DAT, *PKS_TSDU_DAT;

#define KS_DWORD_ALIGN(x)      (((x) + 0x03) & (~(0x03)))
#define KS_TSDU_STRU_SIZE(Len) (KS_DWORD_ALIGN((Len) + FIELD_OFFSET(KS_TSDU_DAT, Data)))

typedef struct _KS_TSDU_MDL {

    USHORT              TsduType;
    USHORT              TsduFlags;

    ULONG               DataLength;
    ULONG               StartOffset;    

    PMDL                Mdl;
    PVOID               Descriptor;

} KS_TSDU_MDL, *PKS_TSDU_MDL;


typedef struct _KS_TSDUMGR {

    struct list_head    TsduList;
    ULONG               NumOfTsdu;
    ULONG               TotalBytes;
    KEVENT              Event;

} KS_TSDUMGR, *PKS_TSDUMGR;


typedef struct _KS_CHAIN {

    KS_TSDUMGR          Normal;
    KS_TSDUMGR          Expedited;

} KS_CHAIN, *PKS_CHAIN;


#define TDINAL_SCHED_FACTOR (1)
#define CAN_BE_SCHED(Len, Limit) (Len >= ((Limit) >> TDINAL_SCHED_FACTOR))

//
// Handler Settings Indictor 
//

#define TDI_EVENT_MAXIMUM_HANDLER (TDI_EVENT_ERROR_EX + 1)


typedef struct _KS_EVENT_HANDLERS {
    BOOLEAN     IsActive[TDI_EVENT_MAXIMUM_HANDLER];
    PVOID       Handler [TDI_EVENT_MAXIMUM_HANDLER];
} KS_EVENT_HANDLERS, *PKS_EVENT_HANDLERS;

#define SetEventHandler(ha, ht, hr) do {        \
            ha.IsActive[ht] = TRUE;             \
            ha.Handler[ht] = (PVOID) (hr);      \
        } while(0)

//
// KSock Internal Structures
//

typedef struct _KS_ADDRESS {

    union {
        TRANSPORT_ADDRESS   Tdi;
        UCHAR               Pading[MAX_ADDRESS_LENGTH];
    };

    HANDLE                  Handle;
    PFILE_OBJECT            FileObject;

} KS_ADDRESS, *PKS_ADDRESS;

//
// Structures for Disconnect Workitem
//

typedef struct _KS_DISCONNECT_WORKITEM {

    WORK_QUEUE_ITEM         WorkItem;       // Workitem to perform disconnection
    ksock_tconn_t *         tconn;          // tdi connecton
    ULONG                   Flags;          // connection broken/discnnection flags
    KEVENT                  Event;          // sync event

} KS_DISCONNECT_WORKITEM, *PKS_DISCONNECT_WORKITEM;


typedef struct _KS_CONNECTION {

    HANDLE                      Handle;     // Handle of the tdi connection
    PFILE_OBJECT                FileObject; // FileObject if the conn object

    PTRANSPORT_ADDRESS          Remote;     // the ConnectionInfo of this connection
    PTDI_CONNECTION_INFORMATION ConnectionInfo;

    ULONG                       nagle;      // Tcp options 

} KS_CONNECTION, *PKS_CONNECTION;


//
// type definitions
//

typedef MDL                         ksock_mdl_t;
typedef UNICODE_STRING              ksock_unicode_name_t;
typedef WORK_QUEUE_ITEM             ksock_workitem_t;


typedef KS_CHAIN                    ksock_chain_t;
typedef KS_ADDRESS                  ksock_tdi_addr_t;
typedef KS_CONNECTION               ksock_tconn_info_t;
typedef KS_DISCONNECT_WORKITEM      ksock_disconnect_workitem_t;


//
// Structures for transmission done Workitem
//

typedef struct _KS_TCPX_FINILIZE {
    ksock_workitem_t        item;
    void *                  tx;
} ksock_tcpx_fini_t;


typedef struct ksock_backlogs {

        struct list_head    list;   /* list to link the backlog connections */
        int                 num;    /* number of backlogs in the list */

} ksock_backlogs_t;


typedef struct ksock_daemon {

    ksock_tconn_t *         tconn;         /* the listener connection object */
    unsigned short          nbacklogs;     /* number of listening backlog conns */
    unsigned short          port;          /* listening port number */ 
    int                     shutdown;      /* daemon threads is to exit */
    struct list_head        list;          /* to be attached into ksock_nal_data_t*/

} ksock_daemon_t ;


typedef enum {

    kstt_sender = 0,    // normal sending connection type, it's active connection, while
                        // child tconn is for passive connection.

    kstt_listener,      // listener daemon type, it just acts as a daemon, and it does
                        // not have real connection. It manages children tcons to accept
                        // or refuse the connecting request from remote peers.

    kstt_child,         // accepted child connection type, it's parent must be Listener
    kstt_lasttype
} ksock_tconn_type;

typedef enum {

    ksts_uninited = 0,	// tconn is just allocated (zero values), not initialized yet

    ksts_inited,        // tconn structure initialized: so it now can be identified as
                        // a sender, listener or a child

    ksts_bind,          // tconn is bound: the local address object (ip/port) is created.
                        // after being bound, we must call ksocknal_put_tconn to release
                        // the tconn objects, it's not safe just to free the memory of tconn.

    ksts_associated,    // the connection object is created and associated with the address
                        // object. so it's ready for connection. only for child and sender.

    ksts_connecting,    // only used by child tconn: in the ConnectEvent handler routine,
                        // it indicts the child tconn is busy to be connected to the peer.

    ksts_connected,     // the connection is built already: for sender and child

    ksts_listening,     // listener daemon is working, only for listener tconn

    ksts_disconnected,  // disconnected by user
    ksts_aborted,       // un-exptected broken status

    ksts_last           // total number of tconn statuses
} ksock_tconn_state;

#define KS_TCONN_MAGIC              'KSTM'

#define KS_TCONN_HANDLERS_SET       0x00000001  // Conection handlers are set.
#define KS_TCONN_DISCONNECT_BUSY    0x00010000  // Disconnect Workitem is queued ...
#define KS_TCONN_DESTROY_BUSY       0x00020000  // Destory Workitem is queued ...

#define KS_TCONN_DAEMON_STARTED     0x00100000  // indict the daemon is started,
                                                // only valid for listener

struct socket {

        ulong_ptr                   kstc_magic;      /* Magic & Flags */
        ulong_ptr                   kstc_flags;

        spinlock_t                  kstc_lock;       /* serialise lock*/
        void *                      kstc_conn;       /* ksock_conn_t */

        ksock_tconn_type            kstc_type;		 /* tdi connection Type */
        ksock_tconn_state           kstc_state;      /* tdi connection state flag */

        ksock_unicode_name_t        kstc_dev;        /* tcp transport device name */

        ksock_tdi_addr_t            kstc_addr;       /* local address handlers / Objects */

        atomic_t                    kstc_refcount;   /* reference count of ksock_tconn */

        struct list_head            kstc_list;       /* linked to global ksocknal_data */

        union {

            struct {
                int                 nbacklog;         /* total number of backlog tdi connections */
                ksock_backlogs_t    kstc_listening;   /* listeing backlog child connections */
                ksock_backlogs_t    kstc_accepted;    /* connected backlog child connections */
                event_t             kstc_accept_event;   /* Signaled by AcceptedHander, 
                                                            ksocknal_wait_accpeted_conns waits on */
                event_t             kstc_destroy_event;  /* Signaled when accepted child is released */
            } listener; 

            struct  {
                ksock_tconn_info_t  kstc_info;      /* Connection Info if Connected */
                ksock_chain_t       kstc_recv;      /* tsdu engine for data receiving */
                ksock_chain_t       kstc_send;      /* tsdu engine for data sending */

                int                 kstc_queued;    /* Attached to Parent->ChildList ... */
                int                 kstc_queueno;   /* 0: Attached to Listening list 
                                                       1: Attached to Accepted list */

                int                 kstc_busy;      /* referred by ConnectEventCallback ? */
                int                 kstc_accepted;  /* the connection is built ready ? */

                struct list_head    kstc_link;      /* linked to parent tdi connection */
                ksock_tconn_t   *   kstc_parent;    /* pointers to it's listener parent */
            } child;

            struct {
                ksock_tconn_info_t  kstc_info;      /* Connection Info if Connected */
                ksock_chain_t       kstc_recv;      /* tsdu engine for data receiving */
                ksock_chain_t       kstc_send;      /* tsdu engine for data sending */
            } sender; 
        };

        ulong_ptr                   kstc_snd_wnd;   /* Sending window size */
        ulong_ptr                   kstc_rcv_wnd;   /* Recving window size */

        ksock_workitem_t            kstc_destroy;    /* tconn destruction workitem */
        ksock_disconnect_workitem_t kstc_disconnect; /* connection disconnect workitem */

        ksock_schedule_cb           kstc_sched_cb;   /* notification callback routine of completion */
        ksock_update_tx             kstc_update_tx;  /* aync sending callback to update tx */
};

#define SOCK_WMEM_QUEUED(sock) (0)

#define TDINAL_WINDOW_DEFAULT_SIZE  (0x100000)


struct _KS_UDP_COMPLETION_CONTEXT;
struct _KS_TCP_COMPLETION_CONTEXT;


typedef
NTSTATUS
(*PKS_UDP_COMPLETION_ROUTINE) (
    IN PIRP     Irp,
    IN struct _KS_UDP_COMPLETION_CONTEXT
                *UdpContext
    );


typedef
NTSTATUS
(*PKS_TCP_COMPLETION_ROUTINE) (
    IN PIRP     Irp,
    IN struct _KS_TCP_COMPLETION_CONTEXT
                *TcpContext
    );

//
// Udp Irp Completion Context
//

typedef struct _KS_UDP_COMPLETION_CONTEXT {

    PKEVENT                             Event;
    union {
        PFILE_OBJECT                    AddressObject;
        ksock_tconn_t *                 tconn;
    };

    PKS_UDP_COMPLETION_ROUTINE          CompletionRoutine;
    PVOID                               CompletionContext;

} KS_UDP_COMPLETION_CONTEXT, *PKS_UDP_COMPLETION_CONTEXT;


//
// Tcp Irp Completion Context (used by tcp data recv/send)
//

typedef struct _KS_TCP_COMPLETION_CONTEXT {

    PKEVENT                             Event;      // Event to be waited on by Irp caller ...

    ksock_tconn_t *                     tconn;      // the tdi connection

    PKS_TCP_COMPLETION_ROUTINE          CompletionRoutine;
    PVOID                               CompletionContext;
    PVOID                               CompletionContext2;

    PKS_TSDUMGR                         KsTsduMgr;  // Tsdu buffer manager

    //
    // These tow new members are for NON_BLOCKING transmission
    //

    BOOLEAN							    bCounted;    // To indict needing refcount to
                                                     // execute CompetionRoutine
    ULONG                               ReferCount;  // Refer count of this structure

} KS_TCP_COMPLETION_CONTEXT, *PKS_TCP_COMPLETION_CONTEXT;

typedef KS_TCP_COMPLETION_CONTEXT  ksock_tdi_tx_t, ksock_tdi_rx_t;


/*
 * tdi extensions
 */

#define IOCTL_TCP_QUERY_INFORMATION_EX        \
                        CTL_CODE(FILE_DEVICE_NETWORK, 0, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_TCP_SET_INFORMATION_EX        \
                        CTL_CODE(FILE_DEVICE_NETWORK, 1, METHOD_BUFFERED, FILE_WRITE_ACCESS)


#define TcpBuildSetInformationEx(Irp, DevObj, FileObj, CompRoutine, Contxt, Buffer, BufferLen)\
    {                                                                        \
        PIO_STACK_LOCATION _IRPSP;                                           \
        if ( CompRoutine != NULL) {                                          \
            IoSetCompletionRoutine( Irp, CompRoutine, Contxt, TRUE, TRUE, TRUE);\
        } else {                                                             \
            IoSetCompletionRoutine( Irp, NULL, NULL, FALSE, FALSE, FALSE);   \
        }                                                                    \
        _IRPSP = IoGetNextIrpStackLocation (Irp);                            \
        _IRPSP->MajorFunction = IRP_MJ_DEVICE_CONTROL;                       \
        _IRPSP->DeviceObject = DevObj;                                       \
        _IRPSP->FileObject = FileObj;                                        \
        _IRPSP->Parameters.DeviceIoControl.OutputBufferLength = 0;           \
        _IRPSP->Parameters.DeviceIoControl.InputBufferLength = BufferLen;    \
        _IRPSP->Parameters.DeviceIoControl.IoControlCode = IOCTL_TCP_SET_INFORMATION_EX;  \
        Irp->AssociatedIrp.SystemBuffer = Buffer;                            \
    }


#define TcpBuildQueryInformationEx(Irp, DevObj, FileObj, CompRoutine, Contxt, InBuffer, InLength, OutBuffer, OutLength)\
    {                                                                        \
        PIO_STACK_LOCATION _IRPSP;                                           \
        if ( CompRoutine != NULL) {                                          \
            IoSetCompletionRoutine( Irp, CompRoutine, Contxt, TRUE, TRUE, TRUE);\
        } else {                                                             \
            IoSetCompletionRoutine( Irp, NULL, NULL, FALSE, FALSE, FALSE);   \
        }                                                                    \
        _IRPSP = IoGetNextIrpStackLocation (Irp);                            \
        _IRPSP->MajorFunction = IRP_MJ_DEVICE_CONTROL;                       \
        _IRPSP->DeviceObject = DevObj;                                       \
        _IRPSP->FileObject = FileObj;                                        \
        _IRPSP->Parameters.DeviceIoControl.OutputBufferLength = OutLength;           \
        _IRPSP->Parameters.DeviceIoControl.InputBufferLength = InLength;    \
        _IRPSP->Parameters.DeviceIoControl.IoControlCode = IOCTL_TCP_QUERY_INFORMATION_EX;  \
        _IRPSP->Parameters.DeviceIoControl.Type3InputBuffer = InBuffer;    \
        Irp->UserBuffer = OutBuffer;                            \
    }


typedef struct ks_addr_slot {
    LIST_ENTRY      link;
    int             up;
    char            iface[40];
    __u32           ip_addr;
    __u32           netmask;
    UNICODE_STRING  devname;
    WCHAR           buffer[1];
} ks_addr_slot_t;

typedef struct {

    /*
     * Tdi client information
     */

    UNICODE_STRING    ksnd_client_name; /* tdi client module name */
    HANDLE            ksnd_pnp_handle;  /* the handle for pnp changes */

    spinlock_t        ksnd_addrs_lock;  /* serialize ip address list access */
    LIST_ENTRY        ksnd_addrs_list;  /* list of the ip addresses */
    int               ksnd_naddrs;      /* number of the ip addresses */

    /*
     *  Tdilnd internal defintions
     */

    int               ksnd_init;            /* initialisation state */

    TDI_PROVIDER_INFO ksnd_provider;    /* tdi tcp/ip provider's information */

    spinlock_t        ksnd_tconn_lock;      /* tdi connections access serialise */

    int               ksnd_ntconns;         /* number of tconns attached in list */
    struct list_head  ksnd_tconns;          /* tdi connections list */
    cfs_mem_cache_t * ksnd_tconn_slab;      /* slabs for ksock_tconn_t allocations */
    event_t           ksnd_tconn_exit;      /* exit event to be signaled by the last tconn */

    spinlock_t        ksnd_tsdu_lock;       /* tsdu access serialise */
        
    int               ksnd_ntsdus;          /* number of tsdu buffers allocated */
    ulong_ptr     ksnd_tsdu_size;       /* the size of a signel tsdu buffer */
    cfs_mem_cache_t * ksnd_tsdu_slab;       /* slab cache for tsdu buffer allocation */

    int               ksnd_nfreetsdus;      /* number of tsdu buffers in the freed list */
    struct list_head  ksnd_freetsdus;          /* List of the freed Tsdu buffer. */

    spinlock_t        ksnd_daemon_lock;     /* stabilize daemon ops */
    int               ksnd_ndaemons;        /* number of listening daemons */
    struct list_head  ksnd_daemons;         /* listening daemon list */
    event_t           ksnd_daemon_exit;     /* the last daemon quiting should singal it */

} ks_data_t;

int
ks_init_tdi_data();

void
ks_fini_tdi_data();


#endif /* __KERNEL__ */
#endif /* __LIBCFS_WINNT_TCPIP_H__ */

/*
 * Local variables:
 * c-indentation-style: "K&R"
 * c-basic-offset: 8
 * tab-width: 8
 * fill-column: 80
 * scroll-step: 1
 * End:
 */
