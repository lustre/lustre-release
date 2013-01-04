/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
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

typedef struct socket ks_tconn_t, cfs_socket_t;

// completion notification callback routine

typedef VOID (*ks_schedule_cb)(struct socket*, int);

#define SOCK_TEST_NOSPACE(s)   (1)

//
// tdinal definitions
//


#if DBG
#define KsPrint(X)     KsPrintf X
#else
#define KsPrint(X)
#endif


//
// Socket Addresses Related ...
//

#define     INADDR_ANY          (ULONG)0x00000000
#define     INADDR_LOOPBACK     (ULONG)0x7f000001
#define     INADDR_BROADCAST    (ULONG)0xffffffff
#define     INADDR_NONE         (ULONG)0xffffffff

/*
 *  TCP / IP options
 */

#define     SOL_TCP             6
#define     SOL_UD              17


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
 
#define MSG_OOB         1
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

    ULONG                 Magic;          /* magic */
    ULONG                 Flags;          /* flags */

    cfs_list_t            Link;           /* link list */

    ULONG                 TotalLength;    /* total size of KS_TSDU */
    ULONG                 StartOffset;    /* offset of the first Tsdu unit */
    ULONG                 LastOffset;     /* end offset of the last Tsdu unit */

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

#define KS_TSDU_COMM_PARTIAL         0x0001

typedef struct _KS_TSDU_BUF {

    USHORT              TsduType;
    USHORT              TsduFlags;

    ULONG               DataLength;
    ULONG               StartOffset;

    PVOID               UserBuffer;
    PMDL                Mdl;         /* mdl */
} KS_TSDU_BUF, *PKS_TSDU_BUF;

typedef struct _KS_TSDU_DAT {

    USHORT              TsduType;
    USHORT              TsduFlags;

    ULONG               DataLength;
    ULONG               StartOffset;

    ULONG               TotalLength;
    PMDL                Mdl;        /* mdl */

    UCHAR               Data[0];

} KS_TSDU_DAT, *PKS_TSDU_DAT;

#define KS_QWORD_ALIGN(x)      (((x) + 0x07) & 0xFFFFFFF8)
#define KS_TSDU_STRU_SIZE(Len) (KS_QWORD_ALIGN((Len) + FIELD_OFFSET(KS_TSDU_DAT, Data[0])))

typedef struct _KS_TSDU_MDL {
    USHORT              TsduType;      /* TSDU_TYPE_MDL */
    USHORT              TsduFlags;     /* */

    ULONG               DataLength;    /* total valid data length */
    ULONG               BaseOffset;    /* payload offset in Tsdu */
    ULONG               StartOffset;   /* offset in payload */

    PVOID               Descriptor;    /* tdi descriptor for receiving */
    PMDL                Mdl;
} KS_TSDU_MDL, *PKS_TSDU_MDL;

typedef struct ks_engine_mgr {
	spinlock_t	lock;
	int		stop;
	event_t		exit;
	event_t		start;
	cfs_list_t	list;
} ks_engine_mgr_t;

typedef struct ks_engine_slot {
    ks_tconn_t *            tconn;
    void *                  tsdumgr;
    cfs_list_t              link;
    int                     queued;
    ks_engine_mgr_t *       emgr;
} ks_engine_slot_t;

typedef struct _KS_TSDUMGR {
	cfs_list_t		TsduList;
	ULONG			NumOfTsdu;
	ULONG			TotalBytes;
	KEVENT			Event;
	spinlock_t		Lock;
	ks_engine_slot_t	Slot;
	ULONG			Payload;
	int			Busy:1;
	int			OOB:1;
} KS_TSDUMGR, *PKS_TSDUMGR;

#define ks_lock_tsdumgr(mgr)	spin_lock(&((mgr)->Lock))
#define ks_unlock_tsdumgr(mgr)	spin_unlock(&((mgr)->Lock))

typedef struct _KS_CHAIN {
    KS_TSDUMGR          Normal;      /* normal queue */
    KS_TSDUMGR          Expedited;   /* OOB/expedited queue */
} KS_CHAIN, *PKS_CHAIN;


#define KS_CAN_SCHED(TM) ((TM)->TotalBytes >= ((TM)->Payload >> 2))

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
    ks_tconn_t *            tconn;          // tdi connecton
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

typedef MDL                         ks_mdl_t;
typedef UNICODE_STRING              ks_unicode_name_t;
typedef WORK_QUEUE_ITEM             ks_workitem_t;


typedef KS_CHAIN                    ks_chain_t;
typedef KS_ADDRESS                  ks_tdi_addr_t;
typedef KS_CONNECTION               ks_tconn_info_t;
typedef KS_DISCONNECT_WORKITEM      ks_disconnect_t;


//
// Structures for transmission done Workitem
//

typedef struct ks_backlogs {

        cfs_list_t           list;   /* list to link the backlog connections */
        int                  num;    /* number of backlogs in the list */

} ks_backlogs_t;


typedef struct ks_daemon {

    ks_tconn_t *            tconn;       /* the listener connection object */
    unsigned short          nbacklogs;   /* number of listening backlog conns */
    unsigned short          port;        /* listening port number */ 
    int                     shutdown;    /* daemon threads is to exit */
    cfs_list_t              list;        /* to be attached into ks_nal_data_t */

} ks_daemon_t;

typedef enum {

    kstt_sender = 0,    // normal sending connection type, it's active connection, while
                        // child tconn is for passive connection.

    kstt_listener,      // listener daemon type, it just acts as a daemon, and it does
                        // not have real connection. It manages children tcons to accept
                        // or refuse the connecting request from remote peers.

    kstt_child,         // accepted child connection type, it's parent must be Listener

    kstt_lasttype

} ks_tconn_type_t;

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

} ks_tconn_state_t;

#define KS_TCONN_MAGIC              'KSTM'

#define KS_TCONN_HANDLERS_SET       0x00000001  // Conection handlers are set.
#define KS_TCONN_DISCONNECT_BUSY    0x00010000  // Disconnect Workitem is queued ...
#define KS_TCONN_DESTROY_BUSY       0x00020000  // Destory Workitem is queued ...

#define KS_TCONN_DAEMON_STARTED     0x00100000  // indict the daemon is started,
                                                // only valid for listener
struct socket {

        ulong                       kstc_magic;      /* Magic & Flags */
        ulong                       kstc_flags;

	spinlock_t		    kstc_lock;       /* serialise lock*/
        void *                      kstc_conn;       /* ks_conn_t */

        ks_tconn_type_t             kstc_type;		 /* tdi connection Type */
        ks_tconn_state_t            kstc_state;      /* tdi connection state flag */

        ks_unicode_name_t           kstc_dev;        /* tcp transport device name */

        ks_tdi_addr_t               kstc_addr;       /* local address handlers / Objects */

        cfs_atomic_t                kstc_refcount;   /* reference count of ks_tconn_t */

        cfs_list_t                  kstc_list;       /* linked to global ksocknal_data */

        union {

            struct {
                int                 nbacklog;         /* total number of backlog tdi connections */
                ks_backlogs_t       kstc_listening;   /* listeing backlog child connections */
                ks_backlogs_t       kstc_accepted;    /* connected backlog child connections */
                event_t             kstc_accept_event;   /* Signaled by AcceptedHander, 
                                                            ksocknal_wait_accpeted_conns waits on */
                event_t             kstc_destroy_event;  /* Signaled when accepted child is released */
            } listener; 

            struct  {
                ks_tconn_info_t       kstc_info;      /* Connection Info if Connected */
                ks_chain_t            kstc_recv;      /* tsdu engine for data receiving */
                ks_chain_t            kstc_send;      /* tsdu engine for data sending */

                int                   kstc_queued;    /* Attached to Parent->ChildList ... */
                int                   kstc_queueno;   /* 0: Attached to Listening list 
                                                       1: Attached to Accepted list */

                int                   kstc_busy;      /* referred by ConnectEventCallback ? */
                int                   kstc_accepted;  /* the connection is built ready ? */

                cfs_list_t            kstc_link;      /* linked to parent tdi connection */
                ks_tconn_t   *        kstc_parent;    /* pointers to it's listener parent */
            } child;

            struct {
                ks_tconn_info_t     kstc_info;      /* Connection Info if Connected */
                ks_chain_t          kstc_recv;      /* tsdu engine for data receiving */
                ks_chain_t          kstc_send;      /* tsdu engine for data sending */
            } sender; 
        };

        ulong                       kstc_snd_wnd;   /* Sending window size */
        ulong                       kstc_rcv_wnd;   /* Recving window size */

        ks_workitem_t               kstc_destroy;    /* tconn destruction workitem */
        ks_disconnect_t             kstc_disconnect; /* connection disconnect workitem */

        ks_schedule_cb              kstc_sched_cb;   /* notification callback routine of completion */
};

static inline int
libcfs_sock_error(struct socket *sock)
{
        return (sock->kstc_state >= ksts_disconnected) ? ECONNRESET : 0;
}


static inline int
libcfs_sock_wmem_queued(struct socket *sock)
{
        return 0;
}

#define TDINAL_WINDOW_DEFAULT_SIZE  (0x100000)
#define TDINAL_MAX_TSDU_QUEUE_SIZE  (0x200000)

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
        ks_tconn_t *                    tconn;
    };

    PKS_UDP_COMPLETION_ROUTINE          CompletionRoutine;
    PVOID                               CompletionContext;

} KS_UDP_COMPLETION_CONTEXT, *PKS_UDP_COMPLETION_CONTEXT;


//
// Tcp Irp Completion Context (used by tcp data recv/send)
//

#define KS_TCP_CONTEXT_MAGIC 'CCTK'

typedef struct _KS_TCP_COMPLETION_CONTEXT {
    PKEVENT                             Event;      // Event to be waited on by Irp caller ...
    ks_tconn_t *                        tconn;      // the tdi connection
    PKS_TCP_COMPLETION_ROUTINE          CompletionRoutine;
    PVOID                               CompletionContext;
    PKS_TSDUMGR                         TsduMgr;    // Tsdu buffer manager
    ULONG                               Length;     // Payload length in KsTsdu queue
    PCHAR                               Buffer;     // User allocated buffer
    ULONG                               Magic;      // Magic key
} KS_TCP_COMPLETION_CONTEXT, *PKS_TCP_COMPLETION_CONTEXT;

typedef KS_TCP_COMPLETION_CONTEXT  ks_tdi_tx_t, ks_tdi_rx_t;


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

	UNICODE_STRING	ksnd_client_name;	/* tdi client module name */
	HANDLE		ksnd_pnp_handle;	/* the handle for pnp changes */

	spinlock_t	ksnd_addrs_lock;	/* serialize ip address list */
    LIST_ENTRY            ksnd_addrs_list;  /* list of the ip addresses */
    int                   ksnd_naddrs;      /* number of the ip addresses */

    /*
     *  Tdilnd internal defintions
     */

    int                   ksnd_init;            /* initialisation state */

    TDI_PROVIDER_INFO     ksnd_provider;        /* tdi tcp/ip provider's information */

	spinlock_t	ksnd_tconn_lock;	/* tdi connections access lock*/

	int		ksnd_ntconns;		/* number of tconns in list */
	cfs_list_t	ksnd_tconns;		/* tdi connections list */
	cfs_mem_cache_t *ksnd_tconn_slab;	/* ks_tconn_t allocation slabs*/
	event_t		ksnd_tconn_exit;	/* event signal by last tconn */

	spinlock_t	ksnd_tsdu_lock;		/* tsdu access serialise */

    int                   ksnd_ntsdus;          /* number of tsdu buffers allocated */
    ulong                 ksnd_tsdu_size;       /* the size of a signel tsdu buffer */
    cfs_mem_cache_t       *ksnd_tsdu_slab;       /* slab cache for tsdu buffer allocation */

    int                   ksnd_nfreetsdus;      /* number of tsdu buffers in the freed list */
    cfs_list_t            ksnd_freetsdus;       /* List of the freed Tsdu buffer. */

    int                   ksnd_engine_nums;     /* number of tcp sending engine threads */
    ks_engine_mgr_t       *ksnd_engine_mgr;      /* tcp sending engine structure */

} ks_tdi_data_t;

int
ks_init_tdi_data();

void
ks_fini_tdi_data();


int
ks_query_local_ipaddr(
    ks_tconn_t *     tconn
    );

void
ks_get_tconn(
    ks_tconn_t * tconn
    );

void
ks_put_tconn(
    ks_tconn_t * tconn
    );

void
ks_abort_tconn(
  ks_tconn_t *     tconn
    );
int
ks_disconnect_tconn(
    ks_tconn_t *    tconn,
    ulong           flags
    );

void
ks_destroy_tconn(
    ks_tconn_t *     tconn
    );

NTSTATUS
KsLockUserBuffer (
    IN PVOID            UserBuffer,
    IN BOOLEAN          bPaged,
    IN ULONG            Length,
    IN LOCK_OPERATION   Operation,
    OUT PMDL *          pMdl
    );

VOID
KsReleaseMdl (IN PMDL   Mdl,
              IN int    Paged );

void
KsQueueTdiEngine(ks_tconn_t * tconn, PKS_TSDUMGR);

void
KsRemoveTdiEngine(PKS_TSDUMGR);

NTSTATUS
ks_set_tcp_option (
    ks_tconn_t *    tconn,
    ULONG           ID,
    PVOID           OptionValue,
    ULONG           Length
    );

int
ks_get_tcp_option (
    ks_tconn_t *        tconn,
    ULONG               ID,
    PVOID               OptionValue,
    PULONG              Length
    );

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
