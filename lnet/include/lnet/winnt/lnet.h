/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef __LNET_LINUX_LNET_H__
#define __LNET_LINUX_LNET_H__

#ifndef __LNET_H__
#error Do not #include this file directly. #include <lnet/lnet.h> instead
#endif

#ifdef __KERNEL__

#include <libcfs/libcfs.h>
#include <lnet/lib-lnet.h>

/*
 * tdilnd routines
 */


PUCHAR
KsNtStatusToString (IN NTSTATUS Status);


VOID
KsPrintf(
    IN LONG  DebugPrintLevel,
    IN PCHAR DebugMessage,
    IN ...
    );


ksock_mdl_t *
ks_lock_iovs(
    IN struct iovec  *iov,
    IN int            niov,
    IN int            recv,
    IN int *          len
    );

ksock_mdl_t *
ks_lock_kiovs(
    IN lnet_kiov_t *   kiov,
    IN int            nkiov,
    IN int            recv,
    IN int *          len
    );

int
ks_send_mdl(
    ksock_tconn_t * tconn,
    void *          tx,
    ksock_mdl_t *   mdl,
    int             len,
    int             flags
    );

int
ks_query_data(
    ksock_tconn_t * tconn,
    size_t *        size,
    int             bIsExpedited);

int
ks_recv_mdl(
    ksock_tconn_t * tconn,
    ksock_mdl_t *   mdl,
    int             size,
    int             flags
    );

int
ks_get_tcp_option (
    ksock_tconn_t *     tconn,
    ULONG               ID,
    PVOID               OptionValue,
    PULONG              Length
    );

NTSTATUS
ks_set_tcp_option (
    ksock_tconn_t * tconn,
    ULONG           ID,
    PVOID           OptionValue,
    ULONG           Length
    );

int
ks_bind_tconn (
    ksock_tconn_t * tconn,
    ksock_tconn_t * parent,
    ulong_ptr   addr,
    unsigned short  port
    );

int
ks_build_tconn(
    ksock_tconn_t *                 tconn,
    ulong_ptr                   addr,
    unsigned short                  port
    );

int
ks_disconnect_tconn(
    ksock_tconn_t *     tconn,
    ulong_ptr       flags
    );

void
ks_abort_tconn(
    ksock_tconn_t *     tconn
    );

int
ks_query_local_ipaddr(
    ksock_tconn_t *     tconn
    );

int
ks_tconn_write (ksock_tconn_t *tconn, void *buffer, int nob);

int
ks_tconn_read (ksock_tconn_t * tconn, void *buffer, int nob);

NTSTATUS
KsTcpCompletionRoutine(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp,
    IN PVOID            Context
    );

NTSTATUS
KsDisconectCompletionRoutine (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp,
    IN PVOID            Context
    );

NTSTATUS
KsTcpReceiveCompletionRoutine(
    IN PIRP                         Irp,
    IN PKS_TCP_COMPLETION_CONTEXT   Context
    );

NTSTATUS
KsTcpSendCompletionRoutine(
    IN PIRP                         Irp,
    IN PKS_TCP_COMPLETION_CONTEXT   Context
    );

NTSTATUS
KsAcceptCompletionRoutine(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp,
    IN PVOID            Context
    );


NTSTATUS
KsConnectEventHandler(
    IN PVOID                    TdiEventContext,
    IN LONG                     RemoteAddressLength,
    IN PVOID                    RemoteAddress,
    IN LONG                     UserDataLength,
    IN PVOID                    UserData,
    IN LONG                     OptionsLength,
    IN PVOID                    Options,
    OUT CONNECTION_CONTEXT *    ConnectionContext,
    OUT PIRP *                  AcceptIrp
    );

NTSTATUS 
KsDisconnectEventHandler(
    IN PVOID                TdiEventContext,
    IN CONNECTION_CONTEXT   ConnectionContext,
    IN LONG                 DisconnectDataLength,
    IN PVOID                DisconnectData,
    IN LONG                 DisconnectInformationLength,
    IN PVOID                DisconnectInformation,
    IN ULONG                DisconnectFlags
    );

NTSTATUS
KsTcpReceiveEventHandler(
    IN PVOID                TdiEventContext, 
    IN CONNECTION_CONTEXT   ConnectionContext,
    IN ULONG                ReceiveFlags,
    IN ULONG                BytesIndicated,
    IN ULONG                BytesAvailable,
    OUT ULONG *             BytesTaken,
    IN PVOID                Tsdu,
    OUT PIRP *              IoRequestPacket
   );

NTSTATUS
KsTcpReceiveExpeditedEventHandler(
    IN PVOID                TdiEventContext, 
    IN CONNECTION_CONTEXT   ConnectionContext,
    IN ULONG                ReceiveFlags,
    IN ULONG                BytesIndicated,
    IN ULONG                BytesAvailable,
    OUT ULONG *             BytesTaken,
    IN PVOID                Tsdu,
    OUT PIRP *              IoRequestPacket
    );

NTSTATUS
KsTcpChainedReceiveEventHandler (
    IN PVOID TdiEventContext,       // the event context
    IN CONNECTION_CONTEXT ConnectionContext,
    IN ULONG ReceiveFlags, 
    IN ULONG ReceiveLength,
    IN ULONG StartingOffset,        // offset of start of client data in TSDU
    IN PMDL  Tsdu,                  // TSDU data chain
    IN PVOID TsduDescriptor         // for call to TdiReturnChainedReceives
    );

NTSTATUS
KsTcpChainedReceiveExpeditedEventHandler (
    IN PVOID                TdiEventContext,       // the event context
    IN CONNECTION_CONTEXT   ConnectionContext,
    IN ULONG                ReceiveFlags, 
    IN ULONG                ReceiveLength,
    IN ULONG                StartingOffset,        // offset of start of client data in TSDU
    IN PMDL                 Tsdu,                  // TSDU data chain
    IN PVOID                TsduDescriptor         // for call to TdiReturnChainedReceives
    );



VOID
KsDisconnectHelper(PKS_DISCONNECT_WORKITEM WorkItem);


ULONG
ks_tdi_send_flags(ULONG SockFlags);

PIRP
KsBuildTdiIrp(
    IN PDEVICE_OBJECT    DeviceObject
    );

NTSTATUS
KsSubmitTdiIrp(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp,
    IN BOOLEAN          bSynchronous,
    OUT PULONG          Information
    );

NTSTATUS
KsOpenControl(
    IN PUNICODE_STRING      DeviceName,
    OUT HANDLE *            Handle,
    OUT PFILE_OBJECT *      FileObject
   );

NTSTATUS
KsCloseControl(
    IN HANDLE             Handle,
    IN PFILE_OBJECT       FileObject
   );

NTSTATUS
KsOpenAddress(
    IN PUNICODE_STRING      DeviceName,
    IN PTRANSPORT_ADDRESS   pAddress,
    IN ULONG                AddressLength,
    OUT HANDLE *            Handle,
    OUT PFILE_OBJECT *      FileObject
   );

NTSTATUS
KsCloseAddress(
    IN HANDLE             Handle,
    IN PFILE_OBJECT       FileObject
    );

NTSTATUS
KsOpenConnection(
    IN PUNICODE_STRING      DeviceName,
    IN CONNECTION_CONTEXT   ConnectionContext,
    OUT HANDLE *            Handle,
    OUT PFILE_OBJECT *      FileObject
   );

NTSTATUS
KsCloseConnection(
    IN HANDLE             Handle,
    IN PFILE_OBJECT       FileObject
    );

NTSTATUS
KsAssociateAddress(
    IN HANDLE           AddressHandle,
    IN PFILE_OBJECT     ConnectionObject
    );


NTSTATUS
KsDisassociateAddress(
    IN PFILE_OBJECT     ConnectionObject
    );


NTSTATUS
KsSetEventHandlers(
    IN PFILE_OBJECT         AddressObject,
    IN PVOID                EventContext,
    IN PKS_EVENT_HANDLERS   Handlers
   );


NTSTATUS
KsQueryProviderInfo(
    PWSTR               TdiDeviceName,
    PTDI_PROVIDER_INFO  ProviderInfo
   );

NTSTATUS
KsQueryAddressInfo(
    IN PFILE_OBJECT         FileObject,
    OUT PTDI_ADDRESS_INFO   AddressInfo,
    OUT PULONG              AddressSize
   );

NTSTATUS
KsQueryConnectionInfo(
    IN PFILE_OBJECT            ConnectionObject,
    OUT PTDI_CONNECTION_INFO   ConnectionInfo,
    OUT PULONG                 ConnectionSize
   );

ULONG
KsInitializeTdiAddress(
    IN OUT PTA_IP_ADDRESS   pTransportAddress,
    IN ULONG                IpAddress,
    IN USHORT               IpPort
    );

ULONG
KsQueryMdlsSize (IN PMDL Mdl);


ULONG
KsQueryTdiAddressLength(
    OUT PTRANSPORT_ADDRESS   pTransportAddress
    );

NTSTATUS
KsQueryIpAddress(
    IN PFILE_OBJECT     FileObject,
    OUT PVOID           TdiAddress,
    OUT ULONG*          AddressLength
    );


NTSTATUS
KsErrorEventHandler(
    IN PVOID            TdiEventContext,
    IN NTSTATUS         Status
   );

int
ks_set_handlers(
    ksock_tconn_t *     tconn
    );


VOID
KsPrintProviderInfo(
   PWSTR DeviceName,
   PTDI_PROVIDER_INFO ProviderInfo
   );

ksock_tconn_t *
ks_create_tconn();

void
ks_free_tconn(
    ksock_tconn_t * tconn
    );

void
ks_init_listener(
    ksock_tconn_t * tconn
    );

void
ks_init_sender(
    ksock_tconn_t * tconn
    );

void
ks_init_child(
    ksock_tconn_t * tconn
    );

void
ks_get_tconn(
    ksock_tconn_t * tconn
    );

void
ks_put_tconn(
    ksock_tconn_t * tconn
    );

int
ks_reset_handlers(
    ksock_tconn_t *     tconn
    );

void
ks_destroy_tconn(
    ksock_tconn_t *     tconn
    );


PKS_TSDU
KsAllocateKsTsdu();

VOID
KsPutKsTsdu(
    PKS_TSDU  KsTsdu
    );

VOID
KsFreeKsTsdu(
    PKS_TSDU  KsTsdu
    );

VOID
KsInitializeKsTsdu(
    PKS_TSDU    KsTsdu,
    ULONG       Length
    );


VOID
KsInitializeKsTsduMgr(
    PKS_TSDUMGR     TsduMgr
    );

VOID
KsInitializeKsChain(
    PKS_CHAIN       KsChain
    );

NTSTATUS
KsCleanupTsduMgr(
    PKS_TSDUMGR     KsTsduMgr
    );

NTSTATUS
KsCleanupKsChain(
    PKS_CHAIN   KsChain
    );

NTSTATUS
KsCleanupTsdu(
    ksock_tconn_t * tconn
    );

NTSTATUS
KsCopyMdlChainToMdlChain(
    IN PMDL     SourceMdlChain,
    IN ULONG    SourceOffset,
    IN PMDL     DestinationMdlChain,
    IN ULONG    DestinationOffset,
    IN ULONG    BytesTobecopied,
    OUT PULONG  BytesCopied
    );

ULONG
KsQueryMdlsSize (PMDL Mdl);

NTSTATUS
KsLockUserBuffer (
    IN PVOID            UserBuffer,
    IN BOOLEAN          bPaged,
    IN ULONG            Length,
    IN LOCK_OPERATION   Operation,
    OUT PMDL *          pMdl
    );

PVOID
KsMapMdlBuffer (PMDL    Mdl);

VOID
KsReleaseMdl ( IN PMDL   Mdl,
               IN int    Paged );

int
ks_lock_buffer (
    void *            buffer,
    int               paged,
    int               length,
    LOCK_OPERATION    access,
    ksock_mdl_t **    kmdl
    );

void *
ks_map_mdl (ksock_mdl_t * mdl);

void
ks_release_mdl (ksock_mdl_t *mdl, int paged);

#endif /* __KERNEL__ */

#endif
