/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=4:tabstop=4:
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Matt Wu <mattwu@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define DEBUG_SUBSYSTEM S_LNET

/*
 *  Included Headers 
 */


#include <libcfs/libcfs.h>


/* libcfs module init/exit routines */
DECLARE_INIT(init_libcfs_module);
DECLARE_EXIT(exit_libcfs_module);

/* portal module init/exit routines */
DECLARE_INIT(init_lnet);
DECLARE_EXIT(fini_lnet);

/* tdinal module init/exit routines */
DECLARE_INIT(ksocknal_module_init);
DECLARE_EXIT(ksocknal_module_fini);

/* pingcli module init/exit routines */
DECLARE_INIT(pingcli_init);
DECLARE_EXIT(pingcli_cleanup);


/* pingsrv module init/exit routines */
DECLARE_INIT(pingsrv_init);
DECLARE_EXIT(pingsrv_cleanup);

/*
 * structure definitions
 */


#define LUSTRE_PING_VERSION   0x00010000               /* ping srv/cli version: 0001.0000 */

#define LUSTRE_PING_DEVICE    L"\\Device\\LNET"     /* device object name */
#define LUSTRE_PING_SYMLNK    L"\\DosDevices\\LNET" /* user-visible name for the device*/

typedef struct _DEVICE_EXTENSION
{
    BOOLEAN    bProcFS;

} DEVICE_EXTENSION, *PDEVICE_EXTENSION;


/*
 *  global definitions
 */

PDEVICE_OBJECT  PingObject = NULL;  /* ping device object */
PDEVICE_OBJECT  ProcObject = NULL;  /* procfs emulator device */


/*
 *  common routines
 */


//
// complete Irp request ...
//

NTSTATUS
UTCompleteIrp(
    PIRP        Irp,
    NTSTATUS    Status,
    ULONG       Info
    )
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Info;
    IoCompleteRequest(Irp,IO_NO_INCREMENT);

    return Status;
}

//
//  Open/Create Device ...
//

NTSTATUS
UTCreate(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    KdPrint(("UTCreate: DeviceCreate ...\n"));

    return UTCompleteIrp(Irp,STATUS_SUCCESS,0);
}

//
// Close Devcie ...
//

NTSTATUS
UTClose(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp)
{
    KdPrint(("UTClose: Device Closed.\n"));

    return UTCompleteIrp(Irp, STATUS_SUCCESS, 0);

    UNREFERENCED_PARAMETER(DeviceObject);
}



NTSTATUS
UTShutdown(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    KdPrint(("UTShutdown: shuting TdiSock ...\n"));

    return UTCompleteIrp(Irp, STATUS_SUCCESS, 0);

    UNREFERENCED_PARAMETER(DeviceObject);
}

//
// driver frame Routines ...
//


NTSTATUS
UTDeviceControl(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    NTSTATUS            Status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION  IrpSp;

    ULONG               ControlCode;
    ULONG               InputLength;
    ULONG               OutputLength;

    PVOID               lpvInBuffer;

    KdPrint(("UTDeviceControl: Device Ioctl ...\n"));

    Irp->IoStatus.Information = 0;
    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    ControlCode  = IrpSp->Parameters.DeviceIoControl.IoControlCode;
    InputLength  = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    OutputLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    lpvInBuffer  = Irp->AssociatedIrp.SystemBuffer;

    ASSERT (IrpSp->MajorFunction == IRP_MJ_DEVICE_CONTROL);

    switch (ControlCode)
    {
        case IOCTL_LIBCFS_VERSION:

            *((ULONG *)lpvInBuffer) = (ULONG)(LUSTRE_PING_VERSION);
            Irp->IoStatus.Information = sizeof(ULONG);
            Status = STATUS_SUCCESS;
            break;

        default:
            break;
    }

    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    KdPrint(("UTDeviceControl: Device Ioctl returned.\n"));

    return Status;
}

NTSTATUS
ProcCreate(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    NTSTATUS                    Status;
    PIO_STACK_LOCATION          IrpSp;

    FILE_FULL_EA_INFORMATION *  ea;
    cfs_file_t *                fp;

    KdPrint(("ProcCreate: Proc device is being opened ...\n"));

    IrpSp = IoGetCurrentIrpStackLocation(Irp);
    ea = (PFILE_FULL_EA_INFORMATION) Irp->AssociatedIrp.SystemBuffer;

    if (!ea) {
        Status = STATUS_INVALID_PARAMETER;
    } else {
        fp = lustre_open_file(&ea->EaName[0]);
        if (!fp) {
            Status = STATUS_OBJECT_NAME_NOT_FOUND;
        } else {
            IrpSp->FileObject->FsContext = fp;
            IrpSp->FileObject->FsContext2 = fp->private_data;
            Status = STATUS_SUCCESS;
        }
    }

    return UTCompleteIrp(Irp, Status, 0);
}

//
// Close Devcie ...
//

NTSTATUS
ProcClose(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp)
{
    PIO_STACK_LOCATION          IrpSp;

    cfs_file_t *                fp;

    KdPrint(("ProcClose: Proc device object is to be closed.\n"));

    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    fp = (cfs_file_t *) IrpSp->FileObject->FsContext;

    ASSERT(fp != NULL);
    ASSERT(IrpSp->FileObject->FsContext2 == fp->private_data);

    lustre_close_file(fp);

    return UTCompleteIrp(Irp, STATUS_SUCCESS, 0);

    UNREFERENCED_PARAMETER(DeviceObject);
}

/*
 * proc frame routines
 */

NTSTATUS
ProcDeviceControl(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    NTSTATUS            Status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION  IrpSp;

    ULONG               ControlCode;
    ULONG               InputLength;
    ULONG               OutputLength;

    PVOID               lpvInBuffer;

    KdPrint(("ProcDeviceControl: Proc device ioctling ...\n"));

    Irp->IoStatus.Information = 0;
    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    ControlCode  = IrpSp->Parameters.DeviceIoControl.IoControlCode;
    InputLength  = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    OutputLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    lpvInBuffer  = Irp->AssociatedIrp.SystemBuffer;

    ASSERT (IrpSp->MajorFunction == IRP_MJ_DEVICE_CONTROL);

    switch (ControlCode)
    {
        case IOCTL_LIBCFS_VERSION:

            *((ULONG *)lpvInBuffer) = (ULONG)(LUSTRE_PING_VERSION);
            Irp->IoStatus.Information = sizeof(ULONG);

            Status = STATUS_SUCCESS;

            break;

        case IOCTL_LIBCFS_ENTRY:
        {
            int rc = 0;
            cfs_file_t * fp;

            fp = (cfs_file_t *) IrpSp->FileObject->FsContext;

            if (!fp) {
                rc = -EINVAL;
            } else {
                rc = lustre_ioctl_file(fp, (PCFS_PROC_IOCTL) (lpvInBuffer));
            }

            if (rc == 0) {
                Irp->IoStatus.Information = InputLength;
                Status = STATUS_SUCCESS;
            }
        }    
    }

    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    KdPrint(("ProcDeviceControl: Proc device ioctl returned with status = %xh.\n", Status));

    return Status;
}



NTSTATUS
ProcReadWrite (PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION  IrpSp;
    NTSTATUS            Status;

    cfs_file_t *        fp;
    int                 rc;
    PCHAR               buf;

    IrpSp = IoGetCurrentIrpStackLocation(Irp);
    if (Irp->MdlAddress) {
        buf = MmGetSystemAddressForMdlSafe(
                        Irp->MdlAddress,
                        NormalPagePriority);
    } else {
        buf = Irp->AssociatedIrp.SystemBuffer;
    }

    if (buf == NULL) {
        Status = STATUS_SUCCESS;
        rc = 0;
    } else {
        fp = (cfs_file_t *) IrpSp->FileObject->FsContext;

        if (!fp) {
            Status = STATUS_INVALID_PARAMETER;
            goto errorout;
        }

        if (IrpSp->MajorFunction == IRP_MJ_READ) {
            rc = lustre_read_file(
                    fp, IrpSp->Parameters.Read.ByteOffset.LowPart,
                    IrpSp->Parameters.Read.Length, buf);
        } else {
            rc = lustre_write_file(
                    fp, IrpSp->Parameters.Write.ByteOffset.LowPart,
                    IrpSp->Parameters.Write.Length, buf);
        }
        if (rc < 0) {
            cfs_enter_debugger();
            Status = STATUS_UNSUCCESSFUL;
        } else {
            Status = STATUS_SUCCESS;
        }
    }

 
errorout:
    return UTCompleteIrp(Irp, Status, rc);
}


//
//  common dispatch routines
//

NTSTATUS
UTDispatchRequest(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP           Irp
    )
{
    NTSTATUS            Status;
    PIO_STACK_LOCATION  IrpSp;

    Status = STATUS_INVALID_DEVICE_REQUEST;

    __try {

        IrpSp = IoGetCurrentIrpStackLocation(Irp);

        switch (IrpSp->MajorFunction) {

            case IRP_MJ_CREATE:
                if (DeviceObject == PingObject) {
                    Status = UTCreate(DeviceObject, Irp);
                } else if (DeviceObject == ProcObject) {
                    Status = ProcCreate(DeviceObject, Irp);
                }
                break;
        
            case IRP_MJ_CLOSE:
                if (DeviceObject == PingObject) {
                    Status = UTClose(DeviceObject, Irp);
                } else if (DeviceObject == ProcObject) {
                    Status = ProcClose(DeviceObject, Irp);
                }
                break;

            case IRP_MJ_READ:
            case IRP_MJ_WRITE:
                if (DeviceObject == ProcObject) {
                    Status = ProcReadWrite(DeviceObject, Irp);
                }
                break;
        
            case IRP_MJ_DEVICE_CONTROL:
                if (DeviceObject == PingObject) {
                    Status = UTDeviceControl(DeviceObject, Irp);
                } else if (DeviceObject == ProcObject) {
                    Status = ProcDeviceControl(DeviceObject, Irp);
                }
                break;

            case IRP_MJ_SHUTDOWN:
                Status = UTShutdown(DeviceObject, Irp);
                break;

            default:

                KdPrint(("UTDispatchRequest: Major Function: %xh is not supported.\n",
                           IrpSp->MajorFunction));
                UTCompleteIrp(Irp, Status, 0);
                break;
        }
    }

    __finally {
    }

    return Status;
}

//
// create a device object and a dosdevice symbol link
//

PDEVICE_OBJECT
CreateDevice(
    IN PDRIVER_OBJECT   DriverObject,
    IN PWCHAR           DeviceName,
    IN PWCHAR           SymlnkName,
    IN BOOLEAN          bProcFS
    )
{
    NTSTATUS            Status;

    UNICODE_STRING      NtDevName;
    UNICODE_STRING      Win32DevName;

    PDEVICE_EXTENSION   DeviceExtension;
    PDEVICE_OBJECT      DeviceObject;

    /* create the device object with the specified name */

    RtlInitUnicodeString(&NtDevName, DeviceName);
    
    Status = IoCreateDevice(
                    DriverObject,
                    sizeof(DEVICE_EXTENSION),
                    &NtDevName,
                    FILE_DEVICE_UNKNOWN,
                    0,
                    FALSE,
                    &DeviceObject );
        
    if (!NT_SUCCESS(Status)) {

        cfs_enter_debugger();
        return NULL;
    }

    /* create the symlink to make the device visible to user */

    RtlInitUnicodeString(&Win32DevName, SymlnkName);
        
    Status = IoCreateSymbolicLink(&Win32DevName, &NtDevName);

    if (!NT_SUCCESS(Status)) {

        IoDeleteDevice(DeviceObject);
        return NULL;
    }

    DeviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceObjectExtension;
    DeviceExtension->bProcFS = bProcFS;

    DeviceObject->Flags |= DO_BUFFERED_IO;
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return DeviceObject;
}


//
// DriverEntry
//

NTSTATUS DriverEntry(
    IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath 
    )
{
    KdPrint(("Lustre ping test: Build Time: " __DATE__ " " __TIME__ "\n"));
    KdPrint(("Lustre ping test: DriverEntry ... \n"));

    /* initialize libcfs module */
    if (module_init_libcfs_module() != 0) {
        KdPrint(("ping: error initialize module: libcfs ...\n"));
        goto errorout;
    }

    /* initialize lnet module */
    if (module_init_lnet() != 0) {
        module_exit_libcfs_module();
        KdPrint(("ping: error initialize module: lnet ...\n"));
        goto errorout;
    }

    /* initialize tdinal module */
    if (module_ksocknal_module_init() != 0) {
        module_fini_lnet();
        module_exit_libcfs_module();
        KdPrint(("ping: error initialize module: tdilnd ...\n"));
        goto errorout;
    }

#if defined(LUSTRE_PING_CLI)
    /* initialize pingcli module */
    if (module_pingcli_init() != 0) {
        module_ksocknal_module_fini();
        module_fini_lnet();
        module_exit_libcfs_module();
        KdPrint(("ping: error initialize module: pingcli ...\n"));
        goto errorout;
    }
#endif

#if defined(LUSTRE_PING_SRV)
    /* initialize pingsrv module */
    if (module_pingsrv_init() != 0) {
        module_ksocknal_module_fini();
        module_fini_lnet();
        module_exit_libcfs_module();
        KdPrint(("ping: error initialize module: pingsrv ...\n"));
        goto errorout;
    }
#endif

    /* create the ping device object */
    PingObject = CreateDevice(
                        DriverObject,
                        LUSTRE_PING_DEVICE,
                        LUSTRE_PING_SYMLNK,
                        FALSE );
    if (!PingObject) {
#if defined(LUSTRE_PING_CLI)
        module_pingcli_cleanup();
#endif
#if defined(LUSTRE_PING_SRV)
        module_pingsrv_cleanup();
#endif
        module_ksocknal_module_fini();
        module_fini_lnet();
        module_exit_libcfs_module();

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* create the libcfs proc fs emultor device object */
    ProcObject  = CreateDevice(
                        DriverObject,
                        LUSTRE_PROC_DEVICE,
                        LUSTRE_PROC_SYMLNK,
                        TRUE );
    if (!ProcObject) {

        IoDeleteDevice(PingObject);
#if defined(LUSTRE_PING_CLI)
        module_pingcli_cleanup();
#endif
#if defined(LUSTRE_PING_SRV)
        module_pingsrv_cleanup();
#endif
        module_ksocknal_module_fini();
        module_fini_lnet();
        module_exit_libcfs_module();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* initialize the driver callback routines */

    DriverObject->MajorFunction[IRP_MJ_CREATE]          = UTDispatchRequest;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]           = UTDispatchRequest;
    DriverObject->MajorFunction[IRP_MJ_READ]            = UTDispatchRequest;
    DriverObject->MajorFunction[IRP_MJ_WRITE]           = UTDispatchRequest;
    DriverObject->MajorFunction[IRP_MJ_SHUTDOWN]        = UTDispatchRequest;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = UTDispatchRequest;

    return STATUS_SUCCESS;

errorout:

    cfs_enter_debugger();

    return STATUS_UNSUCCESSFUL;
}
