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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * winnt selftest driver framework
 *
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

/* selftest module init/exit routines */
DECLARE_INIT(lnet_selftest_init);
DECLARE_EXIT(lnet_selftest_fini);

/*
 * module info
 */

cfs_module_t libcfs_global_module =  {"selftest"};

/*
 * structure definitions
 */

#define LNET_SELFTEST_VERSION   0x00010001                  /* LNET selftest module version */

#define LNET_SELFTEST_DEVICE    L"\\Device\\Selftest"       /* device object name */
#define LNET_SELFTEST_SYMLNK    L"\\DosDevices\\Selftest"   /* user-visible name for the device*/

typedef struct _DEVICE_EXTENSION {
    BOOLEAN    bProcFS;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

/*
 *  global definitions
 */

PDEVICE_OBJECT  SelfObject = NULL;  /* lnet selftest object */
PDEVICE_OBJECT  ProcObject = NULL;  /* procfs emulator device */


/*
 *  common routines
 */


//
// complete Irp request ...
//

NTSTATUS
LstCompleteIrp(
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
LstCreate(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    KdPrint(("LstCreate: DeviceCreate ...\n"));

    return LstCompleteIrp(Irp,STATUS_SUCCESS,0);
}

//
// Close Devcie ...
//

NTSTATUS
LstClose(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp)
{
    KdPrint(("LstClose: Device Closed.\n"));

    return LstCompleteIrp(Irp, STATUS_SUCCESS, 0);

    UNREFERENCED_PARAMETER(DeviceObject);
}


//
// computer is being shut down
//

NTSTATUS
LstShutdown(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    KdPrint(("LstShutdown:  ...\n"));

    return LstCompleteIrp(Irp, STATUS_SUCCESS, 0);

    UNREFERENCED_PARAMETER(DeviceObject);
}

//
// device io control
//


NTSTATUS
LstDeviceControl(
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

            *((ULONG *)lpvInBuffer) = (ULONG)(LNET_SELFTEST_VERSION);
            Irp->IoStatus.Information = sizeof(ULONG);
            Status = STATUS_SUCCESS;
            break;

        default:
            break;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

NTSTATUS
ProcCreate(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
	NTSTATUS			Status;
	PIO_STACK_LOCATION		IrpSp;

	FILE_FULL_EA_INFORMATION	*ea;
	struct file			*fp;

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

    return LstCompleteIrp(Irp, Status, 0);
}

//
// Close Devcie ...
//

NTSTATUS
ProcClose(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp)
{
	PIO_STACK_LOCATION	IrpSp;

	struct file		*fp;

	IrpSp = IoGetCurrentIrpStackLocation(Irp);
	fp = (file_t *) IrpSp->FileObject->FsContext;
    ASSERT(fp != NULL);
    ASSERT(IrpSp->FileObject->FsContext2 == fp->private_data);

    lustre_close_file(fp);

    return LstCompleteIrp(Irp, STATUS_SUCCESS, 0);

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

            *((ULONG *)lpvInBuffer) = (ULONG)(LNET_SELFTEST_VERSION);
            Irp->IoStatus.Information = sizeof(ULONG);

            Status = STATUS_SUCCESS;

            break;

        case IOCTL_LIBCFS_ENTRY:
        {
			int rc = 0;
			struct file *fp;

			fp = (struct file *)IrpSp->FileObject->FsContext;

            if (!fp) {
                rc = -EINVAL;
            } else {
                rc = lustre_ioctl_file(fp, (PCFS_PROC_IOCTL) lpvInBuffer);
            }

            ((PCFS_PROC_IOCTL) lpvInBuffer)->rc = rc;
            Irp->IoStatus.Information = InputLength;
            Status = STATUS_SUCCESS;
        }    
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}


NTSTATUS
ProcReadWrite (PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION	IrpSp;
	NTSTATUS		Status;

	struct file		*fp;
	int			rc;
	PCHAR			buf;

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
		fp = (struct file *)IrpSp->FileObject->FsContext;

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
    return LstCompleteIrp(Irp, Status, rc);
}


//
//  common dispatch routines
//

NTSTATUS
LstDispatchRequest(
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
                if (DeviceObject == SelfObject) {
                    Status = LstCreate(DeviceObject, Irp);
                } else if (DeviceObject == ProcObject) {
                    Status = ProcCreate(DeviceObject, Irp);
                }
                break;
        
            case IRP_MJ_CLOSE:
                if (DeviceObject == SelfObject) {
                    Status = LstClose(DeviceObject, Irp);
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
                if (DeviceObject == SelfObject) {
                    Status = LstDeviceControl(DeviceObject, Irp);
                } else if (DeviceObject == ProcObject) {
                    Status = ProcDeviceControl(DeviceObject, Irp);
                }
                break;

            case IRP_MJ_SHUTDOWN:
                Status = LstShutdown(DeviceObject, Irp);
                break;

            default:

                KdPrint(("LstDispatchRequest: Major Function: %xh is not supported.\n",
                           IrpSp->MajorFunction));
                LstCompleteIrp(Irp, Status, 0);
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
LstCreateDevice(
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

    DeviceObject->AlignmentRequirement = 0;
    DeviceObject->SectorSize = 0;
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
    KdPrint(("LNet selftest: Build Time: " __DATE__ " " __TIME__ "\n"));
    KdPrint(("LNet selftest: DriverEntry ... \n"));

    /* initialize libcfs module */
    if (module_init_libcfs_module() != 0) {
        KdPrint(("selftest: failed to initialize module: libcfs ...\n"));
        goto errorout;
    }

    /* initialize portals module */
    if (module_init_lnet() != 0) {
        KdPrint(("selftest: failed to initialize module: lnet ...\n"));
        module_exit_libcfs_module();
        goto errorout;
    }

    /* initialize tdinal module */
    if (module_ksocknal_module_init() != 0) {
        KdPrint(("selftest: failed to initialize module: socklnd ...\n"));
        module_fini_lnet();
        module_exit_libcfs_module();
        goto errorout;
    }

    /* initialize lnet selttest module */
    if (module_lnet_selftest_init() != 0) {
        KdPrint(("selftest: failed to initialize module: selftest ...\n"));
        module_ksocknal_module_fini();
        module_fini_lnet();
        module_exit_libcfs_module();
        goto errorout;
    }

    /* create lnet selftest device object */
    SelfObject = LstCreateDevice(
                        DriverObject,
                        LNET_SELFTEST_DEVICE,
                        LNET_SELFTEST_SYMLNK,
                        FALSE );
    if (!SelfObject) {
        KdPrint(("selftest: failed to allocate DeviceObject ...\n"));
        module_lnet_selftest_fini();
        module_ksocknal_module_fini();
        module_fini_lnet();
        module_exit_libcfs_module();

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* create the libcfs proc fs emultor device object */
    ProcObject  = LstCreateDevice(
                        DriverObject,
                        LUSTRE_PROC_DEVICE,
                        LUSTRE_PROC_SYMLNK,
                        TRUE );
    if (!ProcObject) {

        KdPrint(("selftest: failed to allocate proc DeviceObject ...\n"));
        /* remove Selftest DeviceObject */
        IoDeleteDevice(SelfObject);
        module_lnet_selftest_fini();
        module_ksocknal_module_fini();
        module_fini_lnet();
        module_exit_libcfs_module();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* initialize the driver callback routines */

    DriverObject->MajorFunction[IRP_MJ_CREATE]          = LstDispatchRequest;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]           = LstDispatchRequest;
    DriverObject->MajorFunction[IRP_MJ_READ]            = LstDispatchRequest;
    DriverObject->MajorFunction[IRP_MJ_WRITE]           = LstDispatchRequest;
    DriverObject->MajorFunction[IRP_MJ_SHUTDOWN]        = LstDispatchRequest;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = LstDispatchRequest;

    return STATUS_SUCCESS;

errorout:

    cfs_enter_debugger();

    return STATUS_UNSUCCESSFUL;
}
