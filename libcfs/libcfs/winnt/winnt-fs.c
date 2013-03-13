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
 */

# define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>

const CHAR *dos_file_prefix[] = {
            "\\??\\", "\\DosDevices\\",
            "\\SystemRoot\\", NULL};

/*
 * filp_open
 *     To open or create a file in kernel mode
 *
 * Arguments:
 *   name:  name of the file to be opened or created, no dos path prefix
 *   flags: open/creation attribute options
 *   mode:  access mode/permission to open or create
 *   err:   error code
 *
 * Return Value:
 *   the pointer to the struct file or NULL if it fails
 *
 * Notes:
 *   N/A
 */

#define is_drv_letter_valid(x) (((x) >= 0 && (x) <= 9) || \
                ( ((x)|0x20) <= 'z' && ((x)|0x20) >= 'a'))

struct file *filp_open(const char *name, int flags, int mode, int *err)
{
	struct file *fp = NULL;

    NTSTATUS            Status;

    OBJECT_ATTRIBUTES   ObjectAttributes;
    HANDLE              FileHandle;
    IO_STATUS_BLOCK     IoStatus;
    ACCESS_MASK         DesiredAccess;
    ULONG               CreateDisposition;
    ULONG               ShareAccess;
    ULONG               CreateOptions;

    USHORT              NameLength = 0;
    USHORT              PrefixLength = 0;

    UNICODE_STRING      UnicodeName;
    PWCHAR              UnicodeString = NULL;

    ANSI_STRING         AnsiName;
    PUCHAR              AnsiString = NULL;

    /* Analyze the flags settings */
    if (cfs_is_flag_set(flags, O_WRONLY)) {
        DesiredAccess = (GENERIC_WRITE | SYNCHRONIZE);
        ShareAccess = 0;
    }  else if (cfs_is_flag_set(flags, O_RDWR)) {
        DesiredAccess = (GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE);
        ShareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE;
    } else {
        DesiredAccess = (GENERIC_READ | SYNCHRONIZE);
        ShareAccess = FILE_SHARE_READ;
    }

    if (cfs_is_flag_set(flags, O_CREAT)) {
        if (cfs_is_flag_set(flags, O_EXCL)) {
            CreateDisposition = FILE_CREATE;
        } else {
            CreateDisposition = FILE_OPEN_IF;
        }
    } else {
        CreateDisposition = FILE_OPEN;
    }

    if (cfs_is_flag_set(flags, O_TRUNC)) {
        if (cfs_is_flag_set(flags, O_EXCL)) {
            CreateDisposition = FILE_OVERWRITE;
        } else {
            CreateDisposition = FILE_OVERWRITE_IF;
        }
    }

    CreateOptions = 0;

    if (cfs_is_flag_set(flags, O_DIRECTORY)) {
        cfs_set_flag(CreateOptions,  FILE_DIRECTORY_FILE);
    }

    if (cfs_is_flag_set(flags, O_SYNC)) {
         cfs_set_flag(CreateOptions, FILE_WRITE_THROUGH);
    }

    if (cfs_is_flag_set(flags, O_DIRECT)) {
         cfs_set_flag(CreateOptions, FILE_NO_INTERMEDIATE_BUFFERING);
    }

    /* Initialize the unicode path name for the specified file */
    NameLength = (USHORT)strlen(name);

	/* Check file & path name */
	if (name[0] != '\\') {
		if (NameLength < 1 || name[1] != ':' ||
		    !is_drv_letter_valid(name[0])) {
			/* invalid file path name */
			return ERR_PTR(-EINVAL);
		}
		PrefixLength = (USHORT)strlen(dos_file_prefix[0]);
	} else {
		int i, j;
		for (i = 0; i < 3 && dos_file_prefix[i] != NULL; i++) {
			j = strlen(dos_file_prefix[i]);
			if (NameLength > j &&
			    _strnicmp(dos_file_prefix[i], name, j) == 0)
				break;
		}
		if (i >= 3)
			return ERR_PTR(-EINVAL);
	}

	AnsiString = cfs_alloc(sizeof(CHAR) * (NameLength + PrefixLength + 1),
				CFS_ALLOC_ZERO);
	if (NULL == AnsiString)
		return ERR_PTR(-ENOMEM);

	UnicodeString =
		cfs_alloc(sizeof(WCHAR) * (NameLength + PrefixLength + 1),
			  CFS_ALLOC_ZERO);
	if (NULL == UnicodeString) {
		cfs_free(AnsiString);
		return ERR_PTR(-ENOMEM);
	}

    if (PrefixLength) {
        RtlCopyMemory(&AnsiString[0], dos_file_prefix[0], PrefixLength);
    }

    RtlCopyMemory(&AnsiString[PrefixLength], name, NameLength);
    NameLength += PrefixLength;

    AnsiName.MaximumLength = NameLength + 1;
    AnsiName.Length = NameLength;
    AnsiName.Buffer = AnsiString;

    UnicodeName.MaximumLength = (NameLength + 1) * sizeof(WCHAR);
    UnicodeName.Length = 0;
    UnicodeName.Buffer = (PWSTR)UnicodeString;

    RtlAnsiStringToUnicodeString(&UnicodeName, &AnsiName, FALSE);

    /* Setup the object attributes structure for the file. */
    InitializeObjectAttributes(
            &ObjectAttributes,
            &UnicodeName,
            OBJ_CASE_INSENSITIVE |
            OBJ_KERNEL_HANDLE,
            NULL,
            NULL );

    /* Now to open or create the file now */
    Status = ZwCreateFile(
            &FileHandle,
            DesiredAccess,
            &ObjectAttributes,
            &IoStatus,
            0,
            FILE_ATTRIBUTE_NORMAL,
            ShareAccess,
            CreateDisposition,
            CreateOptions,
            NULL,
            0 );

	/* Check the returned status of IoStatus... */
	if (!NT_SUCCESS(IoStatus.Status)) {
		cfs_free(UnicodeString);
		cfs_free(AnsiString);
		return ERR_PTR(cfs_error_code(IoStatus.Status));
	}

	/* Allocate the file_t: libcfs file object */
	fp = cfs_alloc(sizeof(*fp) + NameLength, CFS_ALLOC_ZERO);

	if (NULL == fp) {
		Status = ZwClose(FileHandle);
		ASSERT(NT_SUCCESS(Status));
		cfs_free(UnicodeString);
		cfs_free(AnsiString);
		return ERR_PTR(-ENOMEM);
	}

    fp->f_handle = FileHandle;
    strcpy(fp->f_name, name);
    fp->f_flags = flags;
    fp->f_mode  = (mode_t)mode;
    fp->f_count = 1;

    /* free the memory of temporary name strings */
    cfs_free(UnicodeString);
    cfs_free(AnsiString);

    return fp;
}


/*
 * filp_close
 *     To close the opened file and release the filp structure
 *
 * Arguments:
 *   fp:   the pointer of the file structure
 *
 * Return Value:
 *   ZERO: on success
 *   Non-Zero: on failure
 *
 * Notes:
 *   N/A
 */

int filp_close(file_t *fp, void *id)
{
    NTSTATUS    Status;

    ASSERT(fp != NULL);
    ASSERT(fp->f_handle != NULL);

    /* release the file handle */
    Status = ZwClose(fp->f_handle);
    ASSERT(NT_SUCCESS(Status));

    /* free the file flip structure */
    cfs_free(fp);
    return 0;
}


NTSTATUS CompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
    /* copy the IoStatus result */
    if (Irp->UserIosb)
        *Irp->UserIosb = Irp->IoStatus;
    
    /* singal the event we set */
    KeSetEvent((PKEVENT) Context, 0, FALSE);
   
    /* free the Irp we allocated */
    IoFreeIrp(Irp);
    
    return STATUS_MORE_PROCESSING_REQUIRED;
}


NTSTATUS cfs_nt_filp_io(HANDLE Handle, BOOLEAN Writing, PLARGE_INTEGER Offset,
                        ULONG Length,  PUCHAR Buffer,   PULONG Bytes)
{
    NTSTATUS                status;
    IO_STATUS_BLOCK         iosb;

    PIRP                    irp = NULL;
    PIO_STACK_LOCATION      irpSp = NULL;

    PFILE_OBJECT            fileObject = NULL;
    PDEVICE_OBJECT          deviceObject;

    KEVENT                  event;

    KeInitializeEvent(&event, SynchronizationEvent, FALSE);

    status = ObReferenceObjectByHandle( Handle,
                                        Writing ? FILE_WRITE_DATA : 
                                                  FILE_READ_DATA,
                                        *IoFileObjectType,
                                        KernelMode,
                                        (PVOID *) &fileObject,
                                        NULL );
    if (!NT_SUCCESS(status)) {
        goto errorout;
    }

    /* query the DeviceObject in case no input */
    deviceObject = IoGetBaseFileSystemDeviceObject(fileObject);


    /* allocate our own irp */
    irp = IoAllocateIrp(deviceObject->StackSize, FALSE);
    if (NULL == irp) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto errorout;
    }

    irp->Tail.Overlay.OriginalFileObject = fileObject;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();
    irp->Tail.Overlay.AuxiliaryBuffer = (PVOID) NULL;
    irp->PendingReturned = FALSE;
    irp->Cancel = FALSE;
    irp->CancelRoutine = (PDRIVER_CANCEL) NULL;
    irp->RequestorMode = KernelMode;
    irp->UserIosb = &iosb;

    /* set up the next I/O stack location. */
    irpSp = (PIO_STACK_LOCATION)IoGetNextIrpStackLocation(irp);
    irpSp->MajorFunction = Writing ? IRP_MJ_WRITE : IRP_MJ_READ;
    irpSp->FileObject = fileObject;
    irpSp->DeviceObject = deviceObject;

    if (deviceObject->Flags & DO_BUFFERED_IO) {
        irp->AssociatedIrp.SystemBuffer = Buffer;
        irp->UserBuffer = Buffer;
        irp->Flags |= (ULONG) (IRP_BUFFERED_IO |
                               IRP_INPUT_OPERATION);
    } else if (deviceObject->Flags & DO_DIRECT_IO) {

        PMDL mdl = NULL;

        mdl = IoAllocateMdl(Buffer, Length, FALSE, TRUE, irp);
        if (mdl == NULL) {
            KsPrint((0, "cfs_nt_filp_io: failed to allocate MDL for %wZ .\n",
                        &fileObject->FileName));
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto errorout;
        }

        __try {
            MmProbeAndLockPages(mdl, KernelMode, Writing ? IoReadAccess : IoWriteAccess );
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            KsPrint((0, "cfs_nt_filp_io: failed to lock buffer %p for %wZ .\n",
                        Buffer, &fileObject->FileName));
            IoFreeMdl(irp->MdlAddress);
            irp->MdlAddress = NULL;
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    } else {
        irp->UserBuffer = Buffer;
        irp->Flags = 0;
    }

    if (Writing) {
        irp->Flags |= IRP_WRITE_OPERATION | IRP_DEFER_IO_COMPLETION;
        irpSp->Parameters.Write.Length = Length;
        irpSp->Parameters.Write.ByteOffset = *Offset;
    } else {
        irp->Flags |= IRP_READ_OPERATION | IRP_DEFER_IO_COMPLETION;
        irpSp->Parameters.Read.Length = Length;
        irpSp->Parameters.Read.ByteOffset = *Offset;
    }

    /* set the Irp completion routine */
    IoSetCompletionRoutine( irp, CompletionRoutine, 
                            &event, TRUE, TRUE, TRUE);


    /* issue the irp to the lower layer device */
    status = IoCallDriver(deviceObject, irp);

    /* Irp is to be cleaned up in the compleiton routine */
    irp = NULL;

    if (status == STATUS_PENDING) {

        /* we need wait until operation is completed, then we can
           get the returned status and information length */

        status = KeWaitForSingleObject(
                    &event,
                    Executive,
                    KernelMode,
                    FALSE,
                    NULL
                    );
        if (NT_SUCCESS(status)) {
            status = iosb.Status;
        }
    }

    if (NT_SUCCESS(status)) {
        *Bytes = (ULONG)iosb.Information;
    } else {
        *Bytes = 0;
    }

errorout:

    if (fileObject) {
        ObDereferenceObject(fileObject);
    }

    /* free the Irp in error case */
    if (irp) {
        IoFreeIrp(irp);
    }

    return status;
}

/*
 * filp_read
 *     To read data from the opened file
 *
 * Arguments:
 *   fp:   the pointer of the file strcture
 *   buf:  pointer to the buffer to contain the data
 *   nbytes: size in bytes to be read from the file
 *   pos:  offset in file where reading starts, if pos
 *         NULL, then read from current file offset
 *
 * Return Value:
 *   Actual size read into the buffer in success case
 *   Error code in failure case
 *
 * Notes: 
 *   N/A
 */
int filp_read(struct file *fp, void *buf, size_t nbytes, loff_t *pos)
{
    LARGE_INTEGER   offset;
    NTSTATUS        status;
    int             rc = 0;

    /* Read data from the file into the specified buffer */
    if (pos != NULL) {
        offset.QuadPart = *pos;
    } else {
        offset.QuadPart = fp->f_pos;
    }

    status = cfs_nt_filp_io(fp->f_handle, 0, &offset,
                            nbytes, buf, &rc);

    if (!NT_SUCCESS(status)) {
        rc = cfs_error_code(status);
    }

    if (rc > 0) {
        fp->f_pos = offset.QuadPart + rc;
        if (pos != NULL)
            *pos = fp->f_pos;
    }

    return rc;
}

/*
 * cfs_filp_wrtie
 *     To write specified data to the opened file
 *
 * Arguments:
 *   fp:   the pointer of the file strcture
 *   buf:  pointer to the buffer containing the data
 *   nbytes: size in bytes to be written to the file
 *   pos:  offset in file where writing starts, if pos
 *         NULL, then write to current file offset
 *
 * Return Value:
 *   Actual size written into the buffer in success case
 *   Error code in failure case
 *
 * Notes: 
 *   N/A
 */

int filp_write(struct file *fp, void *buf, size_t nbytes, loff_t *pos)
{
    LARGE_INTEGER   offset;
    NTSTATUS        status;
    int             rc = 0;

    /* Read data from the file into the specified buffer */
    if (pos != NULL) {
        offset.QuadPart = *pos;
    } else {
        offset.QuadPart = fp->f_pos;
    }

    status = cfs_nt_filp_io(fp->f_handle, 1, &offset,
                            nbytes, buf, &rc);

    if (!NT_SUCCESS(status)) {
        rc = cfs_error_code(status);
    }

    if (rc > 0) {
        fp->f_pos = offset.QuadPart + rc;
        if (pos != NULL)
            *pos = fp->f_pos;
    }

    return rc;
}

/*
 * filp_fsync
 *     To sync the dirty data of the file to disk
 *
 * Arguments:
 *   fp: the pointer of the file strcture
 *
 * Return Value:
 *   Zero:  in success case
 *   Error code: in failure case
 *
 * Notes: 
 *   Nt kernel doesn't export such a routine to flush a file,
 *   we must allocate our own Irp and issue it to the file
 *   system driver.
 */
int filp_fsync(struct file *fp)
{
    PFILE_OBJECT            FileObject;
    PDEVICE_OBJECT          DeviceObject;

    NTSTATUS                Status;
    PIRP                    Irp;
    KEVENT                  Event;
    IO_STATUS_BLOCK         IoSb;
    PIO_STACK_LOCATION      IrpSp;

    /* get the FileObject and the DeviceObject */
    Status = ObReferenceObjectByHandle(
                fp->f_handle,
                FILE_WRITE_DATA,
                NULL,
                KernelMode,
                (PVOID*)&FileObject,
                NULL );

    if (!NT_SUCCESS(Status)) {
        return cfs_error_code(Status);
    }

    DeviceObject = IoGetRelatedDeviceObject(FileObject);

    /* allocate a new Irp */
    Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
    if (!Irp) {
        ObDereferenceObject(FileObject);
        return -ENOMEM;
    }

    /* intialize the event */
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    /* setup the Irp */
    Irp->UserIosb = &IoSb;
    Irp->RequestorMode = KernelMode;

    Irp->Tail.Overlay.Thread = PsGetCurrentThread();
    Irp->Tail.Overlay.OriginalFileObject = FileObject;

    /* setup the Irp stack location */
    IrpSp = IoGetNextIrpStackLocation(Irp);

    IrpSp->MajorFunction = IRP_MJ_FLUSH_BUFFERS;
    IrpSp->DeviceObject = DeviceObject;
    IrpSp->FileObject = FileObject;

    IoSetCompletionRoutine( Irp, CompletionRoutine,
                            &Event, TRUE, TRUE, TRUE);


    /* issue the Irp to the underlying file system driver */
    IoCallDriver(DeviceObject, Irp);

    /* wait until it is finished */
    KeWaitForSingleObject(&Event, Executive, KernelMode, TRUE, 0);

    /* cleanup our reference on it */
    ObDereferenceObject(FileObject);

    Status = IoSb.Status;

    return cfs_error_code(Status);
}

/*
 * get_file
 *     To increase the reference of the file object
 *
 * Arguments:
 *   fp:   the pointer of the file strcture
 *
 * Return Value:
 *   Zero:  in success case
 *   Non-Zero: in failure case
 *
 * Notes: 
 *   N/A
 */

int get_file(struct file *fp)
{
    InterlockedIncrement(&(fp->f_count));
    return 0;
}


/*
 * fput
 *     To decrease the reference of the file object
 *
 * Arguments:
 *   fp:   the pointer of the file strcture
 *
 * Return Value:
 *   Zero:  in success case
 *   Non-Zero: in failure case
 *
 * Notes:
 *   N/A
 */

int fput(struct file *fp)
{
	if (InterlockedDecrement(&(fp->f_count)) == 0)
		filp_close(fp, NULL);

	return 0;
}


/*
 * file_count
 *   To query the reference count of the file object
 *
 * Arguments:
 *   fp:   the pointer of the file strcture
 *
 * Return Value:
 *   the reference count of the file object
 *
 * Notes: 
 *   N/A
 */

int file_count(struct file *fp)
{
	return (int)(fp->f_count);
}

struct dentry *dget(struct dentry *de)
{
    if (de) {
        cfs_atomic_inc(&de->d_count);
    }
    return de;
}

void dput(struct dentry *de)
{
    if (!de || cfs_atomic_read(&de->d_count) == 0) {
        return;
    }
    if (cfs_atomic_dec_and_test(&de->d_count)) {
        cfs_free(de);
    }
}
