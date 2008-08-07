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

# define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>

const CHAR *dos_file_prefix = "\\??\\";

/*
 * cfs_filp_open
 *     To open or create a file in kernel mode
 *
 * Arguments:
 *   name:  name of the file to be opened or created, no dos path prefix
 *   flags: open/creation attribute options
 *   mode:  access mode/permission to open or create
 *   err:   error code
 *
 * Return Value:
 *   the pointer to the cfs_file_t or NULL if it fails
 *
 * Notes: 
 *   N/A
 */

cfs_file_t *cfs_filp_open(const char *name, int flags, int mode, int *err)
{
    cfs_file_t *        fp = NULL;

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

    if (name[0] != '\\') {
        PrefixLength = (USHORT)strlen(dos_file_prefix);
    }

    AnsiString = cfs_alloc( sizeof(CHAR) * (NameLength + PrefixLength + 1),
                            CFS_ALLOC_ZERO);
    if (NULL == AnsiString) {
        if (err) *err = -ENOMEM;
        return NULL;
    }

    UnicodeString = cfs_alloc( sizeof(WCHAR) * (NameLength + PrefixLength + 1),
                               CFS_ALLOC_ZERO);

    if (NULL == UnicodeString) {
        if (err) *err = -ENOMEM;
        cfs_free(AnsiString);
        return NULL;
    }

    if (PrefixLength) {
        RtlCopyMemory(&AnsiString[0], dos_file_prefix , PrefixLength);
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
        *err = cfs_error_code(IoStatus.Status);
        cfs_free(UnicodeString);
        cfs_free(AnsiString);
        return NULL;
    }

    /* Allocate the cfs_file_t: libcfs file object */

    fp = cfs_alloc(sizeof(cfs_file_t) + NameLength, CFS_ALLOC_ZERO);

    if (NULL == fp) {
        Status = ZwClose(FileHandle);
        ASSERT(NT_SUCCESS(Status));
        *err = -ENOMEM;
        cfs_free(UnicodeString);
        cfs_free(AnsiString);
        return NULL;
    }

    fp->f_handle = FileHandle;
    strcpy(fp->f_name, name);
    fp->f_flags = flags;
    fp->f_mode  = (mode_t)mode;
    fp->f_count = 1;
    *err = 0;

    /* free the memory of temporary name strings */
    cfs_free(UnicodeString);
    cfs_free(AnsiString);

    return fp;
}


/*
 * cfs_filp_close
 *     To close the opened file and release the filp structure
 *
 * Arguments:
 *   fp:   the pointer of the cfs_file_t strcture
 *
 * Return Value:
 *   ZERO: on success
 *   Non-Zero: on failure
 *
 * Notes: 
 *   N/A
 */

int cfs_filp_close(cfs_file_t *fp)
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


/*
 * cfs_filp_read
 *     To read data from the opened file
 *
 * Arguments:
 *   fp:   the pointer of the cfs_file_t strcture
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

int cfs_filp_read(cfs_file_t *fp, void *buf, size_t nbytes, loff_t *pos)
{
    LARGE_INTEGER   address;
    NTSTATUS        Status;
    IO_STATUS_BLOCK IoStatus;

    int             rc = 0;

    /* Read data from the file into the specified buffer */

    if (pos != NULL) {
        address.QuadPart = *pos;
    } else {
        address.QuadPart = fp->f_pos;
    }

    Status = ZwReadFile( fp->f_handle,
                         0,
                         NULL,
                         NULL,
                         &IoStatus,
                         buf,
                         nbytes,
                         &address,
                         NULL );

    if (!NT_SUCCESS(IoStatus.Status)) {
        rc = cfs_error_code(IoStatus.Status);
    } else {
        rc = (int)IoStatus.Information;
        fp->f_pos = address.QuadPart + rc;
 
        if (pos != NULL) {
            *pos = fp->f_pos;
        }   
    }

    return rc;     
}


/*
 * cfs_filp_wrtie
 *     To write specified data to the opened file
 *
 * Arguments:
 *   fp:   the pointer of the cfs_file_t strcture
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

int cfs_filp_write(cfs_file_t *fp, void *buf, size_t nbytes, loff_t *pos)
{
    LARGE_INTEGER   address;
    NTSTATUS        Status;
    IO_STATUS_BLOCK IoStatus;
    int             rc = 0;

    /* Write user specified data into the file */

    if (pos != NULL) {
        address.QuadPart = *pos;
    } else {
        address.QuadPart = fp->f_pos;
    }

    Status = ZwWriteFile( fp->f_handle,
                         0,
                         NULL,
                         NULL,
                         &IoStatus,
                         buf,
                         nbytes,
                         &address,
                         NULL );

    if (!NT_SUCCESS(Status)) {
        rc =  cfs_error_code(Status);
    } else {
        rc = (int)IoStatus.Information;
        fp->f_pos = address.QuadPart + rc;
 
        if (pos != NULL) {
            *pos = fp->f_pos;
        }   
    }

    return rc;
}


NTSTATUS
CompletionRoutine(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    PVOID Context)
{
    /* copy the IoStatus result */
    *Irp->UserIosb = Irp->IoStatus;
    
    /* singal the event we set */
    KeSetEvent(Irp->UserEvent, 0, FALSE);
   
    /* free the Irp we allocated */
    IoFreeIrp(Irp);
    
    return STATUS_MORE_PROCESSING_REQUIRED;
}


/*
 * cfs_filp_fsync
 *     To sync the dirty data of the file to disk
 *
 * Arguments:
 *   fp: the pointer of the cfs_file_t strcture
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

int cfs_filp_fsync(cfs_file_t *fp)
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
    Irp->UserEvent = &Event;
    Irp->UserIosb = &IoSb;
    Irp->RequestorMode = KernelMode;

    Irp->Tail.Overlay.Thread = PsGetCurrentThread();
    Irp->Tail.Overlay.OriginalFileObject = FileObject;

    /* setup the Irp stack location */
    IrpSp = IoGetNextIrpStackLocation(Irp);

    IrpSp->MajorFunction = IRP_MJ_FLUSH_BUFFERS;
    IrpSp->DeviceObject = DeviceObject;
    IrpSp->FileObject = FileObject;

    IoSetCompletionRoutine(Irp, CompletionRoutine, 0, TRUE, TRUE, TRUE);


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
 * cfs_get_file
 *     To increase the reference of the file object
 *
 * Arguments:
 *   fp:   the pointer of the cfs_file_t strcture
 *
 * Return Value:
 *   Zero:  in success case
 *   Non-Zero: in failure case
 *
 * Notes: 
 *   N/A
 */

int cfs_get_file(cfs_file_t *fp)
{
    InterlockedIncrement(&(fp->f_count));
    return 0;
}


/*
 * cfs_put_file
 *     To decrease the reference of the file object
 *
 * Arguments:
 *   fp:   the pointer of the cfs_file_t strcture
 *
 * Return Value:
 *   Zero:  in success case
 *   Non-Zero: in failure case
 *
 * Notes: 
 *   N/A
 */

int cfs_put_file(cfs_file_t *fp)
{
    if (InterlockedDecrement(&(fp->f_count)) == 0) {
        cfs_filp_close(fp);
    }

    return 0;
}


/*
 * cfs_file_count
 *   To query the reference count of the file object
 *
 * Arguments:
 *   fp:   the pointer of the cfs_file_t strcture
 *
 * Return Value:
 *   the reference count of the file object
 *
 * Notes: 
 *   N/A
 */

int cfs_file_count(cfs_file_t *fp)
{
    return (int)(fp->f_count);
}
