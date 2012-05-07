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

#ifndef __KERNEL__

#include <ntddk.h>
#include <libcfs/libcfs.h>
#include <libcfs/user-bitops.h>
#include <lustre_lib.h>

/*
 * Native API definitions
 */

//
//  Disk I/O Routines
//

NTSYSAPI
NTSTATUS
NTAPI
NtReadFile(HANDLE FileHandle,
    HANDLE Event OPTIONAL,
    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    PVOID ApcContext OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset OPTIONAL,
    PULONG Key OPTIONAL);

NTSYSAPI
NTSTATUS
NTAPI
NtWriteFile(HANDLE FileHandle,
    HANDLE Event OPTIONAL,
    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    PVOID ApcContext OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset OPTIONAL,
    PULONG Key OPTIONAL);

NTSYSAPI
NTSTATUS
NTAPI
NtClose(HANDLE Handle);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateFile(PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize OPTIONAL,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer OPTIONAL,
    ULONG EaLength);


NTSYSAPI
NTSTATUS
NTAPI
NtDeviceIoControlFile(
    IN HANDLE  FileHandle,
    IN HANDLE  Event,
    IN PIO_APC_ROUTINE  ApcRoutine,
    IN PVOID  ApcContext,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    IN ULONG  IoControlCode,
    IN PVOID  InputBuffer,
    IN ULONG  InputBufferLength,
    OUT PVOID  OutputBuffer,
    OUT ULONG  OutputBufferLength
    ); 

NTSYSAPI
NTSTATUS
NTAPI
NtFsControlFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG FsControlCode,
    IN PVOID InputBuffer OPTIONAL,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputBufferLength
);


NTSYSAPI
NTSTATUS
NTAPI
NtQueryInformationFile(
    IN HANDLE  FileHandle,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    OUT PVOID  FileInformation,
    IN ULONG  Length,
    IN FILE_INFORMATION_CLASS  FileInformationClass
    );

//
// Random routines ...
//

NTSYSAPI
ULONG
NTAPI
RtlRandom(
    IN OUT PULONG  Seed
    ); 

/*
 * Time routines ...
 */

NTSYSAPI
CCHAR
NTAPI
NtQuerySystemTime(
    OUT PLARGE_INTEGER  CurrentTime
    );


NTSYSAPI
BOOLEAN
NTAPI
RtlTimeToSecondsSince1970(
    IN PLARGE_INTEGER  Time,
    OUT PULONG  ElapsedSeconds
    );


NTSYSAPI
VOID
NTAPI
RtlSecondsSince1970ToTime(
    IN ULONG  ElapsedSeconds,
    OUT PLARGE_INTEGER  Time
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwDelayExecution(
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Interval
);


int nanosleep(const struct timespec *rqtp, struct timespec *rmtp)
{
    NTSTATUS status;
    LARGE_INTEGER Interval;
    Interval.QuadPart = rqtp->tv_sec * 10000000 + rqtp->tv_nsec / 100;
    status = ZwDelayExecution(TRUE, &Interval);
    if (rmtp) {
        rmtp->tv_sec = 0;
        rmtp->tv_nsec = 0;
    }
    if (status == STATUS_ALERTED || status == STATUS_USER_APC) {
       return -1;
    }
    return 0;
}


void cfs_gettimeofday(struct timeval *tv)
{
    LARGE_INTEGER Time;

    NtQuerySystemTime(&Time);

    tv->tv_sec  = (long_ptr_t)  (Time.QuadPart / 10000000);
    tv->tv_usec = (suseconds_t) (Time.QuadPart % 10000000) / 10;
}

int gettimeofday(struct timeval *tv, void * tz)
{
    cfs_gettimeofday(tv);
    return 0;
}

/*
 * proc process routines of user space
 */

struct idr_context *cfs_proc_idp = NULL;

int cfs_proc_open (char * filename, int oflag)
{
    NTSTATUS            status;
    IO_STATUS_BLOCK     iosb;
    int                 rc = 0;

    HANDLE              Handle = INVALID_HANDLE_VALUE;
    OBJECT_ATTRIBUTES   ObjectAttributes;
    ACCESS_MASK         DesiredAccess;
    ULONG               CreateDisposition;
    ULONG               ShareAccess;
    ULONG               CreateOptions;
    UNICODE_STRING      UnicodeName;
    USHORT              NameLength;

    PFILE_FULL_EA_INFORMATION Ea = NULL;
    ULONG               EaLength;
    PUCHAR              EaBuffer = NULL;

    /* Check the filename: should start with "/proc" or "/dev" */
    NameLength = (USHORT)strlen(filename);
    if (NameLength > 0x05) {
        if (_strnicmp(filename, "/proc/", 6) == 0) {
            if (NameLength <= 6) {
                rc = -EINVAL;
                goto errorout;
            }
        } else if (_strnicmp(filename, "/dev/", 5) == 0) {
        } else {
            rc = -EINVAL;
            goto errorout;
        }
    } else {
        rc = -EINVAL;
        goto errorout;
    }

    /* Analyze the flags settings */

    if (cfs_is_flag_set(oflag, O_WRONLY)) {
        DesiredAccess = (GENERIC_WRITE | SYNCHRONIZE);
        ShareAccess = 0;
    }  else if (cfs_is_flag_set(oflag, O_RDWR)) {
        DesiredAccess = (GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE);
        ShareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE;
    } else {
        DesiredAccess = (GENERIC_READ | SYNCHRONIZE);
        ShareAccess = FILE_SHARE_READ;
    }

    if (cfs_is_flag_set(oflag, O_CREAT)) {
        if (cfs_is_flag_set(oflag, O_EXCL)) {
            CreateDisposition = FILE_CREATE;
            rc = -EINVAL;
            goto errorout;
        } else {
            CreateDisposition = FILE_OPEN_IF;
        }
    } else {
        CreateDisposition = FILE_OPEN;
    }

    if (cfs_is_flag_set(oflag, O_TRUNC)) {
        if (cfs_is_flag_set(oflag, O_EXCL)) {
            CreateDisposition = FILE_OVERWRITE;
        } else {
            CreateDisposition = FILE_OVERWRITE_IF;
        }
    }

    CreateOptions = 0;

    if (cfs_is_flag_set(oflag, O_DIRECTORY)) {
        cfs_set_flag(CreateOptions,  FILE_DIRECTORY_FILE);
    }

    if (cfs_is_flag_set(oflag, O_SYNC)) {
         cfs_set_flag(CreateOptions, FILE_WRITE_THROUGH);
    }

    if (cfs_is_flag_set(oflag, O_DIRECT)) {
         cfs_set_flag(CreateOptions, FILE_NO_INTERMEDIATE_BUFFERING);
    }

    /* Initialize the unicode path name for the specified file */
    RtlInitUnicodeString(&UnicodeName, LUSTRE_PROC_SYMLNK);

    /* Setup the object attributes structure for the file. */
    InitializeObjectAttributes(
            &ObjectAttributes,
            &UnicodeName,
            OBJ_CASE_INSENSITIVE,
            NULL,
            NULL );

    /* building EA for the proc entry ...  */
    EaBuffer = malloc(NameLength + sizeof(FILE_FULL_EA_INFORMATION));
    if (!EaBuffer) {
        rc = -ENOMEM;
        goto errorout;
    }
    memset(EaBuffer, 0, NameLength + sizeof(FILE_FULL_EA_INFORMATION));
    Ea = (PFILE_FULL_EA_INFORMATION)EaBuffer;
    Ea->NextEntryOffset = 0;
    Ea->Flags = 0;
    Ea->EaNameLength = (UCHAR)NameLength;
    Ea->EaValueLength = 0;
    RtlCopyMemory(
        &(Ea->EaName),
        filename,
        NameLength + 1
        );
    EaLength =	sizeof(FILE_FULL_EA_INFORMATION) - 1 +
				Ea->EaNameLength + 1;

    /* Now to open or create the file now */
    status = NtCreateFile(
                &Handle,
                DesiredAccess,
                &ObjectAttributes,
                &iosb,
                0,
                FILE_ATTRIBUTE_NORMAL,
                ShareAccess,
                CreateDisposition,
                CreateOptions,
                Ea,
                EaLength );

    /* Check the returned status of Iosb ... */

    if (!NT_SUCCESS(status)) {
        rc = cfs_error_code(status);
        goto errorout;
    }

errorout:

    if (Handle) {
        rc = cfs_idr_get_new(cfs_proc_idp, Handle);
        if (rc < 0) {
            NtClose(Handle);
        }
    }

    if (EaBuffer) {
        free(EaBuffer);
    }

    return rc;
}

int cfs_proc_close(int fd)
{
    HANDLE handle = cfs_idr_find(cfs_proc_idp, fd);

    if (handle) {
        NtClose(handle);
    }

    cfs_idr_remove(cfs_proc_idp, fd);

    return 0;
}

int cfs_proc_read_internal(
    int fd, void *buffer,
    unsigned int count,
    unsigned int offlow,
    unsigned int offhigh
    )
{
    NTSTATUS            status;
    IO_STATUS_BLOCK     iosb;
    LARGE_INTEGER       offset;

    HANDLE handle = cfs_idr_find(cfs_proc_idp, fd);
    offset.HighPart = offhigh;
    offset.LowPart  = offlow;

    /* read file data */
    status = NtReadFile(
                handle,
                0,
                NULL,
                NULL,
                &iosb,
                buffer,
                count,
                &offset,
                NULL);                     

    /* check the return status */
    if (!NT_SUCCESS(status)) {
        printf("NtReadFile request failed with status: 0x%0x\n", status);
        goto errorout;
    }

errorout:

    if (NT_SUCCESS(status)) {
        return (int)(iosb.Information);
    }

    return cfs_error_code(status);
}

int cfs_proc_read(
    int fd, void *buffer,
    unsigned int count
    )
{
    return cfs_proc_read_internal(fd, buffer, count, 0, 0);
}

int cfs_proc_write_internal(
    int fd, void *buffer,
    unsigned int count,
    unsigned int offlow,
    unsigned int offhigh
    )
{
    NTSTATUS            status;
    IO_STATUS_BLOCK     iosb;
    LARGE_INTEGER       offset;

    HANDLE handle = cfs_idr_find(cfs_proc_idp, fd);
    offset.HighPart = offhigh;
    offset.LowPart = offlow;

    /* write buffer to the opened file */
    status = NtWriteFile(
                handle,
                0,
                NULL,
                NULL,
                &iosb,
                buffer,
                count,
                &offset,
                NULL);                     

    /* check the return status */
    if (!NT_SUCCESS(status)) {
        printf("NtWriteFile request failed 0x%0x\n", status);
        goto errorout;
    }

errorout:

    if (NT_SUCCESS(status)) {
        return (int)(iosb.Information);
    }

    return cfs_error_code(status);
}

int cfs_proc_write(
    int fd, void *buffer,
    unsigned int count
    )
{
    return cfs_proc_write_internal(fd, buffer, count, 0, 0);
}

int cfs_proc_ioctl(int fd, int cmd, void *buffer)
{
    PUCHAR          procdat = NULL;
    CFS_PROC_IOCTL  procctl;
    ULONG           length = 0;
    ULONG           extra = 0;
    int             rc = 0;

    NTSTATUS        status = STATUS_UNSUCCESSFUL;
    IO_STATUS_BLOCK iosb;

    struct libcfs_ioctl_data * portal = buffer;
    struct obd_ioctl_data * obd = buffer;
    struct obd_ioctl_data * data;

    HANDLE handle = cfs_idr_find(cfs_proc_idp, fd);
#if defined(_X86_)
    CLASSERT(sizeof(struct obd_ioctl_data) == 528);
#else
    CLASSERT(sizeof(struct obd_ioctl_data) == 576);
#endif
    memset(&procctl, 0, sizeof(CFS_PROC_IOCTL));
    procctl.cmd = cmd;

    if(_IOC_TYPE(cmd) == IOC_LIBCFS_TYPE) {
        length = portal->ioc_len;
    } else if (_IOC_TYPE(cmd) == 'f') {
        length = obd->ioc_len;
        extra = cfs_size_round(obd->ioc_plen1) + cfs_size_round(obd->ioc_plen2);
    } else if(_IOC_TYPE(cmd) == 'u') {
        length = 4;
        extra  = 0;
    } else if(_IOC_TYPE(cmd) == 'i') {
        length = obd->ioc_len;
        extra  = 0;
    } else {
        printf("cfs_proc_ioctl: un-supported ioctl type ...\n");
        cfs_enter_debugger();
        status = STATUS_INVALID_PARAMETER;
        goto errorout;
    }

    procctl.len = length + extra;
    procdat = malloc(length + extra + sizeof(CFS_PROC_IOCTL));

    if (NULL == procdat) {
        printf("user:winnt-proc:cfs_proc_ioctl: no enough memory ...\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        cfs_enter_debugger();
        goto errorout;
    }
    memset(procdat, 0, length + extra + sizeof(CFS_PROC_IOCTL));
    memcpy(procdat, &procctl, sizeof(CFS_PROC_IOCTL));
    memcpy(&procdat[sizeof(CFS_PROC_IOCTL)], buffer, length);
    length += sizeof(CFS_PROC_IOCTL);

    if (_IOC_TYPE(cmd) == 'f') {

        data  = (struct obd_ioctl_data *) (procdat + sizeof(CFS_PROC_IOCTL));
        if ( cmd != (ULONG)OBD_IOC_BRW_WRITE  &&
             cmd != (ULONG)OBD_IOC_BRW_READ ) {

            if (obd->ioc_pbuf1 && data->ioc_plen1) {
                data->ioc_pbuf1 = &procdat[length];
                memcpy(data->ioc_pbuf1, obd->ioc_pbuf1, obd->ioc_plen1); 
                length += cfs_size_round(obd->ioc_plen1);
            } else {
                data->ioc_plen1 = 0;
                data->ioc_pbuf1 = NULL;
            }

            if (obd->ioc_pbuf2 && obd->ioc_plen2) {
                data->ioc_pbuf2 = &procdat[length];
                memcpy(data->ioc_pbuf2, obd->ioc_pbuf2, obd->ioc_plen2);
                length += cfs_size_round(obd->ioc_plen2);
            } else {
                data->ioc_plen2 = 0;
                data->ioc_pbuf2 = NULL;
            }
		} else {
             extra = 0;
        }

        ASSERT(length == extra + sizeof(CFS_PROC_IOCTL) + data->ioc_len);
        if (obd_ioctl_is_invalid(obd)) {
            cfs_enter_debugger();
        }
    }

    status = NtDeviceIoControlFile(
                handle, NULL, NULL,
                NULL, &iosb,
                IOCTL_LIBCFS_ENTRY,
                procdat, length,
                procdat, length );


    if (_IOC_TYPE(cmd) == 'f') {

        length = sizeof(CFS_PROC_IOCTL);
        ASSERT(data  == (struct obd_ioctl_data *) (procdat + sizeof(CFS_PROC_IOCTL)));
		if ( cmd != (ULONG)OBD_IOC_BRW_WRITE  &&
             cmd != (ULONG)OBD_IOC_BRW_READ ) {

            if (obd->ioc_pbuf1) {
                ASSERT(obd->ioc_plen1 == data->ioc_plen1);
                data->ioc_pbuf1 = &procdat[length];
                memcpy(obd->ioc_pbuf1, data->ioc_pbuf1, obd->ioc_plen1);
                length += cfs_size_round(obd->ioc_plen1);
            }
            if (obd->ioc_pbuf2) {
                ASSERT(obd->ioc_plen2 == data->ioc_plen2);
                data->ioc_pbuf2 = &procdat[length];
                memcpy(obd->ioc_pbuf2, data->ioc_pbuf2, obd->ioc_plen2);
                length += cfs_size_round(obd->ioc_plen2);
            }
        }
        data->ioc_inlbuf1 = obd->ioc_inlbuf1;
        data->ioc_inlbuf2 = obd->ioc_inlbuf2;
        data->ioc_inlbuf3 = obd->ioc_inlbuf3;
        data->ioc_inlbuf4 = obd->ioc_inlbuf4;
        data->ioc_pbuf1   = obd->ioc_pbuf1;
        data->ioc_pbuf2   = obd->ioc_pbuf2;
        memcpy(obd, data, obd->ioc_len);

    } else {

        memcpy(buffer, &procdat[sizeof(CFS_PROC_IOCTL)], procctl.len); 
    }

errorout:

    if (STATUS_SUCCESS == status) {
        rc = ((CFS_PROC_IOCTL *)procdat)->rc;
    } else {
        rc = cfs_error_code(status);
    }

    if (procdat) {
        free(procdat);
    }

    return rc;
}


int cfs_proc_mknod(const char *path, mode_t mode, dev_t dev)
{
    return 0;
}

FILE *cfs_proc_fopen(char *path, char * mode)
{
    int fp = cfs_proc_open(path, O_RDWR);
    if (fp > 0) {
        return (FILE *)(LONG_PTR)fp;
    }

    return NULL;
}

char *cfs_proc_fgets(char * buf, int len, FILE *fp)
{
    int rc = 0;

    if (fp == NULL) {
        return NULL;
    }

    rc = cfs_proc_read_internal((int)(LONG_PTR)fp,
                                buf, len, -1, 1);
    if (rc <= 0) {
        return NULL;
    }

    return buf;
}

int cfs_proc_fclose(FILE *fp)
{
    if (fp == NULL) {
        return -1;
    }

    return cfs_proc_close((int)(LONG_PTR)fp);
}

void cfs_libc_init();

int
libcfs_arch_init(void)
{
    cfs_libc_init();
    cfs_proc_idp = cfs_idr_init();

    if (cfs_proc_idp) {
        return 0;
    }

    return -ENOMEM;
}

void
libcfs_arch_cleanup(void)
{
    if (cfs_proc_idp) {
        cfs_idr_exit(cfs_proc_idp);
        cfs_proc_idp = NULL;
    }
}

#endif /* __KERNEL__ */
