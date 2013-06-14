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

#define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>
#include <lnet/lnet.h>

#define TDILND_MODULE_NAME L"tdilnd"

ks_tdi_data_t ks_data;

VOID
KsDumpPrint(PCHAR buffer, ULONG length)
{
    ULONG i;
    for (i=0; i < length; i++) {
        if (((i+1) % 31) == 0)
            printk("\n");
        printk("%2.2x ", (UCHAR)buffer[i]);
    }
    printk("\n");
}

PVOID
KsMapMdlBuffer (PMDL    Mdl);

VOID
KsDumpMdlChain(PMDL Mdl, ULONG length)
{
    PMDL mdl = Mdl;
    PCHAR buffer = NULL;
    ULONG len = 0;
    int i = 0;

    while (mdl) {
        printk("mdl %d:\n", i);
        buffer = KsMapMdlBuffer(mdl);
        KsDumpPrint(buffer, mdl->ByteCount);
        len += mdl->ByteCount;
        mdl = mdl->Next;
    }
    ASSERT(len == length);
}

/*
 * KsLockUserBuffer
 *   Allocate MDL for the buffer and lock the pages into
 *   nonpaged pool
 *
 * Arguments:
 *   UserBuffer:  the user buffer to be locked
 *   Length:      length in bytes of the buffer
 *   Operation:   read or write access
 *   pMdl:        the result of the created mdl
 *
 * Return Value:
 *   NTSTATUS:     kernel status code (STATUS_SUCCESS
 *                 or other error code)
 *
 * NOTES:
 *   N/A
 */

NTSTATUS
KsLockUserBuffer (
    IN PVOID            UserBuffer,
    IN BOOLEAN          bPaged,
    IN ULONG            Length,
    IN LOCK_OPERATION   Operation,
    OUT PMDL *          pMdl
    )
{
    NTSTATUS    Status;
    PMDL        Mdl = NULL;

    LASSERT(UserBuffer != NULL);

    *pMdl = NULL;

    Mdl = IoAllocateMdl(
                UserBuffer,
                Length,
                FALSE,
                FALSE,
                NULL
                );

    if (Mdl == NULL) {

        Status = STATUS_INSUFFICIENT_RESOURCES;

    } else {

        __try {

            if (bPaged) {
                MmProbeAndLockPages(
                    Mdl,
                    KernelMode,
                    Operation
                    );
            } else {
                MmBuildMdlForNonPagedPool(
                    Mdl
                    );
            }

            Status = STATUS_SUCCESS;

            *pMdl = Mdl;

        } __except (EXCEPTION_EXECUTE_HANDLER) {

            IoFreeMdl(Mdl);

            Mdl = NULL;

            cfs_enter_debugger();

            Status = STATUS_INVALID_USER_BUFFER;
        }
    }

    return Status;
}

/*
 * KsMapMdlBuffer
 *   Map the mdl into a buffer in kernel space
 *
 * Arguments:
 *   Mdl:  the mdl to be mapped
 *
 * Return Value:
 *   PVOID: the buffer mapped or NULL in failure
 *
 * NOTES:
 *   N/A
 */

PVOID
KsMapMdlBuffer (PMDL    Mdl)
{
    LASSERT(Mdl != NULL);

    return MmGetSystemAddressForMdlSafe(
                Mdl,
                NormalPagePriority
                );
}


/*
 * KsReleaseMdl
 *   Unlock all the pages in the mdl
 *
 * Arguments:
 *   Mdl:  memory description list to be released
 *
 * Return Value:
 *   N/A
 *
 * NOTES:
 *   N/A
 */

VOID
KsReleaseMdl (IN PMDL   Mdl,
              IN int    Paged )
{
    LASSERT(Mdl != NULL);

    while (Mdl) {

        PMDL    Next;

        Next = Mdl->Next;

        if (Paged) {
            MmUnlockPages(Mdl);
        }

        IoFreeMdl(Mdl);

        Mdl = Next;
    }
}

/*
 * KsQueryMdlsSize
 *   Query the whole size of a MDL (may be chained)
 *
 * Arguments:
 *   Mdl:  the Mdl to be queried
 *
 * Return Value:
 *   ULONG: the total size of the mdl
 *
 * NOTES:
 *   N/A
 */

ULONG
KsQueryMdlsSize (PMDL Mdl)
{
    PMDL    Next = Mdl;
    ULONG   Length = 0;


    //
    // Walking the MDL Chain ...
    //

    while (Next) {
        Length += MmGetMdlByteCount(Next);
        Next = Next->Next;
    }

    return (Length);
}

/*
 * KsCopyMdlToBuffer
 *   Copy payload from  Mdl to buffer
 *
 * Arguments:
 *   SourceMdl: the source mdl
 *   SourceOffset: start offset of the source
 *   DestinationBuffer: the dst buffer
 *   DestinationOffset: the offset where data are to be copied.
 *   BytesTobecopied: the expteced bytes to be copied
 *
 * Return Value:
 *   Length of data copied from MDL to user buffer
 *
 * NOTES:
 *   N/A
 */

ULONG
KsCopyMdlToBuffer(
    IN PMDL     SourceMdl,
    IN ULONG    SourceOffset,
    IN PVOID    DestinationBuffer,
    IN ULONG    DestinationOffset,
    IN ULONG    BytesTobeCopied
    )
{
    PUCHAR      SourceBuffer = NULL;
    PUCHAR      TargetBuffer = DestinationBuffer;
    ULONG       BytesCopied = 0;

    if (MmGetMdlByteCount(SourceMdl) <= SourceOffset) {
        return 0;
    }

    BytesCopied = MmGetMdlByteCount(SourceMdl) - SourceOffset;
    if (BytesCopied > BytesTobeCopied) {
        BytesCopied = BytesTobeCopied;
    }

    SourceBuffer = (PUCHAR)KsMapMdlBuffer(SourceMdl);

    RtlMoveMemory(TargetBuffer + DestinationOffset,
                  SourceBuffer + SourceOffset, BytesCopied);

   return BytesCopied;
}

/*
 * KsInitializeKsTsdu
 *   Initialize the Tsdu buffer header
 *
 * Arguments:
 *   KsTsdu: the Tsdu to be initialized
 *   Length: the total length of the Tsdu
 *
 * Return Value:
 *   VOID
 *
 * NOTES:
 *   N/A
 */

VOID
KsInitializeKsTsdu(
    PKS_TSDU    KsTsdu,
    ULONG       Length
    )
{
    KsTsdu->Magic = KS_TSDU_MAGIC;
    KsTsdu->TotalLength = Length;
    KsTsdu->StartOffset = KsTsdu->LastOffset =
    KS_QWORD_ALIGN(sizeof(KS_TSDU));
}

/*
 * KsAllocateKsTsdu
 *   Reuse a Tsdu from the freelist or allocate a new Tsdu
 *   from the LookAsideList table or the NonPagedPool
 *
 * Arguments:
 *   N/A
 *
 * Return Value:
 *   PKS_Tsdu: the new Tsdu or NULL if it fails
 *
 * Notes:
 *   N/A
 */

PKS_TSDU
KsAllocateKsTsdu()
{
    PKS_TSDU    KsTsdu = NULL;

	spin_lock(&(ks_data.ksnd_tsdu_lock));

    if (!cfs_list_empty (&(ks_data.ksnd_freetsdus))) {

        LASSERT(ks_data.ksnd_nfreetsdus > 0);

        KsTsdu = cfs_list_entry(ks_data.ksnd_freetsdus.next, KS_TSDU, Link);
        cfs_list_del(&(KsTsdu->Link));
        ks_data.ksnd_nfreetsdus--;

    } else {

        KsTsdu = (PKS_TSDU) cfs_mem_cache_alloc(
                        ks_data.ksnd_tsdu_slab, 0);
    }

	spin_unlock(&(ks_data.ksnd_tsdu_lock));

    if (NULL != KsTsdu) {
        RtlZeroMemory(KsTsdu, ks_data.ksnd_tsdu_size);
        KsInitializeKsTsdu(KsTsdu, (ULONG)ks_data.ksnd_tsdu_size);
    }

    return (KsTsdu);
}

/*
 * KsFreeKsTsdu
 *   Release a Tsdu: uninitialize then free it.
 *
 * Arguments:
 *   KsTsdu: Tsdu to be freed.
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

VOID
KsFreeKsTsdu(
    PKS_TSDU  KsTsdu
    )
{
    cfs_mem_cache_free(
            ks_data.ksnd_tsdu_slab,
            KsTsdu );
}

/*
 * KsPutKsTsdu
 *   Move the Tsdu to the free tsdu list in ks_data.
 *
 * Arguments:
 *   KsTsdu: Tsdu to be moved.
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

VOID
KsPutKsTsdu(
    PKS_TSDU  KsTsdu
    )
{
	spin_lock(&(ks_data.ksnd_tsdu_lock));
	if (ks_data.ksnd_nfreetsdus > 128) {
		KsFreeKsTsdu(KsTsdu);
	} else {
		cfs_list_add_tail( &(KsTsdu->Link), &(ks_data.ksnd_freetsdus));
		ks_data.ksnd_nfreetsdus++;
	}
	spin_unlock(&(ks_data.ksnd_tsdu_lock));
}

/* with tconn lock acquired */
ks_mdl_t *
KsLockTsdus(
    ks_tconn_t *    tconn,
    PKS_TSDUMGR     TsduMgr,
    PULONG          Flags,
    PULONG          Length
    )
{
 
    ks_mdl_t *      mdl = NULL;
    ks_mdl_t *      tail = NULL;

    PKS_TSDU        KsTsdu;
    PKS_TSDU_DAT    KsTsduDat;
    PKS_TSDU_BUF    KsTsduBuf;
    PKS_TSDU_MDL    KsTsduMdl;

    *Length  = 0;

    cfs_list_for_each_entry_typed(KsTsdu,
            &TsduMgr->TsduList,KS_TSDU, Link) {

        ULONG   start = 0;

        LASSERT(KsTsdu->Magic == KS_TSDU_MAGIC);
        start = KsTsdu->StartOffset;

        while (start < KsTsdu->LastOffset) {

            ks_mdl_t *  iov = NULL;

            KsTsduDat = (PKS_TSDU_DAT)((PUCHAR)KsTsdu + start);
            KsTsduBuf = (PKS_TSDU_BUF)((PUCHAR)KsTsdu + start);
            KsTsduMdl = (PKS_TSDU_MDL)((PUCHAR)KsTsdu + start);
            LASSERT(KsTsduDat->TsduType == TSDU_TYPE_DAT ||
                    KsTsduBuf->TsduType == TSDU_TYPE_BUF ||
                    KsTsduMdl->TsduType == TSDU_TYPE_MDL);

            if (TSDU_TYPE_DAT == KsTsduDat->TsduType) {

                ASSERT(KsTsdu->LastOffset >= start + KsTsduDat->TotalLength);
                if (KsTsduDat->Mdl) {
                    iov = KsTsduDat->Mdl;
                } else {
                    KsLockUserBuffer(
                        &KsTsduDat->Data[KsTsduDat->StartOffset],
                        FALSE,
                        KsTsduDat->DataLength,
                        IoReadAccess,
                        &iov );
                    KsTsduDat->Mdl = iov;
                }
/*
                printk("KsLockTsdus: %u\n", KsTsduDat->DataLength);
                KsDumpPrint(
                        &KsTsduDat->Data[KsTsduDat->StartOffset],
                        KsTsduDat->DataLength);
*/                        
                *Length += KsTsduDat->DataLength;
                start += KsTsduDat->TotalLength;

            } else if (TSDU_TYPE_BUF == KsTsduBuf->TsduType) {

                ASSERT(KsTsdu->LastOffset >= start + sizeof(KS_TSDU_BUF));
                if (KsTsduBuf->Mdl) {
                    iov = KsTsduBuf->Mdl;
                } else {
                    KsLockUserBuffer(
                        (PUCHAR)KsTsduBuf->UserBuffer + 
                                 KsTsduBuf->StartOffset,
                        FALSE,
                        KsTsduBuf->DataLength,
                        IoReadAccess,
                        &iov );
                    KsTsduBuf->Mdl = iov;
                }

                *Length += KsTsduBuf->DataLength;
                start += sizeof(KS_TSDU_BUF);

            } else {

                LASSERT(TSDU_TYPE_MDL == KsTsduMdl->TsduType);
                ASSERT(KsTsdu->LastOffset >= start + sizeof(KS_TSDU_MDL));
                iov = KsTsduMdl->Mdl; 
                *Length += KsTsduMdl->DataLength;
                start += sizeof(KS_TSDU_MDL);
            }

            if (!iov) {
                cfs_enter_debugger();
                goto cleanup;
            }

            if (tail) {
                tail->Next = iov;
            } else {
                mdl = iov;
            }
            tail = iov;
            tail->Next = NULL;
/*
            printk("KsLockTsdus: mdl %d\n", tail->ByteCount);
            KsDumpMdlChain(tail, tail->ByteCount);
*/
        }
    }
#if 0
    if (Flags) {
        *Flags = TsduFlags;
    }
#endif
    return mdl;

cleanup:
    
    *Length = 0;
    return NULL;
}

ks_mdl_t *
KsSplitMdl(
    IN ks_mdl_t *   master,
    IN ULONG        offset,
    IN ULONG        length
    )
{
    ks_mdl_t *  mdl = NULL;
    char *      ptr = NULL;

    /* calculate the start virtual address */
    ptr = (char *)KsMapMdlBuffer(master) + offset;

    /* allocate new mdl for new memory range */
    mdl = IoAllocateMdl(ptr, length, FALSE, FALSE, NULL);

    if (!mdl) {
        return NULL;
    }
            
    /* initialize the mdl */
    IoBuildPartialMdl(master, mdl, (PVOID)ptr, length);

    return mdl;
}

/* with tconn lock acquired */
VOID
KsReleaseTsdus(
    ks_tconn_t *        tconn,
    PKS_TSDUMGR         TsduMgr,
    ULONG               length
    )
{
    PKS_TSDU        KsTsdu;
    PKS_TSDU_DAT    KsTsduDat;
    PKS_TSDU_BUF    KsTsduBuf;
    PKS_TSDU_MDL    KsTsduMdl;
#if DBG    
    ULONG           total = TsduMgr->TotalBytes;
    ULONG           size = length;
#endif

    LASSERT(TsduMgr->TotalBytes >= length);

    while (!cfs_list_empty(&TsduMgr->TsduList)) {

        ULONG   start = 0;

        KsTsdu = cfs_list_entry(TsduMgr->TsduList.next, KS_TSDU, Link);
        LASSERT(KsTsdu->Magic == KS_TSDU_MAGIC);
        start = KsTsdu->StartOffset;

        while (length > 0 && start < KsTsdu->LastOffset) {

            ULONG           size = 0;
            ks_mdl_t *      mdl = NULL;

            KsTsduDat = (PKS_TSDU_DAT)((PUCHAR)KsTsdu + start);
            KsTsduBuf = (PKS_TSDU_BUF)((PUCHAR)KsTsdu + start);
            KsTsduMdl = (PKS_TSDU_MDL)((PUCHAR)KsTsdu + start);
            LASSERT(KsTsduDat->TsduType == TSDU_TYPE_DAT ||
                    KsTsduBuf->TsduType == TSDU_TYPE_BUF ||
                    KsTsduMdl->TsduType == TSDU_TYPE_MDL);

            if (TSDU_TYPE_DAT == KsTsduDat->TsduType) {

                ASSERT(KsTsdu->LastOffset >= start + KsTsduDat->DataLength);
                if (length >= KsTsduDat->DataLength) {
                    /* whole tsdu is sent out */
                    size = KsTsduDat->DataLength;
                    start += KsTsduDat->TotalLength;
                } else {
                    size = length;
                    KsTsduDat->StartOffset += size;
                }

                if (KsTsduDat->Mdl) {
                    mdl = KsTsduDat->Mdl;
                    KsTsduDat->Mdl = NULL;
                }

                KsTsduDat->DataLength -= size;

            } else if (TSDU_TYPE_BUF == KsTsduBuf->TsduType) {

                ASSERT(KsTsdu->LastOffset >= start + sizeof(KS_TSDU_BUF));
                if (length >= KsTsduBuf->DataLength) {
                    /* whole tsdu is sent out */
                    size = KsTsduBuf->DataLength;
                    start += sizeof(KS_TSDU_BUF);
                    LASSERT(KsTsduBuf->UserBuffer);
                    ExFreePool(KsTsduBuf->UserBuffer);
                    KsTsduBuf->UserBuffer = NULL;
                } else {
                    KsTsduBuf->StartOffset += length;
                    size = length;
                }

                if (KsTsduBuf->Mdl) {
                    mdl = KsTsduBuf->Mdl;
                    KsTsduBuf->Mdl = NULL;
                }

                KsTsduBuf->DataLength -= size;
                
            } else {

                LASSERT(TSDU_TYPE_MDL == KsTsduMdl->TsduType);
                ASSERT(KsTsdu->LastOffset >= start + sizeof(KS_TSDU_MDL));
                mdl = KsTsduMdl->Mdl;
                if (length >= KsTsduMdl->DataLength) {
                    /* whole mdl is sent out */
                    size = KsTsduMdl->DataLength;
                    start += sizeof(KS_TSDU_MDL);
                    KsTsduMdl->Mdl = NULL;
                } else {
                    /* now split the remained data out */
                    ks_mdl_t * mdl1 = KsSplitMdl(mdl, length,
                                  KsTsduMdl->DataLength - length);
                    if (NULL == mdl1) {
                        mdl->ByteOffset += length;
                        mdl = NULL;
                    } else {
                        KsTsduMdl->Mdl = mdl1;
                    }
                    size = length;
                    KsTsduMdl->StartOffset += size;
                }

                KsTsduMdl->DataLength -= size;
            }

            length -= size;
            TsduMgr->TotalBytes -= size;

            if (mdl) {
                mdl->Next = NULL;
                KsReleaseMdl(mdl, FALSE);
            }

            KsTsdu->StartOffset = start;
        }

        if (KsTsdu->StartOffset >= KsTsdu->LastOffset) {

            /* remove KsTsdu from list */
            cfs_list_del(&KsTsdu->Link);
            TsduMgr->NumOfTsdu--;
            KsPutKsTsdu(KsTsdu);
        }

        if (length == 0) {
            break;
        }
    }

    LASSERT(length == 0);
#if DBG
    LASSERT(total - size == TsduMgr->TotalBytes);
    KsPrint((4, "KsReleaseTsdus: TsduMgr=%p Remained=%xh (%xh)\n",
                TsduMgr, TsduMgr->TotalBytes, size ));
#endif
}

PKS_TSDUMGR
KsQueryTsduMgr(
    ks_tconn_t *    tconn,
    BOOLEAN         expedited,
    BOOLEAN         sending
    )
{

    PKS_CHAIN           KsChain;
    PKS_TSDUMGR         TsduMgr;

    /* get the latest Tsdu buffer form TsduMgr list.
       just set NULL if the list is empty. */

    if (sending) {
        if (tconn->kstc_type == kstt_sender) {
            KsChain = &(tconn->sender.kstc_send);
        } else {
            LASSERT(tconn->kstc_type == kstt_child);
            KsChain = &(tconn->child.kstc_send);
        }
    } else {
        if (tconn->kstc_type == kstt_sender) {
            KsChain = &(tconn->sender.kstc_recv);
        } else {
            LASSERT(tconn->kstc_type == kstt_child);
            KsChain = &(tconn->child.kstc_recv);
        }
    }

    if (expedited) {
        TsduMgr = &(KsChain->Expedited);
    } else {
        TsduMgr = &(KsChain->Normal);
    }

    return TsduMgr;
}

PKS_TSDU
KsGetTsdu(PKS_TSDUMGR TsduMgr, ULONG Length)
{
    PKS_TSDU KsTsdu = NULL;

    /* retrieve the latest Tsdu buffer form TsduMgr
       list if the list is not empty. */

    if (cfs_list_empty(&(TsduMgr->TsduList))) {

        LASSERT(TsduMgr->NumOfTsdu == 0);
        KsTsdu = NULL;

    } else {

        LASSERT(TsduMgr->NumOfTsdu > 0);
        KsTsdu = cfs_list_entry(TsduMgr->TsduList.prev, KS_TSDU, Link);

        /* if this Tsdu does not contain enough space, we need
           allocate a new Tsdu queue. */

        if (KsTsdu->LastOffset + Length > KsTsdu->TotalLength) {
            KsTsdu = NULL;
        }
    }

    /* allocate a new Tsdu in case we are not statisfied. */
    if (NULL == KsTsdu) {
        KsTsdu = KsAllocateKsTsdu();
        if (NULL != KsTsdu) {
            cfs_list_add_tail(&(KsTsdu->Link), &(TsduMgr->TsduList));
            TsduMgr->NumOfTsdu++;
        }
    }

    return KsTsdu;
}

ULONG
KsWriteTsduDat(
    PKS_TSDUMGR TsduMgr,
    PCHAR       buffer,
    ULONG       length,
    ULONG       flags
    )
{
    PKS_TSDU            KsTsdu;
    PKS_TSDU_DAT        KsTsduDat;
    PKS_TSDU_BUF        KsTsduBuf;

    BOOLEAN             bNewBuff = FALSE;
    PCHAR               Buffer = NULL;

/*
    printk("KsWriteTsduDat: %u\n", length);
    KsDumpPrint(buffer, length);
*/
    /* if the Tsdu is even larger than the biggest Tsdu, we have
       to allocate new buffer and use TSDU_TYPE_BUF to store it */

    if ( KS_TSDU_STRU_SIZE(length) > ks_data.ksnd_tsdu_size -
         KS_QWORD_ALIGN(sizeof(KS_TSDU))) {
        bNewBuff = TRUE;
    }

    /* allocating the buffer for TSDU_TYPE_BUF */
    if (bNewBuff) {
        Buffer = ExAllocatePool(NonPagedPool, length);
        if (NULL == Buffer) {
            /* there's no enough memory for us. We just try to
               receive maximum bytes with a new Tsdu */
            bNewBuff = FALSE;
            length = ks_data.ksnd_tsdu_size - KS_TSDU_STRU_SIZE(0) - 
                     KS_QWORD_ALIGN(sizeof(KS_TSDU));
        }
    }

    /* get empty Tsdu from TsduMgr */
    KsTsdu = KsGetTsdu(TsduMgr, bNewBuff ? sizeof(KS_TSDU_BUF) :
                                KS_TSDU_STRU_SIZE(length) );

    /* allocate a new Tsdu in case we are not statisfied. */
    if (NULL == KsTsdu) {
        goto errorout;
    }

    KsTsduBuf = (PKS_TSDU_BUF)((PUCHAR)KsTsdu + KsTsdu->LastOffset);
    KsTsduDat = (PKS_TSDU_DAT)((PUCHAR)KsTsdu + KsTsdu->LastOffset);

    if (bNewBuff) {

        /* setup up the KS_TSDU_BUF record */
        KsTsduBuf->TsduType     = TSDU_TYPE_BUF;
        KsTsduBuf->TsduFlags    = 0;
        KsTsduBuf->StartOffset  = 0;
        KsTsduBuf->UserBuffer   = Buffer;
        KsTsduBuf->DataLength   = length;
        KsTsduBuf->Mdl          = NULL;
        if (cfs_is_flag_set(flags, TDI_SEND_PARTIAL)) {
            KsTsduBuf->TsduFlags |= KS_TSDU_COMM_PARTIAL;
        }

        KsTsdu->LastOffset += sizeof(KS_TSDU_BUF);

    } else {

        /* setup the KS_TSDU_DATA to contain all the messages */

        KsTsduDat->TsduType     =  TSDU_TYPE_DAT;
        KsTsduDat->TsduFlags    = 0;

        if ( KsTsdu->TotalLength - KsTsdu->LastOffset < 
            KS_TSDU_STRU_SIZE(length) ) {
            length = KsTsdu->TotalLength - KsTsdu->LastOffset -
                     FIELD_OFFSET(KS_TSDU_DAT, Data);
        }
        KsTsduDat->DataLength   =  length;
        KsTsduDat->TotalLength  =  KS_TSDU_STRU_SIZE(length);
        KsTsduDat->StartOffset  = 0;
        KsTsduDat->Mdl = NULL;
        if (cfs_is_flag_set(flags, TDI_SEND_PARTIAL)) {
            KsTsduDat->TsduFlags |= KS_TSDU_COMM_PARTIAL;
        }

        Buffer = &KsTsduDat->Data[0];
        KsTsdu->LastOffset += KsTsduDat->TotalLength;
    }

    RtlMoveMemory(Buffer, buffer, length);
    TsduMgr->TotalBytes += length;

    KsPrint((4, "KsWriteTsduDat: TsduMgr=%p bytes in queue:%xh (%xh)\n",
                TsduMgr, TsduMgr->TotalBytes, length));
    return length;

errorout:

    return 0;
}

ULONG
KsWriteTsduBuf(
    PKS_TSDUMGR TsduMgr,
    PCHAR       buffer,
    ULONG       length,
    ULONG       flags
    )
{
    PKS_TSDU            KsTsdu;
    PKS_TSDU_BUF        KsTsduBuf;

    /* get empty Tsdu from TsduMgr */
    KsTsdu = KsGetTsdu(TsduMgr, sizeof(KS_TSDU_BUF));

    /* allocate a new Tsdu in case we are not statisfied. */
    if (NULL == KsTsdu) {
        goto errorout;
    }

    /* setup up the KS_TSDU_BUF record */
    KsTsduBuf = (PKS_TSDU_BUF)((PUCHAR)KsTsdu + KsTsdu->LastOffset);
    KsTsduBuf->TsduType     = TSDU_TYPE_BUF;
    KsTsduBuf->TsduFlags    = 0;
    KsTsduBuf->StartOffset  = 0;
    KsTsduBuf->UserBuffer   = buffer;
    KsTsduBuf->DataLength   = length;
    KsTsduBuf->Mdl          = NULL;
    KsTsdu->LastOffset += sizeof(KS_TSDU_BUF);
    if (cfs_is_flag_set(flags, TDI_SEND_PARTIAL)) {
        KsTsduBuf->TsduFlags |= KS_TSDU_COMM_PARTIAL;
    }

    TsduMgr->TotalBytes  +=  length;
    KsPrint((4, "KsWriteTsduBuf: TsduMgr=%p bytes in queue:%xh (%xh)\n",
                TsduMgr, TsduMgr->TotalBytes, length));

    return length;

errorout:
    return 0;
}

ULONG
KsWriteTsduMdl(
    PKS_TSDUMGR     TsduMgr,
    ks_mdl_t *      mdl, 
    PVOID           desc,
    ULONG           offset,
    ULONG           length,
    ULONG           flags
    )
{
    PKS_TSDU            KsTsdu;
    PKS_TSDU_MDL        KsTsduMdl;

    /* get empty Tsdu from TsduMgr */
    KsTsdu = KsGetTsdu(TsduMgr, sizeof(KS_TSDU_MDL));

    /* allocate a new Tsdu in case we are not statisfied. */
    if (NULL == KsTsdu) {
        goto errorout;
    }

    /* setup up the KS_TSDU_MDL record */
    KsTsduMdl = (PKS_TSDU_MDL)((PUCHAR)KsTsdu + KsTsdu->LastOffset);
    KsTsduMdl->TsduType     = TSDU_TYPE_MDL;
    KsTsduMdl->TsduFlags    = 0;
    KsTsduMdl->StartOffset  = 0;
    KsTsduMdl->BaseOffset   = offset;
    KsTsduMdl->DataLength   = length;
    KsTsduMdl->Mdl          = mdl;
    KsTsduMdl->Descriptor   = desc;
    KsTsdu->LastOffset += sizeof(KS_TSDU_MDL);
    if (cfs_is_flag_set(flags, TDI_SEND_PARTIAL)) {
        KsTsduMdl->TsduFlags |= KS_TSDU_COMM_PARTIAL;
    }

    TsduMgr->TotalBytes  +=  length;
    KsPrint((4, "KsWriteTsduMdl: TsduMgr=%p bytes in queue:%xh (%xh)\n",
                TsduMgr, TsduMgr->TotalBytes, length));

    return length;

errorout:
    return 0;
}

ULONG
KsReadTsdu (
    PKS_TSDUMGR     TsduMgr,
    PCHAR           buffer,
    ULONG           length,
    ULONG           flags
    )
{
    PKS_TSDU        KsTsdu;
    PKS_TSDU_DAT    KsTsduDat;
    PKS_TSDU_BUF    KsTsduBuf;
    PKS_TSDU_MDL    KsTsduMdl;

    PUCHAR          Buffer;
    ULONG           BytesRecved = 0;
#if DBG
    ULONG           TotalBytes = TsduMgr->TotalBytes;
#endif    

    KsPrint((4, "KsReadTsdu: TsduMgr=%p request=%xh total=%xh\n",
                TsduMgr, length, TsduMgr->TotalBytes ));
NextTsdu:

    if (TsduMgr->TotalBytes == 0) {

        /* It's a notification event. We need reset it to
           un-signaled state in case there no any tsdus. */

        KeResetEvent(&(TsduMgr->Event));

    } else {

        KsTsdu = cfs_list_entry(TsduMgr->TsduList.next, KS_TSDU, Link);
        LASSERT(KsTsdu->Magic == KS_TSDU_MAGIC);

        /* remove the KsTsdu from TsduMgr list to release the lock */
        cfs_list_del(&(KsTsdu->Link));
        TsduMgr->NumOfTsdu--;

        while (length > BytesRecved) {

            ULONG BytesToCopy = 0;
            ULONG StartOffset = 0;
            ULONG BytesCopied = 0;

            if (KsTsdu->StartOffset >= KsTsdu->LastOffset) {
                /* KsTsdu is empty now, we need free it ... */
                KsPutKsTsdu(KsTsdu);
                KsTsdu = NULL;
                break;
            }

            KsTsduDat = (PKS_TSDU_DAT)((PUCHAR)KsTsdu + KsTsdu->StartOffset);
            KsTsduBuf = (PKS_TSDU_BUF)((PUCHAR)KsTsdu + KsTsdu->StartOffset);
            KsTsduMdl = (PKS_TSDU_MDL)((PUCHAR)KsTsdu + KsTsdu->StartOffset);

            if ( TSDU_TYPE_DAT == KsTsduDat->TsduType ||
                 TSDU_TYPE_BUF == KsTsduBuf->TsduType ) {

                if (TSDU_TYPE_DAT == KsTsduDat->TsduType) {

                    /* Data Tsdu Unit ... */
                    Buffer = &KsTsduDat->Data[0];
                    StartOffset = KsTsduDat->StartOffset;
                    if (KsTsduDat->DataLength - KsTsduDat->StartOffset > length - BytesRecved) {
                        /* Recvmsg requst could be statisfied ... */
                        BytesToCopy = length - BytesRecved;
                    } else {
                        BytesToCopy = KsTsduDat->DataLength - KsTsduDat->StartOffset;
                    }

                } else {

                    /* Buffer Tsdu Unit */
                    ASSERT(TSDU_TYPE_BUF == KsTsduBuf->TsduType);
                    Buffer = KsTsduBuf->UserBuffer;
                    StartOffset = KsTsduBuf->StartOffset;

                    if (KsTsduBuf->DataLength - KsTsduBuf->StartOffset > length - BytesRecved) {
                        /* Recvmsg requst could be statisfied ... */
                        BytesToCopy = length - BytesRecved;
                    } else {
                        BytesToCopy = KsTsduBuf->DataLength - KsTsduBuf->StartOffset;
                    }
                }

                if (BytesToCopy > 0) {
                    RtlMoveMemory(buffer + BytesRecved, Buffer + StartOffset, BytesToCopy);
                }
                BytesCopied = BytesToCopy;
                BytesRecved += BytesCopied;
                LASSERT(TsduMgr->TotalBytes >= BytesCopied);
                TsduMgr->TotalBytes -= BytesCopied;
                KsPrint((4, "KsReadTsdu: TsduMgr=%p copied=%xh recved=%xh\n",
                            TsduMgr, BytesCopied, BytesRecved ));

                if (TSDU_TYPE_DAT == KsTsduDat->TsduType) {

                    KsTsduDat->StartOffset += BytesCopied;
                    if (KsTsduDat->StartOffset == KsTsduDat->DataLength) {
                        if (KsTsduDat->Mdl) {
                            KsTsduDat->Mdl->Next = NULL;
                            KsReleaseMdl(KsTsduDat->Mdl, FALSE);
                        }
                        KsTsdu->StartOffset += KsTsduDat->TotalLength;
                    }

                } else {

                    ASSERT(TSDU_TYPE_BUF == KsTsduBuf->TsduType);
                    KsTsduBuf->StartOffset += BytesCopied;
                    if (KsTsduBuf->StartOffset == KsTsduBuf->DataLength) {
                        KsTsdu->StartOffset += sizeof(KS_TSDU_BUF);
                        /* now we need release the buf to system pool */
                        if (KsTsduBuf->Mdl) {
                            KsTsduBuf->Mdl->Next = NULL;
                            KsReleaseMdl(KsTsduBuf->Mdl, FALSE);
                        }
                        ExFreePool(KsTsduBuf->UserBuffer);
                    }
                }

            } else if (TSDU_TYPE_MDL == KsTsduMdl->TsduType) {

                /* MDL Tsdu Unit ... */
                if (KsTsduMdl->DataLength > length - BytesRecved) {
                    /* Recvmsg requst could be statisfied ... */
                    BytesToCopy = length - BytesRecved;
                } else {
                    BytesToCopy = KsTsduMdl->DataLength;
                }

                BytesCopied = 
                    KsCopyMdlToBuffer(
                            KsTsduMdl->Mdl,
                            KsTsduMdl->StartOffset + 
                            KsTsduMdl->BaseOffset,
                            buffer,
                            BytesRecved,
                            BytesToCopy
                            );
                KsPrint((4, "KsReadTsdu: TsduMgr=%p mdl=%p dec=%p copied=%xh "
                            "recved=%xh\n",
                            TsduMgr, KsTsduMdl->Mdl, KsTsduMdl->Descriptor,
                            BytesCopied, BytesRecved + BytesCopied));
                if (BytesCopied == 0) {
                    cfs_enter_debugger();
                    break;
                }

                KsTsduMdl->StartOffset += BytesCopied;
                KsTsduMdl->DataLength  -= BytesCopied;
                BytesRecved += BytesCopied;
                LASSERT(TsduMgr->TotalBytes >= BytesCopied);
                TsduMgr->TotalBytes -= BytesCopied;

                if (0 == KsTsduMdl->DataLength) {

                    /* Call TdiReturnChainedReceives to release the Tsdu memory */
                    LASSERT(KsTsduMdl->Descriptor != NULL);
                    if (KsTsduMdl->Descriptor) {
                        TdiReturnChainedReceives(
                            &(KsTsduMdl->Descriptor),
                            1 );
                    }

                    KsTsdu->StartOffset += sizeof(KS_TSDU_MDL);
                }

            } else {
                KsPrint((1, "KsReadTsdu: unknown tsdu slot: slot = %x type = %x Start= %x Length=%x\n",
                        KsTsduDat, KsTsduDat->TsduType, KsTsduDat->StartOffset, KsTsduDat->DataLength));
                KsPrint((1, "            Tsdu = %x Magic=%x: Start = %x Last = %x Length = %x\n",
                        KsTsdu, KsTsdu->Magic, KsTsdu->StartOffset, KsTsdu->LastOffset, KsTsdu->TotalLength));
                cfs_enter_debugger();
            }
        }

        /* we need attach the KsTsdu to the list header */
        if (KsTsdu) {
            if (KsTsdu->StartOffset >= KsTsdu->LastOffset) {
                KsPutKsTsdu(KsTsdu);
                KsTsdu = NULL;
            } else {
                TsduMgr->NumOfTsdu++;
                cfs_list_add(&(KsTsdu->Link), &(TsduMgr->TsduList));
            }
        }
        
        if (length > BytesRecved) {
            goto NextTsdu;
        }
    }

#if DBG
    LASSERT(TotalBytes == TsduMgr->TotalBytes + BytesRecved);
#endif
    KsPrint((4, "KsReadTsdu: TsduMgr=%p recved=%xh (%xh) remained=%xh\n",
                TsduMgr, BytesRecved, length, TsduMgr->TotalBytes ));

    return BytesRecved;
}


ULONG
KsTdiSendFlags(int SockFlags)
{
    ULONG   TdiFlags = 0;

    if (cfs_is_flag_set(SockFlags, MSG_OOB)) {
        cfs_set_flag(TdiFlags, TDI_SEND_EXPEDITED);
    }

    if (cfs_is_flag_set(SockFlags, MSG_MORE)) {
        cfs_set_flag(TdiFlags, TDI_SEND_PARTIAL);
    }

    if (cfs_is_flag_set(SockFlags, MSG_DONTWAIT)) {
        cfs_set_flag(TdiFlags, TDI_SEND_NON_BLOCKING);
    }

    return TdiFlags;
}

ULONG
KsTdiRecvFlags(int SockFlags)
{
    ULONG   TdiFlags = 0;

    if (cfs_is_flag_set(SockFlags, MSG_OOB)) {
        cfs_set_flag(TdiFlags, TDI_RECEIVE_EXPEDITED);
    }

    if (cfs_is_flag_set(SockFlags, MSG_MORE)) {
        cfs_set_flag(TdiFlags, TDI_RECEIVE_PARTIAL);
    }

    if (cfs_is_flag_set(SockFlags, MSG_DONTWAIT)) {
        cfs_set_flag(TdiFlags, TDI_SEND_NON_BLOCKING);
    }

    return TdiFlags;
}

int
KsWriteTsdus(PKS_TSDUMGR TsduMgr, char * buffer, int length, int flags)
{
    int rc = 0;

    if (TsduMgr->TotalBytes <= TDINAL_MAX_TSDU_QUEUE_SIZE) {
        rc = KsWriteTsduDat(TsduMgr, buffer, length, flags);
    }

    if (rc > 0) {
        return rc;
    }

   return -EAGAIN;
}

int
KsReadTsdus(PKS_TSDUMGR TsduMgr, char * buffer, int length, int flags)
{
    int rc = KsReadTsdu(TsduMgr, buffer, length, flags);

    if (rc > 0) {
        return rc;
    }

    return -EAGAIN;
}

/*
 * KsInitializeKsTsduMgr
 *   Initialize the management structure of
 *   Tsdu buffers
 *
 * Arguments:
 *   TsduMgr: the TsduMgr to be initialized
 *
 * Return Value:
 *   VOID
 *
 * NOTES:
 *   N/A
 */

VOID
KsInitializeKsTsduMgr(
    PKS_TSDUMGR     TsduMgr
    )
{
    KeInitializeEvent(
            &(TsduMgr->Event),
            NotificationEvent,
            FALSE
            );

    CFS_INIT_LIST_HEAD(
            &(TsduMgr->TsduList)
            );

    TsduMgr->NumOfTsdu  = 0;
    TsduMgr->TotalBytes = 0;

	spin_lock_init(&TsduMgr->Lock);
}


/*
 * KsInitializeKsChain
 *   Initialize the China structure for receiving
 *   or transmitting
 *
 * Arguments:
 *   KsChain: the KsChain to be initialized
 *
 * Return Value:
 *   VOID
 *
 * NOTES:
 *   N/A
 */

VOID
KsInitializeKsChain(
    PKS_CHAIN       KsChain
    )
{
    KsInitializeKsTsduMgr(&(KsChain->Normal));
    KsInitializeKsTsduMgr(&(KsChain->Expedited));
    KsChain->Expedited.OOB = TRUE;
}


/*
 * KsCleanupTsduMgr
 *   Clean up all the Tsdus in the TsduMgr list
 *
 * Arguments:
 *   TsduMgr: the Tsdu list manager
 *
 * Return Value:
 *   NTSTATUS:  nt status code
 *
 * NOTES:
 *   N/A
 */

NTSTATUS
KsCleanupTsduMgr(
    PKS_TSDUMGR     TsduMgr
    )
{
    PKS_TSDU        KsTsdu;
    PKS_TSDU_DAT    KsTsduDat;
    PKS_TSDU_BUF    KsTsduBuf;
    PKS_TSDU_MDL    KsTsduMdl;

    LASSERT(NULL != TsduMgr);

    KsRemoveTdiEngine(TsduMgr);
    KeSetEvent(&(TsduMgr->Event), 0, FALSE);

    while (!cfs_list_empty(&TsduMgr->TsduList)) {

        KsTsdu = cfs_list_entry(TsduMgr->TsduList.next, KS_TSDU, Link);
        LASSERT(KsTsdu->Magic == KS_TSDU_MAGIC);

        if (KsTsdu->StartOffset == KsTsdu->LastOffset) {

            //
            // KsTsdu is empty now, we need free it ...
            //

            cfs_list_del(&(KsTsdu->Link));
            TsduMgr->NumOfTsdu--;

            KsFreeKsTsdu(KsTsdu);

        } else {

            KsTsduDat = (PKS_TSDU_DAT)((PUCHAR)KsTsdu + KsTsdu->StartOffset);
            KsTsduBuf = (PKS_TSDU_BUF)((PUCHAR)KsTsdu + KsTsdu->StartOffset);
            KsTsduMdl = (PKS_TSDU_MDL)((PUCHAR)KsTsdu + KsTsdu->StartOffset);

            if (TSDU_TYPE_DAT == KsTsduDat->TsduType) {

                KsTsdu->StartOffset += KsTsduDat->TotalLength;

            } else if (TSDU_TYPE_BUF == KsTsduBuf->TsduType) {

                ASSERT(KsTsduBuf->UserBuffer != NULL);

                if (KsTsduBuf->DataLength > KsTsduBuf->StartOffset) {
                    if (KsTsduBuf->Mdl) {
                        KsTsduBuf->Mdl->Next = NULL;
                        KsReleaseMdl(KsTsduBuf->Mdl, FALSE);
                    }
                    ExFreePool(KsTsduBuf->UserBuffer);
                } else {
                    cfs_enter_debugger();
                }

                KsTsdu->StartOffset += sizeof(KS_TSDU_BUF);

            } else if (TSDU_TYPE_MDL == KsTsduMdl->TsduType) {

                //
                // MDL Tsdu Unit ...
                //
                if (KsTsduMdl->Descriptor) {
                    TdiReturnChainedReceives(
                        &(KsTsduMdl->Descriptor),
                        1 );
                } else if (KsTsduMdl->Mdl) {
                    KsTsduMdl->Mdl->Next = NULL;
                    KsReleaseMdl(KsTsduMdl->Mdl, FALSE);
                }

                KsTsdu->StartOffset += sizeof(KS_TSDU_MDL);
            }
        }
    }

    return STATUS_SUCCESS;
}


/*
 * KsCleanupKsChain
 *   Clean up the TsduMgrs of the KsChain
 *
 * Arguments:
 *   KsChain: the chain managing TsduMgr
 *
 * Return Value:
 *   NTSTATUS:  nt status code
 *
 * NOTES:
 *   N/A
 */

NTSTATUS
KsCleanupKsChain(
    PKS_CHAIN   KsChain
    )
{
    NTSTATUS    Status;

    LASSERT(NULL != KsChain);

    Status = KsCleanupTsduMgr(
                &(KsChain->Normal)
                );

    if (!NT_SUCCESS(Status)) {
        cfs_enter_debugger();
        goto errorout;
    }

    Status = KsCleanupTsduMgr(
                &(KsChain->Expedited)
                );

    if (!NT_SUCCESS(Status)) {
        cfs_enter_debugger();
        goto errorout;
    }

errorout:

    return Status;
}


/*
 * KsCleanupTsdu
 *   Clean up all the Tsdus of a tdi connected object
 *
 * Arguments:
 *   tconn: the tdi connection which is connected already.
 *
 * Return Value:
 *   Nt status code
 *
 * NOTES:
 *   N/A
 */

NTSTATUS
KsCleanupTsdu(
    ks_tconn_t * tconn
    )
{
    NTSTATUS        Status = STATUS_SUCCESS;


    if (tconn->kstc_type != kstt_sender &&
        tconn->kstc_type != kstt_child ) {

        goto errorout;
    }

    if (tconn->kstc_type == kstt_sender) {

        Status = KsCleanupKsChain(
                    &(tconn->sender.kstc_recv)
                    );

        if (!NT_SUCCESS(Status)) {
            cfs_enter_debugger();
            goto errorout;
        }

        Status = KsCleanupKsChain(
                    &(tconn->sender.kstc_send)
                    );

        if (!NT_SUCCESS(Status)) {
            cfs_enter_debugger();
            goto errorout;
        }

    } else {

        Status = KsCleanupKsChain(
                    &(tconn->child.kstc_recv)
                    );

        if (!NT_SUCCESS(Status)) {
            cfs_enter_debugger();
            goto errorout;
        }

        Status = KsCleanupKsChain(
                    &(tconn->child.kstc_send)
                    );

        if (!NT_SUCCESS(Status)) {
            cfs_enter_debugger();
            goto errorout;
        }

    }

errorout:

    return (Status);
}

NTSTATUS
KsIrpCompletionRoutine(
    IN PDEVICE_OBJECT    DeviceObject,
    IN PIRP              Irp,
    IN PVOID             Context
    )
{
    if (NULL != Context) {
        KeSetEvent((PKEVENT)Context, IO_NETWORK_INCREMENT, FALSE);
    }

    return STATUS_MORE_PROCESSING_REQUIRED;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);
}


/*
 * KsBuildTdiIrp
 *   Allocate a new IRP and initialize it to be issued to tdi
 *
 * Arguments:
 *   DeviceObject:  device object created by the underlying
 *                  TDI transport driver
 *
 * Return Value:
 *   PRIP:   the allocated Irp in success or NULL in failure.
 *
 * NOTES:
 *   N/A
 */

PIRP
KsBuildTdiIrp(
    IN PDEVICE_OBJECT    DeviceObject
    )
{
    PIRP                Irp;
    PIO_STACK_LOCATION  IrpSp;

    //
    // Allocating the IRP ...
    //

    Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);

    if (NULL != Irp) {

        //
        // Getting the Next Stack Location ...
        //

        IrpSp = IoGetNextIrpStackLocation(Irp);

        //
        // Initializing Irp ...
        //

        IrpSp->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;
        IrpSp->Parameters.DeviceIoControl.IoControlCode = 0;
    }

    return Irp;
}

/*
 * KsSubmitTdiIrp
 *   Issue the Irp to the underlying tdi driver
 *
 * Arguments:
 *   DeviceObject:  the device object created by TDI driver
 *   Irp:           the I/O request packet to be processed
 *   bSynchronous:  synchronous or not. If true, we need wait
 *                  until the process is finished.
 *   Information:   returned info
 *
 * Return Value:
 *   NTSTATUS:      kernel status code
 *
 * NOTES:
 *   N/A
 */

NTSTATUS
KsSubmitTdiIrp(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp,
    IN BOOLEAN          bSynchronous,
    OUT PULONG          Information
    )
{
    NTSTATUS            Status;
    KEVENT              Event;

    if (bSynchronous) {

        KeInitializeEvent(
            &Event,
            SynchronizationEvent,
            FALSE
            );


        IoSetCompletionRoutine(
            Irp,
            KsIrpCompletionRoutine,
            &Event,
            TRUE,
            TRUE,
            TRUE
            );
    }

    Status = IoCallDriver(DeviceObject, Irp);

    if (bSynchronous) {

        if (STATUS_PENDING == Status) {

            Status = KeWaitForSingleObject(
                        &Event,
                        Executive,
                        KernelMode,
                        FALSE,
                        NULL
                        );
        }

        Status = Irp->IoStatus.Status;

        if (Information) {
            *Information = (ULONG)(Irp->IoStatus.Information);
        }

        IoFreeIrp(Irp);
    }

    if (!NT_SUCCESS(Status)) {

        KsPrint((1, "KsSubmitTdiIrp: Error when submitting the Irp: "
                    "Status = %xh (%s)\n", Status, KsNtStatusToString(Status)));
    }

    return (Status);
}



/*
 * KsOpenControl
 *   Open the Control Channel Object ...
 *
 * Arguments:
 *   DeviceName:   the device name to be opened
 *   Handle:       opened handle in success case
 *   FileObject:   the fileobject of the device
 *
 * Return Value:
 *   NTSTATUS:     kernel status code (STATUS_SUCCESS
 *                 or other error code)
 *
 * Notes:
 *   N/A
 */

NTSTATUS
KsOpenControl(
    IN PUNICODE_STRING      DeviceName,
    OUT HANDLE *            Handle,
    OUT PFILE_OBJECT *      FileObject
   )
{
    NTSTATUS          Status = STATUS_SUCCESS;

    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK   IoStatus;


    LASSERT( KeGetCurrentIrql() < DISPATCH_LEVEL );

    //
    // Initializing ...
    //

    InitializeObjectAttributes(
        &ObjectAttributes,
        DeviceName,
        OBJ_CASE_INSENSITIVE |
        OBJ_KERNEL_HANDLE,
        NULL,
        NULL
        );

    LASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL );

    //
    // Creating the Transport Address Object ...
    //

    Status = ZwCreateFile(
                Handle,
                FILE_READ_DATA | FILE_WRITE_DATA,
                &ObjectAttributes,
                &IoStatus,
                0,
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN,
                0,
                NULL,
                0
                );


    if (NT_SUCCESS(Status)) {

        //
        // Now Obtaining the FileObject of the Transport Address ...
        //

        Status = ObReferenceObjectByHandle(
                    *Handle,
                    FILE_ANY_ACCESS,
                    NULL,
                    KernelMode,
                    FileObject,
                    NULL
                    );

        if (!NT_SUCCESS(Status)) {

            cfs_enter_debugger();
            ZwClose(*Handle);
        }

    } else {

        cfs_enter_debugger();
    }

    return (Status);
}


/*
 * KsCloseControl
 *   Release the Control Channel Handle and FileObject
 *
 * Arguments:
 *   Handle:       the channel handle to be released
 *   FileObject:   the fileobject to be released
 *
 * Return Value:
 *   NTSTATUS:     kernel status code (STATUS_SUCCESS
 *                 or other error code)
 *
 * Notes:
 *   N/A
 */

NTSTATUS
KsCloseControl(
    IN HANDLE             Handle,
    IN PFILE_OBJECT       FileObject
   )
{
    NTSTATUS  Status = STATUS_SUCCESS;

    LASSERT( KeGetCurrentIrql() < DISPATCH_LEVEL );

    if (FileObject) {

        ObDereferenceObject(FileObject);
    }

    if (Handle) {

        Status = ZwClose(Handle);
    }

    ASSERT(NT_SUCCESS(Status));

    return (Status);
}


/*
 * KsOpenAddress
 *   Open the tdi address object
 *
 * Arguments:
 *   DeviceName:   device name of the address object
 *   pAddress:     tdi address of the address object
 *   AddressLength: length in bytes of the tdi address
 *   Handle:       the newly opened handle
 *   FileObject:   the newly opened fileobject
 *
 * Return Value:
 *   NTSTATUS:     kernel status code (STATUS_SUCCESS
 *                 or other error code)
 *
 * Notes:
 *   N/A
 */

NTSTATUS
KsOpenAddress(
    IN PUNICODE_STRING      DeviceName,
    IN PTRANSPORT_ADDRESS   pAddress,
    IN ULONG                AddressLength,
    OUT HANDLE *            Handle,
    OUT PFILE_OBJECT *      FileObject
   )
{
    NTSTATUS          Status = STATUS_SUCCESS;

    PFILE_FULL_EA_INFORMATION Ea = NULL;
    ULONG             EaLength;
    UCHAR             EaBuffer[EA_MAX_LENGTH];

    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK   IoStatus;

    //
    // Building EA for the Address Object to be Opened ...
    //

    Ea = (PFILE_FULL_EA_INFORMATION)EaBuffer;
    Ea->NextEntryOffset = 0;
    Ea->Flags = 0;
    Ea->EaNameLength = TDI_TRANSPORT_ADDRESS_LENGTH;
    Ea->EaValueLength = (USHORT)AddressLength;
    RtlCopyMemory(
        &(Ea->EaName),
        TdiTransportAddress,
        Ea->EaNameLength + 1
        );
    RtlMoveMemory(
        &(Ea->EaName[Ea->EaNameLength + 1]),
        pAddress,
        AddressLength
        );
    EaLength =  sizeof(FILE_FULL_EA_INFORMATION) +
                Ea->EaNameLength + AddressLength;

    LASSERT( KeGetCurrentIrql() < DISPATCH_LEVEL );


    //
    // Initializing ...
    //

    InitializeObjectAttributes(
        &ObjectAttributes,
        DeviceName,
        OBJ_CASE_INSENSITIVE |
        OBJ_KERNEL_HANDLE,
        NULL,
        NULL
        );

    LASSERT( KeGetCurrentIrql() < DISPATCH_LEVEL );

    //
    // Creating the Transport Address Object ...
    //

    Status = ZwCreateFile(
                Handle,
                FILE_READ_DATA | FILE_WRITE_DATA,
                &ObjectAttributes,
                &IoStatus,
                0,
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE, /* 0: DON'T REUSE */
                FILE_OPEN,
                0,
                Ea,
                EaLength
                );


    if (NT_SUCCESS(Status)) {

        //
        // Now Obtaining the FileObject of the Transport Address ...
        //

        Status = ObReferenceObjectByHandle(
                    *Handle,
                    FILE_ANY_ACCESS,
                    NULL,
                    KernelMode,
                    FileObject,
                    NULL
                    );

        if (!NT_SUCCESS(Status)) {

            cfs_enter_debugger();
            ZwClose(*Handle);
        }

    } else {

        cfs_enter_debugger();
    }

    return (Status);
}

/*
 * KsCloseAddress
 *   Release the Hanlde and FileObject of an opened tdi
 *   address object
 *
 * Arguments:
 *   Handle:       the handle to be released
 *   FileObject:   the fileobject to be released
 *
 * Return Value:
 *   NTSTATUS:     kernel status code (STATUS_SUCCESS
 *                 or other error code)
 *
 * Notes:
 *   N/A
 */

NTSTATUS
KsCloseAddress(
    IN HANDLE             Handle,
    IN PFILE_OBJECT       FileObject
)
{
    NTSTATUS  Status = STATUS_SUCCESS;

    if (FileObject) {

        ObDereferenceObject(FileObject);
    }

    if (Handle) {

        Status = ZwClose(Handle);
    }

    ASSERT(NT_SUCCESS(Status));

    return (Status);
}


/*
 * KsOpenConnection
 *   Open a tdi connection object
 *
 * Arguments:
 *   DeviceName:   device name of the connection object
 *   ConnectionContext: the connection context
 *   Handle:       the newly opened handle
 *   FileObject:   the newly opened fileobject
 *
 * Return Value:
 *   NTSTATUS:     kernel status code (STATUS_SUCCESS
 *                 or other error code)
 *
 * Notes:
 *   N/A
 */

NTSTATUS
KsOpenConnection(
    IN PUNICODE_STRING      DeviceName,
    IN CONNECTION_CONTEXT   ConnectionContext,
    OUT HANDLE *            Handle,
    OUT PFILE_OBJECT *      FileObject
   )
{
    NTSTATUS            Status = STATUS_SUCCESS;

    PFILE_FULL_EA_INFORMATION Ea = NULL;
    ULONG               EaLength;
    UCHAR               EaBuffer[EA_MAX_LENGTH];

    OBJECT_ATTRIBUTES   ObjectAttributes;
    IO_STATUS_BLOCK     IoStatus;

    //
    // Building EA for the Address Object to be Opened ...
    //

    Ea = (PFILE_FULL_EA_INFORMATION)EaBuffer;
    Ea->NextEntryOffset = 0;
    Ea->Flags = 0;
    Ea->EaNameLength = TDI_CONNECTION_CONTEXT_LENGTH;
    Ea->EaValueLength = (USHORT)sizeof(CONNECTION_CONTEXT);
    RtlCopyMemory(
        &(Ea->EaName),
        TdiConnectionContext,
        Ea->EaNameLength + 1
        );
    RtlMoveMemory(
        &(Ea->EaName[Ea->EaNameLength + 1]),
        &ConnectionContext,
        sizeof(CONNECTION_CONTEXT)
        );
    EaLength =	sizeof(FILE_FULL_EA_INFORMATION) - 1 +
				Ea->EaNameLength + 1 + sizeof(CONNECTION_CONTEXT);

    LASSERT( KeGetCurrentIrql() < DISPATCH_LEVEL );


    //
    // Initializing ...
    //

    InitializeObjectAttributes(
        &ObjectAttributes,
        DeviceName,
        OBJ_CASE_INSENSITIVE |
        OBJ_KERNEL_HANDLE,
        NULL,
        NULL
        );

    LASSERT( KeGetCurrentIrql() < DISPATCH_LEVEL );

    //
    // Creating the Connection Object ...
    //

    Status = ZwCreateFile(
                Handle,
                FILE_READ_DATA | FILE_WRITE_DATA,
                &ObjectAttributes,
                &IoStatus,
                NULL,
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN,
                0,
                Ea,
                EaLength
                );


    if (NT_SUCCESS(Status)) {

        //
        // Now Obtaining the FileObject of the Transport Address ...
        //

        Status = ObReferenceObjectByHandle(
                    *Handle,
                    FILE_ANY_ACCESS,
                    NULL,
                    KernelMode,
                    FileObject,
                    NULL
                    );

        if (!NT_SUCCESS(Status)) {

            cfs_enter_debugger();
            ZwClose(*Handle);
        }

    } else {

        cfs_enter_debugger();
    }

    return (Status);
}

/*
 * KsCloseConnection
 *   Release the Hanlde and FileObject of an opened tdi
 *   connection object
 *
 * Arguments:
 *   Handle:       the handle to be released
 *   FileObject:   the fileobject to be released
 *
 * Return Value:
 *   NTSTATUS:     kernel status code (STATUS_SUCCESS
 *                 or other error code)
 *
 * Notes:
 *   N/A
 */

NTSTATUS
KsCloseConnection(
    IN HANDLE             Handle,
    IN PFILE_OBJECT       FileObject
    )
{
    NTSTATUS  Status = STATUS_SUCCESS;

    if (FileObject) {

        ObDereferenceObject(FileObject);
    }

    if (Handle) {

        Status = ZwClose(Handle);
    }

    ASSERT(NT_SUCCESS(Status));

    return (Status);
}


/*
 * KsAssociateAddress
 *   Associate an address object with a connection object
 *
 * Arguments:
 *   AddressHandle:  the handle of the address object
 *   ConnectionObject:  the FileObject of the connection
 *
 * Return Value:
 *   NTSTATUS:     kernel status code (STATUS_SUCCESS
 *                 or other error code)
 *
 * Notes:
 *   N/A
 */

NTSTATUS
KsAssociateAddress(
    IN HANDLE           AddressHandle,
    IN PFILE_OBJECT     ConnectionObject
    )
{
    NTSTATUS            Status;
    PDEVICE_OBJECT      DeviceObject;
    PIRP                Irp;

    //
    // Getting the DeviceObject from Connection FileObject
    //

    DeviceObject = IoGetRelatedDeviceObject(ConnectionObject);

    //
    // Building Tdi Internal Irp ...
    //

    Irp = KsBuildTdiIrp(DeviceObject);

    if (NULL == Irp) {

        Status = STATUS_INSUFFICIENT_RESOURCES;

    } else {

        //
        // Assocating the Address Object with the Connection Object
        //

        TdiBuildAssociateAddress(
            Irp,
            DeviceObject,
            ConnectionObject,
            NULL,
            NULL,
            AddressHandle
            );

        //
        // Calling the Transprot Driver with the Prepared Irp
        //

        Status = KsSubmitTdiIrp(DeviceObject, Irp, TRUE, NULL);
    }

    return (Status);
}


/*
 * KsDisassociateAddress
 *   Disassociate the connection object (the relationship will
 *   the corresponding address object will be dismissed. )
 *
 * Arguments:
 *   ConnectionObject:  the FileObject of the connection
 *
 * Return Value:
 *   NTSTATUS:     kernel status code (STATUS_SUCCESS
 *                 or other error code)
 *
 * Notes:
 *   N/A
 */

NTSTATUS
KsDisassociateAddress(
    IN PFILE_OBJECT     ConnectionObject
    )
{
    NTSTATUS            Status;
    PDEVICE_OBJECT      DeviceObject;
    PIRP                   Irp;

    //
    // Getting the DeviceObject from Connection FileObject
    //

    DeviceObject = IoGetRelatedDeviceObject(ConnectionObject);

    //
    // Building Tdi Internal Irp ...
    //

    Irp = KsBuildTdiIrp(DeviceObject);

    if (NULL == Irp) {

        Status = STATUS_INSUFFICIENT_RESOURCES;

    } else {

        //
        // Disassocating the Address Object with the Connection Object
        //

        TdiBuildDisassociateAddress(
            Irp,
            DeviceObject,
            ConnectionObject,
            NULL,
            NULL
            );

        //
        // Calling the Transprot Driver with the Prepared Irp
        //

        Status = KsSubmitTdiIrp(DeviceObject, Irp, TRUE, NULL);
    }

    return (Status);
}


/*

//
// Connection Control Event Callbacks
//

TDI_EVENT_CONNECT
TDI_EVENT_DISCONNECT
TDI_EVENT_ERROR

//
// Tcp Event Callbacks
//

TDI_EVENT_RECEIVE
TDI_EVENT_RECEIVE_EXPEDITED
TDI_EVENT_CHAINED_RECEIVE
TDI_EVENT_CHAINED_RECEIVE_EXPEDITED

//
// Udp Event Callbacks
//

TDI_EVENT_RECEIVE_DATAGRAM
TDI_EVENT_CHAINED_RECEIVE_DATAGRAM

*/


/*
 * KsSetEventHandlers
 *   Set the tdi event callbacks with an address object
 *
 * Arguments:
 *   AddressObject: the FileObject of the address object
 *   EventContext:  the parameter for the callbacks
 *   Handlers:      the handlers indictor array
 *
 * Return Value:
 *   NTSTATUS:     kernel status code (STATUS_SUCCESS
 *                 or other error code)
 *
 * NOTES:
 *   N/A
 */

NTSTATUS
KsSetEventHandlers(
    IN PFILE_OBJECT                         AddressObject,  // Address File Object
    IN PVOID                                EventContext,   // Context for Handlers
    IN PKS_EVENT_HANDLERS                   Handlers        // Handlers Indictor
   )
{
    NTSTATUS             Status = STATUS_SUCCESS;
    PDEVICE_OBJECT       DeviceObject;
    USHORT               i = 0;

    DeviceObject = IoGetRelatedDeviceObject(AddressObject);

    for (i=0; i < TDI_EVENT_MAXIMUM_HANDLER; i++) {

        //
        // Setup the tdi event callback handler if requested.
        //

        if (Handlers->IsActive[i]) {

            PIRP            Irp;

            //
            // Building Tdi Internal Irp ...
            //

            Irp = KsBuildTdiIrp(DeviceObject);

            if (NULL == Irp) {

                Status = STATUS_INSUFFICIENT_RESOURCES;

            } else {

                //
                // Building the Irp to set the Event Handler ...
                //

                TdiBuildSetEventHandler(
                    Irp,
                    DeviceObject,
                    AddressObject,
                    NULL,
                    NULL,
                    i,                      /* tdi event type */
                    Handlers->Handler[i],   /* tdi event handler */
                    EventContext            /* context for the handler */
                    );

                //
                // Calling the Transprot Driver with the Prepared Irp
                //

                Status = KsSubmitTdiIrp(DeviceObject, Irp, TRUE, NULL);

                //
                // tcp/ip tdi does not support these two event callbacks
                //

                if ((!NT_SUCCESS(Status)) && ( i == TDI_EVENT_SEND_POSSIBLE ||
                     i == TDI_EVENT_CHAINED_RECEIVE_EXPEDITED )) {
                    cfs_enter_debugger();
                    Status = STATUS_SUCCESS;
                }
            }

            if (!NT_SUCCESS(Status)) {
                cfs_enter_debugger();
                goto errorout;
            }
        }
    }


errorout:

    if (!NT_SUCCESS(Status)) {

        KsPrint((1, "KsSetEventHandlers: Error Status = %xh (%s)\n",
                    Status, KsNtStatusToString(Status) ));
    }

    return (Status);
}



/*
 * KsQueryAddressInfo
 *   Query the address of the FileObject specified
 *
 * Arguments:
 *   FileObject:  the FileObject to be queried
 *   AddressInfo: buffer to contain the address info
 *   AddressSize: length of the AddressInfo buffer
 *
 * Return Value:
 *   NTSTATUS:     kernel status code (STATUS_SUCCESS
 *                 or other error code)
 *
 * Notes:
 *   N/A
 */

NTSTATUS
KsQueryAddressInfo(
    PFILE_OBJECT            FileObject,
    PTDI_ADDRESS_INFO       AddressInfo,
    PULONG                  AddressSize
   )
{
    NTSTATUS          Status = STATUS_UNSUCCESSFUL;
    PIRP              Irp = NULL;
    PMDL              Mdl;
    PDEVICE_OBJECT    DeviceObject;

    LASSERT( KeGetCurrentIrql() < DISPATCH_LEVEL );

    DeviceObject = IoGetRelatedDeviceObject(FileObject);

    RtlZeroMemory(AddressInfo, *(AddressSize));

    //
    // Allocating the Tdi Setting Irp ...
    //

    Irp = KsBuildTdiIrp(DeviceObject);

    if (NULL == Irp) {

        Status = STATUS_INSUFFICIENT_RESOURCES;

    } else {

        //
        // Locking the User Buffer / Allocating a MDL for it
        //

        Status = KsLockUserBuffer(
                    AddressInfo,
                    FALSE,
                    *(AddressSize),
                    IoModifyAccess,
                    &Mdl
                    );

        if (!NT_SUCCESS(Status)) {

            IoFreeIrp(Irp);
            Irp = NULL;
        }
    }

    if (Irp) {

        LASSERT(NT_SUCCESS(Status));

        TdiBuildQueryInformation(
                    Irp,
                    DeviceObject,
                    FileObject,
                    NULL,
                    NULL,
                    TDI_QUERY_ADDRESS_INFO,
                    Mdl
                    );

        Status = KsSubmitTdiIrp(
                    DeviceObject,
                    Irp,
                    TRUE,
                    AddressSize
                    );

        KsReleaseMdl(Mdl, FALSE);
    }

    if (!NT_SUCCESS(Status)) {

        cfs_enter_debugger();
        //TDI_BUFFER_OVERFLOW
    }

    return (Status);
}

/*
 * KsQueryProviderInfo
 *   Query the underlying transport device's information
 *
 * Arguments:
 *   TdiDeviceName:  the transport device's name string
 *   ProviderInfo:   TDI_PROVIDER_INFO struncture
 *
 * Return Value:
 *   NTSTATUS:       Nt system status code
  *
 * NOTES:
 *   N/A
 */

NTSTATUS
KsQueryProviderInfo(
    PWSTR               TdiDeviceName,
    PTDI_PROVIDER_INFO  ProviderInfo
   )
{
    NTSTATUS            Status = STATUS_SUCCESS;

    PIRP                Irp = NULL;
    PMDL                Mdl = NULL;

    UNICODE_STRING      ControlName;

    HANDLE              Handle;
    PFILE_OBJECT        FileObject;
    PDEVICE_OBJECT      DeviceObject;

    ULONG               ProviderSize = 0;

    RtlInitUnicodeString(&ControlName, TdiDeviceName);

    //
    // Open the Tdi Control Channel
    //

    Status = KsOpenControl(
                &ControlName,
                &Handle,
                &FileObject
                );

    if (!NT_SUCCESS(Status)) {

        KsPrint((1, "KsQueryProviderInfo: Fail to open the tdi control channel.\n"));
        return (Status);
    }

    //
    // Obtain The Related Device Object
    //

    DeviceObject = IoGetRelatedDeviceObject(FileObject);

    ProviderSize = sizeof(TDI_PROVIDER_INFO);
    RtlZeroMemory(ProviderInfo, ProviderSize);

    //
    // Allocating the Tdi Setting Irp ...
    //

    Irp = KsBuildTdiIrp(DeviceObject);

    if (NULL == Irp) {

        Status = STATUS_INSUFFICIENT_RESOURCES;

    } else {

        //
        // Locking the User Buffer / Allocating a MDL for it
        //

        Status = KsLockUserBuffer(
                    ProviderInfo,
                    FALSE,
                    ProviderSize,
                    IoModifyAccess,
                    &Mdl
                    );

        if (!NT_SUCCESS(Status)) {

            IoFreeIrp(Irp);
            Irp = NULL;
        }
    }

    if (Irp) {

        LASSERT(NT_SUCCESS(Status));

        TdiBuildQueryInformation(
                    Irp,
                    DeviceObject,
                    FileObject,
                    NULL,
                    NULL,
                    TDI_QUERY_PROVIDER_INFO,
                    Mdl
                    );

        Status = KsSubmitTdiIrp(
                    DeviceObject,
                    Irp,
                    TRUE,
                    &ProviderSize
                    );

        KsReleaseMdl(Mdl, FALSE);
    }

    if (!NT_SUCCESS(Status)) {

        cfs_enter_debugger();
        //TDI_BUFFER_OVERFLOW
    }

    KsCloseControl(Handle, FileObject);

    return (Status);
}

/*
 * KsQueryConnectionInfo
 *   Query the connection info of the FileObject specified
 *   (some statics data of the traffic)
 *
 * Arguments:
 *   FileObject:     the FileObject to be queried
 *   ConnectionInfo: buffer to contain the connection info
 *   ConnectionSize: length of the ConnectionInfo buffer
 *
 * Return Value:
 *   NTSTATUS:     kernel status code (STATUS_SUCCESS
 *                 or other error code)
 *
 * NOTES:
 *   N/A
 */

NTSTATUS
KsQueryConnectionInfo(
    PFILE_OBJECT            ConnectionObject,
    PTDI_CONNECTION_INFO    ConnectionInfo,
    PULONG                  ConnectionSize
   )
{
    NTSTATUS          Status = STATUS_UNSUCCESSFUL;
    PIRP              Irp = NULL;
    PMDL              Mdl;
    PDEVICE_OBJECT    DeviceObject;

    LASSERT( KeGetCurrentIrql() < DISPATCH_LEVEL );

    DeviceObject = IoGetRelatedDeviceObject(ConnectionObject);

    RtlZeroMemory(ConnectionInfo, *(ConnectionSize));

    //
    // Allocating the Tdi Query Irp ...
    //

    Irp = KsBuildTdiIrp(DeviceObject);

    if (NULL == Irp) {

        Status = STATUS_INSUFFICIENT_RESOURCES;

    } else {

        //
        // Locking the User Buffer / Allocating a MDL for it
        //

        Status = KsLockUserBuffer(
                    ConnectionInfo,
                    FALSE,
                    *(ConnectionSize),
                    IoModifyAccess,
                    &Mdl
                    );

        if (NT_SUCCESS(Status)) {

            IoFreeIrp(Irp);
            Irp = NULL;
        }
    }

    if (Irp) {

        LASSERT(NT_SUCCESS(Status));

        TdiBuildQueryInformation(
                    Irp,
                    DeviceObject,
                    ConnectionObject,
                    NULL,
                    NULL,
                    TDI_QUERY_CONNECTION_INFO,
                    Mdl
                    );

        Status = KsSubmitTdiIrp(
                    DeviceObject,
                    Irp,
                    TRUE,
                    ConnectionSize
                    );

        KsReleaseMdl(Mdl, FALSE);
    }

    return (Status);
}


/*
 * KsInitializeTdiAddress
 *   Initialize the tdi addresss
 *
 * Arguments:
 *   pTransportAddress: tdi address to be initialized
 *   IpAddress:         the ip address of object
 *   IpPort:            the ip port of the object
 *
 * Return Value:
 *   ULONG: the total size of the tdi address
 *
 * NOTES:
 *   N/A
 */

ULONG
KsInitializeTdiAddress(
    IN OUT PTA_IP_ADDRESS   pTransportAddress,
    IN ULONG                IpAddress,
    IN USHORT               IpPort
    )
{
    pTransportAddress->TAAddressCount = 1;
    pTransportAddress->Address[ 0 ].AddressLength = TDI_ADDRESS_LENGTH_IP;
    pTransportAddress->Address[ 0 ].AddressType   = TDI_ADDRESS_TYPE_IP;
    pTransportAddress->Address[ 0 ].Address[ 0 ].sin_port = IpPort;
    pTransportAddress->Address[ 0 ].Address[ 0 ].in_addr  = IpAddress;

    return (FIELD_OFFSET(TRANSPORT_ADDRESS, Address->Address) + TDI_ADDRESS_LENGTH_IP);
}

/*
 * KsQueryTdiAddressLength
 *   Query the total size of the tdi address
 *
 * Arguments:
 *   pTransportAddress: tdi address to be queried
 *
 * Return Value:
 *   ULONG: the total size of the tdi address
 *
 * NOTES:
 *   N/A
 */

ULONG
KsQueryTdiAddressLength(
    PTRANSPORT_ADDRESS      pTransportAddress
    )
{
    ULONG                   TotalLength = 0;
    LONG                    i;

    PTA_ADDRESS             pTaAddress = NULL;

    ASSERT (NULL != pTransportAddress);

    TotalLength  = FIELD_OFFSET(TRANSPORT_ADDRESS, Address) +
                   FIELD_OFFSET(TA_ADDRESS, Address) * pTransportAddress->TAAddressCount;

    pTaAddress = (PTA_ADDRESS)pTransportAddress->Address;

    for (i = 0; i < pTransportAddress->TAAddressCount; i++)
    {
        TotalLength += pTaAddress->AddressLength;
        pTaAddress = (PTA_ADDRESS)((PCHAR)pTaAddress +
                                           FIELD_OFFSET(TA_ADDRESS,Address) +
                                           pTaAddress->AddressLength );
    }

    return (TotalLength);
}


/*
 * KsQueryIpAddress
 *   Query the ip address of the tdi object
 *
 * Arguments:
 *   FileObject: tdi object to be queried
 *   TdiAddress: TdiAddress buffer, to store the queried
 *               tdi ip address
 *   AddressLength: buffer length of the TdiAddress
 *
 * Return Value:
 *   ULONG: the total size of the tdi ip address
 *
 * NOTES:
 *   N/A
 */

NTSTATUS
KsQueryIpAddress(
    PFILE_OBJECT    FileObject,
    PVOID           TdiAddress,
    ULONG*          AddressLength
    )
{
    NTSTATUS        Status;

    PTDI_ADDRESS_INFO   TdiAddressInfo;
    ULONG               Length;


    //
    // Maximum length of TDI_ADDRESSS_INFO with one TRANSPORT_ADDRESS
    //

    Length = MAX_ADDRESS_LENGTH;

    TdiAddressInfo = (PTDI_ADDRESS_INFO)
                        ExAllocatePoolWithTag(
                            NonPagedPool,
                            Length,
                            'KSAI' );

    if (NULL == TdiAddressInfo) {

        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto errorout;
    }


    Status = KsQueryAddressInfo(
                FileObject,
                TdiAddressInfo,
                &Length
                );

errorout:

    if (NT_SUCCESS(Status)) {

        if (*AddressLength < Length) {
            Status = STATUS_BUFFER_TOO_SMALL;
        } else {
            *AddressLength = Length;
            RtlCopyMemory(
                TdiAddress,
                &(TdiAddressInfo->Address),
                Length
                );
            Status = STATUS_SUCCESS;
        }
    }

    if (NULL != TdiAddressInfo) {
        ExFreePool(TdiAddressInfo);
    }

    return Status;
}


/*
 * KsErrorEventHandler
 *   the common error event handler callback
 *
 * Arguments:
 *   TdiEventContext: should be the socket
 *   Status: the error code
 *
 * Return Value:
 *   Status: STATS_SUCCESS
 *
 * NOTES:
 *   We need not do anything in such a severe
 *   error case. System will process it for us.
 */

NTSTATUS
KsErrorEventHandler(
    IN PVOID        TdiEventContext,
    IN NTSTATUS     Status
   )
{
    KsPrint((1, "KsErrorEventHandler called at Irql = %xh ...\n",
                KeGetCurrentIrql()));

    cfs_enter_debugger();

    return (STATUS_SUCCESS);
}

/*
 * KsAcceptCompletionRoutine
 *   Irp completion routine for TdiBuildAccept (KsConnectEventHandler)
 *
 *   Here system gives us a chance to check the conneciton is built
 *   ready or not.
 *
 * Arguments:
 *   DeviceObject:  the device object of the transport driver
 *   Irp:           the Irp is being completed.
 *   Context:       the context we specified when issuing the Irp
 *
 * Return Value:
 *   Nt status code
 *
 * Notes:
 *   N/A
 */

NTSTATUS
KsAcceptCompletionRoutine(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp,
    IN PVOID            Context
    )
{
    ks_tconn_t * child = (ks_tconn_t *) Context;
    ks_tconn_t * parent = child->child.kstc_parent;

    KsPrint((2, "KsAcceptCompletionRoutine at Irql: %xh child: %p status: %p\n",
                 KeGetCurrentIrql(), child, Irp->IoStatus.Status));

    LASSERT(child->kstc_type == kstt_child);

	spin_lock(&(child->kstc_lock));

    LASSERT(parent->kstc_state == ksts_listening);
    LASSERT(child->kstc_state == ksts_connecting);

    if (NT_SUCCESS(Irp->IoStatus.Status)) {

        child->child.kstc_accepted = TRUE;

        child->kstc_state = ksts_connected;

        /* wake up the daemon thread which waits on this event */
        KeSetEvent(
            &(parent->listener.kstc_accept_event),
            0,
            FALSE
            );

	spin_unlock(&(child->kstc_lock));

        KsPrint((2, "KsAcceptCompletionRoutine: singal parent: %p (child: %p)\n",
                    parent, child));

    } else {

        /* re-use this child connecton  */
        child->child.kstc_accepted = FALSE;
        child->child.kstc_busy = FALSE;
        child->kstc_state = ksts_associated;

	spin_unlock(&(child->kstc_lock));
    }

    /* now free the Irp */
    IoFreeIrp(Irp);

    /* drop the refer count of the child */
    ks_put_tconn(child);

    return (STATUS_MORE_PROCESSING_REQUIRED);
}

ks_addr_slot_t *
KsSearchIpAddress(PUNICODE_STRING  DeviceName)
{
    ks_addr_slot_t * slot = NULL;
    PLIST_ENTRY      list = NULL;

	spin_lock(&ks_data.ksnd_addrs_lock);

    list = ks_data.ksnd_addrs_list.Flink;
    while (list != &ks_data.ksnd_addrs_list) {
        slot = CONTAINING_RECORD(list, ks_addr_slot_t, link);
        if (RtlCompareUnicodeString(
                    DeviceName,
                    &slot->devname,
                    TRUE) == 0) {
            break;
        }
        list = list->Flink;
        slot = NULL;
    }

	spin_unlock(&ks_data.ksnd_addrs_lock);

	return slot;
}

void
KsCleanupIpAddresses()
{
	spin_lock(&ks_data.ksnd_addrs_lock);

    while (!IsListEmpty(&ks_data.ksnd_addrs_list)) {

        ks_addr_slot_t * slot = NULL;
        PLIST_ENTRY      list = NULL;

        list = RemoveHeadList(&ks_data.ksnd_addrs_list);
        slot = CONTAINING_RECORD(list, ks_addr_slot_t, link);
        cfs_free(slot);
        ks_data.ksnd_naddrs--;
    }

    cfs_assert(ks_data.ksnd_naddrs == 0);
	spin_unlock(&ks_data.ksnd_addrs_lock);
}

VOID
KsAddAddressHandler(
    IN  PTA_ADDRESS      Address,
    IN  PUNICODE_STRING  DeviceName,
    IN  PTDI_PNP_CONTEXT Context
    )
{
    PTDI_ADDRESS_IP IpAddress = NULL;

    if ( Address->AddressType == TDI_ADDRESS_TYPE_IP &&
         Address->AddressLength == TDI_ADDRESS_LENGTH_IP ) {

        ks_addr_slot_t * slot = NULL;

        IpAddress = (PTDI_ADDRESS_IP) &Address->Address[0];
        KsPrint((2, "KsAddAddressHandle: Device=%wZ Context=%xh "
                     "IpAddress=%xh(%d.%d.%d.%d)\n",
                     DeviceName, Context, IpAddress->in_addr,
                     (IpAddress->in_addr & 0x000000FF) >> 0,
                     (IpAddress->in_addr & 0x0000FF00) >> 8,
                     (IpAddress->in_addr & 0x00FF0000) >> 16,
                     (IpAddress->in_addr & 0xFF000000) >> 24
               ));

        slot = KsSearchIpAddress(DeviceName);

        if (slot != NULL) {
            slot->up = TRUE;
            slot->ip_addr = ntohl(IpAddress->in_addr);
        } else {

            /* Matt: only add 192.168.10/5/92.xxx for temporary test */
            if ((IpAddress->in_addr & 0x00FFFFFF) != 0x000aa8c0 &&
                (IpAddress->in_addr & 0x00FFFFFF) != 0x0092a8c0 &&
                (IpAddress->in_addr & 0x00FFFFFF) != 0x0005a8c0 ) {
                return;
            }

            slot = cfs_alloc(sizeof(ks_addr_slot_t) + DeviceName->Length, CFS_ALLOC_ZERO);
            if (slot != NULL) {
		spin_lock(&ks_data.ksnd_addrs_lock);
                InsertTailList(&ks_data.ksnd_addrs_list, &slot->link);
                sprintf(slot->iface, "eth%d", ks_data.ksnd_naddrs++);
                slot->ip_addr = ntohl(IpAddress->in_addr);
                slot->netmask = 0x00FFFFFF; /* Matt: hardcode*/
                slot->up = TRUE;
                RtlMoveMemory(&slot->buffer[0], DeviceName->Buffer, DeviceName->Length);
                slot->devname.Length = DeviceName->Length;
                slot->devname.MaximumLength = DeviceName->Length + sizeof(WCHAR);
                slot->devname.Buffer = slot->buffer;
		spin_unlock(&ks_data.ksnd_addrs_lock);

                KsPrint((0, "KsAddAddressHandle: %s added: ip=%xh(%d.%d.%d.%d)\n",
                            slot->iface, IpAddress->in_addr,
                            (IpAddress->in_addr & 0x000000FF) >> 0,
                            (IpAddress->in_addr & 0x0000FF00) >> 8,
                            (IpAddress->in_addr & 0x00FF0000) >> 16,
                            (IpAddress->in_addr & 0xFF000000) >> 24
                       ));
            }
        }
    }
}

VOID
KsDelAddressHandler(
    IN  PTA_ADDRESS      Address,
    IN  PUNICODE_STRING  DeviceName,
    IN  PTDI_PNP_CONTEXT Context
    )
{
    PTDI_ADDRESS_IP IpAddress = NULL;

    if ( Address->AddressType == TDI_ADDRESS_TYPE_IP &&
         Address->AddressLength == TDI_ADDRESS_LENGTH_IP ) {

        ks_addr_slot_t * slot = NULL;

        slot = KsSearchIpAddress(DeviceName);

        if (slot != NULL) {
            slot->up = FALSE;
        }

        IpAddress = (PTDI_ADDRESS_IP) &Address->Address[0];
        KsPrint((2, "KsDelAddressHandle: Device=%wZ Context=%xh IpAddress=%xh(%d.%d.%d.%d)\n",
                  DeviceName, Context, IpAddress->in_addr,
                   (IpAddress->in_addr & 0xFF000000) >> 24,
                   (IpAddress->in_addr & 0x00FF0000) >> 16,
                   (IpAddress->in_addr & 0x0000FF00) >> 8,
                   (IpAddress->in_addr & 0x000000FF) >> 0 ));
    }
}

NTSTATUS
KsRegisterPnpHandlers()
{
    TDI20_CLIENT_INTERFACE_INFO ClientInfo;

    /* initialize the global ks_data members */
    RtlInitUnicodeString(&ks_data.ksnd_client_name, TDILND_MODULE_NAME);
	spin_lock_init(&ks_data.ksnd_addrs_lock);
    InitializeListHead(&ks_data.ksnd_addrs_list);

    /* register the pnp handlers */
    RtlZeroMemory(&ClientInfo, sizeof(ClientInfo));
    ClientInfo.TdiVersion = TDI_CURRENT_VERSION;

    ClientInfo.ClientName = &ks_data.ksnd_client_name;
    ClientInfo.AddAddressHandlerV2 =  KsAddAddressHandler;
    ClientInfo.DelAddressHandlerV2 =  KsDelAddressHandler;

    return TdiRegisterPnPHandlers(&ClientInfo, sizeof(ClientInfo),
                                  &ks_data.ksnd_pnp_handle);
}

VOID
KsDeregisterPnpHandlers()
{
    if (ks_data.ksnd_pnp_handle) {

        /* De-register the pnp handlers */

        TdiDeregisterPnPHandlers(ks_data.ksnd_pnp_handle);
        ks_data.ksnd_pnp_handle = NULL;

        /* cleanup all the ip address slots */
        KsCleanupIpAddresses();
    }
}


/*
 * KsGetVacancyBacklog
 *   Get a vacancy listeing child from the backlog list
 *
 * Arguments:
 *   parent: the listener daemon connection
 *
 * Return Value:
 *   the child listening connection or NULL in failure
 *
 * Notes
 *   Parent's lock should be acquired before calling.
 */

ks_tconn_t *
KsGetVacancyBacklog(
    ks_tconn_t *  parent
    )
{
    ks_tconn_t * child;

    LASSERT(parent->kstc_type == kstt_listener);
    LASSERT(parent->kstc_state == ksts_listening);

    if (cfs_list_empty(&(parent->listener.kstc_listening.list))) {

        child = NULL;

    } else {

        cfs_list_t * tmp;

        /* check the listening queue and try to get a free connecton */

        cfs_list_for_each(tmp, &(parent->listener.kstc_listening.list)) {
            child = cfs_list_entry (tmp, ks_tconn_t, child.kstc_link);
	    spin_lock(&(child->kstc_lock));

            if (!child->child.kstc_busy) {
                LASSERT(child->kstc_state == ksts_associated);
                child->child.kstc_busy = TRUE;
		spin_unlock(&(child->kstc_lock));
                break;
            } else {
		spin_unlock(&(child->kstc_lock));
                child = NULL;
            }
        }
    }

    return child;
}

/*
 * KsConnectEventHandler
 *   Connect event handler event handler, called by the underlying TDI
 *   transport in response to an incoming request to the listening daemon.
 *
 *   it will grab a vacancy backlog from the children tconn list, and
 *   build an acception Irp with it, then transfer the Irp to TDI driver.
 *
 * Arguments:
 *   TdiEventContext:  the tdi connnection object of the listening daemon
 *   ......
 *
 * Return Value:
 *   Nt kernel status code
 *
 * Notes:
 *   N/A
 */

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
    )
{
    ks_tconn_t *                parent;
    ks_tconn_t *                child;

    PFILE_OBJECT                FileObject;
    PDEVICE_OBJECT              DeviceObject;
    NTSTATUS                    Status;

    PIRP                        Irp = NULL;
    PTDI_CONNECTION_INFORMATION ConnectionInfo = NULL;

    KsPrint((2,"KsConnectEventHandler: call at Irql: %u\n", KeGetCurrentIrql()));
    parent = (ks_tconn_t *) TdiEventContext;

    LASSERT(parent->kstc_type == kstt_listener);

	spin_lock(&(parent->kstc_lock));

    if (parent->kstc_state == ksts_listening) {

        /* allocate a new ConnectionInfo to backup the peer's info */

        ConnectionInfo = (PTDI_CONNECTION_INFORMATION)ExAllocatePoolWithTag(
                NonPagedPool, sizeof(TDI_CONNECTION_INFORMATION) +
                RemoteAddressLength, 'iCsK' );

        if (NULL == ConnectionInfo) {

            Status = STATUS_INSUFFICIENT_RESOURCES;
            cfs_enter_debugger();
            goto errorout;
        }

        /* initializing ConnectionInfo structure ... */

        ConnectionInfo->UserDataLength = UserDataLength;
        ConnectionInfo->UserData = UserData;
        ConnectionInfo->OptionsLength = OptionsLength;
        ConnectionInfo->Options = Options;
        ConnectionInfo->RemoteAddressLength = RemoteAddressLength;
        ConnectionInfo->RemoteAddress = ConnectionInfo + 1;

        RtlCopyMemory(
                ConnectionInfo->RemoteAddress,
                RemoteAddress,
                RemoteAddressLength
                );

        /* get the vacancy listening child tdi connections */

        child = KsGetVacancyBacklog(parent);

        if (child) {

	    spin_lock(&(child->kstc_lock));
            child->child.kstc_info.ConnectionInfo = ConnectionInfo;
            child->child.kstc_info.Remote = ConnectionInfo->RemoteAddress;
            child->kstc_state = ksts_connecting;
	    spin_unlock(&(child->kstc_lock));

        } else {

            KsPrint((1, "KsConnectEventHandler: No enough backlogs: Refsued the connectio: %xh\n", parent));
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto errorout;
        }

        FileObject = child->child.kstc_info.FileObject;
        DeviceObject = IoGetRelatedDeviceObject (FileObject);

        Irp = KsBuildTdiIrp(DeviceObject);

        TdiBuildAccept(
                Irp,
                DeviceObject,
                FileObject,
                KsAcceptCompletionRoutine,
                child,
                NULL,
                NULL
                );

        IoSetNextIrpStackLocation(Irp);

        /* grap the refer of the child tdi connection */
        ks_get_tconn(child);

        Status = STATUS_MORE_PROCESSING_REQUIRED;
        *AcceptIrp = Irp;
        *ConnectionContext = child;

    } else {

        Status = STATUS_CONNECTION_REFUSED;
        goto errorout;
    }

	spin_unlock(&(parent->kstc_lock));

    return Status;

errorout:

	spin_unlock(&(parent->kstc_lock));

    *AcceptIrp = NULL;
    *ConnectionContext = NULL;

    if (ConnectionInfo) {
        ExFreePool(ConnectionInfo);
    }

    if (Irp) {
        IoFreeIrp (Irp);
    }

    return Status;
}

/*
 * KsDisconnectCompletionRoutine
 *   the Irp completion routine for TdiBuildDisconect
 *
 *   We just signal the event and return MORE_PRO... to
 *   let the caller take the responsibility of the Irp.
 *
 * Arguments:
 *   DeviceObject:  the device object of the transport
 *   Irp:           the Irp is being completed.
 *   Context:       the event specified by the caller
 *
 * Return Value:
 *   Nt status code
 *
 * Notes:
 *   N/A
 */

NTSTATUS
KsDisconectCompletionRoutine (
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp,
    IN PVOID            Context
    )
{

    KeSetEvent((PKEVENT) Context, 0, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;

    UNREFERENCED_PARAMETER(DeviceObject);
}


/*
 * KsDisconnectHelper
 *   the routine to be executed in the WorkItem procedure
 *   this routine is to disconnect a tdi connection
 *
 * Arguments:
 *   Workitem:  the context transferred to the workitem
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   tconn is already referred in abort_connecton ...
 */

VOID
KsDisconnectHelper(PKS_DISCONNECT_WORKITEM WorkItem)
{
    ks_tconn_t * tconn = WorkItem->tconn;

    KsPrint((1, "KsDisconnectHelper: disconnecting tconn=%p\n", tconn));
    ks_disconnect_tconn(tconn, WorkItem->Flags);

    KeSetEvent(&(WorkItem->Event), 0, FALSE);

	spin_lock(&(tconn->kstc_lock));
	cfs_clear_flag(tconn->kstc_flags, KS_TCONN_DISCONNECT_BUSY);
	spin_unlock(&(tconn->kstc_lock));
	ks_put_tconn(tconn);
}


/*
 * KsDisconnectEventHandler
 *   Disconnect event handler event handler, called by the underlying TDI transport
 *   in response to an incoming disconnection notification from a remote node.
 *
 * Arguments:
 *   ConnectionContext:  tdi connnection object
 *   DisconnectFlags:    specifies the nature of the disconnection
 *   ......
 *
 * Return Value:
 *   Nt kernel status code
 *
 * Notes:
 *   N/A
 */


NTSTATUS
KsDisconnectEventHandler(
    IN PVOID                TdiEventContext,
    IN CONNECTION_CONTEXT   ConnectionContext,
    IN LONG                 DisconnectDataLength,
    IN PVOID                DisconnectData,
    IN LONG                 DisconnectInformationLength,
    IN PVOID                DisconnectInformation,
    IN ULONG                DisconnectFlags
    )
{
    ks_tconn_t *            tconn;
    NTSTATUS                Status;
    PKS_DISCONNECT_WORKITEM WorkItem;

    tconn = (ks_tconn_t *)ConnectionContext;

    KsPrint((2, "KsTcpDisconnectEventHandler: called at Irql: %xh\n",
                KeGetCurrentIrql() ));

    KsPrint((2, "tconn = %x DisconnectFlags= %xh\n",
                 tconn, DisconnectFlags));

    ks_get_tconn(tconn);
    spin_lock(&(tconn->kstc_lock));

    WorkItem = &(tconn->kstc_disconnect);

    if (tconn->kstc_state != ksts_connected) {

        Status = STATUS_SUCCESS;

    } else {

        if (cfs_is_flag_set(DisconnectFlags, TDI_DISCONNECT_ABORT)) {

            Status = STATUS_REMOTE_DISCONNECT;

        } else if (cfs_is_flag_set(DisconnectFlags, TDI_DISCONNECT_RELEASE)) {

            Status = STATUS_GRACEFUL_DISCONNECT;
        }

        if (!cfs_is_flag_set(tconn->kstc_flags, KS_TCONN_DISCONNECT_BUSY)) {

            ks_get_tconn(tconn);

            WorkItem->Flags = DisconnectFlags;
            WorkItem->tconn = tconn;

            cfs_set_flag(tconn->kstc_flags, KS_TCONN_DISCONNECT_BUSY);

            /* queue the workitem to call */
            ExQueueWorkItem(&(WorkItem->WorkItem), DelayedWorkQueue);
        }
    }

    spin_unlock(&(tconn->kstc_lock));
    ks_put_tconn(tconn);

    return  (Status);
}

NTSTATUS
KsTcpReceiveCompletionRoutine(
    IN PIRP                         Irp,
    IN PKS_TCP_COMPLETION_CONTEXT   Context
    )
{
    ks_tconn_t *tconn = Context->tconn;
    NTSTATUS    status = Irp->IoStatus.Status;
    ULONG       length = (ULONG)Irp->IoStatus.Information;

    LASSERT(Context != NULL);

    if (NT_SUCCESS(status)) {

        PKS_TSDUMGR  TsduMgr = Context->TsduMgr;
        PCHAR        Buffer = Context->Buffer;

        KsPrint((4, "KsTcpReceiveCompletionRoutine: Total %xh bytes.\n",
                    TsduMgr->TotalBytes ));

        ks_lock_tsdumgr(TsduMgr);
        KsWriteTsduBuf(TsduMgr, Context->Buffer, length, 0);
        /* signal TsduMgr event */
        KeSetEvent(&(Context->TsduMgr->Event), 0, FALSE);
        ks_unlock_tsdumgr(TsduMgr);

        /* re-active the ks connection and wake up the scheduler */
        if (KS_CAN_SCHED(TsduMgr)) {
            if (tconn->kstc_conn && tconn->kstc_sched_cb) {
                tconn->kstc_sched_cb(tconn, FALSE);
            }
        }

        ks_put_tconn(tconn);

    } else {

        /* un-expected errors occur, we must abort the connection */
        ks_put_tconn(tconn);
        ks_abort_tconn(tconn);
    }


    if (Context) {

        /* free the Context structure... */
        ASSERT(Context->Magic == KS_TCP_CONTEXT_MAGIC);
        Context->Magic = 'CDAB';
        cfs_free(Context);
    }

    /* free the Irp */
    if (Irp) {

        /* release mdl chain */
        if (Irp->MdlAddress) {
            KsReleaseMdl(Irp->MdlAddress, FALSE);
        }

        /* free irp packet */
        IoFreeIrp(Irp);
    }

    return (status);
}


/*
 * KsTcpCompletionRoutine
 *   the Irp completion routine for TdiBuildSend and TdiBuildReceive ...
 *   We need call the use's own CompletionRoutine if specified. Or
 *   it's a synchronous case, we need signal the event.
 *
 * Arguments:
 *   DeviceObject:  the device object of the transport
 *   Irp:           the Irp is being completed.
 *   Context:       the context we specified when issuing the Irp
 *
 * Return Value:
 *   Nt status code
 *
 * Notes:
 *   N/A
 */

NTSTATUS
KsTcpCompletionRoutine(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp,
    IN PVOID            Context
    )
{
    if (Context) {

        PKS_TCP_COMPLETION_CONTEXT  context = NULL;
        ks_tconn_t * tconn = NULL;

        context = (PKS_TCP_COMPLETION_CONTEXT) Context;
        ASSERT(context->Magic == KS_TCP_CONTEXT_MAGIC);
        tconn = context->tconn;

        if (context->CompletionRoutine) {

            //
            // Giving control to user specified CompletionRoutine ...
            //

            context->CompletionRoutine(Irp, context);

        } else {

            //
            // Signaling  the Event ...
            //
            LASSERT(NULL != context->Event);
            KeSetEvent(context->Event, 0, FALSE);

            /* drop the reference count of the tconn object */
            ks_put_tconn(tconn);
        }

    } else {

        /* cfs_enter_debugger(); */
    }

    return STATUS_MORE_PROCESSING_REQUIRED;
}

/*
 * KsTcpSendCompletionRoutine
 *   the user specified Irp completion routine for asynchronous
 *   data transmission requests.
 *
 *   It will do th cleanup job of the ks_tx_t and wake up the
 *   ks scheduler thread
 *
 * Arguments:
 *   Irp:           the Irp is being completed.
 *   Context:       the context we specified when issuing the Irp
 *
 * Return Value:
 *   Nt status code
 *
 * Notes:
 *   N/A
 */

NTSTATUS
KsTcpSendCompletionRoutine(
    IN PIRP                         Irp,
    IN PKS_TCP_COMPLETION_CONTEXT   context
    )
{
    NTSTATUS          status = Irp->IoStatus.Status;
    ULONG             rc = (ULONG)(ULONG_PTR)Irp->IoStatus.Information;
    ks_tconn_t *      tconn = context->tconn;

    PKS_TSDUMGR       TsduMgr = context->TsduMgr;
    PKEVENT           Event = context->Event;

    LASSERT(tconn != NULL && tconn->kstc_magic == KS_TCONN_MAGIC);
    LASSERT(context && context->Magic == KS_TCP_CONTEXT_MAGIC);

    KsPrint((4, "KsTcpSendCompltionRoutine: tconn = %p TsduMgr = %p "
                "status = %xh bytes = %xh/%x\n", tconn, TsduMgr, status,
                Irp->IoStatus.Information, TsduMgr->TotalBytes));

    ks_lock_tsdumgr(TsduMgr);

    if (NT_SUCCESS(status)) {

        /* cleanup processed TsduMgr queue */
        KsReleaseTsdus(tconn, TsduMgr, rc);

        /* queue to delivery engine if there's still remained data */
        TsduMgr->Busy = FALSE;
        if (TsduMgr->TotalBytes > 0) {
            KsQueueTdiEngine(tconn, TsduMgr);
        }
        /* signal TsduMgr event */
        KeSetEvent(&(TsduMgr->Event), 0, FALSE);
        ks_unlock_tsdumgr(TsduMgr);

        /*
         * now it's time to re-queue the conns into the
         * scheduler queue and wake the scheduler thread.
         */

        if (tconn->kstc_conn && tconn->kstc_sched_cb) {
            tconn->kstc_sched_cb(tconn, TRUE);
        }

    } else {

        ks_unlock_tsdumgr(TsduMgr);

        KsPrint((1, "KsTcpSendCompltionRoutine: failed tconn: %p "
                    "TsduMgr: %p status: %xh\n", tconn, TsduMgr, status));

        /* cfs_enter_debugger(); */

        /*
         *  for the case that the transmission is unsuccessful,
         *  we need abort the tdi connection, but not destroy it.
         *  the socknal conn will drop the refer count, then the
         *  tdi connection will be freed.
         */

        ks_abort_tconn(tconn);
    }

    /* drop tconn reference */
    ks_put_tconn(tconn);

    /* freeing the context structure */
    if (context) {
        ASSERT(context->Magic == KS_TCP_CONTEXT_MAGIC);
        context->Magic = 'CDAB';
        cfs_free(context);
    }

    /* free the Irp structure */
    if (Irp) {
        /* mdl chain was released by KsReleaseTsdus*/
        Irp->MdlAddress = NULL;
        IoFreeIrp(Irp);
        Irp = NULL;
    }

    return status;
}

/*
 *  Normal receive event handler
 *
 *  It will move data from system Tsdu to our TsduList
 */

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
   )
{
    NTSTATUS            status;

    ks_tconn_t *        tconn;

    BOOLEAN             bIsExpedited;
    BOOLEAN             bIsCompleteTsdu;

    PCHAR               Buffer = NULL;
    PIRP                Irp = NULL;
    PMDL                Mdl = NULL;
    PFILE_OBJECT        FileObject;
    PDEVICE_OBJECT      DeviceObject;
    PKS_TSDUMGR         TsduMgr;

    PKS_TCP_COMPLETION_CONTEXT context = NULL;

    tconn = (ks_tconn_t *) ConnectionContext;
    ks_get_tconn(tconn);

    /* check expedited flag */
    bIsExpedited = cfs_is_flag_set(ReceiveFlags, TDI_RECEIVE_EXPEDITED);

    /* check whether the whole body of payload is received or not */
    if ( (cfs_is_flag_set(ReceiveFlags, TDI_RECEIVE_ENTIRE_MESSAGE)) &&
         (BytesIndicated == BytesAvailable) ) {
        bIsCompleteTsdu = TRUE;
    } else {
        bIsCompleteTsdu = FALSE;
    }

    KsPrint((4, "KsTcpReceiveEventHandler BytesIndicated = %d BytesAvailable = %d ...\n",
                BytesIndicated, BytesAvailable));
    KsPrint((4, "bIsCompleteTsdu = %d bIsExpedited = %d\n", bIsCompleteTsdu, bIsExpedited ));

    /* check whether we are conntected or not listener */
    if ( !((tconn->kstc_state == ksts_connected) &&
           (tconn->kstc_type == kstt_sender ||
            tconn->kstc_type == kstt_child))) {

        *BytesTaken = BytesIndicated;
        ks_put_tconn(tconn);
        return (STATUS_SUCCESS);
    }

    /* query tsdu mgr */
    TsduMgr = KsQueryTsduMgr(tconn, bIsExpedited, FALSE);

    ks_lock_tsdumgr(TsduMgr);
    if (bIsCompleteTsdu) {

        *BytesTaken = KsWriteTsduDat(TsduMgr, Tsdu, BytesAvailable, 0);
        status = STATUS_SUCCESS;

        /* signal TsduMgr event */
        KeSetEvent(&(TsduMgr->Event), 0, FALSE);
        ks_unlock_tsdumgr(TsduMgr);

        /* re-active the ks connection and wake up the scheduler */
        if (KS_CAN_SCHED(TsduMgr)) {
            if (tconn->kstc_conn && tconn->kstc_sched_cb) {
                tconn->kstc_sched_cb(tconn, FALSE);
            }
        }

    } else {

        ks_unlock_tsdumgr(TsduMgr);

        /* allocate buffer for further data in tsdu queue */
        Buffer = ExAllocatePool(NonPagedPool, BytesAvailable);
        if (NULL == Buffer) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto errorout;
        }

        /* there's still data in tdi internal queue, we need issue a new
           Irp to receive all of them. first allocate the tcp context */
        context = cfs_alloc(sizeof(KS_TCP_COMPLETION_CONTEXT), 0);
        if (!context) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto errorout;
        }

        /* setup the context */
        RtlZeroMemory(context, sizeof(KS_TCP_COMPLETION_CONTEXT));
        context->Magic             = KS_TCP_CONTEXT_MAGIC;
        context->tconn             = tconn;
        context->CompletionRoutine = KsTcpReceiveCompletionRoutine;
        context->CompletionContext = Buffer;
        context->TsduMgr           = TsduMgr;
        context->Buffer            = Buffer;
        context->Event             = &(TsduMgr->Event);

        if (tconn->kstc_type == kstt_sender) {
            FileObject = tconn->sender.kstc_info.FileObject;
        } else {
            FileObject = tconn->child.kstc_info.FileObject;
        }
        DeviceObject = IoGetRelatedDeviceObject(FileObject);

        /* build new tdi Irp and setup it. */
        Irp = KsBuildTdiIrp(DeviceObject);
        if (NULL == Irp) {
            goto errorout;
        }

        status = KsLockUserBuffer(
                    Buffer,
                    FALSE,
                    BytesAvailable,
                    IoModifyAccess,
                    &Mdl
                    );

        if (!NT_SUCCESS(status)) {
            goto errorout;
        }

        TdiBuildReceive(
            Irp,
            DeviceObject,
            FileObject,
            KsTcpCompletionRoutine,
            context,
            Mdl,
            ReceiveFlags & (TDI_RECEIVE_NORMAL | TDI_RECEIVE_EXPEDITED),
            BytesAvailable
          );

        IoSetNextIrpStackLocation(Irp);

        /* return the newly built Irp to transport driver,
           it will process it to receive all the data */

        *IoRequestPacket = Irp;
        *BytesTaken = 0;

        ks_get_tconn(tconn);
        status = STATUS_MORE_PROCESSING_REQUIRED;
    }

    ks_put_tconn(tconn);

    return (status);

errorout:

    if (Mdl) {
        KsReleaseMdl(Mdl, FALSE);
    }

    if (Buffer) {
        ExFreePool(Buffer);
    }

    if (Irp) {
        IoFreeIrp(Irp);
    }

    if (context) {
        ASSERT(context->Magic == KS_TCP_CONTEXT_MAGIC);
        context->Magic = 'CDAB';
        cfs_free(context);
    }

    ks_abort_tconn(tconn);
    ks_put_tconn(tconn);

    *BytesTaken = BytesAvailable;

    return STATUS_SUCCESS;
}

/*
 *  Expedited receive event handler
 */

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
    )
{
    return KsTcpReceiveEventHandler(
                TdiEventContext,
                ConnectionContext,
                ReceiveFlags | TDI_RECEIVE_EXPEDITED,
                BytesIndicated,
                BytesAvailable,
                BytesTaken,
                Tsdu,
                IoRequestPacket
                );
}

/*
 *  Bulk receive event handler
 *
 *  It will queue all the system Tsdus to our TsduList.
 *  Then later ks_recv_mdl will release them.
 */

NTSTATUS
KsTcpChainedReceiveEventHandler (
    IN PVOID TdiEventContext,       // the event context
    IN CONNECTION_CONTEXT ConnectionContext,
    IN ULONG ReceiveFlags,
    IN ULONG ReceiveLength,
    IN ULONG StartingOffset,        // offset of start of client data in TSDU
    IN PMDL  Tsdu,                  // TSDU data chain
    IN PVOID TsduDescriptor         // for call to TdiReturnChainedReceives
    )
{

    NTSTATUS            status;
    ks_tconn_t *        tconn;

    PKS_TSDUMGR         TsduMgr;

    BOOLEAN             expedited;

    tconn = (ks_tconn_t *) ConnectionContext;
    expedited = cfs_is_flag_set(ReceiveFlags, TDI_RECEIVE_EXPEDITED);

    KsPrint((4, "KsTcpChainedReceive: sock: %p conn: %p ReceiveLength: %xh "
                "bIsExpedited: %d Tsdu=%p TsduDesc=%p data=%xh\n",
                 tconn, tconn->kstc_conn, ReceiveLength, expedited,
                 Tsdu, TsduDescriptor, *((PULONG)KsMapMdlBuffer(Tsdu))));

    ks_get_tconn(tconn);

    /* check whether we are conntected or not listener */
    if ( !((tconn->kstc_state == ksts_connected) &&
         (tconn->kstc_type == kstt_sender ||
          tconn->kstc_type == kstt_child))) {

        ks_put_tconn(tconn);
        return (STATUS_SUCCESS);
    }

    if (Tsdu) {

        TsduMgr = KsQueryTsduMgr(tconn, expedited, FALSE);
        ks_lock_tsdumgr(TsduMgr);
#if FALSE
        KsWriteTsduMdl(TsduMgr, Tsdu,  TsduDescriptor,
                       StartingOffset, ReceiveLength, 0);
        status = STATUS_PENDING;
#else
        KsWriteTsduDat(TsduMgr, (PCHAR)KsMapMdlBuffer(Tsdu) + 
                       StartingOffset, ReceiveLength, 0);
        status = STATUS_SUCCESS;
#endif
        KeSetEvent(&(TsduMgr->Event), 0, FALSE);
        ks_unlock_tsdumgr(TsduMgr);

        /* re-active the ks connection and wake up the scheduler */
        if (KS_CAN_SCHED(TsduMgr)) {
            if (tconn->kstc_conn && tconn->kstc_sched_cb) {
                tconn->kstc_sched_cb(tconn, FALSE);
            }
        }

    } else {

        ks_abort_tconn(tconn);
        status = STATUS_CONNECTION_ABORTED;
    }

    ks_put_tconn(tconn);

    /* Return STATUS_PENDING to system because we are still
       owning the MDL resources. ks_recv_mdl is expected
       to free the MDL resources. */

    return (status);
}


/*
 *  Expedited & Bulk receive event handler
 */

NTSTATUS
KsTcpChainedReceiveExpeditedEventHandler (
    IN PVOID                TdiEventContext,       // the event context
    IN CONNECTION_CONTEXT   ConnectionContext,
    IN ULONG                ReceiveFlags,
    IN ULONG                ReceiveLength,
    IN ULONG                StartingOffset,        // offset of start of client data in TSDU
    IN PMDL                 Tsdu,                  // TSDU data chain
    IN PVOID                TsduDescriptor         // for call to TdiReturnChainedReceives
    )
{
    return KsTcpChainedReceiveEventHandler(
                TdiEventContext,
                ConnectionContext,
                ReceiveFlags | TDI_RECEIVE_EXPEDITED,
                ReceiveLength,
                StartingOffset,
                Tsdu,
                TsduDescriptor );
}


/*
 * KsSetHandlers
 *   setup all the event handler callbacks
 *
 * Arguments:
 *   tconn: the tdi connecton object
 *
 * Return Value:
 *   int: ks error code
 *
 * NOTES:
 *   N/A
 */

int
KsSetHandlers(
    ks_tconn_t *     tconn
    )
{
    NTSTATUS            status = STATUS_SUCCESS;
    KS_EVENT_HANDLERS   handlers;

    /* to make sure the address object is opened already */
    if (tconn->kstc_addr.FileObject == NULL) {
        goto errorout;
    }

    /* initialize the handlers indictor array. for sender and listenr,
       there are different set of callbacks. for child, we just return. */

    memset(&handlers, 0, sizeof(KS_EVENT_HANDLERS));

    SetEventHandler(handlers, TDI_EVENT_ERROR, KsErrorEventHandler);
    SetEventHandler(handlers, TDI_EVENT_DISCONNECT, KsDisconnectEventHandler);
    SetEventHandler(handlers, TDI_EVENT_RECEIVE, KsTcpReceiveEventHandler);
    SetEventHandler(handlers, TDI_EVENT_RECEIVE_EXPEDITED, KsTcpReceiveExpeditedEventHandler);
    SetEventHandler(handlers, TDI_EVENT_CHAINED_RECEIVE, KsTcpChainedReceiveEventHandler);

    // SetEventHandler(handlers, TDI_EVENT_CHAINED_RECEIVE_EXPEDITED, KsTcpChainedReceiveExpeditedEventHandler);

    if (tconn->kstc_type == kstt_listener) {
        SetEventHandler(handlers, TDI_EVENT_CONNECT, KsConnectEventHandler);
    } else if (tconn->kstc_type == kstt_child) {
        goto errorout;
    }

    /* set all the event callbacks */
    status = KsSetEventHandlers(
                tconn->kstc_addr.FileObject, /* Address File Object  */
                tconn,                       /* Event Context */
                &handlers                    /* Event callback handlers */
                );

errorout:

    return cfs_error_code(status);
}


/*
 * KsResetHandlers
 *   disable all the event handler callbacks (set to NULL)
 *
 * Arguments:
 *   tconn: the tdi connecton object
 *
 * Return Value:
 *   int: ks error code
 *
 * NOTES:
 *   N/A
 */

int
KsResetHandlers(
    ks_tconn_t *     tconn
    )
{
    NTSTATUS            status = STATUS_SUCCESS;
    KS_EVENT_HANDLERS   handlers;

    /* to make sure the address object is opened already */
    if (tconn->kstc_addr.FileObject == NULL) {
        goto errorout;
    }

    /* initialize the handlers indictor array. for sender and listenr,
       there are different set of callbacks. for child, we just return. */

    memset(&handlers, 0, sizeof(KS_EVENT_HANDLERS));

    SetEventHandler(handlers, TDI_EVENT_ERROR, NULL);
    SetEventHandler(handlers, TDI_EVENT_DISCONNECT, NULL);
    SetEventHandler(handlers, TDI_EVENT_RECEIVE, NULL);
    SetEventHandler(handlers, TDI_EVENT_RECEIVE_EXPEDITED, NULL);
    SetEventHandler(handlers, TDI_EVENT_CHAINED_RECEIVE, NULL);
    // SetEventHandler(handlers, TDI_EVENT_CHAINED_RECEIVE_EXPEDITED, NULL);

    if (tconn->kstc_type == kstt_listener) {
        SetEventHandler(handlers, TDI_EVENT_CONNECT, NULL);
    } else if (tconn->kstc_type == kstt_child) {
        goto errorout;
    }

    /* set all the event callbacks */
    status = KsSetEventHandlers(
                tconn->kstc_addr.FileObject, /* Address File Object  */
                tconn,                       /* Event Context */
                &handlers                    /* Event callback handlers */
                );

errorout:

    return cfs_error_code(status);
}

VOID
KsPrintProviderInfo(
   PWSTR DeviceName,
   PTDI_PROVIDER_INFO ProviderInfo
   )
{
    KsPrint((2, "%ws ProviderInfo:\n", DeviceName));

    KsPrint((2, "  Version              : 0x%4.4X\n", ProviderInfo->Version ));
    KsPrint((2, "  MaxSendSize          : %d\n", ProviderInfo->MaxSendSize ));
    KsPrint((2, "  MaxConnectionUserData: %d\n", ProviderInfo->MaxConnectionUserData ));
    KsPrint((2, "  MaxDatagramSize      : %d\n", ProviderInfo->MaxDatagramSize ));
    KsPrint((2, "  ServiceFlags         : 0x%8.8X\n", ProviderInfo->ServiceFlags ));

    if (ProviderInfo->ServiceFlags & TDI_SERVICE_CONNECTION_MODE) {
        KsPrint((2, "  CONNECTION_MODE\n"));
    }

    if (ProviderInfo->ServiceFlags & TDI_SERVICE_ORDERLY_RELEASE) {
        KsPrint((2, "  ORDERLY_RELEASE\n"));
    }

    if (ProviderInfo->ServiceFlags & TDI_SERVICE_CONNECTIONLESS_MODE) {
        KsPrint((2, "  CONNECTIONLESS_MODE\n"));
    }

    if (ProviderInfo->ServiceFlags & TDI_SERVICE_ERROR_FREE_DELIVERY) {
        KsPrint((2, "  ERROR_FREE_DELIVERY\n"));
    }

    if( ProviderInfo->ServiceFlags & TDI_SERVICE_SECURITY_LEVEL ) {
        KsPrint((2, "  SECURITY_LEVEL\n"));
    }

    if (ProviderInfo->ServiceFlags & TDI_SERVICE_BROADCAST_SUPPORTED) {
        KsPrint((2, "  BROADCAST_SUPPORTED\n"));
    }

    if (ProviderInfo->ServiceFlags & TDI_SERVICE_MULTICAST_SUPPORTED) {
        KsPrint((2, "  MULTICAST_SUPPORTED\n"));
    }

    if (ProviderInfo->ServiceFlags & TDI_SERVICE_DELAYED_ACCEPTANCE) {
        KsPrint((2, "  DELAYED_ACCEPTANCE\n"));
    }

    if (ProviderInfo->ServiceFlags & TDI_SERVICE_EXPEDITED_DATA) {
        KsPrint((2, "  EXPEDITED_DATA\n"));
    }

    if( ProviderInfo->ServiceFlags & TDI_SERVICE_INTERNAL_BUFFERING) {
        KsPrint((2, "  INTERNAL_BUFFERING\n"));
    }

    if (ProviderInfo->ServiceFlags & TDI_SERVICE_ROUTE_DIRECTED) {
        KsPrint((2, "  ROUTE_DIRECTED\n"));
    }

    if (ProviderInfo->ServiceFlags & TDI_SERVICE_NO_ZERO_LENGTH) {
        KsPrint((2, "  NO_ZERO_LENGTH\n"));
    }

    if (ProviderInfo->ServiceFlags & TDI_SERVICE_POINT_TO_POINT) {
        KsPrint((2, "  POINT_TO_POINT\n"));
    }

    if (ProviderInfo->ServiceFlags & TDI_SERVICE_MESSAGE_MODE) {
        KsPrint((2, "  MESSAGE_MODE\n"));
    }

    if (ProviderInfo->ServiceFlags & TDI_SERVICE_HALF_DUPLEX) {
        KsPrint((2, "  HALF_DUPLEX\n"));
    }

    KsPrint((2, "  MinimumLookaheadData : %d\n", ProviderInfo->MinimumLookaheadData ));
    KsPrint((2, "  MaximumLookaheadData : %d\n", ProviderInfo->MaximumLookaheadData ));
    KsPrint((2, "  NumberOfResources    : %d\n", ProviderInfo->NumberOfResources ));
}


/*
 * ks_create_tconn
 *   allocate a new tconn structure from the SLAB cache or
 *   NonPaged sysetm pool
 *
 * Arguments:
 *   N/A
 *
 * Return Value:
 *   ks_tconn_t *: the address of tconn or NULL if it fails
 *
 * NOTES:
 *   N/A
 */

ks_tconn_t *
ks_create_tconn()
{
    ks_tconn_t * tconn = NULL;

    /* allocate ksoc_tconn_t from the slab cache memory */
    tconn = (ks_tconn_t *)cfs_mem_cache_alloc(
                ks_data.ksnd_tconn_slab, CFS_ALLOC_ZERO);

    if (tconn) {

        /* zero tconn elements */
        memset(tconn, 0, sizeof(ks_tconn_t));

        /* initialize the tconn ... */
        tconn->kstc_magic = KS_TCONN_MAGIC;

        ExInitializeWorkItem(
                &(tconn->kstc_disconnect.WorkItem),
                KsDisconnectHelper,
                &(tconn->kstc_disconnect)
                );

        KeInitializeEvent(
                &(tconn->kstc_disconnect.Event),
                SynchronizationEvent,
                FALSE );

        ExInitializeWorkItem(
                &(tconn->kstc_destroy),
                ks_destroy_tconn,
                tconn
            );

	spin_lock_init(&(tconn->kstc_lock));

        ks_get_tconn(tconn);
	spin_lock(&(ks_data.ksnd_tconn_lock));

        /* attach it into global list in ks_data */

        cfs_list_add(&(tconn->kstc_list), &(ks_data.ksnd_tconns));
        ks_data.ksnd_ntconns++;
	spin_unlock(&(ks_data.ksnd_tconn_lock));

        tconn->kstc_rcv_wnd = tconn->kstc_snd_wnd = 0x10000;
    }
    KsPrint((3, "ks_create_tconn: new connection: %p\n", tconn));
    return (tconn);
}

/*
 * ks_free_tconn
 *   free the tconn structure to the SLAB cache or NonPaged
 *   sysetm pool
 *
 * Arguments:
 *   tconn:  the tcon is to be freed
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

void
ks_free_tconn(ks_tconn_t * tconn)
{
    LASSERT(cfs_atomic_read(&(tconn->kstc_refcount)) == 0);

	spin_lock(&(ks_data.ksnd_tconn_lock));

    /* remove it from the global list */
    cfs_list_del(&tconn->kstc_list);
    ks_data.ksnd_ntconns--;

    /* if this is the last tconn, it would be safe for
       ks_tdi_fini_data to quit ... */
    if (ks_data.ksnd_ntconns == 0) {
        cfs_wake_event(&ks_data.ksnd_tconn_exit);
    }
	spin_unlock(&(ks_data.ksnd_tconn_lock));

    /* free the structure memory */
    cfs_mem_cache_free(ks_data.ksnd_tconn_slab, tconn);

    KsPrint((3, "ks_free_tconn: tconn %p is freed.\n", tconn));
}


/*
 * ks_init_listener
 *   Initialize the tconn as a listener (daemon)
 *
 * Arguments:
 *   tconn: the listener tconn
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

void
ks_init_listener(
    ks_tconn_t * tconn
    )
{
    /* preparation: intialize the tconn members */

    tconn->kstc_type = kstt_listener;

    RtlInitUnicodeString(&(tconn->kstc_dev), TCP_DEVICE_NAME);

    CFS_INIT_LIST_HEAD(&(tconn->listener.kstc_listening.list));
    CFS_INIT_LIST_HEAD(&(tconn->listener.kstc_accepted.list));

    cfs_init_event( &(tconn->listener.kstc_accept_event),
                    TRUE,
                    FALSE );

    cfs_init_event( &(tconn->listener.kstc_destroy_event),
                    TRUE,
                    FALSE );

    tconn->kstc_state = ksts_inited;
}


/*
 * ks_init_sender
 *   Initialize the tconn as a sender
 *
 * Arguments:
 *   tconn: the sender tconn
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

void
ks_init_sender(
    ks_tconn_t * tconn
    )
{
    tconn->kstc_type = kstt_sender;
    RtlInitUnicodeString(&(tconn->kstc_dev), TCP_DEVICE_NAME);

    KsInitializeKsChain(&(tconn->sender.kstc_recv));
    KsInitializeKsChain(&(tconn->sender.kstc_send));

    tconn->kstc_snd_wnd = TDINAL_WINDOW_DEFAULT_SIZE;
    tconn->kstc_rcv_wnd = TDINAL_WINDOW_DEFAULT_SIZE;

    tconn->kstc_state = ksts_inited;
}

/*
 * ks_init_child
 *   Initialize the tconn as a child
 *
 * Arguments:
 *   tconn: the child tconn
 *
 * Return Value:
 *   N/A
 *
 * NOTES:
 *   N/A
 */

void
ks_init_child(
    ks_tconn_t * tconn
    )
{
    tconn->kstc_type = kstt_child;
    RtlInitUnicodeString(&(tconn->kstc_dev), TCP_DEVICE_NAME);

    KsInitializeKsChain(&(tconn->child.kstc_recv));
    KsInitializeKsChain(&(tconn->child.kstc_send));

    tconn->kstc_snd_wnd = TDINAL_WINDOW_DEFAULT_SIZE;
    tconn->kstc_rcv_wnd = TDINAL_WINDOW_DEFAULT_SIZE;

    tconn->kstc_state = ksts_inited;
}

/*
 * ks_get_tconn
 *   increase the reference count of the tconn with 1
 *
 * Arguments:
 *   tconn: the tdi connection to be referred
 *
 * Return Value:
 *   N/A
 *
 * NOTES:
 *   N/A
 */

void
ks_get_tconn(
    ks_tconn_t * tconn
    )
{
    cfs_atomic_inc(&(tconn->kstc_refcount));
}

/*
 * ks_put_tconn
 *   decrease the reference count of the tconn and destroy
 *   it if the refercount becomes 0.
 *
 * Arguments:
 *   tconn: the tdi connection to be dereferred
 *
 * Return Value:
 *   N/A
 *
 * NOTES:
 *   N/A
 */

void
ks_put_tconn(
    ks_tconn_t *tconn
    )
{
    if (cfs_atomic_dec_and_test(&(tconn->kstc_refcount))) {

	spin_lock(&(tconn->kstc_lock));

        if ( ( tconn->kstc_type == kstt_child ||
               tconn->kstc_type == kstt_sender ) &&
             ( tconn->kstc_state == ksts_connected ) ) {

	    spin_unlock(&(tconn->kstc_lock));

            ks_abort_tconn(tconn);

        } else {

            if (cfs_is_flag_set(tconn->kstc_flags, KS_TCONN_DESTROY_BUSY)) {
                cfs_enter_debugger();
            } else {
                ExQueueWorkItem(
                        &(tconn->kstc_destroy),
                        DelayedWorkQueue
                        );

                cfs_set_flag(tconn->kstc_flags, KS_TCONN_DESTROY_BUSY);
            }

	    spin_unlock(&(tconn->kstc_lock));
        }
    }
}

/*
 * ks_destroy_tconn
 *   cleanup the tdi connection and free it
 *
 * Arguments:
 *   tconn: the tdi connection to be cleaned.
 *
 * Return Value:
 *   N/A
 *
 * NOTES:
 *   N/A
 */

void
ks_destroy_tconn(
    ks_tconn_t *     tconn
    )
{
    LASSERT(tconn->kstc_refcount.counter == 0);

    if (tconn->kstc_type == kstt_listener) {

        KsResetHandlers(tconn);

        /* for listener, we just need to close the address object */
        KsCloseAddress(
                tconn->kstc_addr.Handle,
                tconn->kstc_addr.FileObject
                );

        tconn->kstc_state = ksts_inited;

    } else if (tconn->kstc_type == kstt_child) {

        /* for child tdi conections */

        /* disassociate the relation between it's connection object
           and the address object */

        if (tconn->kstc_state == ksts_associated) {
            KsDisassociateAddress(
                tconn->child.kstc_info.FileObject
                );
        }

        /* release the connection object */

        KsCloseConnection(
                tconn->child.kstc_info.Handle,
                tconn->child.kstc_info.FileObject
                );

        /* release it's refer of it's parent's address object */
        KsCloseAddress(
                NULL,
                tconn->kstc_addr.FileObject
                );

	spin_lock(&tconn->child.kstc_parent->kstc_lock);
	spin_lock(&tconn->kstc_lock);

        tconn->kstc_state = ksts_inited;

        /* remove it frome it's parent's queues */

        if (tconn->child.kstc_queued) {

            cfs_list_del(&(tconn->child.kstc_link));

            if (tconn->child.kstc_queueno) {

                LASSERT(tconn->child.kstc_parent->listener.kstc_accepted.num > 0);
                tconn->child.kstc_parent->listener.kstc_accepted.num -= 1;

            } else {

                LASSERT(tconn->child.kstc_parent->listener.kstc_listening.num > 0);
                tconn->child.kstc_parent->listener.kstc_listening.num -= 1;
            }

            tconn->child.kstc_queued = FALSE;
        }

	spin_unlock(&tconn->kstc_lock);
	spin_unlock(&tconn->child.kstc_parent->kstc_lock);

        /* drop the reference of the parent tconn */
        ks_put_tconn(tconn->child.kstc_parent);

    } else if (tconn->kstc_type == kstt_sender) {

        KsResetHandlers(tconn);

        /* release the connection object */

        KsCloseConnection(
                tconn->sender.kstc_info.Handle,
                tconn->sender.kstc_info.FileObject
                );

        /* release it's refer of it's parent's address object */
        KsCloseAddress(
                tconn->kstc_addr.Handle,
                tconn->kstc_addr.FileObject
                );

        tconn->kstc_state = ksts_inited;

    } else {
        cfs_enter_debugger();
    }

    /* free the tconn structure ... */

    ks_free_tconn(tconn);
}

/*
 * ks_get_tcp_option
 *   Query the the options of the tcp stream connnection
 *
 * Arguments:
 *   tconn:         the tdi connection
 *   ID:            option id
 *   OptionValue:   buffer to store the option value
 *   Length:        the length of the value, to be returned
 *
 * Return Value:
 *   int:           ks return code
 *
 * NOTES:
 *   N/A
 */

int
ks_get_tcp_option (
    ks_tconn_t *        tconn,
    ULONG               ID,
    PVOID               OptionValue,
    PULONG              Length
    )
{
    NTSTATUS            Status = STATUS_SUCCESS;

    IO_STATUS_BLOCK     IoStatus;

    TCP_REQUEST_QUERY_INFORMATION_EX QueryInfoEx;

    PFILE_OBJECT        ConnectionObject;
    PDEVICE_OBJECT      DeviceObject = NULL;

    PIRP                Irp = NULL;
    PIO_STACK_LOCATION  IrpSp = NULL;

    KEVENT              Event;

    /* make sure the tdi connection is connected ? */

    ks_get_tconn(tconn);

    if (tconn->kstc_state != ksts_connected) {
        Status = STATUS_INVALID_PARAMETER;
        goto errorout;
    }

    LASSERT(tconn->kstc_type == kstt_sender ||
           tconn->kstc_type == kstt_child);

    if (tconn->kstc_type == kstt_sender) {
        ConnectionObject = tconn->sender.kstc_info.FileObject;
    } else {
        ConnectionObject = tconn->child.kstc_info.FileObject;
    }

    QueryInfoEx.ID.toi_id = ID;
    QueryInfoEx.ID.toi_type   = INFO_TYPE_CONNECTION;
    QueryInfoEx.ID.toi_class  = INFO_CLASS_PROTOCOL;
    QueryInfoEx.ID.toi_entity.tei_entity   = CO_TL_ENTITY;
    QueryInfoEx.ID.toi_entity.tei_instance = 0;

    RtlZeroMemory(&(QueryInfoEx.Context), CONTEXT_SIZE);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    DeviceObject = IoGetRelatedDeviceObject(ConnectionObject);

    Irp = IoBuildDeviceIoControlRequest(
                IOCTL_TCP_QUERY_INFORMATION_EX,
                DeviceObject,
                &QueryInfoEx,
                sizeof(TCP_REQUEST_QUERY_INFORMATION_EX),
                OptionValue,
                *Length,
                FALSE,
                &Event,
                &IoStatus
                );

    if (Irp == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto errorout;
    }

    IrpSp = IoGetNextIrpStackLocation(Irp);

    if (IrpSp == NULL) {

        IoFreeIrp(Irp);
        Irp = NULL;
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto errorout;
    }

    IrpSp->FileObject = ConnectionObject;
    IrpSp->DeviceObject = DeviceObject;

    Status = IoCallDriver(DeviceObject, Irp);

    if (Status == STATUS_PENDING) {

        KeWaitForSingleObject(
                &Event,
                Executive,
                KernelMode,
                FALSE,
                NULL
                );

        Status = IoStatus.Status;
    }


    if (NT_SUCCESS(Status)) {
        *Length = (ULONG)(ULONG_PTR)IoStatus.Information;
    } else {
        cfs_enter_debugger();
        memset(OptionValue, 0, *Length);
        Status = STATUS_SUCCESS;
    }

errorout:

    ks_put_tconn(tconn);

    return cfs_error_code(Status);
}

/*
 * ks_set_tcp_option
 *   Set the the options for the tcp stream connnection
 *
 * Arguments:
 *   tconn:     the tdi connection
 *   ID:        option id
 *   OptionValue: buffer containing the new option value
 *   Length:    the length of the value
 *
 * Return Value:
 *   int:       ks return code
 *
 * NOTES:
 *   N/A
 */

NTSTATUS
ks_set_tcp_option (
    ks_tconn_t *    tconn,
    ULONG           ID,
    PVOID           OptionValue,
    ULONG           Length
    )
{
    NTSTATUS            Status = STATUS_SUCCESS;

    IO_STATUS_BLOCK     IoStatus;

    ULONG               SetInfoExLength;
    PTCP_REQUEST_SET_INFORMATION_EX SetInfoEx = NULL;

    PFILE_OBJECT        ConnectionObject;
    PDEVICE_OBJECT      DeviceObject = NULL;

    PIRP                Irp = NULL;
    PIO_STACK_LOCATION  IrpSp = NULL;

    PKEVENT             Event;

    /* make sure the tdi connection is connected ? */

    ks_get_tconn(tconn);

    if (tconn->kstc_state != ksts_connected) {
        Status = STATUS_INVALID_PARAMETER;
        goto errorout;
    }

    LASSERT(tconn->kstc_type == kstt_sender ||
           tconn->kstc_type == kstt_child);

    if (tconn->kstc_type == kstt_sender) {
        ConnectionObject = tconn->sender.kstc_info.FileObject;
    } else {
        ConnectionObject = tconn->child.kstc_info.FileObject;
    }

    SetInfoExLength =  sizeof(TCP_REQUEST_SET_INFORMATION_EX) - 1 + Length + sizeof(KEVENT);

    SetInfoEx = ExAllocatePoolWithTag(
                    NonPagedPool,
                    SetInfoExLength,
                    'TSSK'
                    );

    if (SetInfoEx == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto errorout;
    }

    SetInfoEx->ID.toi_id = ID;

    SetInfoEx->ID.toi_type  = INFO_TYPE_CONNECTION;
    SetInfoEx->ID.toi_class = INFO_CLASS_PROTOCOL;
    SetInfoEx->ID.toi_entity.tei_entity   = CO_TL_ENTITY;
    SetInfoEx->ID.toi_entity.tei_instance = TL_INSTANCE;

    SetInfoEx->BufferSize = Length;
    RtlCopyMemory(&(SetInfoEx->Buffer[0]), OptionValue, Length);

    Event = (PKEVENT)(&(SetInfoEx->Buffer[Length]));
    KeInitializeEvent(Event, NotificationEvent, FALSE);

    DeviceObject = IoGetRelatedDeviceObject(ConnectionObject);

    Irp = IoBuildDeviceIoControlRequest(
                IOCTL_TCP_SET_INFORMATION_EX,
                DeviceObject,
                SetInfoEx,
                SetInfoExLength,
                NULL,
                0,
                FALSE,
                Event,
                &IoStatus
                );

    if (Irp == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto errorout;
    }

    IrpSp = IoGetNextIrpStackLocation(Irp);

    if (IrpSp == NULL) {
        IoFreeIrp(Irp);
        Irp = NULL;
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto errorout;
    }

    IrpSp->FileObject = ConnectionObject;
    IrpSp->DeviceObject = DeviceObject;

    Status = IoCallDriver(DeviceObject, Irp);

    if (Status == STATUS_PENDING) {

        KeWaitForSingleObject(
                Event,
                Executive,
                KernelMode,
                FALSE,
                NULL
                );

        Status = IoStatus.Status;
    }

errorout:

    if (SetInfoEx) {
        ExFreePool(SetInfoEx);
    }

    if (!NT_SUCCESS(Status)) {
        KsPrint((0, "ks_set_tcp_option: error setup tcp option: "
                    "ID (%d) Status = %xh\n", ID, Status));
        Status = STATUS_SUCCESS;
    }

    ks_put_tconn(tconn);

    return cfs_error_code(Status);
}

/*
 * ks_bind_tconn
 *   bind the tdi connection object with an address
 *
 * Arguments:
 *   tconn:    tconn to be bound
 *   parent:   the parent tconn object
 *   ipaddr:   the ip address
 *   port:     the port number
 *
 * Return Value:
 *   int:   0 for success or ks error codes.
 *
 * NOTES:
 *   N/A
 */

int
ks_bind_tconn (
    ks_tconn_t *    tconn,
    ks_tconn_t *    parent,
    ulong           addr,
    unsigned short  port
    )
{
    NTSTATUS            status;
    int                 rc = 0;

    ks_tdi_addr_t    taddr;

    memset(&taddr, 0, sizeof(ks_tdi_addr_t));

    if (tconn->kstc_state != ksts_inited) {

        status = STATUS_INVALID_PARAMETER;
        rc = cfs_error_code(status);
        goto errorout;

    } else if (tconn->kstc_type == kstt_child) {

        if (NULL == parent) {
            status = STATUS_INVALID_PARAMETER;
            rc = cfs_error_code(status);

            goto errorout;
        }

        /* refer it's parent's address object */

        taddr = parent->kstc_addr;
        ObReferenceObject(taddr.FileObject);

        ks_get_tconn(parent);

    } else {

        PTRANSPORT_ADDRESS TdiAddress = &(taddr.Tdi);
        ULONG              AddrLen = 0;

        /* intialize the tdi address*/

        TdiAddress->TAAddressCount = 1;
        TdiAddress->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
        TdiAddress->Address[0].AddressType   = TDI_ADDRESS_TYPE_IP;

        ((PTDI_ADDRESS_IP)&(TdiAddress->Address[0].Address))->sin_port = htons(port);
        ((PTDI_ADDRESS_IP)&(TdiAddress->Address[0].Address))->in_addr = (ULONG)htonl(addr);

        memset(&(((PTDI_ADDRESS_IP)&(TdiAddress->Address[0].Address))->sin_zero[0]),0,8);


        /* open the transport address object */

        AddrLen = FIELD_OFFSET(TRANSPORT_ADDRESS, Address->Address) +
                  TDI_ADDRESS_LENGTH_IP;

        status = KsOpenAddress(
                    &(tconn->kstc_dev),
                    &(taddr.Tdi),
                    AddrLen,
                    &(taddr.Handle),
                    &(taddr.FileObject)
                    );

        if (!NT_SUCCESS(status)) {

            KsPrint((1, "ks_bind_tconn: failed to open ip addr object (%x:%d), status = %xh\n",
                        addr, port,  status ));
            rc = cfs_error_code(status);
            goto errorout;
        }
    }

    if (tconn->kstc_type == kstt_child) {
        tconn->child.kstc_parent = parent;
    }

    tconn->kstc_state = ksts_bind;
    tconn->kstc_addr  = taddr;

errorout:

    return (rc);
}

/*
 * ks_build_tconn
 *  build tcp/streaming connection to remote peer
 *
 * Arguments:
 *   tconn:    tconn to be connected to the peer
 *   addr:     the peer's ip address
 *   port:     the peer's port number
 *
 * Return Value:
 *   int:   0 for success or ks error codes.
 *
 * Notes:
 *   N/A
 */

int
ks_build_tconn(
    ks_tconn_t *                    tconn,
    ulong                           addr,
    unsigned short                  port
    )
{
    int                             rc = 0;
    NTSTATUS                        status = STATUS_SUCCESS;


    PFILE_OBJECT                    ConnectionObject = NULL;
    PDEVICE_OBJECT                  DeviceObject = NULL;

    PTDI_CONNECTION_INFORMATION     ConnectionInfo = NULL;
    ULONG                           AddrLength;

    PIRP                            Irp = NULL;

    LASSERT(tconn->kstc_type == kstt_sender);
    LASSERT(tconn->kstc_state == ksts_bind);

    ks_get_tconn(tconn);

    {
        /* set the event callbacks */
        rc = KsSetHandlers(tconn);

        if (rc < 0) {
            cfs_enter_debugger();
            goto errorout;
        }
    }

    /* create the connection file handle / object  */
    status = KsOpenConnection(
                &(tconn->kstc_dev),
                (CONNECTION_CONTEXT)tconn,
                &(tconn->sender.kstc_info.Handle),
                &(tconn->sender.kstc_info.FileObject)
                );

    if (!NT_SUCCESS(status)) {
        rc = cfs_error_code(status);
        cfs_enter_debugger();
        goto errorout;
    }

    /* associdate the the connection with the adress object of the tconn */

    status = KsAssociateAddress(
                tconn->kstc_addr.Handle,
                tconn->sender.kstc_info.FileObject
                );

    if (!NT_SUCCESS(status)) {
        rc = cfs_error_code(status);
        cfs_enter_debugger();
        goto errorout;
    }

    tconn->kstc_state = ksts_associated;

    /* Allocating Connection Info Together with the Address */
    AddrLength = FIELD_OFFSET(TRANSPORT_ADDRESS, Address->Address)
                 + TDI_ADDRESS_LENGTH_IP;

    ConnectionInfo = (PTDI_CONNECTION_INFORMATION)ExAllocatePoolWithTag(
    NonPagedPool, sizeof(TDI_CONNECTION_INFORMATION) + AddrLength, 'iCsK');

    if (NULL == ConnectionInfo) {

        status = STATUS_INSUFFICIENT_RESOURCES;
        rc = cfs_error_code(status);
        cfs_enter_debugger();
        goto errorout;
    }

    /* Initializing ConnectionInfo ... */
    {
        PTRANSPORT_ADDRESS TdiAddress;

        /* ConnectionInfo settings */

        ConnectionInfo->UserDataLength = 0;
        ConnectionInfo->UserData = NULL;
        ConnectionInfo->OptionsLength = 0;
        ConnectionInfo->Options = NULL;
        ConnectionInfo->RemoteAddressLength = AddrLength;
        ConnectionInfo->RemoteAddress = ConnectionInfo + 1;


        /* intialize the tdi address*/

        TdiAddress = ConnectionInfo->RemoteAddress;

        TdiAddress->TAAddressCount = 1;
        TdiAddress->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
        TdiAddress->Address[0].AddressType   = TDI_ADDRESS_TYPE_IP;

        ((PTDI_ADDRESS_IP)&(TdiAddress->Address[0].Address))->sin_port = htons(port);
        ((PTDI_ADDRESS_IP)&(TdiAddress->Address[0].Address))->in_addr = (ULONG)htonl(addr);

        memset(&(((PTDI_ADDRESS_IP)&(TdiAddress->Address[0].Address))->sin_zero[0]),0,8);
    }

    /* Now prepare to connect the remote peer ... */

    ConnectionObject = tconn->sender.kstc_info.FileObject;
    DeviceObject = IoGetRelatedDeviceObject(ConnectionObject);

    /* allocate a new Irp */

    Irp = KsBuildTdiIrp(DeviceObject);

    if (NULL == Irp) {

        status = STATUS_INSUFFICIENT_RESOURCES;
        rc = cfs_error_code(status);
        cfs_enter_debugger();
        goto errorout;
    }

    /* setup the Irp */

    TdiBuildConnect(
            Irp,
            DeviceObject,
            ConnectionObject,
            NULL,
            NULL,
            NULL,
            ConnectionInfo,
            NULL
            );


    /* sumbit the Irp to the underlying transport driver */
    status = KsSubmitTdiIrp(
                    DeviceObject,
                    Irp,
                    TRUE,
                    NULL
                    );

	spin_lock(&(tconn->kstc_lock));

    if (NT_SUCCESS(status)) {

        /* Connected! the conneciton is built successfully. */

        tconn->kstc_state = ksts_connected;

        tconn->sender.kstc_info.ConnectionInfo = ConnectionInfo;
        tconn->sender.kstc_info.Remote         = ConnectionInfo->RemoteAddress;

	spin_unlock(&(tconn->kstc_lock));

    } else {

        /* Not connected! Abort it ... */

        if (rc != 0) {
            cfs_enter_debugger();
        }

        Irp = NULL;
        rc = cfs_error_code(status);

        tconn->kstc_state = ksts_associated;
	spin_unlock(&(tconn->kstc_lock));

        /* disassocidate the connection and the address object,
           after cleanup,  it's safe to set the state to abort ... */

        if ( NT_SUCCESS(KsDisassociateAddress(
                        tconn->sender.kstc_info.FileObject))) {
            tconn->kstc_state = ksts_aborted;
        }

        /* reset the event callbacks */
        rc = KsResetHandlers(tconn);

        goto errorout;
    }

errorout:

    if (NT_SUCCESS(status)) {

        ks_query_local_ipaddr(tconn);

    } else {

        if (ConnectionInfo) {
            ExFreePool(ConnectionInfo);
        }
        if (Irp) {
            IoFreeIrp(Irp);
        }
    }

    ks_put_tconn(tconn);

    return (rc);
}


/*
 * ks_disconnect_tconn
 *   disconnect the tconn from a connection
 *
 * Arguments:
 *   tconn: the tdi connecton object connected already
 *   flags: flags & options for disconnecting
 *
 * Return Value:
 *   int: ks error code
 *
 * Notes:
 *   N/A
 */

int
ks_disconnect_tconn(
    ks_tconn_t *    tconn,
    ulong           flags
    )
{
    NTSTATUS            status = STATUS_SUCCESS;

    ks_tconn_info_t *   info;

    PFILE_OBJECT        ConnectionObject;
    PDEVICE_OBJECT      DeviceObject = NULL;

    PIRP                Irp = NULL;

    KEVENT              Event;

    ks_get_tconn(tconn);

    /* make sure tt's connected already and it
       must be a sender or a child ...       */

    LASSERT(tconn->kstc_state == ksts_connected);
    LASSERT( tconn->kstc_type == kstt_sender ||
            tconn->kstc_type == kstt_child);

    /* reset all the event handlers to NULL */

    if (tconn->kstc_type != kstt_child) {
        KsResetHandlers (tconn);
    }

    /* Disconnecting to the remote peer ... */

    if (tconn->kstc_type == kstt_sender) {
        info = &(tconn->sender.kstc_info);
    } else {
        info = &(tconn->child.kstc_info);
    }

    ConnectionObject = info->FileObject;
    DeviceObject = IoGetRelatedDeviceObject(ConnectionObject);

    /* allocate an Irp and setup it */

    Irp = KsBuildTdiIrp(DeviceObject);

    if (NULL == Irp) {

        status = STATUS_INSUFFICIENT_RESOURCES;
        cfs_enter_debugger();
        goto errorout;
    }

    KeInitializeEvent(
            &Event,
            SynchronizationEvent,
            FALSE
            );

    TdiBuildDisconnect(
            Irp,
            DeviceObject,
            ConnectionObject,
            KsDisconectCompletionRoutine,
            &Event,
            NULL,
            flags,
            NULL,
            NULL
            );

    /* issue the Irp to the underlying transport
       driver to disconnect the connection    */

    status = IoCallDriver(DeviceObject, Irp);

    if (STATUS_PENDING == status) {

        status = KeWaitForSingleObject(
                     &Event,
                     Executive,
                     KernelMode,
                     FALSE,
                     NULL
                     );

        status = Irp->IoStatus.Status;
    }

    KsPrint((2, "KsDisconnect: Disconnection is done with Status = %xh (%s) ...\n",
                status, KsNtStatusToString(status)));

    IoFreeIrp(Irp);

    if (info->ConnectionInfo) {

        /* disassociate the association between connection/address objects */

        status = KsDisassociateAddress(ConnectionObject);

        if (!NT_SUCCESS(status)) {
            cfs_enter_debugger();
        }

	spin_lock(&(tconn->kstc_lock));

        /* cleanup the tsdumgr Lists */
        KsCleanupTsdu (tconn);

        /* set the state of the tconn */
        if (NT_SUCCESS(status)) {
            tconn->kstc_state = ksts_disconnected;
        } else {
            tconn->kstc_state = ksts_associated;
        }

        /* free  the connection info to system pool*/
        ExFreePool(info->ConnectionInfo);
        info->ConnectionInfo = NULL;
        info->Remote = NULL;

	spin_unlock(&(tconn->kstc_lock));
    }

    status = STATUS_SUCCESS;

errorout:

    ks_put_tconn(tconn);

    return cfs_error_code(status);
}


/*
 * ks_abort_tconn
 *   The connection is broken un-expectedly. We need do
 *   some cleanup.
 *
 * Arguments:
 *   tconn: the tdi connection
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

void
ks_abort_tconn(
    ks_tconn_t *     tconn
    )
{
    PKS_DISCONNECT_WORKITEM WorkItem = NULL;

    WorkItem = &(tconn->kstc_disconnect);

    ks_get_tconn(tconn);
	spin_lock(&(tconn->kstc_lock));

    if (tconn->kstc_state != ksts_connected) {
        ks_put_tconn(tconn);
    } else {

        if (!cfs_is_flag_set(tconn->kstc_flags, KS_TCONN_DISCONNECT_BUSY)) {

            WorkItem->Flags = TDI_DISCONNECT_ABORT;
            WorkItem->tconn = tconn;

            cfs_set_flag(tconn->kstc_flags, KS_TCONN_DISCONNECT_BUSY);

            ExQueueWorkItem(
                    &(WorkItem->WorkItem),
                    DelayedWorkQueue
                    );
        }
    }

	spin_unlock(&(tconn->kstc_lock));
}


/*
 * ks_query_local_ipaddr
 *   query the local connection ip address
 *
 * Arguments:
 *   tconn:  the tconn which is connected
 *
 * Return Value:
 *   int: ks error code
 *
 * Notes:
 *   N/A
 */

int
ks_query_local_ipaddr(
    ks_tconn_t *     tconn
    )
{
    PFILE_OBJECT    FileObject = NULL;
    NTSTATUS        status;

    PTRANSPORT_ADDRESS TdiAddress;
    ULONG              AddressLength;

    if (tconn->kstc_type == kstt_sender) {
        FileObject = tconn->sender.kstc_info.FileObject;
    } else if (tconn->kstc_type == kstt_child) {
        FileObject = tconn->child.kstc_info.FileObject;
    } else {
        status = STATUS_INVALID_PARAMETER;
        goto errorout;
    }

    TdiAddress = &(tconn->kstc_addr.Tdi);
    AddressLength = MAX_ADDRESS_LENGTH;

    status =  KsQueryIpAddress(FileObject, TdiAddress, &AddressLength);

    if (NT_SUCCESS(status)) {
        KsPrint((2, "ks_query_local_ipaddr: Local ip address = %xh port = %xh\n",
                ((PTDI_ADDRESS_IP)(&(TdiAddress->Address[0].Address)))->in_addr,
                ((PTDI_ADDRESS_IP)(&(TdiAddress->Address[0].Address)))->sin_port ));
    } else {
        KsPrint((2, "ks_query_local_ipaddr: Failed to query the connection local ip address.\n"));
    }

errorout:

    return cfs_error_code(status);
}

int
KsCalcWhichEngine(ks_tconn_t * tconn)
{
    PTRANSPORT_ADDRESS TdiAddress = &(tconn->kstc_addr.Tdi);
    ULONG addr = ((PTDI_ADDRESS_IP)(&(TdiAddress->Address[0].Address)))->in_addr;
    ULONG sum = (addr & 0xFF) + ((addr & 0xFF00) >> 8) + ((addr & 0xFF0000) >> 16);

    return (int)(sum % ks_data.ksnd_engine_nums);
}

void
KsQueueTdiEngine(ks_tconn_t * tconn, PKS_TSDUMGR TsduMgr)
{
    ks_engine_mgr_t *   engm;
    ks_engine_slot_t *  engs;

    engm = &ks_data.ksnd_engine_mgr[KsCalcWhichEngine(tconn)];
    engs = &TsduMgr->Slot;

    if (!engs->queued) {
	spin_lock(&engm->lock);
        if (!engs->queued) {
            cfs_list_add_tail(&engs->link, &engm->list);
            engs->queued = TRUE;
            engs->tconn = tconn;
            engs->emgr = engm;
            engs->tsdumgr = TsduMgr;
            KeSetEvent(&(engm->start),0, FALSE);
        }
	spin_unlock(&engm->lock);
        KsPrint((4, "KsQueueTdiEngine: TsduMgr=%p is queued to engine %p\n",
                    TsduMgr, engm));
    }
    KeSetEvent(&(engm->start),0, FALSE);
}

void
KsRemoveTdiEngine(PKS_TSDUMGR TsduMgr)
{
    ks_engine_mgr_t *   engm;
    ks_engine_slot_t *  engs;

    engs = &TsduMgr->Slot;
    if (engs->queued) {
        engm = engs->emgr;
        LASSERT(engm != NULL);
	spin_lock(&engm->lock);
        if (engs->queued) {
            cfs_list_del(&engs->link);
            engs->queued = FALSE;
            engs->tconn = NULL;
            engs->emgr = NULL;
            engs->tsdumgr = NULL;
        }
	spin_unlock(&engm->lock);
        KsPrint((4, "KsQueueTdiEngine: TsduMgr %p is removed from engine %p\n",
                    TsduMgr, engm));
    }
}

int
KsDeliveryIrp(ks_tconn_t * tconn, PIRP irp)
{
    PFILE_OBJECT        connobj;
    PDEVICE_OBJECT      devobj;
    NTSTATUS            status;
    int                 rc = 0;

    /* construct Irp */
    if (tconn->kstc_type == kstt_sender) {
        connobj = tconn->sender.kstc_info.FileObject;
    } else {
        LASSERT(tconn->kstc_type == kstt_child);
        connobj = tconn->child.kstc_info.FileObject;
    }
    devobj = IoGetRelatedDeviceObject(connobj);
    
    /* send irp to transport layer */
    status = IoCallDriver(devobj, irp);

    /* convert status to linux error code */
    if (!NT_SUCCESS(status)) {
        rc = cfs_error_code(status);
    }

    KsPrint((4, "KsDeliveryIrp: tconn=%p irp=%p status=%xh rc=%d.\n",
                 tconn, irp, status, rc));
    return rc;
}

PIRP
KsBuildSend(ks_tconn_t * tconn, PKS_TSDUMGR TsduMgr,
            ks_mdl_t * mdl, ulong flags )
{
    ks_tdi_tx_t *       context;
    PIRP                irp = NULL;
    PFILE_OBJECT        connobj;
    PDEVICE_OBJECT      devobj;
    NTSTATUS            status;
    ULONG               length;

    int                 rc = 0;

    /* query mdl chain total length */
    length = KsQueryMdlsSize(mdl);

    /* we need allocate the ks_tx_t structure from memory pool. */
    context = cfs_alloc(sizeof(ks_tdi_tx_t), 0);
    if (!context) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto errorout;
    }

    /* intialize the TcpContext */
    memset(context,0, sizeof(ks_tdi_tx_t));
    context->Magic = KS_TCP_CONTEXT_MAGIC;
    context->tconn = tconn;
    context->CompletionRoutine = KsTcpSendCompletionRoutine;
    context->TsduMgr = TsduMgr;
    context->Length = length;

    /* construct Irp */
    if (tconn->kstc_type == kstt_sender) {
        connobj = tconn->sender.kstc_info.FileObject;
    } else {
        LASSERT(tconn->kstc_type == kstt_child);
        connobj = tconn->child.kstc_info.FileObject;
    }
    devobj = IoGetRelatedDeviceObject(connobj);
    irp = KsBuildTdiIrp(devobj);
    if (NULL == irp) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto errorout;
    }

    /* grab tconn reference */
    ks_get_tconn(tconn);

    /* delivery the sending request */
    TdiBuildSend(
        irp,
        devobj,
        connobj,
        KsTcpCompletionRoutine,
        context,
        mdl,
        flags,
        length
      );

      return irp;

errorout:

    /* free the context if is not used at all */
    if (context) {
        ASSERT(context->Magic == KS_TCP_CONTEXT_MAGIC);
        context->Magic = 'CDAB';
        cfs_free(context);
    }

    /* here need free the Irp. */
    if (irp) {
        IoFreeIrp(irp);
        irp = NULL;
    }

    return NULL;
}

int
KsDeliveryTsdus(ks_tconn_t * tconn, PKS_TSDUMGR TsduMgr)
{
    int                 rc = 0;
    ulong               length = 0;
    ulong               tflags = 0;
    ks_mdl_t *          mdl = NULL;
    PIRP                irp = NULL;
    BOOLEAN             expedited;

    LASSERT(tconn->kstc_magic == KS_TCONN_MAGIC);

    ks_get_tconn(tconn);
    ks_lock_tsdumgr(TsduMgr);

    if ( tconn->kstc_type != kstt_sender &&
         tconn->kstc_type != kstt_child) {
        rc = -EINVAL;
        ks_unlock_tsdumgr(TsduMgr);
        goto errorout;
    }

    if (tconn->kstc_state != ksts_connected) {
        rc = -ENOTCONN;
        ks_unlock_tsdumgr(TsduMgr);
        goto errorout;
    }

    if (TsduMgr->OOB) {
        tflags = TDI_SEND_NON_BLOCKING | TDI_SEND_EXPEDITED;
    } else {
        tflags = TDI_SEND_NON_BLOCKING;
    }
   
    if (cfs_list_empty(&TsduMgr->TsduList)) {
        LASSERT(TsduMgr->TotalBytes == 0);
        ks_unlock_tsdumgr(TsduMgr);
        goto errorout;
    }

    /* check whether there's outstanding sending requests */
    if (TsduMgr->Busy) {
        rc = -EAGAIN;
        ks_unlock_tsdumgr(TsduMgr);
        goto errorout;
    }

    /* probe all Tsdus and merge buffers together */
    mdl = KsLockTsdus(tconn, TsduMgr, &tflags, &length);
    if (NULL == mdl) {
         if (length == 0) {
            LASSERT(TsduMgr->TotalBytes == 0);
            rc = -EAGAIN;
        } else {
            rc = -ENOMEM;
        }
        ks_unlock_tsdumgr(TsduMgr);
        goto errorout;
    }

    KsPrint((4, "KsDeliveryTsdus: tconn=%p TsudMgr=%p, length=%xh/%xh\n",
                tconn, TsduMgr, length, TsduMgr->TotalBytes));

    /* build send irp request */
    irp = KsBuildSend(tconn, TsduMgr, mdl, tflags);
    if (NULL == irp) {
        rc = -ENOMEM;
        ks_unlock_tsdumgr(TsduMgr);
        goto errorout;
    }
    TsduMgr->Busy = TRUE;
    ks_unlock_tsdumgr(TsduMgr);

    /* delivery mdl chain */
    LASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    rc = KsDeliveryIrp(tconn, irp);
    if (rc < 0) {
        goto errorout;
    }

errorout:

    LASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    ks_put_tconn(tconn);
    return rc;
}

int
KsDeliveryEngineThread(void * context)
{
    ks_engine_mgr_t *   engm = context;
    ks_engine_slot_t *  engs;
    cfs_list_t *        list;
    ks_tconn_t *        tconn;

    cfs_set_thread_priority(31);

    while (!engm->stop) {

        cfs_wait_event_internal(&engm->start, 0);

	spin_lock(&engm->lock);
        if (cfs_list_empty(&engm->list)) {
	    spin_unlock(&engm->lock);
            continue;
        }

        list = engm->list.next;
        cfs_list_del(list);
        engs = cfs_list_entry(list, ks_engine_slot_t, link);
        LASSERT(engs->emgr == engm);
        LASSERT(engs->queued);
        engs->emgr = NULL;
        engs->queued = FALSE;
	spin_unlock(&engm->lock);

        tconn = engs->tconn;
        LASSERT(tconn->kstc_magic == KS_TCONN_MAGIC);

        KsPrint((4, "KsDeliveryEngineThread: %p active: tconn=%p "
                    "TsduMgr=%p\n", engm, tconn, engs->tsdumgr));
        KsDeliveryTsdus(tconn, engs->tsdumgr);

        LASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    }

    KeSetEvent(&engm->exit, 0, FALSE);

    return 0;
}

/*
 * ks_init_tdi_data
 *   initialize the global data in ksockal_data
 *
 * Arguments:
 *   N/A
 *
 * Return Value:
 *   int: ks error code
 *
 * Notes:
 *   N/A
 */

int
ks_init_tdi_data()
{
    int rc = 0, i;

    /* initialize tconn related globals */
    RtlZeroMemory(&ks_data, sizeof(ks_tdi_data_t));

	spin_lock_init(&ks_data.ksnd_tconn_lock);
    CFS_INIT_LIST_HEAD(&ks_data.ksnd_tconns);
    cfs_init_event(&ks_data.ksnd_tconn_exit, TRUE, FALSE);

    ks_data.ksnd_tconn_slab = cfs_mem_cache_create(
        "tcon", sizeof(ks_tconn_t) , 0, 0);

    if (!ks_data.ksnd_tconn_slab) {
        rc = -ENOMEM;
        goto errorout;
    }

    /* initialize tsdu related globals */
	spin_lock_init(&ks_data.ksnd_tsdu_lock);
    CFS_INIT_LIST_HEAD(&ks_data.ksnd_freetsdus);
    ks_data.ksnd_tsdu_size = TDINAL_TSDU_DEFAULT_SIZE; /* 64k */
    ks_data.ksnd_tsdu_slab = cfs_mem_cache_create(
        "tsdu", ks_data.ksnd_tsdu_size, 0, 0);

    if (!ks_data.ksnd_tsdu_slab) {
        rc = -ENOMEM;
        goto errorout;
    }

    /* initialize engine threads list */
    ks_data.ksnd_engine_nums = cfs_num_online_cpus();
    if (ks_data.ksnd_engine_nums < 4) {
        ks_data.ksnd_engine_nums = 4;
    }
    ks_data.ksnd_engine_mgr = cfs_alloc(sizeof(ks_engine_mgr_t) * 
                         ks_data.ksnd_engine_nums,CFS_ALLOC_ZERO);
    if (ks_data.ksnd_engine_mgr == NULL) {
        rc = -ENOMEM;
        goto errorout;
    }
    for (i = 0; i < ks_data.ksnd_engine_nums; i++) {
		spin_lock_init(&ks_data.ksnd_engine_mgr[i].lock);
	cfs_init_event(&ks_data.ksnd_engine_mgr[i].start, TRUE, FALSE);
	cfs_init_event(&ks_data.ksnd_engine_mgr[i].exit, TRUE, FALSE);
	CFS_INIT_LIST_HEAD(&ks_data.ksnd_engine_mgr[i].list);
	kthread_run(KsDeliveryEngineThread, &ks_data.ksnd_engine_mgr[i], "");
    }

    /* register pnp handlers to watch network condition */
    KsRegisterPnpHandlers();

errorout:

    /* do cleanup in case we get failures */
    if (rc < 0) {
        if (ks_data.ksnd_tconn_slab) {
            cfs_mem_cache_destroy(ks_data.ksnd_tconn_slab);
            ks_data.ksnd_tconn_slab = NULL;
        }
    }

    return rc;
}


/*
 * ks_fini_tdi_data
 *   finalize the global data in ksockal_data
 *
 * Arguments:
 *   N/A
 *
 * Return Value:
 *   int: ks error code
 *
 * Notes:
 *   N/A
 */

void
ks_fini_tdi_data()
{
    PKS_TSDU            KsTsdu = NULL;
    cfs_list_t *        list   = NULL;
    int i;

    /* clean up the pnp handler and address slots */
    KsDeregisterPnpHandlers();

    /* stop all tcp sending engines */
    for (i = 0; i < ks_data.ksnd_engine_nums; i++) {
        ks_data.ksnd_engine_mgr[i].stop = TRUE;
        KeSetEvent(&ks_data.ksnd_engine_mgr[i].start, 0, FALSE);
    }

    for (i = 0; i < ks_data.ksnd_engine_nums; i++) {
        cfs_wait_event_internal(&ks_data.ksnd_engine_mgr[i].exit, 0);
    }

    /* we need wait until all the tconn are freed */
	spin_lock(&(ks_data.ksnd_tconn_lock));

    if (cfs_list_empty(&(ks_data.ksnd_tconns))) {
        cfs_wake_event(&ks_data.ksnd_tconn_exit);
    }
	spin_unlock(&(ks_data.ksnd_tconn_lock));

    /* now wait on the tconn exit event */
    cfs_wait_event_internal(&ks_data.ksnd_tconn_exit, 0);

    /* it's safe to delete the tconn slab ... */
    cfs_mem_cache_destroy(ks_data.ksnd_tconn_slab);
    ks_data.ksnd_tconn_slab = NULL;

    /* clean up all the tsud buffers in the free list */
	spin_lock(&(ks_data.ksnd_tsdu_lock));
    cfs_list_for_each (list, &ks_data.ksnd_freetsdus) {
        KsTsdu = cfs_list_entry (list, KS_TSDU, Link);

        cfs_mem_cache_free(
                ks_data.ksnd_tsdu_slab,
                KsTsdu );
    }
	spin_unlock(&(ks_data.ksnd_tsdu_lock));

    /* it's safe to delete the tsdu slab ... */
    cfs_mem_cache_destroy(ks_data.ksnd_tsdu_slab);
    ks_data.ksnd_tsdu_slab = NULL;

    /* good! it's smooth to do the cleaning up...*/
}

/*
 * ks_create_child_tconn
 *   Create the backlog child connection for a listener
 *
 * Arguments:
 *   parent: the listener daemon connection
 *
 * Return Value:
 *   the child connection or NULL in failure
 *
 * Notes:
 *   N/A
 */

ks_tconn_t *
ks_create_child_tconn(
    ks_tconn_t * parent
    )
{
    NTSTATUS            status;
    ks_tconn_t *        backlog;

    /* allocate the tdi connecton object */
    backlog = ks_create_tconn();

    if (!backlog) {
        goto errorout;
    }

    /* initialize the tconn as a child */
    ks_init_child(backlog);


    /* now bind it */
    if (ks_bind_tconn(backlog, parent, 0, 0) < 0) {
        ks_free_tconn(backlog);
        backlog = NULL;
        goto errorout;
    }

    /* open the connection object */
    status = KsOpenConnection(
                &(backlog->kstc_dev),
                (PVOID)backlog,
                &(backlog->child.kstc_info.Handle),
                &(backlog->child.kstc_info.FileObject)
                );

    if (!NT_SUCCESS(status)) {

        ks_put_tconn(backlog);
        backlog = NULL;
        cfs_enter_debugger();
        goto errorout;
    }

    /* associate it now ... */
    status = KsAssociateAddress(
                backlog->kstc_addr.Handle,
                backlog->child.kstc_info.FileObject
                );

    if (!NT_SUCCESS(status)) {

        ks_put_tconn(backlog);
        backlog = NULL;
        cfs_enter_debugger();
        goto errorout;
    }

    backlog->kstc_state = ksts_associated;

errorout:

    return backlog;
}

/*
 * ks_replenish_backlogs(
 *   to replenish the backlogs listening...
 *
 * Arguments:
 *   tconn: the parent listen tdi connect
 *   nbacklog: number fo child connections in queue
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

void
ks_replenish_backlogs(
    ks_tconn_t *    parent,
    int             nbacklog
    )
{
    ks_tconn_t *    backlog;
    int             n = 0;

    /* calculate how many backlogs needed */
    if ( ( parent->listener.kstc_listening.num +
           parent->listener.kstc_accepted.num ) < nbacklog ) {
        n = nbacklog - ( parent->listener.kstc_listening.num +
            parent->listener.kstc_accepted.num );
    } else {
        n = 0;
    }

    while (n--) {

        /* create the backlog child tconn */
        backlog = ks_create_child_tconn(parent);

	spin_lock(&(parent->kstc_lock));

        if (backlog) {
	    spin_lock(&backlog->kstc_lock);
            /* attch it into the listing list of daemon */
            cfs_list_add( &backlog->child.kstc_link,
                      &parent->listener.kstc_listening.list );
            parent->listener.kstc_listening.num++;

            backlog->child.kstc_queued = TRUE;
	    spin_unlock(&backlog->kstc_lock);
        } else {
            cfs_enter_debugger();
        }

	spin_unlock(&(parent->kstc_lock));
    }
}

/*
 * ks_start_listen
 *   setup the listener tdi connection and make it listen
 *    on the user specified ip address and port.
 *
 * Arguments:
 *   tconn: the parent listen tdi connect
 *   nbacklog: number fo child connections in queue
 *
 * Return Value:
 *   ks error code >=: success; otherwise error.
 *
 * Notes:
 *   N/A
 */

int
ks_start_listen(ks_tconn_t *tconn, int nbacklog)
{
    int rc = 0;

    /* now replenish the backlogs */
    ks_replenish_backlogs(tconn, nbacklog);

    /* set the event callback handlers */
    rc = KsSetHandlers(tconn);

    if (rc < 0) {
        return rc;
    }

	spin_lock(&(tconn->kstc_lock));
	tconn->listener.nbacklog = nbacklog;
	tconn->kstc_state = ksts_listening;
	cfs_set_flag(tconn->kstc_flags, KS_TCONN_DAEMON_STARTED);
	spin_unlock(&(tconn->kstc_lock));

	return rc;
}

void
ks_stop_listen(ks_tconn_t *tconn)
{
    cfs_list_t *            list;
    ks_tconn_t *            backlog;

    /* reset all tdi event callbacks to NULL */
    KsResetHandlers (tconn);

	spin_lock(&tconn->kstc_lock);

    cfs_clear_flag(tconn->kstc_flags, KS_TCONN_DAEMON_STARTED);

    /* cleanup all the listening backlog child connections */
    cfs_list_for_each (list, &(tconn->listener.kstc_listening.list)) {
        backlog = cfs_list_entry(list, ks_tconn_t, child.kstc_link);

        /* destory and free it */
        ks_put_tconn(backlog);
    }

	spin_unlock(&tconn->kstc_lock);

    /* wake up it from the waiting on new incoming connections */
    KeSetEvent(&tconn->listener.kstc_accept_event, 0, FALSE);

    /* free the listening daemon tconn */
    ks_put_tconn(tconn);
}


/*
 * ks_wait_child_tconn
 *   accept a child connection from peer
 *
 * Arguments:
 *   parent:   the daemon tdi connection listening
 *   child:    to contain the accepted connection
 *
 * Return Value:
 *   ks error code;
 *
 * Notes:
 *   N/A
 */

int
ks_wait_child_tconn(
    ks_tconn_t *    parent,
    ks_tconn_t **   child
    )
{
    cfs_list_t * tmp;
    ks_tconn_t * backlog = NULL;

    ks_replenish_backlogs(parent, parent->listener.nbacklog);

	spin_lock(&(parent->kstc_lock));

	if (parent->listener.kstc_listening.num <= 0) {
		spin_unlock(&(parent->kstc_lock));
        return -1;
    }

again:

    /* check the listening queue and try to search the accepted connecton */

    cfs_list_for_each(tmp, &(parent->listener.kstc_listening.list)) {
        backlog = cfs_list_entry (tmp, ks_tconn_t, child.kstc_link);

	spin_lock(&(backlog->kstc_lock));

        if (backlog->child.kstc_accepted) {

            LASSERT(backlog->kstc_state == ksts_connected);
            LASSERT(backlog->child.kstc_busy);

            cfs_list_del(&(backlog->child.kstc_link));
            cfs_list_add(&(backlog->child.kstc_link),
                         &(parent->listener.kstc_accepted.list));
            parent->listener.kstc_accepted.num++;
            parent->listener.kstc_listening.num--;
            backlog->child.kstc_queueno = 1;

	    spin_unlock(&(backlog->kstc_lock));

            break;
        } else {
	    spin_unlock(&(backlog->kstc_lock));
            backlog = NULL;
        }
    }

	spin_unlock(&(parent->kstc_lock));

    /* we need wait until new incoming connections are requested
       or the case of shuting down the listenig daemon thread  */
    if (backlog == NULL) {

        NTSTATUS    Status;

        Status = KeWaitForSingleObject(
                &(parent->listener.kstc_accept_event),
                Executive,
                KernelMode,
                FALSE,
                NULL
                );

	spin_lock(&(parent->kstc_lock));

        /* check whether it's exptected to exit ? */
        if (!cfs_is_flag_set(parent->kstc_flags, KS_TCONN_DAEMON_STARTED)) {
	    spin_unlock(&(parent->kstc_lock));
        } else {
            goto again;
        }
    }

    KsPrint((2, "ks_wait_child_tconn: connection %p accepted.\n", backlog));

    if (backlog) {
        /* query the local ip address of the connection */
        ks_query_local_ipaddr(backlog);
    } else {
        return -EINTR;
    }
    *child = backlog;

    return 0;
}

int
ks_query_iovs_length(struct iovec  *iov, int niov)
{
    int             i;
    int             total = 0;

    LASSERT(iov != NULL);
    LASSERT(niov > 0);

    for (i=0; i < niov; i++) {
        total += iov[i].iov_len;
    }

    return total;
}

int
ks_query_kiovs_length(lnet_kiov_t *kiov, int nkiov)
{
    int             i;
    int             total = 0;

    LASSERT(kiov != NULL);
    LASSERT(nkiov > 0);

    for (i=0; i < nkiov; i++) {
        total += kiov[i].kiov_len;
    }

    return total;
}

int
ks_sock_buf_cb(void *tsdu, int ns, int off, char **buf)
{
    int rc = 0;

    if (off < ns) {
        *buf = (char *)tsdu + off;
        rc = ns - off;
    }
    return rc;
}

int
ks_sock_iov_cb(void *tsdu, int ns, int off, char **buf)
{
    int rc = 0, i;
    struct iovec *iov = tsdu;

    for (i=0; i < ns; i++) {
        if ((size_t)off >= iov[i].iov_len) {
            off -= iov[i].iov_len;
        } else {
            *buf = (char *)iov[i].iov_base + off;
            rc = iov[i].iov_len - off;
            break;
        }
    }
    return rc;
}

int
ks_sock_kiov_cb(void *tsdu, int ns, int off, char **buf)
{
    int rc = 0, i;
    lnet_kiov_t *kiov = tsdu;

    for (i=0; i < ns; i++) {
        if ((size_t)off >= kiov[i].kiov_len) {
            off -= kiov[i].kiov_len;
        } else {
            *buf = (char *)kiov[i].kiov_page->addr +
                    kiov[i].kiov_offset + off;
            rc = kiov[i].kiov_len - off;
            break;
        }
    }
    return rc;
}

typedef int (*ks_tsdu_cb_t)(void *tsdu, int ns, int off, char **buf);

int
ks_sock_io(ks_tconn_t *tconn, void *tsdu, int ns, int reqlen,
           int flags, int timeout, int out, ks_tsdu_cb_t callback)
{
    ULONG       tflags;
    BOOLEAN     expedited;
    PKS_TSDUMGR TsduMgr;

    int         rc;
    int         length;
    int         total = 0;
    int64_t     remained;
    PCHAR       buffer;
    BOOLEAN     async;

    LASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);
    remained = (int64_t)cfs_time_seconds(timeout);

    /* query tsdu manager */
    expedited = cfs_is_flag_set(flags, MSG_OOB);
    TsduMgr = KsQueryTsduMgr(tconn, expedited, (BOOLEAN)out);

    /* check whether equest is nonblocking */
    if (async = cfs_is_flag_set(flags, MSG_DONTWAIT)) {
        timeout = 0;
    }

    ks_get_tconn(tconn);
    ks_lock_tsdumgr(TsduMgr);
    if ( tconn->kstc_type != kstt_sender &&
         tconn->kstc_type != kstt_child) {
        rc = -EINVAL;
        goto errorout;
    }

    while (length = callback(tsdu, ns, total, &buffer)) {

        /* check whether socket is stil valid */
        if (tconn->kstc_state != ksts_connected) {
            rc = -ENOTCONN;
            goto errorout;
        }

        if (out) {
            tflags = KsTdiSendFlags(flags);
            rc = KsWriteTsdus(TsduMgr, buffer, length, tflags);
        } else {
            tflags = KsTdiRecvFlags(flags);
            rc = KsReadTsdus(TsduMgr, buffer, length, tflags);
        }

        if (rc > 0) {
            total += rc;
        } else if (!async && rc == -EAGAIN) {
            if (timeout) {
                if (remained) { 
                    ks_unlock_tsdumgr(TsduMgr);
                    remained = cfs_wait_event_internal(
                                    &TsduMgr->Event,
                                    remained );
                } else {
                    goto errorout;
                }
            } else {
                ks_unlock_tsdumgr(TsduMgr);
                cfs_wait_event_internal(&TsduMgr->Event, 0);
            }
            ks_lock_tsdumgr(TsduMgr);
        } else {
            break;
        }
    }

errorout:

    if (!out) {
        TsduMgr->Payload = reqlen - total;
    }
    ks_unlock_tsdumgr(TsduMgr);

    KsPrint((4, "ks_sock_io: tconn=%p tsdumgr=%p %c total=%xh/%xh rc=%d\n",
                tconn, TsduMgr, out?'W':'R', total, TsduMgr->TotalBytes, rc));

    if (total) {
        if (out) {
            /* signal Tdi sending engine */
            KsQueueTdiEngine(tconn, TsduMgr);
        }
        rc = total;
    }

    ks_put_tconn(tconn);

    LASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);
    return rc;
}

int ks_send_buf(ks_tconn_t * tconn, char *buf,
                int len, int flags, int timeout)
{
    return ks_sock_io(tconn, buf, len, len, flags,
                      timeout, 1, ks_sock_buf_cb);
}

int ks_recv_buf(ks_tconn_t * tconn, char *buf,
                int len, int flags, int timeout)
{
    return ks_sock_io(tconn, buf, len, len, flags,
                      timeout, 0, ks_sock_buf_cb);
}

int ks_send_iovs(ks_tconn_t * tconn, struct iovec *iov,
                 int niov, int flags, int timeout)
{
    int reqlen = ks_query_iovs_length(iov, niov);
    return ks_sock_io(tconn, iov, niov, reqlen, flags,
                      timeout, TRUE, ks_sock_iov_cb);
}

int ks_recv_iovs(ks_tconn_t * tconn, struct iovec *iov,
                 int niov, int flags, int timeout)
{
    int reqlen = ks_query_iovs_length(iov, niov);
    return ks_sock_io(tconn, iov, niov, reqlen, flags,
                      timeout, FALSE, ks_sock_iov_cb);
}

int ks_send_kiovs(ks_tconn_t * tconn, lnet_kiov_t *kiov,
                  int nkiov, int flags, int timeout)
{
    int reqlen = ks_query_kiovs_length(kiov, nkiov);
    return ks_sock_io(tconn, kiov, nkiov, reqlen, flags,
                      timeout, TRUE, ks_sock_kiov_cb);
}

int ks_recv_kiovs(ks_tconn_t * tconn, lnet_kiov_t *kiov,
                  int nkiov, int flags, int timeout)
{
    int reqlen = ks_query_kiovs_length(kiov, nkiov);
    return ks_sock_io(tconn, kiov, nkiov, reqlen, flags,
                      timeout, FALSE, ks_sock_kiov_cb);
}

int libcfs_ipif_query(char *name, int *up, __u32 *ip, __u32 *mask)
{
    ks_addr_slot_t * slot = NULL;
    PLIST_ENTRY      list = NULL;

	spin_lock(&ks_data.ksnd_addrs_lock);

    list = ks_data.ksnd_addrs_list.Flink;
    while (list != &ks_data.ksnd_addrs_list) {
        slot = CONTAINING_RECORD(list, ks_addr_slot_t, link);
        if (_stricmp(name, &slot->iface[0]) == 0) {
            *up = slot->up;
            *ip = slot->ip_addr;
            *mask = slot->netmask;
            break;
        }
        list = list->Flink;
        slot = NULL;
    }

	spin_unlock(&ks_data.ksnd_addrs_lock);

    return (int)(slot == NULL);
}

int libcfs_ipif_enumerate(char ***names)
{
    ks_addr_slot_t * slot = NULL;
    PLIST_ENTRY      list = NULL;
    int              nips = 0;

	spin_lock(&ks_data.ksnd_addrs_lock);

    *names = cfs_alloc(sizeof(char *) * ks_data.ksnd_naddrs, CFS_ALLOC_ZERO);
    if (*names == NULL) {
        goto errorout;
    }

    list = ks_data.ksnd_addrs_list.Flink;
    while (list != &ks_data.ksnd_addrs_list) {
        slot = CONTAINING_RECORD(list, ks_addr_slot_t, link);
        list = list->Flink;
        (*names)[nips++] = slot->iface;
        cfs_assert(nips <= ks_data.ksnd_naddrs);
    }

    cfs_assert(nips == ks_data.ksnd_naddrs);

errorout:

	spin_unlock(&ks_data.ksnd_addrs_lock);
    return nips;
}

void libcfs_ipif_free_enumeration(char **names, int n)
{
    if (names) {
        cfs_free(names);
    }
}

int libcfs_sock_listen(struct socket **sockp, __u32 ip, int port, int backlog)
{
    int                 rc = 0;
    ks_tconn_t *        parent;

    parent = ks_create_tconn();
    if (!parent) {
        rc = -ENOMEM;
        goto errorout;
    }

    /* initialize the tconn as a listener */
    ks_init_listener(parent);

    /* bind the daemon->tconn */
    rc = ks_bind_tconn(parent, NULL, ip, (unsigned short)port);

    if (rc < 0) {
        ks_free_tconn(parent);
        goto errorout;
    }

    /* create listening children and make it to listen state*/
    rc = ks_start_listen(parent, backlog);
    if (rc < 0) {
        ks_stop_listen(parent);
        goto errorout;
    }

    *sockp = parent;

errorout:

    return rc;
}

int libcfs_sock_accept(struct socket **newsockp, struct socket *sock)
{
    /* wait for incoming connecitons */
    return ks_wait_child_tconn(sock, newsockp);
}

void libcfs_sock_abort_accept(struct socket *sock)
{
    LASSERT(sock->kstc_type == kstt_listener);

	spin_lock(&(sock->kstc_lock));

    /* clear the daemon flag */
    cfs_clear_flag(sock->kstc_flags, KS_TCONN_DAEMON_STARTED);

    /* wake up it from the waiting on new incoming connections */
    KeSetEvent(&sock->listener.kstc_accept_event, 0, FALSE);

	spin_unlock(&(sock->kstc_lock));
}

/*
 * libcfs_sock_connect
 *   build a conntion between local ip/port and the peer ip/port.
 *
 * Arguments:
 *   laddr: local ip address
 *   lport: local port number
 *   paddr: peer's ip address
 *   pport: peer's port number
 *
 * Return Value:
 *   int:   return code ...
 *
 * Notes:
 *   N/A
 */


int libcfs_sock_connect(struct socket **sockp, int *fatal,
                        __u32 local_ip, int local_port,
                        __u32 peer_ip, int peer_port)
{
    ks_tconn_t *    tconn = NULL;
    int             rc = 0;

    *sockp = NULL;
    if (fatal) *fatal = 0;

    KsPrint((2, "libcfs_sock_connect: connecting to %x:%d with %x:%d...\n",
                peer_ip, peer_port, local_ip, local_port ));

    /* create the tdi connecion structure */
    tconn = ks_create_tconn();
    if (!tconn) {
        rc = -ENOMEM;
        goto errorout;
    }

    /* initialize the tdi sender connection */
    ks_init_sender(tconn);

    /* bind the local ip address with the tconn */
    rc = ks_bind_tconn(tconn, NULL, local_ip, (unsigned short)local_port);
    if (rc < 0) {
        KsPrint((1, "libcfs_sock_connect: failed to bind address %x:%d...\n",
                    local_ip, local_port ));
        ks_free_tconn(tconn);
        goto errorout;
    }

    /* connect to the remote peer */
    rc = ks_build_tconn(tconn, peer_ip, (unsigned short)peer_port);
    if (rc < 0) {
        KsPrint((1, "libcfs_sock_connect: failed to connect %x:%d ...\n",
                    peer_ip, peer_port ));

        ks_put_tconn(tconn);
        goto errorout;
    }

    *sockp = tconn;

errorout:

    return rc;
}

int libcfs_sock_setbuf(struct socket *socket, int txbufsize, int rxbufsize)
{
    return 0;
}

int libcfs_sock_getbuf(struct socket *socket, int *txbufsize, int *rxbufsize)
{
    return 0;
}

int libcfs_sock_getaddr(struct socket *socket, int remote, __u32 *ip, int *port)
{
    PTRANSPORT_ADDRESS  taddr = NULL;

	spin_lock(&socket->kstc_lock);
    if (remote) {
        if (socket->kstc_type == kstt_sender) {
            taddr = socket->sender.kstc_info.Remote;
        } else if (socket->kstc_type == kstt_child) {
            taddr = socket->child.kstc_info.Remote;
        }
    } else {
        taddr = &(socket->kstc_addr.Tdi);
    }

    if (taddr) {
        PTDI_ADDRESS_IP addr = (PTDI_ADDRESS_IP)(&(taddr->Address[0].Address));
        if (ip != NULL)
            *ip = ntohl (addr->in_addr);
        if (port != NULL)
            *port = ntohs (addr->sin_port);
    } else {
		spin_unlock(&socket->kstc_lock);
		return -ENOTCONN;
	}

	spin_unlock(&socket->kstc_lock);
	return 0;
}

int libcfs_sock_write(struct socket *sock, void *buffer, int nob, int timeout)
{
    int           rc;
    int           offset = 0;

    while (nob > offset) {

        rc = ks_send_buf(sock, (char *)buffer + offset, nob - offset, 0, timeout);

        if (rc <= 0) {
            goto errorout;
        } else {
            offset += rc;
            rc = 0;
        }
    }

errorout:

    KsPrint((4, "libcfs_sock_write: sock: %p %d bytes rc: %d\n", sock, offset, rc));
    return rc;
}

int libcfs_sock_read(struct socket *sock, void *buffer, int nob, int timeout)
{
    int           rc = 0;
    int           offset = 0;

    while (nob > offset) {

        rc = ks_recv_buf(sock, (char *)buffer + offset, nob - offset, 0, timeout);

        if (rc <= 0) {
            goto errorout;
        } else {
            offset += rc;
            rc = 0;
        }
    }

errorout:

    KsPrint((4, "libcfs_sock_read: sock: %p %d bytes rc: %d\n", sock, offset, rc));
    return rc;
}

void libcfs_sock_release(struct socket *sock)
{
    if (sock->kstc_type == kstt_listener &&
        sock->kstc_state == ksts_listening) {
        ks_stop_listen(sock);
    } else {
        ks_put_tconn(sock);
    }
}
