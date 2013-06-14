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
 * Copyright (c) 2011, 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>


/*
 *  Thread routines
 */

/*
 * cfs_thread_proc
 *   Lustre thread procedure wrapper routine (It's an internal routine)
 *
 * Arguments:
 *   context:  a structure of cfs_thread_context_t, containing
 *             all the necessary parameters
 *
 * Return Value:
 *   void: N/A
 *
 * Notes:
 *   N/A
 */

void
cfs_thread_proc(
    void * context
    )
{
    cfs_thread_context_t * thread_context =
        (cfs_thread_context_t *) context;

    /* Execute the specified function ... */

    if (thread_context->func) {
        (thread_context->func)(thread_context->arg);
    }

    /* Free the context memory */

    cfs_free(context);

    /* Terminate this system thread */

    PsTerminateSystemThread(STATUS_SUCCESS);
}

/*
 * kthread_run
 *   Create a system thread to execute the routine specified
 *
 * Arguments:
 *   func:  function to be executed in the thread
 *   arg:   argument transferred to func function
 *   name:  thread name to create
 *
 * Return Value:
 *   cfs_task_t:   0 on success or error codes
 *
 * Notes:
 *   N/A
 */

cfs_task_t kthread_run(int (*func)(void *), void *arg, char *name)
{
    cfs_handle_t  thread = NULL;
    NTSTATUS      status;
    cfs_thread_context_t * context = NULL;

    /* Allocate the context to be transferred to system thread */

    context = cfs_alloc(sizeof(cfs_thread_context_t), CFS_ALLOC_ZERO);

    if (!context) {
	return ERR_PTR(-ENOMEM);
    }

    context->func  = func;
    context->arg   = arg;

    /* Create system thread with the cfs_thread_proc wrapper */

    status = PsCreateSystemThread(
                &thread,
                (ACCESS_MASK)0L,
                0, 0, 0,
                cfs_thread_proc,
                context);

    if (!NT_SUCCESS(status)) {


        cfs_free(context);

        /* We need translate the nt status to linux error code */

	return ERR_PTR(cfs_error_code(status));
    }

    //
    //  Query the thread id of the newly created thread
    //

    ZwClose(thread);

	return (cfs_task_t)0;
}


/*
 * Symbols routines
 */


static DECLARE_RWSEM(cfs_symbol_lock);
CFS_LIST_HEAD(cfs_symbol_list);

int libcfs_is_mp_system = FALSE;

/*
 * cfs_symbol_get
 *   To query the specified symbol form the symbol table
 *
 * Arguments:
 *   name:  the symbol name to be queried
 *
 * Return Value:
 *   If the symbol is in the table, return the address of it.
 *   If not, return NULL.
 *
 * Notes:
 *   N/A
 */

void *
cfs_symbol_get(const char *name)
{
    cfs_list_t              *walker;
    struct cfs_symbol       *sym = NULL;

	down_read(&cfs_symbol_lock);
    cfs_list_for_each(walker, &cfs_symbol_list) {
        sym = cfs_list_entry (walker, struct cfs_symbol, sym_list);
        if (!strcmp(sym->name, name)) {
            sym->ref ++;
            break;
        }
    }
	up_read(&cfs_symbol_lock);

    if (sym != NULL)
        return sym->value;

    return NULL;
}

/*
 * cfs_symbol_put
 *   To decrease the reference of  the specified symbol
 *
 * Arguments:
 *   name:  the symbol name to be dereferred
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

void
cfs_symbol_put(const char *name)
{
    cfs_list_t              *walker;
    struct cfs_symbol       *sym = NULL;

	down_read(&cfs_symbol_lock);
    cfs_list_for_each(walker, &cfs_symbol_list) {
        sym = cfs_list_entry (walker, struct cfs_symbol, sym_list);
        if (!strcmp(sym->name, name)) {
            LASSERT(sym->ref > 0);
            sym->ref--;
            break;
        }
    }
	up_read(&cfs_symbol_lock);

    LASSERT(sym != NULL);
}


/*
 * cfs_symbol_register
 *   To register the specified symbol infromation
 *
 * Arguments:
 *   name:  the symbol name to be dereferred
 *   value: the value that the symbol stands for
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   Zero: Succeed to register
 *   Non-Zero: Fail to register the symbol
 */

int
cfs_symbol_register(const char *name, const void *value)
{
    cfs_list_t              *walker;
    struct cfs_symbol       *sym = NULL;
    struct cfs_symbol       *new = NULL;

    new = cfs_alloc(sizeof(struct cfs_symbol), CFS_ALLOC_ZERO);
    if (!new) {
        return (-ENOMEM);
    }
    strncpy(new->name, name, CFS_SYMBOL_LEN);
    new->value = (void *)value;
    new->ref = 0;
    CFS_INIT_LIST_HEAD(&new->sym_list);

	down_write(&cfs_symbol_lock);
	cfs_list_for_each(walker, &cfs_symbol_list) {
		sym = cfs_list_entry (walker, struct cfs_symbol, sym_list);
		if (!strcmp(sym->name, name)) {
			up_write(&cfs_symbol_lock);
			cfs_free(new);
			return 0; /* alreay registerred */
		}
	}
	cfs_list_add_tail(&new->sym_list, &cfs_symbol_list);
	up_write(&cfs_symbol_lock);

    return 0;
}

/*
 * cfs_symbol_unregister
 *   To unregister/remove the specified symbol
 *
 * Arguments:
 *   name:  the symbol name to be dereferred
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

void
cfs_symbol_unregister(const char *name)
{
    cfs_list_t              *walker;
    cfs_list_t              *nxt;
    struct cfs_symbol       *sym = NULL;

	down_write(&cfs_symbol_lock);
    cfs_list_for_each_safe(walker, nxt, &cfs_symbol_list) {
        sym = cfs_list_entry (walker, struct cfs_symbol, sym_list);
        if (!strcmp(sym->name, name)) {
            LASSERT(sym->ref == 0);
            cfs_list_del (&sym->sym_list);
            cfs_free(sym);
            break;
        }
    }
	up_write(&cfs_symbol_lock);
}

/*
 * cfs_symbol_clean
 *   To clean all the symbols
 *
 * Arguments:
 *   N/A
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

void
cfs_symbol_clean()
{
    cfs_list_t          *walker;
    struct cfs_symbol   *sym = NULL;

	down_write(&cfs_symbol_lock);
	cfs_list_for_each(walker, &cfs_symbol_list) {
		sym = cfs_list_entry (walker, struct cfs_symbol, sym_list);
		LASSERT(sym->ref == 0);
		cfs_list_del (&sym->sym_list);
		cfs_free(sym);
	}
	up_write(&cfs_symbol_lock);
	return;
}



/*
 * Timer routines
 */


/* Timer dpc procedure */

static void
cfs_timer_dpc_proc (
    IN PKDPC Dpc,
    IN PVOID DeferredContext,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2)
{
    cfs_timer_t *   timer;
    KIRQL           Irql;

    timer = (cfs_timer_t *) DeferredContext;

    /* clear the flag */
    KeAcquireSpinLock(&(timer->Lock), &Irql);
    cfs_clear_flag(timer->Flags, CFS_TIMER_FLAG_TIMERED);
    KeReleaseSpinLock(&(timer->Lock), Irql);

    /* call the user specified timer procedure */
    timer->proc((long_ptr_t)timer->arg);
}

void cfs_init_timer(cfs_timer_t *timer)
{
    memset(timer, 0, sizeof(cfs_timer_t));
}

/*
 * cfs_timer_init
 *   To initialize the cfs_timer_t
 *
 * Arguments:
 *   timer:  the cfs_timer to be initialized
 *   func:   the timer callback procedure
 *   arg:    argument for the callback proc
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

void cfs_timer_init(cfs_timer_t *timer, void (*func)(ulong_ptr_t), void *arg)
{
    memset(timer, 0, sizeof(cfs_timer_t));

    timer->proc = func;
    timer->arg  = arg;

    KeInitializeSpinLock(&(timer->Lock));
    KeInitializeTimer(&timer->Timer);
    KeInitializeDpc (&timer->Dpc, cfs_timer_dpc_proc, timer);

    cfs_set_flag(timer->Flags, CFS_TIMER_FLAG_INITED);
}

/*
 * cfs_timer_done
 *   To finialize the cfs_timer_t (unused)
 *
 * Arguments:
 *   timer:  the cfs_timer to be cleaned up
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

void cfs_timer_done(cfs_timer_t *timer)
{
    return;
}

/*
 * cfs_timer_arm
 *   To schedule the timer while touching @deadline
 *
 * Arguments:
 *   timer:  the cfs_timer to be freed
 *   dealine: timeout value to wake up the timer
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

void cfs_timer_arm(cfs_timer_t *timer, cfs_time_t deadline)
{
    LARGE_INTEGER   timeout;
    KIRQL           Irql;

    KeAcquireSpinLock(&(timer->Lock), &Irql);
    if (!cfs_is_flag_set(timer->Flags, CFS_TIMER_FLAG_TIMERED)){

        timeout.QuadPart = (LONGLONG)-1*1000*1000*10/CFS_HZ*deadline;

        if (KeSetTimer(&timer->Timer, timeout, &timer->Dpc)) {
            cfs_set_flag(timer->Flags, CFS_TIMER_FLAG_TIMERED);
        }

        timer->deadline = deadline;
    }

    KeReleaseSpinLock(&(timer->Lock), Irql);
}

/*
 * cfs_timer_disarm
 *   To discard the timer to be scheduled
 *
 * Arguments:
 *   timer:  the cfs_timer to be discarded
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

void cfs_timer_disarm(cfs_timer_t *timer)
{
    KIRQL   Irql;

    KeAcquireSpinLock(&(timer->Lock), &Irql);
    KeCancelTimer(&(timer->Timer));
    cfs_clear_flag(timer->Flags, CFS_TIMER_FLAG_TIMERED);
    KeReleaseSpinLock(&(timer->Lock), Irql);
}


/*
 * cfs_timer_is_armed
 *   To check the timer is scheduled or not
 *
 * Arguments:
 *   timer:  the cfs_timer to be checked
 *
 * Return Value:
 *   1:  if it's armed.
 *   0:  if it's not.
 *
 * Notes:
 *   N/A
 */

int cfs_timer_is_armed(cfs_timer_t *timer)
{
    int     rc = 0;
    KIRQL   Irql;

    KeAcquireSpinLock(&(timer->Lock), &Irql);
    if (cfs_is_flag_set(timer->Flags, CFS_TIMER_FLAG_TIMERED)) {
        rc = 1;
    }
    KeReleaseSpinLock(&(timer->Lock), Irql);

    return rc;
}

/*
 * cfs_timer_deadline
 *   To query the deadline of the timer
 *
 * Arguments:
 *   timer:  the cfs_timer to be queried
 *
 * Return Value:
 *   the deadline value
 *
 * Notes:
 *   N/A
 */

cfs_time_t cfs_timer_deadline(cfs_timer_t * timer)
{
    return timer->deadline;
}

int unshare_fs_struct()
{
	return 0;
}

/*
 *  routine related with sigals
 */

cfs_sigset_t cfs_block_allsigs()
{
        return 0;
}

cfs_sigset_t cfs_block_sigs(sigset_t bit)
{
        return 0;
}

/* Block all signals except for the @sigs. It's only used in
 * Linux kernel, just a dummy here. */
cfs_sigset_t cfs_block_sigsinv(unsigned long sigs)
{
        return 0;
}

void cfs_restore_sigs(cfs_sigset_t old)
{
}

int cfs_signal_pending(void)
{
    return 0;
}

void cfs_clear_sigpending(void)
{
    return;
}

/*
 *  thread cpu affinity routines
 */

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    KPRIORITY Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION;

typedef THREAD_BASIC_INFORMATION *PTHREAD_BASIC_INFORMATION;

#define THREAD_QUERY_INFORMATION       (0x0040)

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenThread (
    __out PHANDLE ThreadHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt PCLIENT_ID ClientId
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationThread (
    __in HANDLE ThreadHandle,
    __in THREADINFOCLASS ThreadInformationClass,
    __out_bcount(ThreadInformationLength) PVOID ThreadInformation,
    __in ULONG ThreadInformationLength,
    __out_opt PULONG ReturnLength
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwSetInformationThread (
    __in HANDLE ThreadHandle,
    __in THREADINFOCLASS ThreadInformationClass,
    __in_bcount(ThreadInformationLength) PVOID ThreadInformation,
    __in ULONG ThreadInformationLength
    );

HANDLE
cfs_open_current_thread()
{
    NTSTATUS         status;
    HANDLE           handle = NULL;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID        cid;

    /* initialize object attributes */
    InitializeObjectAttributes( &oa, NULL, OBJ_KERNEL_HANDLE |
                                OBJ_CASE_INSENSITIVE, NULL, NULL);

    /* initialize client id */
    cid.UniqueProcess = PsGetCurrentProcessId();
    cid.UniqueThread  = PsGetCurrentThreadId();

    /* get thread handle */
    status = ZwOpenThread( &handle, THREAD_QUERY_INFORMATION |
                           THREAD_SET_INFORMATION, &oa, &cid);
    if (!NT_SUCCESS(status)) {
        handle = NULL;
    }

    return handle;
}

void
cfs_close_thread_handle(HANDLE handle)
{
    if (handle)
        ZwClose(handle);
}

KAFFINITY
cfs_query_thread_affinity()
{
    NTSTATUS         status;
    HANDLE           handle = NULL;
    DWORD            size;
    THREAD_BASIC_INFORMATION TBI = {0};

    /* open current thread */
    handle = cfs_open_current_thread();
    if (!handle) {
        goto errorout;
    }

    /* query thread cpu affinity */
    status = ZwQueryInformationThread(handle, ThreadBasicInformation,
                       &TBI, sizeof(THREAD_BASIC_INFORMATION), &size);
    if (!NT_SUCCESS(status)) {
        goto errorout;
    }

errorout:

    cfs_close_thread_handle(handle);
    return TBI.AffinityMask;
}

int
cfs_set_thread_affinity(KAFFINITY affinity)
{
    NTSTATUS         status;
    HANDLE           handle = NULL;

    /* open current thread */
    handle = cfs_open_current_thread();
    if (!handle) {
        goto errorout;
    }

    /* set thread cpu affinity */
    status = ZwSetInformationThread(handle, ThreadAffinityMask,
                                    &affinity, sizeof(KAFFINITY));
    if (!NT_SUCCESS(status)) {
        goto errorout;
    }

errorout:

    cfs_close_thread_handle(handle);
    return NT_SUCCESS(status);
}

int
cfs_tie_thread_to_cpu(int cpu)
{
    return cfs_set_thread_affinity((KAFFINITY) (1 << cpu));
}

int
cfs_set_thread_priority(KPRIORITY priority)
{
    NTSTATUS         status;
    HANDLE           handle = NULL;

    /* open current thread */
    handle = cfs_open_current_thread();
    if (!handle) {
        goto errorout;
    }

    /* set thread cpu affinity */
    status = ZwSetInformationThread(handle, ThreadPriority,
                                    &priority, sizeof(KPRIORITY));
    if (!NT_SUCCESS(status)) {
        KdPrint(("set_thread_priority failed: %xh\n", status));
        goto errorout;
    }

errorout:

    cfs_close_thread_handle(handle);
    return NT_SUCCESS(status);
}

int cfs_need_resched(void)
{
        return 0;
}

void cfs_cond_resched(void)
{
}

/**
 **  Initialize routines
 **/

void cfs_libc_init();

int
libcfs_arch_init(void)
{
	int		rc;
	spinlock_t	lock;

	/* Workground to check the system is MP build or UP build */
	spin_lock_init(&lock);
	spin_lock(&lock);
	libcfs_is_mp_system = (int)lock.lock;
	/* MP build system: it's a real spin, for UP build system, it
	 * only raises the IRQL to DISPATCH_LEVEL */
	spin_unlock(&lock);

    /* initialize libc routines (confliction between libcnptr.lib
       and kernel ntoskrnl.lib) */
    cfs_libc_init();

    /* create slab memory caches for page alloctors */
    cfs_page_t_slab = cfs_mem_cache_create(
        "CPGT", sizeof(cfs_page_t), 0, 0 );

    cfs_page_p_slab = cfs_mem_cache_create(
        "CPGP", CFS_PAGE_SIZE, 0, 0 );

    if ( cfs_page_t_slab == NULL ||
         cfs_page_p_slab == NULL ){
        rc = -ENOMEM;
        goto errorout;
    }

    rc = init_task_manager();
    if (rc != 0) {
        cfs_enter_debugger();
        KdPrint(("winnt-prim.c:libcfs_arch_init: error initializing task manager ...\n"));
        goto errorout;
    }

    /* initialize the proc file system */
    rc = proc_init_fs();
    if (rc != 0) {
        cfs_enter_debugger();
        KdPrint(("winnt-prim.c:libcfs_arch_init: error initializing proc fs ...\n"));
        cleanup_task_manager();
        goto errorout;
    }

    /* initialize the tdi data */
    rc = ks_init_tdi_data();
    if (rc != 0) {
        cfs_enter_debugger();
        KdPrint(("winnt-prim.c:libcfs_arch_init: failed to initialize tdi.\n"));
        proc_destroy_fs();
        cleanup_task_manager();
        goto errorout;
    }

    rc = start_shrinker_timer();

errorout:

    if (rc != 0) {
        /* destroy the taskslot cache slab */
        if (cfs_page_t_slab) {
            cfs_mem_cache_destroy(cfs_page_t_slab);
        }
        if (cfs_page_p_slab) {
            cfs_mem_cache_destroy(cfs_page_p_slab);
        }
    }

    return rc;
}

void
libcfs_arch_cleanup(void)
{
    /* stop shrinker timer */
    stop_shrinker_timer();

    /* finialize the tdi data */
    ks_fini_tdi_data();

    /* detroy the whole proc fs tree and nodes */
    proc_destroy_fs();

    /* cleanup context of task manager */
    cleanup_task_manager();

    /* destroy the taskslot cache slab */
    if (cfs_page_t_slab) {
        cfs_mem_cache_destroy(cfs_page_t_slab);
    }

    if (cfs_page_p_slab) {
        cfs_mem_cache_destroy(cfs_page_p_slab);
    }

    return;
}

EXPORT_SYMBOL(libcfs_arch_init);
EXPORT_SYMBOL(libcfs_arch_cleanup);
