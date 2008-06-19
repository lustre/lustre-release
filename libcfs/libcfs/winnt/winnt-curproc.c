/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=4:tabstop=4:
 *
 *  Copyright (c) 2004 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or modify it under
 *   the terms of version 2 of the GNU General Public License as published by
 *   the Free Software Foundation. Lustre is distributed in the hope that it
 *   will be useful, but WITHOUT ANY WARRANTY; without even the implied
 *   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details. You should have received a
 *   copy of the GNU General Public License along with Lustre; if not, write
 *   to the Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139,
 *   USA.
 *
 * Impletion of winnt curproc routines.
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>
#include <libcfs/kp30.h>


/*
 * Implementation of cfs_curproc API (see portals/include/libcfs/curproc.h)
 * for Linux kernel.
 */

cfs_task_t this_task = 
    { 0, 0, 0, 0, 0, 0, 0, 
      0, 0, 0, 0,  1, 0,  0, 0, 0,
      "sysetm\0" };


uid_t  cfs_curproc_uid(void)
{
    return this_task.uid;
}

gid_t  cfs_curproc_gid(void)
{
    return this_task.gid;
}

uid_t  cfs_curproc_fsuid(void)
{
    return this_task.fsuid;
}

gid_t cfs_curproc_fsgid(void)
{
    return this_task.fsgid;
}

pid_t cfs_curproc_pid(void)
{
    return cfs_current()->pid;
}

int cfs_curproc_groups_nr(void)
{
    return this_task.ngroups;
}

void cfs_curproc_groups_dump(gid_t *array, int size)
{
    LASSERT(size <= NGROUPS);
    size = min_t(int, size, this_task.ngroups);
    memcpy(array, this_task.groups, size * sizeof(__u32));
}

int cfs_curproc_is_in_groups(gid_t gid)
{
    return in_group_p(gid);
}

mode_t cfs_curproc_umask(void)
{
    return this_task.umask;
}

char  *cfs_curproc_comm(void)
{
    return this_task.comm;
}

cfs_kernel_cap_t cfs_curproc_cap_get(void)
{
    return this_task.cap_effective;
}

void cfs_curproc_cap_set(cfs_kernel_cap_t cap)
{
    this_task.cap_effective = cap;
}


/*
 * Implementation of linux task management routines
 */


/* global of the task manager structure */

TASK_MAN TaskMan;


/*
 *  task slot routiens
 */

PTASK_SLOT
alloc_task_slot()
{
    PTASK_SLOT task = NULL;

    if (TaskMan.slab) {
        task = cfs_mem_cache_alloc(TaskMan.slab, 0);
    } else {
        task = cfs_alloc(sizeof(TASK_SLOT), 0);
    }

    return task;
}

void
init_task_slot(PTASK_SLOT task)
{
    memset(task, 0, sizeof(TASK_SLOT));
    task->Magic = TASKSLT_MAGIC;
    task->task  = this_task;
    task->task.pid = (pid_t)PsGetCurrentThreadId();
    cfs_init_event(&task->Event, TRUE, FALSE);
}


void
cleanup_task_slot(PTASK_SLOT task)
{
    if (TaskMan.slab) {
        cfs_mem_cache_free(TaskMan.slab, task);
    } else {
        cfs_free(task);
    }
}

/*
 *  task manager related routines
 */

VOID
task_manager_notify(
    IN HANDLE   ProcessId,
    IN HANDLE   ThreadId,
    IN BOOLEAN  Create
    )
{
    PLIST_ENTRY ListEntry = NULL; 
    PTASK_SLOT  TaskSlot  = NULL;

    spin_lock(&(TaskMan.Lock));

    ListEntry = TaskMan.TaskList.Flink;

    while (ListEntry != (&(TaskMan.TaskList))) {

        TaskSlot = CONTAINING_RECORD(ListEntry, TASK_SLOT, Link);

        if (TaskSlot->Pid == ProcessId && TaskSlot->Tid == ThreadId) {

            if (Create) {
/*
                DbgPrint("task_manager_notify: Pid=%xh Tid %xh resued (TaskSlot->Tet = %xh)...\n",
                         ProcessId, ThreadId, TaskSlot->Tet);
*/
            } else {
                /* remove the taskslot */
                RemoveEntryList(&(TaskSlot->Link));
                TaskMan.NumOfTasks--;

                /* now free the task slot */
                cleanup_task_slot(TaskSlot);
            }
        }

        ListEntry = ListEntry->Flink;
    }

    spin_unlock(&(TaskMan.Lock));
}

int
init_task_manager()
{
    NTSTATUS    status;

    /* initialize the content and magic */
    memset(&TaskMan, 0, sizeof(TASK_MAN));
    TaskMan.Magic = TASKMAN_MAGIC;

    /* initialize the spinlock protection */
    spin_lock_init(&TaskMan.Lock);

    /* create slab memory cache */
    TaskMan.slab = cfs_mem_cache_create(
        "TSLT", sizeof(TASK_SLOT), 0, 0);

    /* intialize the list header */
    InitializeListHead(&(TaskMan.TaskList));

    /* set the thread creation/destruction notify routine */
    status = PsSetCreateThreadNotifyRoutine(task_manager_notify);

    if (!NT_SUCCESS(status)) {
        cfs_enter_debugger();
    }

    return 0;
}

void
cleanup_task_manager()
{
    PLIST_ENTRY ListEntry = NULL; 
    PTASK_SLOT  TaskSlot  = NULL;

    /* we must stay in system since we succeed to register the
       CreateThreadNotifyRoutine: task_manager_notify */
    cfs_enter_debugger();


    /* cleanup all the taskslots attached to the list */
    spin_lock(&(TaskMan.Lock));

    while (!IsListEmpty(&(TaskMan.TaskList))) {

        ListEntry = TaskMan.TaskList.Flink;
        TaskSlot = CONTAINING_RECORD(ListEntry, TASK_SLOT, Link);

        RemoveEntryList(ListEntry);
        cleanup_task_slot(TaskSlot);
    }

    spin_unlock(&TaskMan.Lock);

    /* destroy the taskslot cache slab */
    cfs_mem_cache_destroy(TaskMan.slab);
    memset(&TaskMan, 0, sizeof(TASK_MAN));
}


/*
 * schedule routines (task slot list)
 */


cfs_task_t *
cfs_current()
{
    HANDLE      Pid = PsGetCurrentProcessId();
    HANDLE      Tid = PsGetCurrentThreadId();
    PETHREAD    Tet = PsGetCurrentThread();

    PLIST_ENTRY ListEntry = NULL; 
    PTASK_SLOT  TaskSlot  = NULL;

    spin_lock(&(TaskMan.Lock));

    ListEntry = TaskMan.TaskList.Flink;

    while (ListEntry != (&(TaskMan.TaskList))) {

        TaskSlot = CONTAINING_RECORD(ListEntry, TASK_SLOT, Link);

        if (TaskSlot->Pid == Pid && TaskSlot->Tid == Tid) {
            if (TaskSlot->Tet != Tet) {

/*
                DbgPrint("cfs_current: Pid=%xh Tid %xh Tet = %xh resued (TaskSlot->Tet = %xh)...\n",
                         Pid, Tid, Tet, TaskSlot->Tet);
*/
                //
                // The old thread was already exit. This must be a
                // new thread which get the same Tid to the previous.
                //

                TaskSlot->Tet = Tet;
            }
            break;

        } else {

            if ((ULONG)TaskSlot->Pid > (ULONG)Pid) {
                TaskSlot = NULL;
                break;
            } else if ((ULONG)TaskSlot->Pid == (ULONG)Pid) {
                if ((ULONG)TaskSlot->Tid > (ULONG)Tid) {
                    TaskSlot = NULL;
                    break;
                }
            }

            TaskSlot =  NULL;
        }

        ListEntry = ListEntry->Flink;
    }

    if (!TaskSlot) {

        TaskSlot = alloc_task_slot();

        if (!TaskSlot) {
            cfs_enter_debugger();
            goto errorout;
        }

        init_task_slot(TaskSlot);

        TaskSlot->Pid = Pid;
        TaskSlot->Tid = Tid;
        TaskSlot->Tet = Tet;

        if (ListEntry == (&(TaskMan.TaskList))) {
            //
            // Empty case or the biggest case, put it to the tail.
            //
            InsertTailList(&(TaskMan.TaskList), &(TaskSlot->Link));
        } else {
            //
            // Get a slot and smaller than it's tid, put it just before.
            //
            InsertHeadList(ListEntry->Blink, &(TaskSlot->Link));
        }

        TaskMan.NumOfTasks++;
    }

    //
    // To Check whether he task structures are arranged in the expected order ?
    //

    {
        PTASK_SLOT  Prev = NULL, Curr = NULL;
        
        ListEntry = TaskMan.TaskList.Flink;

        while (ListEntry != (&(TaskMan.TaskList))) {

            Curr = CONTAINING_RECORD(ListEntry, TASK_SLOT, Link);
            ListEntry = ListEntry->Flink;

            if (Prev) {
                if ((ULONG)Prev->Pid > (ULONG)Curr->Pid) {
                    cfs_enter_debugger();
                } else if ((ULONG)Prev->Pid == (ULONG)Curr->Pid) {
                    if ((ULONG)Prev->Tid > (ULONG)Curr->Tid) {
                        cfs_enter_debugger();
                    }
                }
            }

            Prev = Curr;
        }
    }

errorout:

    spin_unlock(&(TaskMan.Lock));

    if (!TaskSlot) {
        cfs_enter_debugger();
        return NULL;
    }

    return (&(TaskSlot->task));
}

int
schedule_timeout(int64_t time)
{
    cfs_task_t * task = cfs_current();
    PTASK_SLOT   slot = NULL;

    if (!task) {
        cfs_enter_debugger();
        return 0;
    }

    slot = CONTAINING_RECORD(task, TASK_SLOT, task);
    cfs_assert(slot->Magic == TASKSLT_MAGIC);

    if (time == MAX_SCHEDULE_TIMEOUT) {
        time = 0;
    }

    return (cfs_wait_event(&(slot->Event), time) != 0);
}

int
schedule()
{
    return schedule_timeout(0);
}

int
wake_up_process(
    cfs_task_t * task
    )
{
    PTASK_SLOT   slot = NULL;

    if (!task) {
        cfs_enter_debugger();
        return 0;
    }

    slot = CONTAINING_RECORD(task, TASK_SLOT, task);
    cfs_assert(slot->Magic == TASKSLT_MAGIC);

    cfs_wake_event(&(slot->Event));

    return TRUE;
}

void
sleep_on(
    cfs_waitq_t *waitq
    )
{
	cfs_waitlink_t link;
	
	cfs_waitlink_init(&link);
	cfs_waitq_add(waitq, &link);
	cfs_waitq_wait(&link, CFS_TASK_INTERRUPTIBLE);
	cfs_waitq_del(waitq, &link);
}

EXPORT_SYMBOL(cfs_curproc_uid);
EXPORT_SYMBOL(cfs_curproc_pid);
EXPORT_SYMBOL(cfs_curproc_gid);
EXPORT_SYMBOL(cfs_curproc_fsuid);
EXPORT_SYMBOL(cfs_curproc_fsgid);
EXPORT_SYMBOL(cfs_curproc_umask);
EXPORT_SYMBOL(cfs_curproc_comm);
EXPORT_SYMBOL(cfs_curproc_groups_nr);
EXPORT_SYMBOL(cfs_curproc_groups_dump);
EXPORT_SYMBOL(cfs_curproc_is_in_groups);
EXPORT_SYMBOL(cfs_curproc_cap_get);
EXPORT_SYMBOL(cfs_curproc_cap_set);
