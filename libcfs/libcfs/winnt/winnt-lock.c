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


# define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>


#if defined(_X86_)

void __declspec (naked) FASTCALL
cfs_atomic_add(
    int i,
    cfs_atomic_t *v
    )
{
    // ECX = i
    // EDX = v ; [EDX][0] = v->counter

    __asm {
        lock add dword ptr [edx][0], ecx
        ret
    }
}

void __declspec (naked) FASTCALL
cfs_atomic_sub(
    int i,
    cfs_atomic_t *v
   ) 
{
    // ECX = i
    // EDX = v ; [EDX][0] = v->counter

    __asm {
        lock sub dword ptr [edx][0], ecx
        ret
    }
}

void __declspec (naked) FASTCALL
cfs_atomic_inc(
    cfs_atomic_t *v
    )
{
    //InterlockedIncrement((PULONG)(&((v)->counter)));

    //` ECX = v ; [ECX][0] = v->counter

    __asm {
        lock inc dword ptr [ecx][0]
        ret
    }
}

void __declspec (naked) FASTCALL
cfs_atomic_dec(
    cfs_atomic_t *v
    )
{
    // ECX = v ; [ECX][0] = v->counter

    __asm {
        lock dec dword ptr [ecx][0]
        ret
    }
}

int __declspec (naked) FASTCALL 
cfs_atomic_sub_and_test(
    int i,
    cfs_atomic_t *v
    )
{

    // ECX = i
    // EDX = v ; [EDX][0] = v->counter

    __asm {
        xor eax, eax
        lock sub dword ptr [edx][0], ecx
        sete al
        ret
    }
}

int __declspec (naked) FASTCALL
cfs_atomic_inc_and_test(
    cfs_atomic_t *v
    )
{
    // ECX = v ; [ECX][0] = v->counter

    __asm {
        xor eax, eax
        lock inc dword ptr [ecx][0]
        sete al
        ret
    }
}

int __declspec (naked) FASTCALL
cfs_atomic_dec_and_test(
    cfs_atomic_t *v
    )
{
    // ECX = v ; [ECX][0] = v->counter

    __asm {
        xor eax, eax
        lock dec dword ptr [ecx][0]
        sete al
        ret
    }
}

#elif defined(_AMD64_)

void FASTCALL
cfs_atomic_add(
    int i,
    cfs_atomic_t *v
    )
{
    InterlockedExchangeAdd( (PULONG)(&((v)->counter)) , (LONG) (i));
}

void FASTCALL
cfs_atomic_sub(
    int i,
    cfs_atomic_t *v
   ) 
{
    InterlockedExchangeAdd( (PULONG)(&((v)->counter)) , (LONG) (-1*i));
}

void FASTCALL
cfs_atomic_inc(
    cfs_atomic_t *v
    )
{
   InterlockedIncrement((PULONG)(&((v)->counter)));
}

void FASTCALL
cfs_atomic_dec(
    cfs_atomic_t *v
    )
{
    InterlockedDecrement((PULONG)(&((v)->counter)));
}

int FASTCALL 
cfs_atomic_sub_and_test(
    int i,
    cfs_atomic_t *v
    )
{
    int counter, result;

    do {

        counter = v->counter;
        result = counter - i;

    } while ( InterlockedCompareExchange(
                &(v->counter),
                result,
                counter) !=  counter);

    return (result == 0);
}

int FASTCALL
cfs_atomic_inc_and_test(
    cfs_atomic_t *v
    )
{
    int counter, result;

    do {

        counter = v->counter;
        result = counter + 1;

    } while ( InterlockedCompareExchange(
                &(v->counter),
                result,
                counter) !=  counter);

    return (result == 0);
}

int FASTCALL
cfs_atomic_dec_and_test(
    cfs_atomic_t *v
    )
{
    int counter, result;

    do {

        counter = v->counter;
        result = counter - 1;

    } while ( InterlockedCompareExchange(
                &(v->counter),
                result,
                counter) !=  counter);

    return (result == 0);
}

#else

#error CPU arch type isn't specified.

#endif

/**
 * atomic_add_return - add integer and return
 * \param v pointer of type atomic_t
 * \param i integer value to add
 *
 * Atomically adds \a i to \a v and returns \a i + \a v
 */
int FASTCALL cfs_atomic_add_return(int i, cfs_atomic_t *v)
{
    int counter, result;

    do {

        counter = v->counter;
        result = counter + i;

    } while ( InterlockedCompareExchange(
                &(v->counter),
                result,
                counter) !=  counter);

    return result;

}

/**
 * atomic_sub_return - subtract integer and return
 * \param v pointer of type atomic_t
 * \param i integer value to subtract
 *
 * Atomically subtracts \a i from \a v and returns \a v - \a i
 */
int FASTCALL cfs_atomic_sub_return(int i, cfs_atomic_t *v)
{
	return cfs_atomic_add_return(-i, v);
}

int FASTCALL cfs_atomic_dec_and_lock(cfs_atomic_t *v, spinlock_t *lock)
{
	if (cfs_atomic_read(v) != 1)
		return 0;

	spin_lock(lock);
	if (cfs_atomic_dec_and_test(v))
		return 1;
	spin_unlock(lock);
	return 0;
}


/*
 * rw spinlock
 */


void
rwlock_init(rwlock_t *rwlock)
{
	spin_lock_init(&rwlock->guard);
	rwlock->count = 0;
}

void
cfs_rwlock_fini(rwlock_t *rwlock)
{
}

void
read_lock(rwlock_t *rwlock)
{
    cfs_task_t * task = cfs_current();
    PTASK_SLOT   slot = NULL;

    if (!task) {
        /* should bugchk here */
        cfs_enter_debugger();
        return;
    }

    slot = CONTAINING_RECORD(task, TASK_SLOT, task);
    ASSERT(slot->Magic == TASKSLT_MAGIC);
   
    slot->irql = KeRaiseIrqlToDpcLevel();

	while (TRUE) {
		spin_lock(&rwlock->guard);
			if (rwlock->count >= 0)
				break;
		spin_unlock(&rwlock->guard);
	}

	rwlock->count++;
	spin_unlock(&rwlock->guard);
}

void
read_unlock(rwlock_t *rwlock)
{
    cfs_task_t * task = cfs_current();
    PTASK_SLOT   slot = NULL;

    if (!task) {
        /* should bugchk here */
        cfs_enter_debugger();
        return;
    }

    slot = CONTAINING_RECORD(task, TASK_SLOT, task);
    ASSERT(slot->Magic == TASKSLT_MAGIC);

	spin_lock(&rwlock->guard);
	ASSERT(rwlock->count > 0);
	rwlock->count--;
	if (rwlock < 0)
		cfs_enter_debugger();
	spin_unlock(&rwlock->guard);

	KeLowerIrql(slot->irql);
}

void
write_lock(rwlock_t *rwlock)
{
    cfs_task_t * task = cfs_current();
    PTASK_SLOT   slot = NULL;

    if (!task) {
        /* should bugchk here */
        cfs_enter_debugger();
        return;
    }

    slot = CONTAINING_RECORD(task, TASK_SLOT, task);
    ASSERT(slot->Magic == TASKSLT_MAGIC);
   
    slot->irql = KeRaiseIrqlToDpcLevel();

	while (TRUE) {
		spin_lock(&rwlock->guard);
		if (rwlock->count == 0)
			break;
		spin_unlock(&rwlock->guard);
	}

	rwlock->count = -1;
	spin_unlock(&rwlock->guard);
}

void
write_unlock(rwlock_t *rwlock)
{
    cfs_task_t * task = cfs_current();
    PTASK_SLOT   slot = NULL;

    if (!task) {
        /* should bugchk here */
        cfs_enter_debugger();
        return;
    }

    slot = CONTAINING_RECORD(task, TASK_SLOT, task);
    ASSERT(slot->Magic == TASKSLT_MAGIC);

	spin_lock(&rwlock->guard);
	ASSERT(rwlock->count == -1);
	rwlock->count = 0;
	spin_unlock(&rwlock->guard);

	KeLowerIrql(slot->irql);
}
