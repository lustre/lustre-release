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
 *
 * libcfs/include/libcfs/winnt/winnt-prim.h
 *
 * Basic library routines.
 */

#ifndef __LIBCFS_WINNT_CFS_PRIM_H__
#define __LIBCFS_WINNT_CFS_PRIM_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif


/*
 * libcfs proc device object
 */


#define LUSTRE_PROC_DEVICE  L"\\Device\\lproc"      /* proc fs emulator device object */
#define LUSTRE_PROC_SYMLNK  L"\\DosDevices\\lproc"  /* proc fs user-visible device */


/*
 * Device IO Control Code Definitions
 */

#define FILE_DEVICE_LIBCFS      ('LC')

#define FILE_DEVICE_LIBCFS      ('LC')

#define FUNC_LIBCFS_VERSION     0x101  // get version of current libcfs
#define FUNC_LIBCFS_IOCTL       0x102  // Device i/o control to proc fs


#define IOCTL_LIBCFS_VERSION \
     CTL_CODE (FILE_DEVICE_LIBCFS, FUNC_LIBCFS_VERSION, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_LIBCFS_ENTRY   \
     CTL_CODE(FILE_DEVICE_LIBCFS, FUNC_LIBCFS_IOCTL,   METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(4)

typedef struct _CFS_PROC_IOCTL {

    ULONG           cmd;    // ioctl command identifier
    ULONG           len;    // length of data

    // UCHAR        data[]; // content of the real ioctl

} CFS_PROC_IOCTL, *PCFS_PROC_IOCTL;

#pragma pack()

#ifdef __KERNEL__

#include <libcfs/list.h>

/*
 * Symbol functions for libcfs
 *
 * OSX has no facility for use to register symbol.
 * So we have to implement it.
 */
#define CFS_SYMBOL_LEN     64

struct  cfs_symbol {
	char    name[CFS_SYMBOL_LEN];
	void    *value;
	int     ref;
	struct  list_head sym_list;
};

extern int      cfs_symbol_register(const char *, const void *);
extern void     cfs_symbol_unregister(const char *);
extern void *   cfs_symbol_get(const char *);
extern void     cfs_symbol_put(const char *);
extern void     cfs_symbol_clean();



typedef struct file_operations cfs_file_operations_t;
typedef struct file cfs_file_t;

/*
 * Pseudo device register
 */

typedef struct
{
    int                     minor;
    const char *            name;
    cfs_file_operations_t * fops;
} cfs_psdev_t;

int cfs_psdev_register(cfs_psdev_t * psdev);
int cfs_psdev_deregister(cfs_psdev_t * psdev);


/*
 * Proc emulator file system APIs
 */

typedef int cfs_read_proc_t(char *page, char **start, off_t off,
			  int count, int *eof, void *data);
typedef int cfs_write_proc_t(struct file *file, const char *buffer,
			   ulong_ptr count, void *data);

#define CFS_PROC_ENTRY_MAGIC 'CPEM'

#define CFS_PROC_FLAG_DIRECTORY    0x00000001 // directory node
#define CFS_PROC_FLAG_ATTACHED     0x00000002 // node is attached to proc
#define CFS_PROC_FLAG_MISCDEV      0x00000004 // miscellaneous device

typedef struct cfs_proc_entry
{
    ULONG                   magic;      // Magic
    ULONG                   flags;      // Flags

    struct _dir_entry {                 // proc directory entry
        PRTL_SPLAY_LINKS    root;
    };

    struct _file_entry {                // proc file / leaf entry
	    cfs_read_proc_t  *  read_proc;
	    cfs_write_proc_t *  write_proc;
    };

    mode_t                  mode;
    unsigned short          nlink;

	
    struct file_operations * proc_fops;
	void * data;

    // proc_dir_entry ended.

    RTL_SPLAY_LINKS         s_link;       // splay link

    //
    // Maximum length of proc entry name is 0x20
    //

    char                    name[0x20];

} cfs_proc_entry_t, cfs_proc_dir_entry_t;

typedef cfs_proc_entry_t cfs_proc_dir_entry_t;

#define PROC_BLOCK_SIZE    PAGE_SIZE

/*
 * Sysctl register
 */

typedef struct ctl_table		    cfs_sysctl_table_t;
typedef struct ctl_table_header		cfs_sysctl_table_header_t;


typedef int ctl_handler (
            cfs_sysctl_table_t *table,
            int *name,    int nlen,
			void *oldval, size_t *oldlenp,
			void *newval, size_t newlen, 
			void **context );

typedef int proc_handler (
            cfs_sysctl_table_t *ctl,
            int write, struct file * filp,
			void *buffer, size_t *lenp );


int proc_dointvec(cfs_sysctl_table_t *table, int write, struct file *filp,
		     void *buffer, size_t *lenp);

int proc_dostring(cfs_sysctl_table_t *table, int write, struct file *filp,
		  void *buffer, size_t *lenp);

int sysctl_string(cfs_sysctl_table_t *table, int *name, int nlen,
		  void *oldval, size_t *oldlenp,
		  void *newval, size_t newlen, void **context);


/*
 *  System io control definitions
 */

#define CTL_MAXNAME 10

#define CTL_ANY     -1  /* Matches any name */
#define CTL_NONE    0

enum
{
    CTL_KERN=1,     /* General kernel info and control */
    CTL_VM=2,       /* VM management */
    CTL_NET=3,      /* Networking */
    CTL_PROC=4,     /* Process info */
    CTL_FS=5,       /* Filesystems */
    CTL_DEBUG=6,        /* Debugging */
    CTL_DEV=7,      /* Devices */
    CTL_BUS=8,      /* Busses */
    CTL_ABI=9,      /* Binary emulation */
    CTL_CPU=10      /* CPU stuff (speed scaling, etc) */
};

/* sysctl table definitons */
struct ctl_table 
{
	int ctl_name;
	char *procname;
	void *data;
	int maxlen;
	mode_t mode;
	cfs_sysctl_table_t *child;
	proc_handler *proc_handler;	/* text formatting callback */
	ctl_handler *strategy;		/* read / write callback functions */
	cfs_proc_entry_t *de;	/* proc entry block */
	void *extra1;
	void *extra2;
};


/* the mantaner of the cfs_sysctl_table trees */
struct ctl_table_header
{
	cfs_sysctl_table_t *    ctl_table;
	struct list_head        ctl_entry;
};


cfs_proc_entry_t * create_proc_entry(char *name, mode_t mod,
					  cfs_proc_entry_t *parent);
void proc_free_entry(cfs_proc_entry_t *de);
void remove_proc_entry(char *name, cfs_proc_entry_t *entry);
cfs_proc_entry_t * search_proc_entry(char * name,
                        cfs_proc_entry_t *  root );

#define cfs_create_proc_entry create_proc_entry
#define cfs_free_proc_entry   proc_free_entry
#define cfs_remove_proc_entry remove_proc_entry

#define register_cfs_sysctl_table(t, a)	register_sysctl_table(t, a)
#define unregister_cfs_sysctl_table(t)	unregister_sysctl_table(t, a)


/*
 *  declaration of proc kernel process routines
 */

cfs_file_t *
lustre_open_file(char * filename);

int
lustre_close_file(cfs_file_t * fh);

int
lustre_do_ioctl( cfs_file_t * fh,
                 unsigned long cmd,
                 ulong_ptr arg );

int
lustre_ioctl_file( cfs_file_t * fh,
                   PCFS_PROC_IOCTL devctl);

size_t
lustre_read_file( cfs_file_t *    fh,
                  loff_t          off,
                  size_t          size,
                  char *          buf
                  );

size_t
lustre_write_file( cfs_file_t *    fh,
                   loff_t          off,
                   size_t          size,
                   char *          buf
                   );

/*
 * Wait Queue
 */


typedef int cfs_task_state_t;

#define CFS_TASK_INTERRUPTIBLE	0x00000001
#define CFS_TASK_UNINT	        0x00000002
#define CFS_TASK_RUNNING        0x00000003


#define CFS_WAITQ_MAGIC     'CWQM'
#define CFS_WAITLINK_MAGIC  'CWLM'

typedef struct cfs_waitq {

    unsigned int        magic;
    unsigned int        flags;
    
    spinlock_t          guard;
    struct list_head    waiters;

} cfs_waitq_t;


typedef struct cfs_waitlink cfs_waitlink_t;

#define CFS_WAITQ_CHANNELS     (2)

#define CFS_WAITQ_CHAN_NORMAL  (0)
#define CFS_WAITQ_CHAN_FORWARD (1)



typedef struct cfs_waitlink_channel {
    struct list_head        link;
    cfs_waitq_t *           waitq;
    cfs_waitlink_t *        waitl;
} cfs_waitlink_channel_t;

struct cfs_waitlink {

    unsigned int            magic;
    int                     flags;
    event_t  *              event;
    atomic_t *              hits;

    cfs_waitlink_channel_t  waitq[CFS_WAITQ_CHANNELS];
};

enum {
	CFS_WAITQ_EXCLUSIVE = 1
};

#define CFS_DECL_WAITQ(name) cfs_waitq_t name


void cfs_waitq_init(struct cfs_waitq *waitq);
void cfs_waitlink_init(struct cfs_waitlink *link);

void cfs_waitq_add(struct cfs_waitq *waitq, struct cfs_waitlink *link);
void cfs_waitq_add_exclusive(struct cfs_waitq *waitq, 
			     struct cfs_waitlink *link);
void cfs_waitq_del(struct cfs_waitq *waitq, struct cfs_waitlink *link);
int  cfs_waitq_active(struct cfs_waitq *waitq);

void cfs_waitq_signal(struct cfs_waitq *waitq);
void cfs_waitq_signal_nr(struct cfs_waitq *waitq, int nr);
void cfs_waitq_broadcast(struct cfs_waitq *waitq);

void cfs_waitq_wait(struct cfs_waitlink *link, cfs_task_state_t state);
cfs_duration_t cfs_waitq_timedwait(struct cfs_waitlink *link, 
				   cfs_task_state_t state, cfs_duration_t timeout);



/* Kernel thread */

typedef int (*cfs_thread_t) (void *arg);

typedef struct _cfs_thread_context {
    cfs_thread_t        func;
    void *              arg;
} cfs_thread_context_t;

int cfs_kernel_thread(int (*func)(void *), void *arg, int flag);

/*
 * thread creation flags from Linux, not used in winnt
 */
#define CSIGNAL         0x000000ff      /* signal mask to be sent at exit */
#define CLONE_VM        0x00000100      /* set if VM shared between processes */
#define CLONE_FS        0x00000200      /* set if fs info shared between processes */
#define CLONE_FILES     0x00000400      /* set if open files shared between processes */
#define CLONE_SIGHAND   0x00000800      /* set if signal handlers and blocked signals shared */
#define CLONE_PID       0x00001000      /* set if pid shared */
#define CLONE_PTRACE    0x00002000      /* set if we want to let tracing continue on the child too */
#define CLONE_VFORK     0x00004000      /* set if the parent wants the child to wake it up on mm_release */
#define CLONE_PARENT    0x00008000      /* set if we want to have the same parent as the cloner */
#define CLONE_THREAD    0x00010000      /* Same thread group? */
#define CLONE_NEWNS     0x00020000      /* New namespace group? */

#define CLONE_SIGNAL    (CLONE_SIGHAND | CLONE_THREAD)


/*
 * sigset ...
 */

typedef sigset_t cfs_sigset_t;

/*
 * Task struct
 */

#define MAX_SCHEDULE_TIMEOUT    ((long_ptr)(~0UL>>12))


#define NGROUPS 1
#define CFS_CURPROC_COMM_MAX (16)
typedef struct task_sruct{
    mode_t umask;

	pid_t pid;
	pid_t pgrp;

	uid_t uid,euid,suid,fsuid;
	gid_t gid,egid,sgid,fsgid;

	int ngroups;
	gid_t	groups[NGROUPS];
	cfs_kernel_cap_t   cap_effective,
                       cap_inheritable,
                       cap_permitted;

	char comm[CFS_CURPROC_COMM_MAX];
    void * journal_info;
}  cfs_task_t;


/*
 *  linux task struct emulator ...
 */

#define TASKMAN_MAGIC  'TMAN'   /* Task Manager */
#define TASKSLT_MAGIC  'TSLT'   /* Task Slot */

typedef struct _TASK_MAN {

    ULONG       Magic;      /* Magic and Flags */
    ULONG       Flags;

    spinlock_t  Lock;       /* Protection lock */

    cfs_mem_cache_t * slab; /* Memory slab for task slot */

    ULONG       NumOfTasks; /* Total tasks (threads) */
    LIST_ENTRY  TaskList;   /* List of task slots */

} TASK_MAN, *PTASK_MAN;

typedef struct _TASK_SLOT {

    ULONG       Magic;      /* Magic and Flags */
    ULONG       Flags;

    LIST_ENTRY  Link;       /* To be linked to TaskMan */

    event_t     Event;      /* Schedule event */

    HANDLE      Pid;        /* Process id */
    HANDLE      Tid;        /* Thread id */
    PETHREAD    Tet;        /* Pointer to ethread */

    atomic_t    count;      /* refer count */
    atomic_t    hits;       /* times of waken event singaled */

    KIRQL       irql;       /* irql for rwlock ... */

    cfs_task_t  task;       /* linux task part */

} TASK_SLOT, *PTASK_SLOT;


#define current                 cfs_current()
#define set_current_state(s)	do {;} while (0)

#define wait_event(wq, condition)                           \
do {                                                        \
    cfs_waitlink_t __wait;	                                \
                                                            \
    cfs_waitlink_init(&__wait);	                            \
	while (TRUE) {                                          \
		cfs_waitq_add(&wq, &__wait);	                    \
		if (condition)	{		                            \
			break;			                                \
        }                                                   \
		cfs_waitq_wait(&__wait, CFS_TASK_INTERRUPTIBLE);	\
		cfs_waitq_del(&wq, &__wait);	                    \
	}					                                    \
	cfs_waitq_del(&wq, &__wait);		                    \
} while(0)

#define wait_event_interruptible(wq, condition, __ret)      \
do {                                                        \
    cfs_waitlink_t __wait;	                                \
                                                            \
    __ret = 0;                                              \
    cfs_waitlink_init(&__wait);	                            \
	while (TRUE) {                                          \
		cfs_waitq_add(&wq, &__wait);	                    \
		if (condition)	{		                            \
			break;			                                \
        }                                                   \
		cfs_waitq_wait(&__wait, CFS_TASK_INTERRUPTIBLE);    \
		cfs_waitq_del(&wq, &__wait);	                    \
	}					                                    \
	cfs_waitq_del(&wq, &__wait);		                    \
} while(0)


int     init_task_manager();
void    cleanup_task_manager();
cfs_task_t * cfs_current();
int     schedule_timeout(int64_t time);
int     schedule();
int     wake_up_process(cfs_task_t * task);
#define cfs_schedule_timeout(state, time)  schedule_timeout(time)
void sleep_on(cfs_waitq_t *waitq);

#define CFS_DECL_JOURNAL_DATA	
#define CFS_PUSH_JOURNAL	    do {;} while(0)
#define CFS_POP_JOURNAL		    do {;} while(0)


/* module related definitions */

#ifndef __exit
#define __exit
#endif
#ifndef __init
#define __init
#endif

#define request_module(x) (0)

#define EXPORT_SYMBOL(s)
#define MODULE_AUTHOR(s)
#define MODULE_DESCRIPTION(s)
#define MODULE_LICENSE(s)
#define MODULE_PARM(a, b)
#define MODULE_PARM_DESC(a, b)

#define module_init(X) int  __init module_##X() {return X();}
#define module_exit(X) void __exit module_##X() {X();}

#define DECLARE_INIT(X) extern int  __init  module_##X(void)
#define DECLARE_EXIT(X) extern void __exit  module_##X(void)

#define MODULE_INIT(X) do { int rc = module_##X(); \
                            if (rc) goto errorout; \
                          } while(0)

#define MODULE_EXIT(X) do { module_##X(); } while(0)


/* Module interfaces */
#define cfs_module(name, version, init, fini) \
module_init(init);                            \
module_exit(fini)


/*
 *  Linux kernel version definition
 */

#define KERNEL_VERSION(a,b,c) ((a)*100+(b)*10+c)
#define LINUX_VERSION_CODE (2*100+6*10+7)


/*
 * Signal
 */
#define SIGNAL_MASK_ASSERT()

/*
 * Timer
 */

#define CFS_TIMER_FLAG_INITED   0x00000001  // Initialized already
#define CFS_TIMER_FLAG_TIMERED  0x00000002  // KeSetTimer is called

typedef struct cfs_timer {

    KSPIN_LOCK      Lock;

    ULONG           Flags;

    KDPC            Dpc;
    KTIMER          Timer;

    cfs_time_t      deadline;

    void (*proc)(ulong_ptr);
    void *          arg;

} cfs_timer_t;


typedef  void (*timer_func_t)(ulong_ptr);

#define cfs_init_timer(t)

void cfs_timer_init(cfs_timer_t *timer, void (*func)(ulong_ptr), void *arg);
void cfs_timer_done(cfs_timer_t *t);
void cfs_timer_arm(cfs_timer_t *t, cfs_time_t deadline);
void cfs_timer_disarm(cfs_timer_t *t);
int  cfs_timer_is_armed(cfs_timer_t *t);
cfs_time_t cfs_timer_deadline(cfs_timer_t *t);


/* deschedule for a bit... */
static inline void cfs_pause(cfs_duration_t ticks)
{
    cfs_schedule_timeout(TASK_UNINTERRUPTIBLE, ticks);
}


static inline void cfs_enter_debugger(void)
{
#if _X86_
    __asm int 3;
#else
    KdBreakPoint();
#endif
}

/*
 *  libcfs globals initialization/cleanup
 */

int
libcfs_arch_init(void);

void
libcfs_arch_cleanup(void);

/*
 * SMP ...
 */

#define SMP_CACHE_BYTES             128
#define __cacheline_aligned
#define NR_CPUS					    (2)
#define smp_processor_id()		    KeGetCurrentProcessorNumber()
#define smp_num_cpus                NR_CPUS
#define num_online_cpus() smp_num_cpus
#define smp_call_function(f, a, n, w)		do {} while(0)

/*
 *  Irp related
 */

#define NR_IRQS				    512
#define in_interrupt()			(0)

/*
 *  printk flags
 */

#define KERN_EMERG      "<0>"   /* system is unusable                   */
#define KERN_ALERT      "<1>"   /* action must be taken immediately     */
#define KERN_CRIT       "<2>"   /* critical conditions                  */
#define KERN_ERR        "<3>"   /* error conditions                     */
#define KERN_WARNING    "<4>"   /* warning conditions                   */
#define KERN_NOTICE     "<5>"   /* normal but significant condition     */
#define KERN_INFO       "<6>"   /* informational                        */
#define KERN_DEBUG      "<7>"   /* debug-level messages                 */

/*
 * Misc
 */


#define inter_module_get(n)			cfs_symbol_get(n)
#define inter_module_put(n)			cfs_symbol_put(n)

#ifndef likely
#define likely(exp) (exp)
#endif
#ifndef unlikely
#define unlikely(exp) (exp)
#endif

#define lock_kernel()               do {} while(0)
#define unlock_kernel()             do {} while(0)

#define USERMODEHELPER(path, argv, envp)	(0)


#define local_irq_save(x)
#define local_irq_restore(x)

#define cfs_assert                      ASSERT

#define THREAD_NAME

#else   /* !__KERNEL__ */

#define PAGE_CACHE_SIZE PAGE_SIZE
#define PAGE_CACHE_MASK PAGE_MASK

#define getpagesize()   (PAGE_SIZE)


typedef struct {
    int foo;
} pthread_mutex_t;

typedef struct {
    int foo;
} pthread_cond_t;

#define pthread_mutex_init(x, y)    do {} while(0)
#define pthread_cond_init(x, y)     do {} while(0)

#define pthread_mutex_lock(x)       do {} while(0)
#define pthread_mutex_unlock(x)     do {} while(0)

#define pthread_cond_wait(x,y)      do {} while(0)
#define pthread_cond_broadcast(x)   do {} while(0)

typedef struct file {
    int foo;
} cfs_file_t;

typedef struct cfs_proc_dir_entry{
	void		*data;
}cfs_proc_dir_entry_t;



#include "../user-prim.h"

#include <sys/stat.h>
#include <sys/types.h>

#define strcasecmp  strcmp
#define strncasecmp strncmp
#define snprintf   _snprintf
#define getpid()   (0)


#define getpwuid(x) (NULL)
#define getgrgid(x) (NULL)

int cfs_proc_mknod(const char *path, mode_t mode, dev_t dev);

int gethostname(char * name, int namelen);

#define setlinebuf(x) do {} while(0)


NTSYSAPI VOID NTAPI DebugBreak();


static inline void cfs_enter_debugger(void)
{
#if _X86_
    __asm int 3;
#else
    DebugBreak();
#endif
}

/* Maximum EA Information Length */
#define EA_MAX_LENGTH  (sizeof(FILE_FULL_EA_INFORMATION) + 15)


/*
 *  proc user mode routines
 */

HANDLE cfs_proc_open (char * filename, int oflag);
int cfs_proc_close(HANDLE handle);
int cfs_proc_read(HANDLE handle, void *buffer, unsigned int count);
int cfs_proc_write(HANDLE handle, void *buffer, unsigned int count);
int cfs_proc_ioctl(HANDLE handle, int cmd, void *buffer);


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

#endif /* __KERNEL__ */


//
// Inode flags (Linux uses octad number, but why ? strange!!!)
//

#undef S_IFMT
#undef S_IFDIR
#undef S_IFCHR
#undef S_IFREG
#undef S_IREAD
#undef S_IWRITE
#undef S_IEXEC

#define S_IFMT   0x0F000            /* 017 0000 */
#define S_IFSOCK 0x0C000            /* 014 0000 */
#define S_IFLNK  0x0A000            /* 012 0000 */
#define S_IFREG  0x08000            /* 010 0000 */
#define S_IFBLK  0x06000            /* 006 0000 */
#define S_IFDIR  0x04000            /* 004 0000 */
#define S_IFCHR  0x02000            /* 002 0000 */
#define S_IFIFO  0x01000            /* 001 0000 */
#define S_ISUID  0x00800            /* 000 4000 */
#define S_ISGID  0x00400            /* 000 2000 */
#define S_ISVTX  0x00200            /* 000 1000 */

#define S_ISREG(m)      (((m) & S_IFMT) == S_IFREG)
#define S_ISSOCK(m)     (((m) & S_IFMT) == S_IFSOCK)
#define S_ISLNK(m)      (((m) & S_IFMT) == S_IFLNK)
#define S_ISFIL(m)      (((m) & S_IFMT) == S_IFFIL)
#define S_ISBLK(m)      (((m) & S_IFMT) == S_IFBLK)
#define S_ISDIR(m)      (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)      (((m) & S_IFMT) == S_IFCHR)
#define S_ISFIFO(m)     (((m) & S_IFMT) == S_IFIFO)

#define S_IPERMISSION_MASK 0x1FF /*  */

#define S_IRWXU  0x1C0              /* 0 0700 */
#define S_IRUSR  0x100              /* 0 0400 */
#define S_IWUSR  0x080              /* 0 0200 */
#define S_IXUSR  0x040              /* 0 0100 */

#define S_IRWXG  0x038              /* 0 0070 */
#define S_IRGRP  0x020              /* 0 0040 */
#define S_IWGRP  0x010              /* 0 0020 */
#define S_IXGRP  0x008              /* 0 0010 */

#define S_IRWXO  0x007              /* 0 0007 */
#define S_IROTH  0x004              /* 0 0004 */
#define S_IWOTH  0x002              /* 0 0002 */
#define S_IXOTH  0x001              /* 0 0001 */

#define S_IRWXUGO   (S_IRWXU|S_IRWXG|S_IRWXO)
#define S_IALLUGO   (S_ISUID|S_ISGID|S_ISVTX|S_IRWXUGO)
#define S_IRUGO     (S_IRUSR|S_IRGRP|S_IROTH)
#define S_IWUGO     (S_IWUSR|S_IWGRP|S_IWOTH)
#define S_IXUGO     (S_IXUSR|S_IXGRP|S_IXOTH)

/*
 *  linux ioctl coding definitions
 */
 
#define _IOC_NRBITS 8
#define _IOC_TYPEBITS   8
#define _IOC_SIZEBITS   14
#define _IOC_DIRBITS    2

#define _IOC_NRMASK ((1 << _IOC_NRBITS)-1)
#define _IOC_TYPEMASK   ((1 << _IOC_TYPEBITS)-1)
#define _IOC_SIZEMASK   ((1 << _IOC_SIZEBITS)-1)
#define _IOC_DIRMASK    ((1 << _IOC_DIRBITS)-1)

#define _IOC_NRSHIFT    0
#define _IOC_TYPESHIFT  (_IOC_NRSHIFT+_IOC_NRBITS)
#define _IOC_SIZESHIFT  (_IOC_TYPESHIFT+_IOC_TYPEBITS)
#define _IOC_DIRSHIFT   (_IOC_SIZESHIFT+_IOC_SIZEBITS)

/*
 * Direction bits.
 */
#define _IOC_NONE   0U
#define _IOC_WRITE  1U
#define _IOC_READ   2U

#define _IOC(dir,type,nr,size) \
    (((dir)  << _IOC_DIRSHIFT) | \
     ((type) << _IOC_TYPESHIFT) | \
     ((nr)   << _IOC_NRSHIFT) | \
     ((size) << _IOC_SIZESHIFT))

/* used to create numbers */
#define _IO(type,nr)      _IOC(_IOC_NONE,(type),(nr),0)
#define _IOR(type,nr,size)    _IOC(_IOC_READ,(type),(nr),sizeof(size))
#define _IOW(type,nr,size)    _IOC(_IOC_WRITE,(type),(nr),sizeof(size))
#define _IOWR(type,nr,size) _IOC(_IOC_READ|_IOC_WRITE,(type),(nr),sizeof(size))

/* used to decode ioctl numbers.. */
#define _IOC_DIR(nr)        (((nr) >> _IOC_DIRSHIFT) & _IOC_DIRMASK)
#define _IOC_TYPE(nr)       (((nr) >> _IOC_TYPESHIFT) & _IOC_TYPEMASK)
#define _IOC_NR(nr)         (((nr) >> _IOC_NRSHIFT) & _IOC_NRMASK)
#define _IOC_SIZE(nr)       (((nr) >> _IOC_SIZESHIFT) & _IOC_SIZEMASK)

/*
 * Io vector ...  
 */

struct iovec
{
    void *iov_base;
    size_t iov_len;
};


#define ULONG_LONG_MAX ((__u64)(0xFFFFFFFFFFFFFFFF))
/*
 * Convert a string to an unsigned long long integer.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
static inline __u64
strtoull(
	char *nptr,
	char **endptr,
	int base)
{
	char *s = nptr;
	__u64 acc, cutoff;
	int c, neg = 0, any, cutlim;

	/*
	 * See strtol for comments as to the logic used.
	 */
	do {
		c = *s++;
	} while (isspace(c));
	if (c == '-') {
		neg = 1;
		c = *s++;
	} else if (c == '+')
		c = *s++;
	if ((base == 0 || base == 16) &&
	    c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		base = 16;
	}
	if (base == 0)
		base = c == '0' ? 8 : 10;
	cutoff = (__u64)ULONG_LONG_MAX / (__u64)base;
	cutlim = (int)((__u64)ULONG_LONG_MAX % (__u64)base);
	for (acc = 0, any = 0;; c = *s++) {
		if (isdigit(c))
			c -= '0';
		else if (isalpha(c))
			c -= isupper(c) ? 'A' - 10 : 'a' - 10;
		else
			break;
		if (c >= base)
			break;
               if (any < 0 || acc > cutoff || (acc == cutoff && c > cutlim))
			any = -1;
		else {
			any = 1;
			acc *= base;
			acc += c;
		}
	}
	if (any < 0) {
		acc = ULONG_LONG_MAX;
	} else if (neg)
		acc = 0 - acc;
	if (endptr != 0)
		*endptr = (char *) (any ? s - 1 : nptr);
	return (acc);
}

#endif
