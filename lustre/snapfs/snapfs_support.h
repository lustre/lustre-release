/*Got these defination from lustre*/
#define S_SNAP	    (1 << 0)

#define D_TRACE     (1 << 0) /* ENTRY/EXIT markers */
#define D_INODE     (1 << 1)
#define D_SUPER     (1 << 2)
#define D_EXT2      (1 << 3) /* anything from ext2_debug */
#define D_MALLOC    (1 << 4) /* print malloc, free information */
#define D_CACHE     (1 << 5) /* cache-related items */
#define D_INFO      (1 << 6) /* general information */
#define D_IOCTL     (1 << 7) /* ioctl related information */
#define D_BLOCKS    (1 << 8) /* ext2 block allocation */
#define D_NET       (1 << 9) /* network communications */
#define D_WARNING   (1 << 10) /* CWARN(...) == CDEBUG (D_WARNING, ...) */
#define D_BUFFS     (1 << 11)
#define D_OTHER     (1 << 12)
#define D_DENTRY    (1 << 13)
#define D_PAGE      (1 << 15) /* bulk page handling */
#define D_DLMTRACE  (1 << 16)
#define D_ERROR     (1 << 17) /* CERROR(...) == CDEBUG (D_ERROR, ...) */
#define D_EMERG     (1 << 18) /* CEMERG(...) == CDEBUG (D_EMERG, ...) */
#define D_HA        (1 << 19) /* recovery and failover */
#define D_RPCTRACE  (1 << 20) /* for distributed debugging */
#define D_VFSTRACE  (1 << 21)
#define D_SNAP      (1 << 22)

#ifdef __KERNEL__
# include <linux/sched.h> /* THREAD_SIZE */
#else 
# ifndef THREAD_SIZE /* x86_64 has THREAD_SIZE in userspace */
#  define THREAD_SIZE 8192
# endif
#endif

# include <linux/vmalloc.h> 
# define snap_debug_msg(mask, file, fn, line, stack, format, a...)    \
    printk("%02x (@%lu %s:%s,l. %d %d %lu): " format,                    \
           (mask), (long)time(0), file, fn, line,                   \
           getpid() , stack, ## a);

#define LUSTRE_TRACE_SIZE (THREAD_SIZE >> 5)

#ifdef __KERNEL__
# ifdef  __ia64__
#  define CDEBUG_STACK (THREAD_SIZE -                                      \
                        ((unsigned long)__builtin_dwarf_cfa() &            \
                         (THREAD_SIZE - 1)))
# else
#  define CDEBUG_STACK (THREAD_SIZE -                                      \
                        ((unsigned long)__builtin_frame_address(0) &       \
                         (THREAD_SIZE - 1)))
# endif

#define CHECK_STACK(stack)                                                    \
        do {                                                                  \
                if ((stack) > 3*THREAD_SIZE/4 && (stack) > snap_stack) {      \
                        printk( "maximum lustre stack %u\n",        	      \
                                          snap_stack = (stack));              \
                }                                                             \
        } while (0)
#else /* __KERNEL__ */
#define CHECK_STACK(stack) do { } while(0)
#define CDEBUG_STACK (0L)
#endif /* __KERNEL__ */

#if 1
#define CDEBUG(mask, format, a...)                                            \
do {                                                                          \
        CHECK_STACK(CDEBUG_STACK);                                            \
        if (!(mask) || ((mask) & (D_ERROR | D_EMERG | D_WARNING)) ||          \
            (snap_debug_level & (mask)))                                      \
		printk(format, ## a);                			      \
} while (0)

#define CWARN(format, a...)  CDEBUG(D_WARNING, format, ## a)
#define CERROR(format, a...) CDEBUG(D_ERROR, format, ## a)
#define CEMERG(format, a...) CDEBUG(D_EMERG, format, ## a)

#define GOTO(label, rc)                                                 \
do {                                                                    \
        long GOTO__ret = (long)(rc);                                    \
        CDEBUG(D_TRACE,"Process leaving via %s (rc=%lu : %ld : %lx)\n", \
               #label, (unsigned long)GOTO__ret, (signed long)GOTO__ret,\
               (signed long)GOTO__ret);                                 \
        goto label;                                                     \
} while (0)

#define RETURN(rc)                                                      \
do {                                                                    \
        typeof(rc) RETURN__ret = (rc);                                  \
        CDEBUG(D_TRACE, "Process %d leaving %s (rc=%lu : %ld : %lx)\n", \
               current->pid, __FUNCTION__, (long)RETURN__ret,		\
	       (long)RETURN__ret, (long)RETURN__ret);			\
        return RETURN__ret;                                             \
} while (0)

#define ENTRY                                                           \
do {                                                                    \
	CDEBUG(D_TRACE,  "Process %d enter %s\n",       		\
	       current->pid, __FUNCTION__);                             \
} while (0)

#define EXIT                                                            \
do {                                                                    \
        CDEBUG(D_TRACE, "Process %d leaving %s \n",			\
	      current->pid, __FUNCTION__);				\
} while(0)
#else
#define CDEBUG(mask, format, a...)      do { } while (0)
#define CWARN(format, a...)             do { } while (0)
#define CERROR(format, a...)            printk("<3>" format, ## a)
#define CEMERG(format, a...)            printk("<0>" format, ## a)
#define GOTO(label, rc)                 do { (void)(rc); goto label; } while (0)
#define RETURN(rc)                      return (rc)
#define ENTRY                           do { } while (0)
#define EXIT                            do { } while (0)
#endif

#define SNAP_ALLOC(ptr, size)						\
do {									\
	if (size <= 4096) {						\
		ptr = kmalloc((unsigned long) size, GFP_KERNEL);	\
                CDEBUG(D_MALLOC, "Proc %d %s:%d kmalloced: %d at %x.\n",\
		       current->pid, __FUNCTION__, __LINE__,		\
		       (int) size, (int) ptr);				\
	} else {							\
		ptr = vmalloc((unsigned long) size);			\
		CDEBUG(D_MALLOC, "Proc %d %s:%d vmalloced: %d at %x.\n",\
		       current->pid, __FUNCTION__, __LINE__,		\
		       (int) size, (int) ptr);				\
	}								\
	if (ptr == 0) {							\
		printk("kernel malloc returns 0 at %s:%d\n",		\
		       __FILE__, __LINE__);				\
	} else {							\
		memset(ptr, 0, size);					\
		snap_kmemory += size;					\
	}								\
} while (0)

#define SNAP_FREE(ptr,size)						\
do {									\
	snap_kmemory -= size;						\
	if (size <= 4096) {						\
		CDEBUG(D_MALLOC, "Proc %d %s:%d kfreed: %d at %x.\n",	\
		       current->pid, __FUNCTION__, __LINE__,		\
		       (int) size, (int) ptr);				\
		kfree((ptr));						\
	} else {							\
		CDEBUG(D_MALLOC, "Proc %d %s:%d vfreed: %d at %x.\n",	\
		       current->pid, __FUNCTION__, __LINE__,		\
		       (int) size, (int) ptr);				\
		vfree((ptr));						\
	}								\
} while (0)

