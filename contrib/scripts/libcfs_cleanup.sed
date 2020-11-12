#!/bin/sed -f

# Script to cleanup libcfs macros, it runs against the tree at build time.
# Migrate libcfs to emulate Linux kernel APIs.
# https://jira.whamcloud.com/browse/LU-1346

# Run this script like:
#	find libcfs lnet lustre -name "*.[ch]" | grep -v gnilnd |
#		xargs sed -i "" -f contrib/scripts/libcfs_cleanup.sed


################################################################################
# lock - spinlock, rw_semaphore, rwlock, completion, semaphore, mutex
#      - lock_kernel, unlock_kernel, lockdep

# spinlock
/typedef  *spinlock_t  *cfs_spinlock_t;/d
s/\bcfs_spinlock_t\b/spinlock_t/g
s/\bcfs_spin_lock_init\b/spin_lock_init/g
/#[ \t]*define[ \t]*\bspin_lock_init\b *( *\w* *)[ \t]*\bspin_lock_init\b *( *\w* *)/d
s/\bcfs_spin_lock\b/spin_lock/g
/#[ \t]*define[ \t]*\bspin_lock\b *( *\w* *)[ \t]*\bspin_lock\b *( *\w* *)/d
s/\bcfs_spin_lock_bh\b/spin_lock_bh/g
/#[ \t]*define[ \t]*\bspin_lock_bh\b *( *\w* *)[ \t]*\bspin_lock_bh\b *( *\w* *)/d
s/\bcfs_spin_lock_bh_init\b/spin_lock_bh_init/g
/#[ \t]*define[ \t]*\bspin_lock_bh_init\b *( *\w* *)[ \t]*\bspin_lock_bh_init\b *( *\w* *)/d
s/\bcfs_spin_unlock\b/spin_unlock/g
/#[ \t]*define[ \t]*\bspin_unlock\b *( *\w* *)[ \t]*\bspin_unlock\b *( *\w* *)/d
s/\bcfs_spin_unlock_bh\b/spin_unlock_bh/g
/#[ \t]*define[ \t]*\bspin_unlock_bh\b *( *\w* *)[ \t]*\bspin_unlock_bh\b *( *\w* *)/d
s/\bcfs_spin_trylock\b/spin_trylock/g
/#[ \t]*define[ \t]*\bspin_trylock\b *( *\w* *)[ \t]*\bspin_trylock\b *( *\w* *)/d
s/\bcfs_spin_is_locked\b/spin_is_locked/g
/#[ \t]*define[ \t]*\bspin_is_locked\b *( *\w* *)[ \t]*\bspin_is_locked\b *( *\w* *)/d

s/\bcfs_spin_lock_irq\b/spin_lock_irq/g
/#[ \t]*define[ \t]*\bspin_lock_irq\b *( *\w* *)[ \t]*\bspin_lock_irq\b *( *\w* *)/d
s/\bcfs_spin_unlock_irq\b/spin_unlock_irq/g
/#[ \t]*define[ \t]*\bspin_unlock_irq\b *( *\w* *)[ \t]*\bspin_unlock_irq\b *( *\w* *)/d
s/\bcfs_read_lock_irqsave\b/read_lock_irqsave/g
/#[ \t]*define[ \t]*\bread_lock_irqsave\b *( *\w* *, *\w* *)[ \t]*\bread_lock_irqsave\b *( *\w* *, *\w* *)/d
s/\bcfs_write_lock_irqsave\b/write_lock_irqsave/g
/#[ \t]*define[ \t]*\bwrite_lock_irqsave\b *( *\w* *, *\w* *)[ \t]*\bwrite_lock_irqsave\b *( *\w* *, *\w* *)/d
s/\bcfs_write_unlock_irqrestore\b/write_unlock_irqrestore/g
/#[ \t]*define[ \t]*\bwrite_unlock_irqrestore\b *( *\w* *, *\w* *)[ \t]*\bwrite_unlock_irqrestore\b *( *\w* *, *\w* *)/d
s/\bcfs_spin_lock_irqsave\b/spin_lock_irqsave/g
/#[ \t]*define[ \t]*\bspin_lock_irqsave\b *( *\w* *, *\w* *)[ \t]*\bspin_lock_irqsave\b *( *\w* *, *\w* *)/d
s/\bcfs_spin_unlock_irqrestore\b/spin_unlock_irqrestore/g
/#[ \t]*define[ \t]*\bspin_unlock_irqrestore\b *( *\w* *, *\w* *)[ \t]*\bspin_unlock_irqrestore\b *( *\w* *, *\w* *)/d
s/\bCFS_SPIN_LOCK_UNLOCKED\b/SPIN_LOCK_UNLOCKED/g
/#[ \t]*define[ \t]*\bSPIN_LOCK_UNLOCKED\b[ \t]*\bSPIN_LOCK_UNLOCKED\b/d

# rw_semaphore
s/\bcfs_semaphore\b/semaphore/g
s/\bcfs_rw_semaphore_t\b/struct rw_semaphore/g
s/\bcfs_init_rwsem\b/init_rwsem/g
/#[ \t]*define[ \t]*\binit_rwsem\b *( *\w* *)[ \t]*\binit_rwsem\b *( *\w* *)/d
s/\bcfs_down_read\b/down_read/g
/#[ \t]*define[ \t]*\bdown_read\b *( *\w* *)[ \t]*\bdown_read\b *( *\w* *)/d
s/\bcfs_down_read_trylock\b/down_read_trylock/g
/#[ \t]*define[ \t]*\bdown_read_trylock\b *( *\w* *)[ \t]*\bdown_read_trylock\b *( *\w* *)/d
s/\bcfs_up_read\b/up_read/g
/#[ \t]*define[ \t]*\bup_read\b *( *\w* *)[ \t]*\bup_read\b *( *\w* *)/d
s/\bcfs_down_write\b/down_write/g
/#[ \t]*define[ \t]*\bdown_write\b *( *\w* *)[ \t]*\bdown_write\b *( *\w* *)/d
s/\bcfs_down_write_trylock\b/down_write_trylock/g
/#[ \t]*define[ \t]*\bdown_write_trylock\b *( *\w* *)[ \t]*\bdown_write_trylock\b *( *\w* *)/d
s/\bcfs_up_write\b/up_write/g
/#[ \t]*define[ \t]*\bup_write\b *( *\w* *)[ \t]*\bup_write\b *( *\w* *)/d
s/\bcfs_fini_rwsem\b/fini_rwsem/g
s/\bCFS_DECLARE_RWSEM\b/DECLARE_RWSEM/g
/#[ \t]*define[ \t]*\bDECLARE_RWSEM\b *( *\w* *)[ \t]*\bDECLARE_RWSEM\b *( *\w* *)/d

#finish this with other atomics
#s/\bcfs_mt_atomic_t\b/atomic_t/g
#s/\bcfs_mt_atomic_read\b/atomic_read/g
#s/\bcfs_mt_atomic_set\b/atomic_set/g
#s/\bcfs_mt_atomic_dec_and_test\b/atomic_dec_and_test/g
#s/\bcfs_mt_atomic_inc\b/atomic_inc/g
#s/\bcfs_mt_atomic_dec\b/atomic_dec/g
#s/\bcfs_mt_atomic_add\b/atomic_add/g
#s/\bcfs_mt_atomic_sub\b/atomic_sub/g

# rwlock
/typedef  *rwlock_t  *cfs_rwlock_t;/d
s/\bcfs_rwlock_t\b/rwlock_t/g
s/\bcfs_rwlock_init\b/rwlock_init/g
/#[ \t]*define[ \t]*\brwlock_init\b *( *\w* *)[ \t]*\brwlock_init\b *( *\w* *)/d
s/\bcfs_read_lock\b/read_lock/g
/#[ \t]*define[ \t]*\bread_lock\b *( *\w* *)[ \t]*\bread_lock\b *( *\w* *)/d
s/\bcfs_read_unlock\b/read_unlock/g
/#[ \t]*define[ \t]*\bread_unlock\b *( *\w* *)[ \t]*\bread_unlock\b *( *\w* *)/d
s/\bcfs_read_unlock_irqrestore\b/read_unlock_irqrestore/g
#/#[ \t]*define[ \t]*\bread_unlock_irqrestore\b *( *\w* *)[ \t]*\bread_unlock_irqrestore\b *( *\w* *)/d
/#define read_unlock_irqrestore(lock,flags) \\/{N;d;}
s/\bcfs_write_lock\b/write_lock/g
/#[ \t]*define[ \t]*\bwrite_lock\b *( *\w* *)[ \t]*\bwrite_lock\b *( *\w* *)/d
s/\bcfs_write_unlock\b/write_unlock/g
/#[ \t]*define[ \t]*\bwrite_unlock\b *( *\w* *)[ \t]*\bwrite_unlock\b *( *\w* *)/d
s/\bcfs_write_lock_bh\b/write_lock_bh/g
/#[ \t]*define[ \t]*\bwrite_lock_bh\b *( *\w* *)[ \t]*\bwrite_lock_bh\b *( *\w* *)/d
s/\bcfs_write_unlock_bh\b/write_unlock_bh/g
/#[ \t]*define[ \t]*\bwrite_unlock_bh\b *( *\w* *)[ \t]*\bwrite_unlock_bh\b *( *\w* *)/d
s/\bCFS_RW_LOCK_UNLOCKED\b/RW_LOCK_UNLOCKED/g
/#[ \t]*define[ \t]*\bRW_LOCK_UNLOCKED\b  *\bRW_LOCK_UNLOCKED\b */d

# completion
s/\bcfs_completion_t\b/struct completion/g
s/\bcfs_mt_completion_t\b/struct completion/g
s/\bcfs_mt_init_completion\b/init_completion/g
s/\bcfs_mt_wait_for_completion\b/wait_for_completion/g
s/\bcfs_mt_complete\b/complete/g
s/\bcfs_mt_fini_completion\b/fini_completion/g
s/\bCFS_DECLARE_COMPLETION\b/DECLARE_COMPLETION/g
/#[ \t]*define[ \t]*\bDECLARE_COMPLETION\b *( *\w* *)[ \t]*\bDECLARE_COMPLETION\b *( *\w* *)/d
s/\bCFS_INIT_COMPLETION\b/INIT_COMPLETION/g
/#[ \t]*define[ \t]*\bINIT_COMPLETION\b *( *\w* *)[ \t]*\bINIT_COMPLETION\b *( *\w* *)/d
s/\bCFS_COMPLETION_INITIALIZER\b/COMPLETION_INITIALIZER/g
/#[ \t]*define[ \t]*\bCOMPLETION_INITIALIZER\b *( *\w* *)[ \t]*\bCOMPLETION_INITIALIZER\b *( *\w* *)/d
s/\bcfs_init_completion\b/init_completion/g
/#[ \t]*define[ \t]*\binit_completion\b *( *\w* *)[ \t]*\binit_completion\b *( *\w* *)/d
s/\bcfs_complete\b/complete/g
/#[ \t]*define[ \t]*\bcomplete\b *( *\w* *)[ \t]*\bcomplete\b *( *\w* *)/d
s/\bcfs_wait_for_completion\b/wait_for_completion/g
/#[ \t]*define[ \t]*\bwait_for_completion\b *( *\w* *)[ \t]*\bwait_for_completion\b *( *\w* *)/d
s/\bcfs_wait_for_completion_interruptible\b/wait_for_completion_interruptible/g
/#define wait_for_completion_interruptible(c) \\/{N;d;}
s/\bcfs_complete_and_exit\b/complete_and_exit/g
/#[ \t]*define[ \t]*\bcomplete_and_exit\b *( *\w* *, *\w* *)[ \t]*\bcomplete_and_exit\b *( *\w* *, *\w* *)/d
s/\bcfs_fini_completion\b/fini_completion/g

# semaphore
s/\bcfs_semaphore_t\b/struct semaphore/g
s/\bCFS_DEFINE_SEMAPHORE\b/DEFINE_SEMAPHORE/g
/#[ \t]*define[ \t]*\bDEFINE_SEMAPHORE\b *( *\w* *)[ \t]*\bDEFINE_SEMAPHORE\b *( *\w* *)/d
s/\bcfs_sema_init\b/sema_init/g
/#[ \t]*define[ \t]*\bsema_init\b *( *\w* *, *\w* *)[ \t]*\bsema_init\b *( *\w* *, *\w* *)/d
s/\bcfs_up\b/up/g
/#[ \t]*define[ \t]*\bup\b *( *\w* *)[ \t]*\bup\b *( *\w* *)/d
s/\bcfs_down\b/down/g
/#[ \t]*define[ \t]*\bdown\b *( *\w* *)[ \t]*\bdown\b *( *\w* *)/d
s/\bcfs_down_interruptible\b/down_interruptible/g
/#[ \t]*define[ \t]*\bdown_interruptible\b *( *\w* *)[ \t]*\bdown_interruptible\b *( *\w* *)/d
s/\bcfs_down_trylock\b/down_trylock/g
/#[ \t]*define[ \t]*\bdown_trylock\b *( *\w* *)[ \t]*\bdown_trylock\b *( *\w* *)/d

# mutex
s/\bcfs_mutex_t\b/struct mutex/g
s/\bCFS_DEFINE_MUTEX\b/DEFINE_MUTEX/g
/#[ \t]*define[ \t]*\DEFINE_MUTEX\b *( *name *)[ \t]*\bDEFINE_MUTEX\b *( *name *)/d
s/\bcfs_mutex_init\b/mutex_init/g
/#[ \t]*define[ \t]*\bmutex_init\b *( *\w* *)[ \t]*\bmutex_init\b *( *\w* *)/d
s/\bcfs_mutex_lock\b/mutex_lock/g
/#[ \t]*define[ \t]*\bmutex_lock\b *( *\w* *)[ \t]*\bmutex_lock\b *( *\w* *)/d
s/\bcfs_mutex_unlock\b/mutex_unlock/g
/#[ \t]*define[ \t]*\bmutex_unlock\b *( *\w* *)[ \t]*\bmutex_unlock\b *( *\w* *)/d
s/\bcfs_mutex_lock_interruptible\b/mutex_lock_interruptible/g
/#[ \t]*define[ \t]*\bmutex_lock_interruptible\b *( *\w* *)[ \t]*\bmutex_lock_interruptible\b *( *\w* *)/d
s/\bcfs_mutex_trylock\b/mutex_trylock/g
/#[ \t]*define[ \t]*\bmutex_trylock\b *( *\w* *)[ \t]*\bmutex_trylock\b *( *\w* *)/d
s/\bcfs_mutex_is_locked\b/mutex_is_locked/g
/#[ \t]*define[ \t]*\bmutex_is_locked\b *( *\w* *)[ \t]*\bmutex_is_locked\b *( *\w* *)/d
s/\bcfs_mutex_destroy\b/mutex_destroy/g
/#[ \t]*define[ \t]*\bmutex_destroy\b *( *\w* *)[ \t]*\bmutex_destroy\b *( *\w* *)/d

# lock_kernel, unlock_kernel
# s/\bcfs_lock_kernel\b/lock_kernel/g
# /#[ \t]*define[ \t]*\block_kernel\b *( *)[ \t]*\block_kernel\b *( *)/d
# s/\bcfs_unlock_kernel\b/unlock_kernel/g
# /#[ \t]*define[ \t]*\bunlock_kernel\b *( *)[ \t]*\bunlock_kernel\b *( *)/d

# lockdep
s/\bcfs_lock_class_key\b/lock_class_key/g
s/\bcfs_lock_class_key_t\b/struct lock_class_key/g
s/\bcfs_lockdep_set_class\b/lockdep_set_class/g
s/\bcfs_lockdep_off\b/lockdep_off/g
s/\bcfs_lockdep_on\b/lockdep_on/g
/#[ \t]*define[ \t]*\blockdep_off\b *( *)[ \t]*\blockdep_off\b *( *)/d
/#[ \t]*define[ \t]*\blockdep_on\b *( *)[ \t]*\blockdep_on\b *( *)/d
/#[ \t]*define[ \t]*\blockdep_set_class\b *( *\w* *, *\w* *)[ \t]*\blockdep_set_class\b *( *\w* *, *\w* *)/d

s/\bcfs_mutex_lock_nested\b/mutex_lock_nested/g
#/#[ \t]*define[ \t]*\bmutex_lock_nested\b *( *\w* *, *\w* *)[ \t]*\bmutex_lock_nested\b *( *\w* *, *\w* *)/d
/#define mutex_lock_nested(mutex, subclass) \\/{N;d;}
s/\bcfs_spin_lock_nested\b/spin_lock_nested/g
/#[ \t]*define[ \t]*\bspin_lock_nested\b *( *\w* *, *\w* *)[ \t]*\bspin_lock_nested\b *( *\w* *, *\w* *)/d
s/\bcfs_down_read_nested\b/down_read_nested/g
/#[ \t]*define[ \t]*\bdown_read_nested\b *( *\w* *, *\w* *)[ \t]*\bdown_read_nested\b *( *\w* *, *\w* *)/d
s/\bcfs_down_write_nested\b/down_write_nested/g
/#[ \t]*define[ \t]*\bdown_write_nested\b *( *\w* *, *\w* *)[ \t]*\bdown_write_nested\b *( *\w* *, *\w* *)/d

###############################################################################
# bitops

s/\bcfs_test_bit\b/test_bit/g
/#[ \t]*define[ \t]*\btest_bit\b *( *\w* *, *\w* *)[ \t]*\btest_bit\b *( *\w* *, *\w* *)/d
s/\bcfs_set_bit\b/set_bit/g
/#[ \t]*define[ \t]*\bset_bit\b *( *\w* *, *\w* *)[ \t]*\bset_bit\b *( *\w* *, *\w* *)/d
s/\bcfs_clear_bit\b/clear_bit/g
/#[ \t]*define[ \t]*\bclear_bit\b *( *\w* *, *\w* *)[ \t]*\bclear_bit\b *( *\w* *, *\w* *)/d
s/\bcfs_test_and_set_bit\b/test_and_set_bit/g
/#[ \t]*define[ \t]*\btest_and_set_bit\b *( *\w* *, *\w* *)[ \t]*\btest_and_set_bit\b *( *\w* *, *\w* *)/d
s/\bcfs_test_and_clear_bit\b/test_and_clear_bit/g
/#[ \t]*define[ \t]*\btest_and_clear_bit\b *( *\w* *, *\w* *)[ \t]*\btest_and_clear_bit\b *( *\w* *, *\w* *)/d
s/\bcfs_find_first_bit\b/find_first_bit/g
/#[ \t]*define[ \t]*\bfind_first_bit\b *( *\w* *, *\w* *)[ \t]*\bfind_first_bit\b *( *\w* *, *\w* *)/d
s/\bcfs_find_first_zero_bit\b/find_first_zero_bit/g
/#[ \t]*define[ \t]*\bfind_first_zero_bit\b *( *\w* *, *\w* *)[ \t]*\bfind_first_zero_bit\b *( *\w* *, *\w* *)/d
s/\bcfs_find_next_bit\b/find_next_bit/g
/#[ \t]*define[ \t]*\bfind_next_bit\b *( *\w* *, *\w* *, *\w* *)[ \t]*\bfind_next_bit\b *( *\w* *, *\w* *, *\w* *)/d
s/\bcfs_find_next_zero_bit\b/find_next_zero_bit/g
/#define find_next_zero_bit(addr, size, off) \\/{N;d;}
s/\bcfs_ffz\b/ffz/g
/#[ \t]*define[ \t]*\bffz\b *( *\w* *)[ \t]*\bffz\b *( *\w* *)/d
s/\bcfs_ffs\b/ffs/g
/#[ \t]*define[ \t]*\bffs\b *( *\w* *)[ \t]*\bffs\b *( *\w* *)/d
s/\bcfs_fls\b/fls/g
/#[ \t]*define[ \t]*\bfls\b *( *\w* *)[ \t]*\bfls\b *( *\w* *)/d

################################################################################
# file operations

s/\bcfs_file_t\b/struct file/g
s/\bcfs_dentry_t\b/struct dentry/g
s/\bcfs_dirent_t\b/struct dirent64/g
s/\bcfs_kstatfs_t\b/struct kstatfs/g
s/\bcfs_filp_size\b/filp_size/g
s/\bcfs_filp_poff\b/filp_poff/g
s/\bcfs_filp_open\b/filp_open/g
/#[ \t]*define[ \t]*\bfilp_open\b *( *\w* *, *\w* *, *\w* *)[ \t]*\bfilp_open\b *( *\w* *, *\w* *, *\w* *)/d
s/\bcfs_do_fsync\b/do_fsync/g
s/\bcfs_filp_close\b/filp_close/g
/#[ \t]*define[ \t]*\bfilp_close\b *( *\w* *, *\w* *)[ \t]*\bfilp_close\b *( *\w* *, *\w* *)/d
s/\bcfs_filp_read\b/filp_read/g
s/\bcfs_filp_write\b/filp_write/g
s/\bcfs_filp_fsync\b/filp_fsync/g
s/\bcfs_get_file\b/get_file/g
/#[ \t]*define[ \t]*\bget_file\b *( *\w* *)[ \t]*\bget_file\b *( *\w* *)/d
s/\bcfs_get_fd\b/fget/g
/#[ \t]*define[ \t]*\bfget\b *( *\w* *)[ \t]*\bfget\b *( *\w* *)/d
s/\bcfs_put_file\b/fput/g
/#[ \t]*define[ \t]*\bfput\b *( *\w* *)[ \t]*\bfput\b *( *\w* *)/d
s/\bcfs_file_count\b/file_count/g
/#[ \t]*define[ \t]*\bfile_count\b *( *\w* *)[ \t]*\bfile_count\b *( *\w* *)/d
s/\bCFS_INT_LIMIT\b/INT_LIMIT/g
s/\bCFS_OFFSET_MAX\b/OFFSET_MAX/g
s/\bcfs_flock_t\b/struct file_lock/g
s/\b[cfs_]*flock_type(\([^)]*\))\b/\1->fl_type/g
s/\b[cfs_]*flock_set_type(\([^,]*\), \([^)]*\))\b/\1->fl_type = \2/g
s/\b[cfs_]*flock_pid(\([^)]*\))\b/\1->fl_pid/g
s/\b[cfs_]*flock_set_pid(\([^,]*\), \([^)]*\))\b/\1->fl_pid = \2/g
s/\b[cfs_]*flock_start(\([^)]*\))\b/\1->fl_start/g
s/\b[cfs_]*flock_set_start(\([^,]*\), \([^)]*\))\b/\1->fl_start = \2/g
s/\b[cfs_]*flock_end(\([^)]*\))\b/\1->fl_end/g
s/\b[cfs_]*flock_set_end(\([^,]*\), \([^)]*\))\b/\1->fl_end = \2/g
s/\bcfs_user_write\b/user_write/g

################################################################################
# memory operations
s/\bcfs_page_t\b/struct page/g
/typedef[ \t]*\bstruct page\b[ \t]*\bstruct page\b/d
s/\bCFS_PAGE_SIZE\b/PAGE_CACHE_SIZE/g
/#[ \t]*define[ \t]*\bPAGE_CACHE_SIZE\b[ \t]*\bPAGE_CACHE_SIZE\b/d
s/\bCFS_PAGE_SHIFT\b/PAGE_CACHE_SHIFT/g
/#[ \t]*define[ \t]*\bPAGE_CACHE_SHIFT\b[ \t]*\bPAGE_CACHE_SHIFT\b/d
s/\bcfs_num_physpages\b/num_physpages/g
/#[ \t]*define[ \t]*\bnum_physpages\b[ \t]*\bnum_physpages\b/d
s/\bcfs_copy_from_user\b/copy_from_user/g
/#[ \t]*define[ \t]*\bcopy_from_user\b *( *\w* *, *\w* *, *\w* *)[ \t]*\bcopy_from_user\b *( *\w* *, *\w* *, *\w* *)/d
s/\bcfs_copy_to_user\b/copy_to_user/g
/#[ \t]*define[ \t]*\bcopy_to_user\b *( *\w* *, *\w* *, *\w* *)[ \t]*\bcopy_to_user\b *( *\w* *, *\w* *, *\w* *)/d
s/\bcfs_page_address\b/page_address/g
/#[ \t]*define[ \t]*\bpage_address\b *( *\w* *)[ \t]*\bpage_address\b *( *\w* *)/d
s/\bcfs_kmap\b/kmap/g
/#[ \t]*define[ \t]*\bkmap\b *( *\w* *)[ \t]*\bkmap\b *( *\w* *)/d
s/\bcfs_kunmap\b/kunmap/g
/#[ \t]*define[ \t]*\bkunmap\b *( *\w* *)[ \t]*\bkunmap\b *( *\w* *)/d
s/\bcfs_get_page\b/get_page/g
/#[ \t]*define[ \t]*\bget_page\b *( *\w* *)[ \t]*\bget_page\b *( *\w* *)/d
s/\bcfs_page_count\b/page_count/g
/#[ \t]*define[ \t]*\bpage_count\b *( *\w* *)[ \t]*\bpage_count\b *( *\w* *)/d
s/\bcfs_page_index\b/page_index/g
/#[ \t]*define[ \t]*\bpage_index\b *( *\w* *)[ \t]*\bpage_index\b *( *\w* *)/d
s/\bcfs_page_pin\b/page_cache_get/g
/#[ \t]*define[ \t]*\bpage_cache_get\b *( *\w* *)[ \t]*\bpage_cache_get\b *( *\w* *)/d
s/\bcfs_page_unpin\b/page_cache_release/g
/#[ \t]*define[ \t]*\bpage_cache_release\b *( *\w* *)[ \t]*\bpage_cache_release\b *( *\w* *)/d
s/\bcfs_memory_pressure_get\b/memory_pressure_get/g
s/\bcfs_memory_pressure_set\b/memory_pressure_set/g
s/\bcfs_memory_pressure_clr\b/memory_pressure_clr/g
s/\bCFS_NUM_CACHEPAGES\b/NUM_CACHEPAGES/g
 # memory allocator
s/\bCFS_ALLOC_ATOMIC\b/GFP_ATOMIC/g
/#[ \t]*define[ \t]*\bGFP_ATOMIC\b[ \t]*\bGFP_ATOMIC\b/d
s/\bCFS_ALLOC_WAIT\b/__GFP_WAIT/g
/#[ \t]*define[ \t]*\b__GFP_WAIT\b[ \t]*\b__GFP_WAIT\b/d
s/\bCFS_ALLOC_ZERO\b/__GFP_ZERO/g
/#[ \t]*define[ \t]*\b__GFP_ZERO\b[ \t]*\b__GFP_ZERO\b/d
s/\bCFS_ALLOC_FS\b/__GFP_FS/g
/#[ \t]*define[ \t]*\b__GFP_FS\b[ \t]*\b__GFP_FS\b/d
s/\bCFS_ALLOC_IO\b/__GFP_IO/g
/#[ \t]*define[ \t]*\b__GFP_IO\b[ \t]*\b__GFP_IO\b/d
s/\bCFS_ALLOC_NOWARN\b/__GFP_NOWARN/g
/#[ \t]*define[ \t]*\b__GFP_NOWARN\b[ \t]*\b__GFP_NOWARN\b/d
s/\bCFS_ALLOC_STD\b/GFP_IOFS/g
/#[ \t]*define[ \t]*\bGFP_IOFS\b[ \t]*\bGFP_IOFS\b/d
s/\bCFS_ALLOC_USER\b/GFP_USER/g
/#[ \t]*define[ \t]*\bGFP_USER\b[ \t]*\bGFP_USER\b/d
s/\bCFS_ALLOC_KERNEL\b/GFP_KERNEL/g
/#[ \t]*define[ \t]*\bGFP_KERNEL\b[ \t]*\bGFP_KERNEL\b/d
s/\bCFS_ALLOC_NOFS\b/GFP_NOFS/g
/#[ \t]*define[ \t]*\bGFP_NOFS\b[ \t]*\bGFP_NOFS\b/d
s/\bCFS_ALLOC_HIGHMEM\b/__GFP_HIGHMEM/g
/#[ \t]*define[ \t]*\b__GFP_HIGHMEM\b[ \t]*\b__GFP_HIGHMEM\b/d
s/\bCFS_ALLOC_HIGHUSER\b/GFP_HIGHUSER/g
/#[ \t]*define[ \t]*\bGFP_HIGHUSER\b[ \t]*\bGFP_HIGHUSER\b/d
s/\bCFS_ALLOC_ATOMIC_TRY\b/ALLOC_ATOMIC_TRY/g
s/\bcfs_alloc\b/kmalloc/g
/#[ \t]*define[ \t]*\bkmalloc\b *( *\w* *, *\w* *)[ \t]*\bkmalloc\b *( *\w* *, *\w* *)/d
s/\bcfs_free\b/kfree/g
/#[ \t]*define[ \t]*\bkfree\b *( *\w* *)[ \t]*\bkfree\b *( *\w* *)/d
s/\bcfs_alloc_large\b/vmalloc/g
/#[ \t]*define[ \t]*\bvmalloc\b *( *\w* *)[ \t]*\bvmalloc\b *( *\w* *)/d
s/\bcfs_free_large\b/vfree/g
/#[ \t]*define[ \t]*\bvfree\b *( *\w* *)[ \t]*\bvfree\b *( *\w* *)/d
s/\bcfs_alloc_page\b/alloc_page/g
/#[ \t]*define[ \t]*\balloc_page\b *( *\w* *)[ \t]*\balloc_page\b *( *\w* *)/d
s/\bcfs_free_page\b/__free_page/g
/#[ \t]*define[ \t]*\b__free_page\b *( *\w* *)[ \t]*\b__free_page\b *( *\w* *)/d
# TODO: SLAB allocator
s/\bCFS_DECL_MMSPACE\b/DECL_MMSPACE/g
s/\bCFS_MMSPACE_OPEN\b/MMSPACE_OPEN/g
s/\bCFS_MMSPACE_CLOSE\b/MMSPACE_CLOSE/g
s/\bCFS_SLAB_HWCACHE_ALIGN\b/SLAB_HWCACHE_ALIGN/g
/#[ \t]*define[ \t]*\bSLAB_HWCACHE_ALIGN\b[ \t]*\bSLAB_HWCACHE_ALIGN\b/d
s/\bCFS_SLAB_KERNEL\b/SLAB_KERNEL/g
/#[ \t]*define[ \t]*\bSLAB_KERNEL\b[ \t]*\bSLAB_KERNEL\b/d
s/\bCFS_SLAB_NOFS\b/SLAB_NOFS/g
/#[ \t]*define[ \t]*\bSLAB_NOFS\b[ \t]*\bSLAB_NOFS\b/d
s/\bcfs_shrinker\b/shrinker/g
/#[ \t]*define[ \t]*\bshrinker\b[ \t]*\bshrinker\b/d
s/\bcfs_shrinker_t\b/shrinker_t/g
/typedef[ \t]*\bshrinker_t\b[ \t]*\bshrinker_t\b/d
s/\bcfs_set_shrinker\b/set_shrinker/g
/#[ \t]*define[ \t]*\bset_shrinker\b *( *\w* *, *\w* *)[ \t]*\bset_shrinker\b *( *\w* *, *\w* *)/d
s/\bcfs_remove_shrinker\b/remove_shrinker/g
/#[ \t]*define[ \t]*\bremove_shrinker\b *( *\w* *)[ \t]*\bremove_shrinker\b *( *\w* *)/d
s/\bCFS_DEFAULT_SEEKS\b/DEFAULT_SEEKS/g
/#[ \t]*define[ \t]*\bDEFAULT_SEEKS\b[ \t]*\bDEFAULT_SEEKS\b/d
s/cfs_mem_cache_t/struct kmem_cache/g
s/cfs_mem_cache_create/kmem_cache_create/g
s/\w+[ =]*cfs_mem_cache_destroy/kmem_cache_destroy/g
s/cfs_mem_cache_destroy/kmem_cache_destroy/g
s/cfs_mem_cache_alloc/kmem_cache_alloc/g
s/cfs_mem_cache_free/kmem_cache_free/g
s/cfs_mem_is_in_cache/kmem_is_in_cache/g

################################################################################
# macros in kp30.h

s/\bcfs_num_online_cpus\b/num_online_cpus/g
/#[ \t]*define[ \t]*\bnum_online_cpus\b *( *)[ \t]*\bnum_online_cpus\b *( *)/d
s/\bwait_on_page\b/wait_on_page_locked/g
/#[ \t]*define[ \t]*\bwait_on_page_locked\b[ \t]*\bwait_on_page_locked\b/d
s/^\([ \t]*\)LASSERT_SPIN_LOCKED\b *\((.*)\)/\1LASSERT(spin_is_locked\2)/g
/#[ \t]*define[ \t]*\bLASSERT_SPIN_LOCKED\b/d
s/^\([ \t]*\)LINVRNT_SPIN_LOCKED\b *\((.*)\)/\1LINVRNT(spin_is_locked\2)/g
/#[ \t]*define[ \t]*\bLINVRNT_SPIN_LOCKED\b/d
s/^\([ \t]*\)LASSERT_SEM_LOCKED\b *\((.*)\)/\1LASSERT(down_trylock\2 != 0)/g
/#[ \t]*define[ \t]*\bLASSERT_SEM_LOCKED\b/d
s/^\([ \t]*\)LASSERT_MUTEX_LOCKED\b *\((.*)\)/\1LASSERT(mutex_is_locked\2)/g
/#[ \t]*define[ \t]*\bLASSERT_MUTEX_LOCKED\b/d
s/\bLIBCFS_PANIC\b/panic/g
/#[ \t]*define[ \t]*\bpanic\b *( *\w* *)[ \t]*\bpanic\b *( *\w* *)/d
s/\bcfs_num_possible_cpus\b/num_possible_cpus/g
/#[ \t]*define[ \t]*\bnum_possible_cpus\b *( *)[ \t]*\bnum_possible_cpus\b *( *)/d
s/\bcfs_smp_processor_id\b/smp_processor_id/g
/#[ \t]*define[ \t]*\bsmp_processor_id\b *( *)[ \t]*\bsmp_processor_id\b *( *)/d
s/\bcfs_get_cpu\b/get_cpu/g
/#[ \t]*define[ \t]*\bget_cpu\b *( *)[ \t]*\bget_cpu\b *( *)/d
s/\bcfs_put_cpu\b/put_cpu/g
/#[ \t]*define[ \t]*\bput_cpu\b *( *)[ \t]*\bput_cpu\b *( *)/d

################################################################################
# macros in linux-time.h
s/\bCFS_HZ\b/HZ/g
/#[ \t]*define[ \t]*\bHZ\b[ \t]*\bHZ\b/d
s/\bCURRENT_KERN_TIME\b/CURRENT_TIME/g
/#[ \t]*define[ \t]*\bCURRENT_TIME\b[ \t]*\bCURRENT_TIME\b/d
s/\bcfs_gettimeofday\b/do_gettimeofday/g
/#[ \t]*define[ \t]*\bdo_gettimeofday\b *( *\w* *)[ \t]*\bdo_gettimeofday\b *( *\w* *)/d

################################################################################
# macros in linux-type.h
s/\bcfs_umode_t\b/umode_t/g
/typedef[ \t]*\bumode_t\b[ \t]*\bumode_t\b/d

################################################################################
# macros in libcfs/include/libcfs/linux/libcfs.h
s/\bCFS_THREAD_SIZE\b/THREAD_SIZE/g
/#[ \t]*define[ \t]*\bTHREAD_SIZE\b[ \t]*\bTHREAD_SIZE\b/d
s/\bcfs_kernel_cap_t\b/kernel_cap_t/g
/typedef[ \t]*\bkernel_cap_t\b[ \t]*\bkernel_cap_t\b/d

################################################################################
# macros in libcfs/include/libcfs/linux/portals_compat25.h
s/\bRECALC_SIGPENDING\b/recalc_sigpending()/g
/#[ \t]*define[ \t]*\brecalc_sigpending\b *( *)[ \t]*\brecalc_sigpending\b *( *)/d
s/\bCLEAR_SIGPENDING\b/clear_tsk_thread_flag(current, TIF_SIGPENDING)/g
/#[ \t]*define[ \t]*\bclear_tsk_thread_flag\b *( *\w* *, *\w* *)[ \t]*\bclear_tsk_thread_flag\b *( *\w* *, *\w* *)/d
s/\bCURRENT_SECONDS\b/get_seconds()/g
/#[ \t]*define[ \t]*\bget_seconds\b *( *)[ \t]*\bget_seconds\b *( *)/d
s/\bCFS_NR_CPUS\b/NR_CPUS/g
/#[ \t]*define[ \t]*\bNR_CPUS\b[ \t]*\bNR_CPUS\b/d

################################################################################
# cfs_curproc_xxx macros
s/\bcfs_curproc_uid\b/current_uid/g
/#[ \t]*define[ \t]*\bcurrent_uid\b *( *)[ \t]*\bcurrent_uid\b *( *)/d
s/\bcfs_curproc_gid\b/current_gid/g
/#[ \t]*define[ \t]*\bcurrent_gid\b *( *)[ \t]*\bcurrent_gid\b *( *)/d
s/\bcfs_curproc_euid\b/current_euid/g
/#[ \t]*define[ \t]*\bcurrent_euid\b *( *)[ \t]*\bcurrent_euid\b *( *)/d
s/\bcfs_curproc_egid\b/current_egid/g
/#[ \t]*define[ \t]*\bcurrent_egid\b *( *)[ \t]*\bcurrent_egid\b *( *)/d
s/\bcfs_curproc_fsuid\b/current_fsuid/g
/#[ \t]*define[ \t]*\bcurrent_fsuid\b *( *)[ \t]*\bcurrent_fsuid\b *( *)/d
s/\bcfs_curproc_fsgid\b/current_fsgid/g
/#[ \t]*define[ \t]*\bcurrent_fsgid\b *( *)[ \t]*\bcurrent_fsgid\b *( *)/d
s/\bcfs_curproc_pid\b/current_pid/g
s/\bcfs_curproc_is_in_groups\b/in_group_p/g
s/\bcfs_curproc_umask\b/current_umask/g
s/\bcfs_curproc_comm\b/current_comm/g
s/\bcfs_curproc_is_32bit\b/current_is_32bit/g

################################################################################
# linux primitives (linux-prim.h)
# debug level
s/\bCFS_KERN_EMERG\b/KERN_EMERG/g
/#[ \t]*define[ \t]*\bKERN_EMERG\b[ \t]*\bKERN_EMERG\b/d
s/\bCFS_KERN_ALERT\b/KERN_ALERT/g
/#[ \t]*define[ \t]*\bKERN_ALERT\b[ \t]*\bKERN_ALERT\b/d
s/\bCFS_KERN_CRIT\b/KERN_CRIT/g
/#[ \t]*define[ \t]*\bKERN_CRIT\b[ \t]*\bKERN_CRIT\b/d
s/\bCFS_KERN_ERR\b/KERN_ERR/g
/#[ \t]*define[ \t]*\bKERN_ERR\b[ \t]*\bKERN_ERR\b/d
s/\bCFS_KERN_WARNING\b/KERN_WARNING/g
/#[ \t]*define[ \t]*\bKERN_WARNING\b[ \t]*\bKERN_WARNING\b/d
s/\bCFS_KERN_NOTICE\b/KERN_NOTICE/g
/#[ \t]*define[ \t]*\bKERN_NOTICE\b[ \t]*\bKERN_NOTICE\b/d
s/\bCFS_KERN_INFO\b/KERN_INFO/g
/#[ \t]*define[ \t]*\bKERN_INFO\b[ \t]*\bKERN_INFO\b/d
s/\bCFS_KERN_DEBUG\b/KERN_DEBUG/g
/#[ \t]*define[ \t]*\bKERN_DEBUG\b[ \t]*\bKERN_DEBUG\b/d
# cache
s/\bCFS_L1_CACHE_ALIGN\b/L1_CACHE_ALIGN/g
/#[ \t]*define[ \t]*\bL1_CACHE_ALIGN\b *( *\w* *)[ \t]*\bL1_CACHE_ALIGN\b *( *\w* *)/d
# IRQs
s/\bCFS_NR_IRQS\b/NR_IRQS/g
/#[ \t]*define[ \t]*\bNR_IRQS\b[ \t]*\bNR_IRQS\b/d
s/\bCFS_EXPORT_SYMBOL\b/EXPORT_SYMBOL/g
/#[ \t]*define[ \t]*\bEXPORT_SYMBOL\b *( *\w* *)[ \t]*\bEXPORT_SYMBOL\b *( *\w* *)/d
# Pseudo device register
s/\bcfs_psdev_t\b/struct miscdevice/g
s/\bcfs_psdev_register\b/misc_register/g
/#[ \t]*define[ \t]*\bmisc_register\b *( *\w* *)[ \t]*\bmisc_register\b *( *\w* *)/d
s/\bcfs_psdev_deregister\b/misc_deregister/g
/#[ \t]*define[ \t]*\bmisc_deregister\b *( *\w* *)[ \t]*\bmisc_deregister\b *( *\w* *)/d
# Sysctl register
s/\bcfs_sysctl_table_t\b/struct ctl_table/g
s/\bcfs_sysctl_table_header_t\b/struct ctl_table_header/g
# Symbol register
s/\bcfs_register_sysctl_table\b/register_sysctl_table/g
s/\bcfs_unregister_sysctl_table\b/unregister_sysctl_table/g
/#[ \t]*define[ \t]*\bunregister_sysctl_table\b *( *\w* *)[ \t]*\bunregister_sysctl_table\b *( *\w* *)/d
s/\bPORTAL_SYMBOL_PUT\b/symbol_put/g
/#[ \t]*define[ \t]*\bsymbol_put\b *( *\w* *)[ \t]*\bsymbol_put\b *( *\w* *)/d
s/\bPORTAL_SYMBOL_GET\b/symbol_get/g
/#[ \t]*define[ \t]*\bsymbol_get\b *( *\w* *)[ \t]*\bsymbol_get\b *( *\w* *)/d
# Module interfaces
s/\bPORTAL_MODULE_USE\b/cfs_module_get()/g
s/\bcfs_module_get()/try_module_get(THIS_MODULE)/g
s/\bcfs_try_module_get\b/try_module_get/g
/#[ \t]*define[ \t]*\btry_module_get\b.*\btry_module_get\b/d
s/\bPORTAL_MODULE_UNUSE\b/cfs_module_put(THIS_MODULE)/g
s/\bcfs_module_put\b/module_put/g
/#[ \t]*define[ \t]*\bmodule_put\b *( *\w* *)[ \t]*\bmodule_put\b *( *\w* *)/d
s/\b__cfs_module_get\b/__module_get/g
/#[ \t]*define[ \t]*\b__module_get\b *( *\w* *)[ \t]*\b__module_get\b *( *\w* *)/d
s/\bcfs_module_refcount\b/module_refcount/g
/#[ \t]*define[ \t]*\bmodule_refcount\b *( *\w* *)[ \t]*\bmodule_refcount\b *( *\w* *)/d
s/\bcfs_module_t\b/struct module/g
# s/\bcfs_module\b/declare_module/g
s/\bcfs_request_module\b/request_module/g
/#[ \t]*define[ \t]*\brequest_module\b[ \t]*\brequest_module\b/d
# Wait Queue
s/\bCFS_TASK_INTERRUPTIBLE\b/TASK_INTERRUPTIBLE/g
/#[ \t]*define[ \t]*\bTASK_INTERRUPTIBLE\b[ \t]*\bTASK_INTERRUPTIBLE\b/d
s/\bCFS_TASK_UNINT\b/TASK_UNINTERRUPTIBLE/g
/#[ \t]*define[ \t]*\bTASK_UNINTERRUPTIBLE\b[ \t]*\bTASK_UNINTERRUPTIBLE\b/d
s/\bCFS_TASK_RUNNING\b/TASK_RUNNING/g
/#[ \t]*define[ \t]*\bTASK_RUNNING\b[ \t]*\bTASK_RUNNING\b/d
s/\bcfs_set_current_state\b/set_current_state/g
/#[ \t]*define[ \t]*\bset_current_state\b *( *\w* *)[ \t]*\bset_current_state\b *( *\w* *)/d
s/\bcfs_wait_event\b/wait_event/g
/#[ \t]*define[ \t]*\bwait_event\b *( *\w* *, *\w* *)[ \t]*\bwait_event\b *( *\w* *, *\w* *)/d
s/\bcfs_waitlink_t\b/wait_queue_t/g
/typedef[ \t]*\bwait_queue_t\b[ \t]*\bwait_queue_t\b/d
s/\bcfs_waitq_t\b/wait_queue_head_t/g
/typedef[ \t]*\bwait_queue_head_t\b[ \t]*\bwait_queue_head_t\b/d
#s/\bcfs_task_state_t\b/task_state_t/g
s/\bcfs_waitq_init\b/init_waitqueue_head/g
/#[ \t]*define[ \t]*\binit_waitqueue_head\b *( *\w* *)[ \t]*\binit_waitqueue_head\b *( *\w* *)/d
s/\bcfs_waitlink_init\b/init_waitqueue_entry_current/g
s/\bcfs_waitq_add\b/add_wait_queue/g
/#[ \t]*define[ \t]*\badd_wait_queue\b *( *\w* *, *\w* *)[ \t]*\badd_wait_queue\b *( *\w* *, *\w* *)/d
s/\bcfs_waitq_add_exclusive\b/add_wait_queue_exclusive/g
/#[ \t]*define[ \t]*\badd_wait_queue_exclusive\b *( *\w* *, *\w* *)[ \t]*\badd_wait_queue_exclusive\b *( *\w* *, *\w* *)/d
s/\bcfs_waitq_del\b/remove_wait_queue/g
/#[ \t]*define[ \t]*\bremove_wait_queue\b *( *\w* *, *\w* *)[ \t]*\bremove_wait_queue\b *( *\w* *, *\w* *)/d
s/\bcfs_waitq_active\b/waitqueue_active/g
/#[ \t]*define[ \t]*\bwaitqueue_active\b *( *\w* *)[ \t]*\bwaitqueue_active\b *( *\w* *)/d
s/\bcfs_waitq_signal\b/wake_up/g
/#[ \t]*define[ \t]*\bwake_up\b *( *\w* *)[ \t]*\bwake_up\b *( *\w* *)/d
s/\bcfs_waitq_signal_nr\b/wake_up_nr/g
/#[ \t]*define[ \t]*\bwake_up_nr\b *( *\w* *, *\w* *)[ \t]*\bwake_up_nr\b *( *\w* *, *\w* *)/d
s/\bcfs_waitq_broadcast\b/wake_up_all/g
/#[ \t]*define[ \t]*\bwake_up_all\b *( *\w* *)[ \t]*\bwake_up_all\b *( *\w* *)/d
s/\bcfs_waitq_wait\b/waitq_wait/g
s/\bcfs_waitq_timedwait\b/waitq_timedwait/g
s/\bcfs_schedule_timeout\b/schedule_timeout/g
/#[ \t]*define[ \t]*\bschedule_timeout\b *( *\w* *)[ \t]*\bschedule_timeout\b *( *\w* *)/d
s/\bcfs_schedule\b/schedule/g
/#[ \t]*define[ \t]*\bschedule\b *( *)[ \t]*\bschedule\b *( *)/d
s/\bcfs_need_resched\b/need_resched/g
/#[ \t]*define[ \t]*\bneed_resched\b *( *)[ \t]*\bneed_resched\b *( *)/d
s/\bcfs_cond_resched\b/cond_resched/g
/#[ \t]*define[ \t]*\bcond_resched\b *( *)[ \t]*\bcond_resched\b *( *)/d
s/\bcfs_waitq_add_exclusive_head\b/add_wait_queue_exclusive_head/g
s/\bcfs_schedule_timeout_and_set_state\b/schedule_timeout_and_set_state/g
s/\bCFS_MAX_SCHEDULE_TIMEOUT\b/MAX_SCHEDULE_TIMEOUT/g
s/\bcfs_task_state_t\b/long/g

# Kernel thread
s/\bcfs_kthread_run\b/kthread_run/g
/#[ \t]*define[ \t]*\bkthread_run\b.*\bkthread_run\b/d
#s/\bcfs_thread_t\b/thread_t/g
s/\bCFS_DAEMON_FLAGS\b/DAEMON_FLAGS/g
#s/\bcfs_create_thread\b/create_thread/g
# Task struct
s/\bcfs_task_t\b/struct task_struct/g
s/\bcfs_current()/current/g
/#[ \t]*define[ \t]*\bcurrent\b[ \t]*\bcurrent\b/d
s/\bcfs_task_lock\b/task_lock/g
/#[ \t]*define[ \t]*\btask_lock\b *( *\w* *)[ \t]*\btask_lock\b *( *\w* *)/d
s/\bcfs_task_unlock\b/task_unlock/g
/#[ \t]*define[ \t]*\btask_unlock\b *( *\w* *)[ \t]*\btask_unlock\b *( *\w* *)/d
s/\bCFS_DECL_JOURNAL_DATA\b/DECL_JOURNAL_DATA/g
s/\bCFS_PUSH_JOURNAL\b/PUSH_JOURNAL/g
s/\bCFS_POP_JOURNAL\b/POP_JOURNAL/g
# Signal
s/\bcfs_sigset_t\b/sigset_t/g
/typedef[ \t]*\bsigset_t\b[ \t]*\bsigset_t\b/d
# Timer
s/\bcfs_timer_t\b/struct timer_list/g
s/\bCFS_MAX_SCHEDULE_TIMEOUT\b/MAX_SCHEDULE_TIMEOUT/g
/#[ \t]*define[ \t]*\bMAX_SCHEDULE_TIMEOUT\b[ \t]*\bMAX_SCHEDULE_TIMEOUT\b/d

# membar
s/\bcfs_mb\b/smp_mb/g
/#[ \t]*define[ \t]*\bmb\b *( *)[ \t]*\bmb\b *( *)/d
# interrupt
s/\bcfs_in_interrupt\b/in_interrupt/g
/#[ \t]*define[ \t]*\bin_interrupt\b *( *)[ \t]*\bin_interrupt\b *( *)/d
# might_sleep
s/\bcfs_might_sleep\b/might_sleep/g
/#[ \t]*define[ \t]*\bmight_sleep\b *( *)[ \t]*\bmight_sleep\b *( *)/d
# group_info
s/\bcfs_group_info_t\b/struct group_info/g
s/\bcfs_get_group_info\b/get_group_info/g
/#[ \t]*define[ \t]*\bget_group_info\b *( *\w* *)[ \t]*\bget_group_info\b *( *\w* *)/d
s/\bcfs_put_group_info\b/put_group_info/g
/#[ \t]*define[ \t]*\bput_group_info\b *( *\w* *)[ \t]*\bput_group_info\b *( *\w* *)/d
s/\bcfs_set_current_groups\b/set_current_groups/g
/#[ \t]*define[ \t]*\bset_current_groups\b *( *\w* *)[ \t]*\bset_current_groups\b *( *\w* *)/d
s/\bcfs_groups_free\b/groups_free/g
/#[ \t]*define[ \t]*\bgroups_free\b *( *\w* *)[ \t]*\bgroups_free\b *( *\w* *)/d
s/\bcfs_groups_alloc\b/groups_alloc/g
/#[ \t]*define[ \t]*\bgroups_alloc\b *( *\w* *)[ \t]*\bgroups_alloc\b *( *\w* *)/d
# Random bytes
s/\bcfs_get_random_bytes_prim\b/get_random_bytes/g
/#[ \t]*define[ \t]*\bget_random_bytes\b *( *\w* *, *\w* *)[ \t]*\bget_random_bytes\b *( *\w* *, *\w* *)/d

################################################################################
# list operations
s/\bcfs_hlist_for_each\b/hlist_for_each/g
/#[ \t]*define[ \t]*\bhlist_for_each\b *(.*)[ \t]*\bhlist_for_each\b *(.*)/d
s/\bcfs_hlist_for_each_safe\b/hlist_for_each_safe/g
/#[ \t]*define[ \t]*\bhlist_for_each_safe\b *(.*)[ \t]*\bhlist_for_each_safe\b *(.*)/d
s/\bcfs_hlist_for_each_entry_continue\b/hlist_for_each_entry_continue/g
/#[ \t]*define[ \t]*\bhlist_for_each_entry_continue\b *(.*)[ \t]*\bhlist_for_each_entry_continue\b *(.*)/d
s/\bcfs_hlist_for_each_entry_from\b/hlist_for_each_entry_from/g
/#[ \t]*define[ \t]*\bhlist_for_each_entry_from\b *(.*)[ \t]*\bhlist_for_each_entry_from\b *(.*)/d
