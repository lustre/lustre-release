#ifndef __LINUX_PING_H__
#define __LINUX_PING_H__

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/version.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#include <linux/workqueue.h>
#else
#include <linux/tqueue.h>
#endif
#include <linux/wait.h>
#include <linux/smp_lock.h>
#include <linux/poll.h>
                                                                                                                                                                           
#include <asm/unistd.h>
#include <asm/semaphore.h>

#endif
