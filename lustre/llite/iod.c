#include <linux/version.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/sched.h>
#include <linux/smp_lock.h>
#include <linux/kmod.h>
#include <asm/unistd.h>

#define DEBUG_SUBSYSTEM S_LLITE
#include <linux/lustre_lite.h>

/* wakeup every 30s */
#define LIOD_WAKEUP_CYCLE	(30)

static int liod_main(void *arg)
{
        struct ll_io_daemon *iod = (struct ll_io_daemon *)arg;

        ENTRY;

        lock_kernel();
        daemonize();
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        spin_lock_irq(&current->sigmask_lock);
        sigfillset(&current->blocked);
        our_recalc_sigpending(current);
        spin_unlock_irq(&current->sigmask_lock);
#else
        sigfillset(&current->blocked);
        our_recalc_sigpending(current);
#endif

        sprintf(current->comm, "liod");
        unlock_kernel();

        /* declear we are ready */
	spin_lock(&iod->io_lock);
	iod->io_flag |= LIOD_FLAG_ALIVE;
        wake_up(&iod->io_waitq);
	spin_unlock(&iod->io_lock);

        CDEBUG(D_NET, "liod(%d) started\n", current->pid);
        while (1) {
		int t;

		/* check the stop command */
		if (iod->io_flag & LIOD_FLAG_STOP)
			break;

		t = interruptible_sleep_on_timeout(&iod->io_sleepq,
					       LIOD_WAKEUP_CYCLE*HZ);
		CDEBUG(D_NET, "liod(%d) active due to %s\n",
				(t ? "wakeup" : "timeout"));
        }

	spin_lock(&iod->io_lock);
	iod->io_flag &= ~LIOD_FLAG_ALIVE;
	iod->io_flag |= LIOD_FLAG_STOPPED;
        wake_up(&iod->io_waitq);
	spin_unlock(&iod->io_lock);

        CDEBUG(D_NET, "liod(%d) exit\n", current->pid);
        RETURN(0);
}

int liod_start(struct ll_io_daemon *iod)
{
        DECLARE_WAITQUEUE(queue, current);
        int rc;

        /* initialize */
        iod->io_flag = 0;
        spin_lock_init(&iod->io_lock);
        init_waitqueue_head(&iod->io_sleepq);
        init_waitqueue_head(&iod->io_waitq);

        spin_lock(&iod->io_lock);

        rc = kernel_thread(liod_main, (void *) iod,
                           CLONE_VM | CLONE_FS | CLONE_FILES);

        if (rc < 0) {
		CERROR("fail to start liod, error %d\n", rc);
                spin_unlock(&iod->io_lock);
                return rc;
        }

        set_current_state(TASK_UNINTERRUPTIBLE);
        add_wait_queue(&iod->io_waitq, &queue);
        spin_unlock(&iod->io_lock);

	/* wait liod start */
        schedule();

        set_current_state(TASK_RUNNING);
        remove_wait_queue(&iod->io_waitq, &queue);

        if (iod->io_flag & LIOD_FLAG_ALIVE)
                return 0;
        else
                return -ENOMEM;
}

void liod_wakeup(struct ll_io_daemon *iod)
{
        wake_up(&iod->io_sleepq);
}

void liod_stop(struct ll_io_daemon *iod)
{
        DECLARE_WAITQUEUE(queue, current);

        spin_lock(&iod->io_lock);

        /* send the kill command */
        iod->io_flag |= LIOD_FLAG_STOP;

        /* if wakeup daemon */
        wake_up(&iod->io_sleepq);

        /* wait daemon's exit */
        set_current_state(TASK_UNINTERRUPTIBLE);
        add_wait_queue(&iod->io_waitq, &queue);
        spin_unlock(&iod->io_lock);

        schedule();
        /* must woken up by liod */

	return;
}
