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

        /* declare we are ready */
	set_bit(LIOD_FLAG_ALIVE, &iod->io_flag);
        wake_up(&iod->io_waitq);

        CDEBUG(D_NET, "liod(%d) started\n", current->pid);
        while (1) {
		int t;

		/* check the stop command */
		if (test_bit(LIOD_FLAG_STOP, &iod->io_flag))
			break;

		t = interruptible_sleep_on_timeout(&iod->io_sleepq,
					       LIOD_WAKEUP_CYCLE*HZ);
		CDEBUG(D_NET, "liod(%d) active due to %s\n",
				(t ? "wakeup" : "timeout"));
        }

	clear_bit(LIOD_FLAG_ALIVE, &iod->io_flag);
        wake_up(&iod->io_waitq);

        CDEBUG(D_NET, "liod(%d) exit\n", current->pid);
        RETURN(0);
}

int liod_start(struct ll_io_daemon *iod)
{
        int rc;

        /* initialize */
        iod->io_flag = 0;
        init_waitqueue_head(&iod->io_sleepq);
        init_waitqueue_head(&iod->io_waitq);

        rc = kernel_thread(liod_main, (void *) iod,
                           CLONE_VM | CLONE_FS | CLONE_FILES);

        if (rc < 0) {
		CERROR("fail to start liod, error %d\n", rc);
                return rc;
        }

	/* wait liod start */
	wait_event(iod->io_waitq, test_bit(LIOD_FLAG_ALIVE, &iod->io_flag));

        return 0;
}

void liod_wakeup(struct ll_io_daemon *iod)
{
        wake_up(&iod->io_sleepq);
}

void liod_stop(struct ll_io_daemon *iod)
{
	if (!test_bit(LIOD_FLAG_ALIVE, &iod->io_flag)) {
		CERROR("liod died unexpectedly!\n");
		return;
	}

        /* send the kill command */
	set_bit(LIOD_FLAG_STOP, &iod->io_flag);

        /* if wakeup daemon */
        wake_up(&iod->io_sleepq);

	/* wait liod exit */
	wait_event(iod->io_waitq, !test_bit(LIOD_FLAG_ALIVE, &iod->io_flag));

	return;
}
