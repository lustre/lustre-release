/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#define DEBUG_SUBSYSTEM S_LNET

#include "selftest.h"


#define LST_INIT_NONE           0
#define LST_INIT_RPC            1
#define LST_INIT_FW             2
#define LST_INIT_CONSOLE        3

extern int lstcon_console_init(void);
extern int lstcon_console_fini(void);

static int lst_init_step = LST_INIT_NONE;

void
lnet_selftest_fini (void)
{
        switch (lst_init_step) {
#ifdef __KERNEL__
                case LST_INIT_CONSOLE:
                        lstcon_console_fini();
#endif
                case LST_INIT_FW:
                        sfw_shutdown();
                case LST_INIT_RPC:
                        srpc_shutdown();
                case LST_INIT_NONE:
                        break;
                default:
                        LBUG();
        }
        return;
}

int
lnet_selftest_init (void)
{
        int	rc;

        rc = srpc_startup();
        if (rc != 0) {
                CERROR("LST can't startup rpc\n");
                goto error;
        }
        lst_init_step = LST_INIT_RPC;

        rc = sfw_startup();
        if (rc != 0) {
                CERROR("LST can't startup framework\n");
                goto error;
        }
        lst_init_step = LST_INIT_FW;

#ifdef __KERNEL__
        rc = lstcon_console_init();
        if (rc != 0) {
                CERROR("LST can't startup console\n");
                goto error;
        }
        lst_init_step = LST_INIT_CONSOLE;  
#endif

        return 0;
error:
        lnet_selftest_fini();
        return rc;
}

#ifdef __KERNEL__

MODULE_DESCRIPTION("LNet Selftest");
MODULE_LICENSE("GPL");

cfs_module(lnet, "0.9.0", lnet_selftest_init, lnet_selftest_fini);

#else

int
selftest_wait_events (void)
{
        int evts = 0;

        for (;;) {
                /* Consume all pending events */
                while (srpc_check_event(0))
                        evts++;
                evts += stt_check_events();
                evts += swi_check_events();
                if (evts != 0) break;

                /* Nothing happened, block for events */
                evts += srpc_check_event(stt_poll_interval());
                /* We may have blocked, check for expired timers */
                evts += stt_check_events();
                if (evts == 0) /* timed out and still no event */
                        break;
        }

        return evts;
}

#endif
