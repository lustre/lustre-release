/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002, Lawrence Livermore National Labs (LLNL)
 * Author: Brian Behlendorf <behlendorf1@llnl.gov>
 *         Kedar Sovani (kedar@calsoftinc.com)
 *         Amey Inamdar (amey@calsoftinc.com)
 *
 * This file is part of Portals, http://www.sf.net/projects/lustre/
 *
 * Portals is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * Portals is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Portals; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#define DEBUG_SUBSYSTEM S_PINGER

#include <linux/kp30.h>
#include <portals/p30.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/poll.h>
#include "ping.h"
/* int portal_debug = D_PING_CLI;  */


#define STDSIZE (sizeof(int) + sizeof(int) + sizeof(struct timeval))

#define MAX_TIME 100000

/* This should be enclosed in a structure */

static struct pingcli_data *client = NULL;

static int count = 0;

static void
pingcli_shutdown(int err)
{
        int rc;

        /* Yes, we are intentionally allowing us to fall through each
         * case in to the next.  This allows us to pass an error
         * code to just clean up the right stuff.
         */
        switch (err) {
                case 1:
                        /* Unlink any memory descriptors we may have used */
                        if ((rc = PtlMDUnlink (client->md_out_head_h)))
                                PDEBUG ("PtlMDUnlink", rc);
                case 2:
                        if ((rc = PtlMDUnlink (client->md_in_head_h)))
                                PDEBUG ("PtlMDUnlink", rc);

                        /* Free the event queue */
                        if ((rc = PtlEQFree (client->eq)))
                                PDEBUG ("PtlEQFree", rc);

                        if ((rc = PtlMEUnlink (client->me)))
                                PDEBUG ("PtlMEUnlink", rc);
                case 3:
                        kportal_put_ni (client->args->ioc_nal);

                case 4:
                        /* Free our buffers */

                        if (client != NULL)
                                PORTAL_FREE (client,
                                                sizeof(struct pingcli_data));
        }


        CDEBUG (D_OTHER, "ping client released resources\n");
} /* pingcli_shutdown() */

static int pingcli_callback(ptl_event_t *ev)
{
        int i, magic;
        i = *(int *)(ev->mem_desc.start + ev->offset + sizeof(unsigned));
        magic = *(int *)(ev->mem_desc.start + ev->offset);

        if(magic != 0xcafebabe) {
                printk ("Unexpected response \n");
                return 1;
        }

        if((i == count) || !count)
                wake_up_process (client->tsk);
        else
                printk ("Received response after timeout for %d\n",i);
        return 1;
}


static struct pingcli_data *
pingcli_start(struct portal_ioctl_data *args)
{
        ptl_handle_ni_t *nip;
        unsigned ping_head_magic = PING_HEADER_MAGIC;
        unsigned ping_bulk_magic = PING_BULK_MAGIC;
        int rc;
        struct timeval tv1, tv2;
        client->tsk = current;
        client->args = args;
        CDEBUG (D_OTHER, "pingcli_setup args: nid "LPX64",  \
                        nal %d, size %u, count: %u, timeout: %u\n",
                        args->ioc_nid, args->ioc_nal, args->ioc_size,
                        args->ioc_count, args->ioc_timeout);


        PORTAL_ALLOC (client->outbuf, STDSIZE + args->ioc_size) ;
        if (client->outbuf == NULL)
        {
                CERROR ("Unable to allocate out_buf ("LPSZ" bytes)\n", STDSIZE);
                pingcli_shutdown (4);
                return (NULL);
        }

        PORTAL_ALLOC (client->inbuf,
                        (args->ioc_size + STDSIZE) * args->ioc_count);
        if (client->inbuf == NULL)
        {
                CERROR ("Unable to allocate out_buf ("LPSZ" bytes)\n", STDSIZE);
                pingcli_shutdown (4);
                return (NULL);
        }

        /* Aquire and initialize the proper nal for portals. */
        if ((nip = kportal_get_ni (args->ioc_nal)) == NULL)
        {
                CERROR ("NAL %d not loaded\n", args->ioc_nal);
                pingcli_shutdown (4);
                return (NULL);
        }

        /* Based on the initialization aquire our unique portal ID. */
        if ((rc = PtlGetId (*nip, &client->myid)))
        {
                CERROR ("PtlGetId error %d\n", rc);
                pingcli_shutdown (2);
                return (NULL);
        }

        /* Setup the local match entries */
        client->id_local.nid = PTL_NID_ANY;
        client->id_local.pid = PTL_PID_ANY;

        /* Setup the remote match entries */
        client->id_remote.nid = args->ioc_nid;
        client->id_remote.pid = 0;

        if ((rc = PtlMEAttach (*nip, PTL_PING_CLIENT,
                   client->id_local, 0, ~0, PTL_RETAIN,
                   PTL_INS_AFTER, &client->me)))
        {
                CERROR ("PtlMEAttach error %d\n", rc);
                pingcli_shutdown (2);
                return (NULL);
        }

        /* Allocate the event queue for this network interface */
        if ((rc = PtlEQAlloc (*nip, 64, pingcli_callback, &client->eq)))
        {
                CERROR ("PtlEQAlloc error %d\n", rc);
                pingcli_shutdown (2);
                return (NULL);
        }

        count = args->ioc_count;

        client->md_in_head.start     = client->inbuf;
        client->md_in_head.length    = (args->ioc_size + STDSIZE)
                                                * count;
        client->md_in_head.threshold = PTL_MD_THRESH_INF;
        client->md_in_head.options   = PTL_MD_OP_PUT;
        client->md_in_head.user_ptr  = NULL;
        client->md_in_head.eventq    = client->eq;
        memset (client->inbuf, 0, (args->ioc_size + STDSIZE) * count);

        /* Attach the incoming buffer */
        if ((rc = PtlMDAttach (client->me, client->md_in_head,
                              PTL_UNLINK, &client->md_in_head_h))) {
                CERROR ("PtlMDAttach error %d\n", rc);
                pingcli_shutdown (1);
                return (NULL);
        }
        /* Setup the outgoing ping header */
        client->md_out_head.start     = client->outbuf;
        client->md_out_head.length    = STDSIZE + args->ioc_size;
        client->md_out_head.threshold = args->ioc_count;
        client->md_out_head.options   = PTL_MD_OP_PUT;
        client->md_out_head.user_ptr  = NULL;
        client->md_out_head.eventq    = PTL_EQ_NONE;

        memcpy (client->outbuf, &ping_head_magic, sizeof(ping_bulk_magic));

        count = 0;

        /* Bind the outgoing ping header */
        if ((rc=PtlMDBind (*nip, client->md_out_head,
                                        &client->md_out_head_h))) {
                CERROR ("PtlMDBind error %d\n", rc);
                pingcli_shutdown (1);
                return NULL;
        }
        while ((args->ioc_count - count)) {
                memcpy (client->outbuf + sizeof(unsigned),
                       &(count), sizeof(unsigned));
                 /* Put the ping packet */
                do_gettimeofday (&tv1);

                memcpy(client->outbuf+sizeof(unsigned)+sizeof(unsigned),&tv1,
                       sizeof(struct timeval));

                if((rc = PtlPut (client->md_out_head_h, PTL_NOACK_REQ,
                          client->id_remote, PTL_PING_SERVER, 0, 0, 0, 0))) {
                         PDEBUG ("PtlPut (header)", rc);
                         pingcli_shutdown (1);
                         return NULL;
                }
                printk ("sent msg no %d", count);

                set_current_state (TASK_INTERRUPTIBLE);
                rc = schedule_timeout (20 * args->ioc_timeout);
                if (rc == 0) {
                        printk ("   ::  timeout .....\n");
                } else {
                        do_gettimeofday (&tv2);
                        printk("   ::  Reply in %u usec\n",
                                (unsigned)((tv2.tv_sec - tv1.tv_sec)
                                 * 1000000 +  (tv2.tv_usec - tv1.tv_usec)));
                }
                count++;
        }

        if (client->outbuf != NULL)
                PORTAL_FREE (client->outbuf, STDSIZE + args->ioc_size);

        if (client->inbuf != NULL)
                PORTAL_FREE (client->inbuf,
                               (args->ioc_size + STDSIZE) * args->ioc_count);

        pingcli_shutdown (2);

        /* Success! */
        return NULL;
} /* pingcli_setup() */



/* called by the portals_ioctl for ping requests */
int kping_client(struct portal_ioctl_data *args)
{
        PORTAL_ALLOC (client, sizeof(struct pingcli_data));
        if (client == NULL)
        {
                CERROR ("Unable to allocate client structure\n");
                return (0);
        }
        memset (client, 0, sizeof(struct pingcli_data));
        pingcli_start (args);

        return 0;
} /* kping_client() */


static int __init pingcli_init(void)
{
        PORTAL_SYMBOL_REGISTER(kping_client);
        return 0;
} /* pingcli_init() */


static void __exit pingcli_cleanup(void)
{
        PORTAL_SYMBOL_UNREGISTER (kping_client);
} /* pingcli_cleanup() */


MODULE_AUTHOR("Brian Behlendorf (LLNL)");
MODULE_DESCRIPTION("A simple kernel space ping client for portals testing");
MODULE_LICENSE("GPL");

module_init(pingcli_init);
module_exit(pingcli_cleanup);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
EXPORT_SYMBOL (kping_client);
#endif
