/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002, Lawrence Livermore National Labs (LLNL)
 * Author: Brian Behlendorf <behlendorf1@llnl.gov>
 * 	   Amey Inamdar	    <amey@calsoftinc.com>
 * 	   Kedar Sovani	    <kedar@calsoftinc.com>
 *
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
 */

/* This is a striped down version of pinger. It follows a single
 * request-response protocol. Doesn't do Bulk data pinging. Also doesn't 
 * send multiple packets in a single ioctl.
 */

#define DEBUG_SUBSYSTEM S_PINGER

#include <libcfs/kp30.h>
#include <portals/p30.h>
#include "ping.h"

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

#include <asm/unistd.h>
#include <asm/semaphore.h>

#define STDSIZE (sizeof(int) + sizeof(int) + 4)

static unsigned long packets_valid = 0;         // Valid packets 
static int running = 1;
atomic_t pkt;
       
static struct pingsrv_data *server=NULL;             // Our ping server

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#endif

static void *pingsrv_shutdown(int err)
{
        int rc;

        /* Yes, we are intentionally allowing us to fall through each
         * case in to the next.  This allows us to pass an error
         * code to just clean up the right stuff.
         */
        switch (err) {
                case 1:
                        /* Unlink any memory descriptors we may have used */
                        if ((rc = LNetMDUnlink (server->mdin_h)))
                                PDEBUG ("LNetMDUnlink (out head buffer)", rc);
                case 2:
                        /* Free the event queue */
                        if ((rc = LNetEQFree (server->eq)))
                                PDEBUG ("LNetEQFree", rc);

                        /* Unlink the client portal from the ME list */
                        if ((rc = LNetMEUnlink (server->me)))
                                        PDEBUG ("LNetMEUnlink", rc);

                case 3:
                        LNetNIFini(server->ni);

                case 4:
                        
                        if (server->in_buf != NULL)
                                PORTAL_FREE (server->in_buf, STDSIZE);
                        
                        if (server != NULL)
                                PORTAL_FREE (server, 
                                             sizeof (struct pingsrv_data));
                        
        }

        CDEBUG (D_OTHER, "ping sever resources released\n");
        return NULL;
} /* pingsrv_shutdown() */


int pingsrv_thread(void *arg)
{
        int rc;
        
        kportal_daemonize ("pingsrv");
        server->tsk = current;
        
        while (running) {
                set_current_state (TASK_INTERRUPTIBLE);
                if (atomic_read (&pkt) == 0) {
                        schedule_timeout (MAX_SCHEDULE_TIMEOUT);
                        continue;
                }
                               
                server->mdout.start     = server->in_buf;
                server->mdout.length    = STDSIZE;
                server->mdout.threshold = 1; 
                server->mdout.options   = LNET_MD_OP_PUT;
                server->mdout.user_ptr  = NULL;
                server->mdout.eq_handle = LNET_EQ_NONE;
       
                /* Bind the outgoing buffer */
                if ((rc = LNetMDBind (server->ni, server->mdout, 
                                     LNET_UNLINK, &server->mdout_h))) {
                         PDEBUG ("LNetMDBind", rc);
                         pingsrv_shutdown (1);
                         return 1;
	        }
         
                
                server->mdin.start     = server->in_buf;
                server->mdin.length    = STDSIZE;
                server->mdin.threshold = 1; 
                server->mdin.options   = LNET_MD_OP_PUT;
                server->mdin.user_ptr  = NULL;
                server->mdin.eq_handle = server->eq;
        
                if ((rc = LNetMDAttach (server->me, server->mdin,
                        LNET_UNLINK, &server->mdin_h))) {
                        PDEBUG ("LNetMDAttach (bulk)", rc);
                        CDEBUG (D_OTHER, "ping server resources allocated\n");
                }
                
                if ((rc = LNetPut (server->mdout_h, LNET_NOACK_REQ,
                         server->evnt.initiator, PTL_PING_CLIENT, 0, 0, 0, 0)))
                         PDEBUG ("LNetPut", rc);
                
                atomic_dec (&pkt);
                
        }
        pingsrv_shutdown (1);
        running = 1;
        return 0;    
}

static void pingsrv_packet(lnet_event_t *ev)
{
        atomic_inc (&pkt);
        wake_up_process (server->tsk);
} /* pingsrv_head() */

static void pingsrv_callback(lnet_event_t *ev)
{
        
        if (ev == NULL) {
                CERROR ("null in callback, ev=%p\n", ev);
                return;
        }
        server->evnt = *ev;
        
        CWARN("Lustre: received ping from nid "LPX64" "
              "(off=%u rlen=%u mlen=%u head=%x)\n",
              ev->initiator.nid, ev->offset, ev->rlength, ev->mlength,
              *((int *)(ev->md.start + ev->offset)));
        
        packets_valid++;

        pingsrv_packet(ev);
        
} /* pingsrv_callback() */


static struct pingsrv_data *pingsrv_setup(void)
{
        int rc;

        server->ni = LNET_INVALID_HANDLE;

        rc = LNetNIInit(LNET_IFACE_DEFAULT, 0, NULL, NULL, &server->ni);
        if (rc != 0 && rc != 1) {
                CDEBUG (D_OTHER, "LNetNIInit: error %d\n", rc);
                return pingsrv_shutdown (4);
        }

        /* Based on the initialization aquire our unique portal ID. */
        if ((rc = LNetGetId (server->ni, &server->my_id))) {
                PDEBUG ("LNetGetId", rc);
                return pingsrv_shutdown (2);
        }

        server->id_local.nid = LNET_NID_ANY;
        server->id_local.pid = LNET_PID_ANY;

        /* Attach a match entries for header packets */
        if ((rc = LNetMEAttach (server->ni, PTL_PING_SERVER,
            server->id_local,0, ~0,
            LNET_RETAIN, LNET_INS_AFTER, &server->me))) {
                PDEBUG ("LNetMEAttach", rc);
                return pingsrv_shutdown (2);
        }


        if ((rc = LNetEQAlloc (server->ni, 64, pingsrv_callback,
                                        &server->eq))) {
                PDEBUG ("LNetEQAlloc (callback)", rc);
                return pingsrv_shutdown (2);
        }
        
        PORTAL_ALLOC (server->in_buf, STDSIZE);
        if(!server->in_buf){
                CDEBUG (D_OTHER,"Allocation error\n");
                return pingsrv_shutdown(2);
        }
        
        /* Setup the incoming buffer */
        server->mdin.start     = server->in_buf;
        server->mdin.length    = STDSIZE;
        server->mdin.threshold = 1; 
        server->mdin.options   = LNET_MD_OP_PUT;
        server->mdin.user_ptr  = NULL;
        server->mdin.eq_handle = server->eq;
        memset (server->in_buf, 0, STDSIZE);
        
        if ((rc = LNetMDAttach (server->me, server->mdin,
                LNET_UNLINK, &server->mdin_h))) {
                    PDEBUG ("LNetMDAttach (bulk)", rc);
                CDEBUG (D_OTHER, "ping server resources allocated\n");
       }
 
        /* Success! */
        return server; 
} /* pingsrv_setup() */

static int pingsrv_start(void)
{
        /* Setup our server */
        if (!pingsrv_setup()) {
                CDEBUG (D_OTHER, "pingsrv_setup() failed, server stopped\n");
                return -ENOMEM;
        }
        kernel_thread (pingsrv_thread,NULL,0);
        return 0;
} /* pingsrv_start() */



static int __init pingsrv_init(void)
{
        PORTAL_ALLOC (server, sizeof(struct pingsrv_data));  
        return pingsrv_start ();
} /* pingsrv_init() */


static void /*__exit*/ pingsrv_cleanup(void)
{
        remove_proc_entry ("net/pingsrv", NULL);
        
        running = 0;
        wake_up_process (server->tsk);
        while (running != 1) {
                set_current_state (TASK_UNINTERRUPTIBLE);
                schedule_timeout (HZ);
        }
        
} /* pingsrv_cleanup() */


MODULE_AUTHOR("Brian Behlendorf (LLNL)");
MODULE_DESCRIPTION("A kernel space ping server for portals testing");
MODULE_LICENSE("GPL");

module_init(pingsrv_init);
module_exit(pingsrv_cleanup);
