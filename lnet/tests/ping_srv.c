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

#define DEBUG_SUBSYSTEM S_PINGER

#include <linux/kp30.h>
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

#define STDSIZE (sizeof(int) + sizeof(int) + sizeof(struct timeval))
#define MAXSIZE (16*1024*1024)

static unsigned ping_head_magic;
static unsigned ping_bulk_magic;
static int nal  = 0;                            // Your NAL,
static unsigned long packets_valid = 0;         // Valid packets 
static int running = 1;
atomic_t pkt;
       
static struct pingsrv_data *server=NULL;             // Our ping server

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
                        if ((rc = PtlMDUnlink (server->mdin_h)))
                                PDEBUG ("PtlMDUnlink (out head buffer)", rc);
                case 2:
                        /* Free the event queue */
                        if ((rc = PtlEQFree (server->eq)))
                                PDEBUG ("PtlEQFree", rc);

                        /* Unlink the client portal from the ME list */
                        if ((rc = PtlMEUnlink (server->me)))
                                        PDEBUG ("PtlMEUnlink", rc);

                case 3:
                        kportal_put_ni (nal);

                case 4:
                        
                case 5:
                        if (server->in_buf != NULL)
                                PORTAL_FREE (server->in_buf, MAXSIZE);
                        
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
        unsigned long magic;
        unsigned long ping_bulk_magic = 0xcafebabe;
        
        kportal_daemonize ("pingsrv");
        server->tsk =  current;
        
        while (running) {
                set_current_state (TASK_INTERRUPTIBLE);
                if (atomic_read (&pkt) == 0) {
                        schedule_timeout (MAX_SCHEDULE_TIMEOUT);
                        continue;
                }
               
                magic =  *((int *)(server->evnt.mem_desc.start 
                                        + server->evnt.offset));
                
                
                if(magic != 0xdeadbeef) {
                        printk("Unexpected Packet to the server\n");
                        
                } 
                memcpy (server->in_buf, &ping_bulk_magic, sizeof(ping_bulk_magic));
                                
                server->mdout.length    = server->evnt.rlength;
                server->mdout.start     = server->in_buf;
                server->mdout.threshold = 1; 
                server->mdout.options   = PTL_MD_OP_PUT;
                server->mdout.user_ptr  = NULL;
                server->mdout.eventq    = PTL_EQ_NONE;
       
                /* Bind the outgoing buffer */
                if ((rc = PtlMDBind (server->ni, server->mdout, 
                                                &server->mdout_h))) {
                         PDEBUG ("PtlMDBind", rc);
                         pingsrv_shutdown (1);
                         return 1;
	        }
         
                
                server->mdin.start     = server->in_buf;
                server->mdin.length    = MAXSIZE;
                server->mdin.threshold = 1; 
                server->mdin.options   = PTL_MD_OP_PUT;
                server->mdin.user_ptr  = NULL;
                server->mdin.eventq    = server->eq;
        
                if ((rc = PtlMDAttach (server->me, server->mdin,
                        PTL_UNLINK, &server->mdin_h))) {
                        PDEBUG ("PtlMDAttach (bulk)", rc);
                        CDEBUG (D_OTHER, "ping server resources allocated\n");
                }
                
                if ((rc = PtlPut (server->mdout_h, PTL_NOACK_REQ,
                         server->evnt.initiator, PTL_PING_CLIENT, 0, 0, 0, 0)))
                         PDEBUG ("PtlPut", rc);
                
                atomic_dec (&pkt);
                
        }
        pingsrv_shutdown (1);
        running = 1;
        return 0;    
}

static int pingsrv_packet(ptl_event_t *ev)
{
        atomic_inc (&pkt);
        wake_up_process (server->tsk);
        return 1;
} /* pingsrv_head() */

static int pingsrv_callback(ptl_event_t *ev)
{
        
        if (ev == NULL) {
                CERROR ("null in callback, ev=%p\n", ev);
                return 0;
        }
        server->evnt = *ev;
        
        printk ("received ping from nid "LPX64" "
               "(off=%u rlen=%u mlen=%u head=%x seq=%d size=%d)\n",
               ev->initiator.nid, ev->offset, ev->rlength, ev->mlength,
               *((int *)(ev->mem_desc.start + ev->offset)),
               *((int *)(ev->mem_desc.start + ev->offset + sizeof(unsigned))),
               *((int *)(ev->mem_desc.start + ev->offset + 2 * 
                               sizeof(unsigned))));
        
        packets_valid++;

        return pingsrv_packet(ev);
        
} /* pingsrv_callback() */


static struct pingsrv_data *pingsrv_setup(void)
{
        ptl_handle_ni_t *nip;
        int rc;

       /* Aquire and initialize the proper nal for portals. */
        if ((nip = kportal_get_ni (nal)) == NULL) {
                CDEBUG (D_OTHER, "NAL %d not loaded\n", nal);
                return pingsrv_shutdown (4);
        }

        server->ni= *nip;

        /* Based on the initialization aquire our unique portal ID. */
        if ((rc = PtlGetId (server->ni, &server->my_id))) {
                PDEBUG ("PtlGetId", rc);
                return pingsrv_shutdown (2);
        }

        server->id_local.nid = PTL_NID_ANY;
        server->id_local.pid = PTL_PID_ANY;

        /* Attach a match entries for header packets */
        if ((rc = PtlMEAttach (server->ni, PTL_PING_SERVER,
            server->id_local,0, ~0,
            PTL_RETAIN, PTL_INS_AFTER, &server->me))) {
                PDEBUG ("PtlMEAttach", rc);
                return pingsrv_shutdown (2);
        }


        if ((rc = PtlEQAlloc (server->ni, 1024, pingsrv_callback,
                                        &server->eq))) {
                PDEBUG ("PtlEQAlloc (callback)", rc);
                return pingsrv_shutdown (2);
        }
        
        PORTAL_ALLOC (server->in_buf, MAXSIZE);
        if(!server->in_buf){
                CDEBUG (D_OTHER,"Allocation error\n");
                return pingsrv_shutdown(2);
        }
        
        /* Setup the incoming buffer */
        server->mdin.start     = server->in_buf;
        server->mdin.length    = MAXSIZE;
        server->mdin.threshold = 1; 
        server->mdin.options   = PTL_MD_OP_PUT;
        server->mdin.user_ptr  = NULL;
        server->mdin.eventq    = server->eq;
        memset (server->in_buf, 0, STDSIZE);
        
        if ((rc = PtlMDAttach (server->me, server->mdin,
                PTL_UNLINK, &server->mdin_h))) {
                    PDEBUG ("PtlMDAttach (bulk)", rc);
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
        ping_head_magic = PING_HEADER_MAGIC;
        ping_bulk_magic = PING_BULK_MAGIC;
        PORTAL_ALLOC (server, sizeof(struct pingsrv_data));  
        return pingsrv_start ();
} /* pingsrv_init() */


static void __exit pingsrv_cleanup(void)
{
        remove_proc_entry ("net/pingsrv", NULL);
        
        running = 0;
        wake_up_process (server->tsk);
        while (running != 1) {
                set_current_state (TASK_UNINTERRUPTIBLE);
                schedule_timeout (HZ);
        }
        
} /* pingsrv_cleanup() */


MODULE_PARM(nal, "i");
MODULE_PARM_DESC(nal, "Use the specified NAL "
                "(6-kscimacnal, 4-toenal, 2-ksocknal, 1-kqswnal)");
 
MODULE_AUTHOR("Brian Behlendorf (LLNL)");
MODULE_DESCRIPTION("A kernel space ping server for portals testing");
MODULE_LICENSE("GPL");

module_init(pingsrv_init);
module_exit(pingsrv_cleanup);
