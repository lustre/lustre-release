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
 */

#include "ptllnd.h"

#ifdef CRAY_XT3
static struct semaphore   ptltrace_mutex;
static struct semaphore   ptltrace_signal;

void
kptllnd_ptltrace_to_file(char *filename)
{
        CFS_DECL_JOURNAL_DATA;
        CFS_DECL_MMSPACE;

        cfs_file_t *filp;
        char       *start;
        char       *tmpbuf;
        int         len;
        int         rc;
        loff_t      offset = 0;
        int         eof = 0;

        CWARN("dumping ptltrace to %s\n", filename);

        LIBCFS_ALLOC(tmpbuf, PAGE_SIZE);
        if (tmpbuf == NULL) {
                CERROR("Can't allocate page buffer to dump %s\n", filename);
                return;
        }
        
        CFS_PUSH_JOURNAL;

        filp = cfs_filp_open(filename,
                             O_CREAT|O_EXCL|O_WRONLY|O_LARGEFILE, 0600, &rc);
        if (filp == NULL) {
                if (rc != -EEXIST)
                        CERROR("Error %d creating %s\n", rc, filename);
                goto out;
        }

        CFS_MMSPACE_OPEN;

        while (!eof) { 
                start = NULL; 
                len = ptl_proc_read(tmpbuf, &start, offset,
                                    PAGE_SIZE, &eof, NULL);

                /* we don't allow ptl_proc_read to mimic case 0 or 1 behavior
                 * for a proc_read method, only #2: from proc_file_read
                 *
                 * 2) Set *start = an address within the buffer.
                 *    Put the data of the requested offset at *start.
                 *    Return the number of bytes of data placed there.
                 *    If this number is greater than zero and you
                 *    didn't signal eof and the reader is prepared to
                 *    take more data you will be called again with the
                 *    requested offset advanced by the number of bytes
                 *    absorbed.
                 */

                if (len == 0)   /* end of file */
                        break;

                if (len < 0) {
                        CERROR("ptl_proc_read: error %d\n", len);
                        break;
                }

                if (start < tmpbuf || start + len > tmpbuf + PAGE_SIZE) {
                        CERROR("ptl_proc_read bug: %p for %d not in %p for %ld\n",
                               start, len, tmpbuf, PAGE_SIZE);
                        break;
                }

                rc = cfs_filp_write(filp, start, len, cfs_filp_poff(filp));
                if (rc != len) {
                        if (rc < 0)
                                CERROR("Error %d writing %s\n", rc, filename);
                        else
                                CERROR("Partial write %d(%d) to %s\n",
                                       rc, len, filename);
                        break;
                }

                offset += len;
        }

        CFS_MMSPACE_CLOSE;

        rc = cfs_filp_fsync(filp);
        if (rc != 0)
                CERROR("Error %d syncing %s\n", rc, filename);

        cfs_filp_close(filp);
out:
        CFS_POP_JOURNAL;
        LIBCFS_FREE(tmpbuf, PAGE_SIZE);
}

int
kptllnd_dump_ptltrace_thread(void *arg)
{
        static char fname[1024];

        libcfs_daemonize("ptltracedump");

        /* serialise with other instances of me */
        mutex_down(&ptltrace_mutex);

        snprintf(fname, sizeof(fname), "%s.%ld.%ld",
                 *kptllnd_tunables.kptl_ptltrace_basename,
                 cfs_time_current_sec(), (long)arg);

        kptllnd_ptltrace_to_file(fname);

        mutex_up(&ptltrace_mutex);

        /* unblock my creator */
        mutex_up(&ptltrace_signal);
        
        return 0;
}

void
kptllnd_dump_ptltrace(void)
{
        int            rc;     

        if (!*kptllnd_tunables.kptl_ptltrace_on_timeout)
                return;

        rc = cfs_kernel_thread(kptllnd_dump_ptltrace_thread,
                               (void *)(long)cfs_curproc_pid(),
                               CLONE_VM | CLONE_FS | CLONE_FILES);
        if (rc < 0) {
                CERROR("Error %d starting ptltrace dump thread\n", rc);
        } else {
                /* block until thread completes */
                mutex_down(&ptltrace_signal);
        }
}

void
kptllnd_init_ptltrace(void)
{
        init_mutex(&ptltrace_mutex);
        init_mutex_locked(&ptltrace_signal);
}

#else

void
kptllnd_dump_ptltrace(void)
{
}

void
kptllnd_init_ptltrace(void)
{
}

#endif
