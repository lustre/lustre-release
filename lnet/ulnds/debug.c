/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Phil Schwan <phil@clusterfs.com>
 *
 *   This file is part of Portals, http://www.sf.net/projects/sandiaportals/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2.1 of the GNU Lesser General
 *   Public License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with Portals; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/time.h>

int smp_processor_id = 1;
char debug_file_path[1024] = "/tmp/lustre-log";
char debug_file_name[1024];
FILE *debug_file_fd;

int portals_do_debug_dumplog(void *arg)
{
        printf("Look in %s\n", debug_file_name);
        return 0;
}


void portals_debug_print(void)
{
        return;
}


void portals_debug_dumplog(void)
{
        printf("Look in %s\n", debug_file_name);
        return;
}


int portals_debug_init(unsigned long bufsize)
{ 
        debug_file_fd = stdout;
        return 0;
}

int portals_debug_cleanup(void)
{
        return 0; //close(portals_debug_fd);
}

int portals_debug_clear_buffer(void)
{
        return 0;
}

int portals_debug_mark_buffer(char *text)
{

        fprintf(debug_file_fd, "*******************************************************************************\n");
        fprintf(debug_file_fd, "DEBUG MARKER: %s\n", text);
        fprintf(debug_file_fd, "*******************************************************************************\n");

        return 0;
}

int portals_debug_copy_to_user(char *buf, unsigned long len)
{
        return 0;
}

/* FIXME: I'm not very smart; someone smarter should make this better. */
void
portals_debug_msg (int subsys, int mask, char *file, const char *fn, 
                   const int line, const char *format, ...)
{
        va_list       ap;
        unsigned long flags;
        struct timeval tv;
        int nob;


        /* NB since we pass a non-zero sized buffer (at least) on the first
         * print, we can be assured that by the end of all the snprinting,
         * we _do_ have a terminated buffer, even if our message got truncated.
         */

        gettimeofday(&tv, NULL);

        nob += fprintf(debug_file_fd,
                              "%02x:%06x:%d:%lu.%06lu ",
                              subsys >> 24, mask, smp_processor_id,
                              tv.tv_sec, tv.tv_usec);

        nob += fprintf(debug_file_fd,
                            "(%s:%d:%s() %d+%ld): ",
                            file, line, fn, 0,
                            8192 - ((unsigned long)&flags & 8191UL));

        va_start (ap, format);
        nob += fprintf(debug_file_fd, format, ap);
        va_end (ap);


}

