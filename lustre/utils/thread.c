/*****************************************************************************
 *  $Id: thread.c,v 1.1.2.1 2008/11/21 15:27:33 yangsheng Exp $
 *****************************************************************************
 *  Copyright (C) 2003 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 *  Written by Chris Dunlap <cdunlap@llnl.gov>.
 *
 *  This file is from LSD-Tools, the LLNL Software Development Toolbox.
 *
 *  LSD-Tools is free software; you can redistribute it and/or modify it under
 *  the terms of the GNU General Public License as published by the Free
 *  Software Foundation; either version 2 of the License, or (at your option)
 *  any later version.
 *
 *  LSD-Tools is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 *  more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with LSD-Tools; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA.
 *****************************************************************************/


#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include "thread.h"


#if WITH_PTHREADS
#ifndef NDEBUG
int
lsd_mutex_is_locked (pthread_mutex_t *mutex)
{
/*  Returns true if the mutex is locked; o/w, returns false.
 */
    int rc;

    assert (mutex != NULL);
    rc = pthread_mutex_trylock (mutex);
    return (rc == EBUSY ? 1 : 0);
}
#endif /* !NDEBUG */
#endif /* WITH_PTHREADS */
