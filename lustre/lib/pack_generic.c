/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <braam@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * (Un)packing of OST requests
 *
 */

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/sched.h>
#include <linux/lp.h>
#include <linux/slab.h>
#include <linux/ioport.h>
#include <linux/fcntl.h>
#include <linux/delay.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/list.h>
#include <asm/io.h>
#include <asm/segment.h>
#include <asm/system.h>
#include <asm/poll.h>
#include <asm/uaccess.h>

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/obd_class.h>
#include <linux/lustre_net.h>

int lustre_pack_msg(int count, int *lens, char **bufs, int *len, char **buf)
{
        char *ptr;
        struct lustre_msg *m;
        int size = 0;
        int i;

        for (i=0 ; i<count; i++) { 
                size += size_round(lens[i]);
        }
        *len = sizeof(*m) + size; 

        OBD_ALLOC(*buf, *len);
        if (!*buf) {
                EXIT;
                return -ENOMEM;
        }

        memset(*buf, 0, *len); 
        m = (struct lustre_msg *)(*buf);
        m->type = PTL_RPC_REQUEST;

        m->bufcount = HTON__u32(count);
        for (i=0 ; i<count; i++) { 
                m->buflens[i] = HTON__u32(lens[i]);
        }
        
        ptr = *buf + sizeof(*m) + sizeof(__u32) * count;
        for (i=0 ; i<count ; i++) { 
                LOGL(buf[i], lens[i], ptr); 
        }

        return 0;
}

int lustre_unpack_msg(char *buf, int len)
{
        struct lustre_msg *m = (struct lustre_msg *)buf;
        int required_len, i;

        required_len = sizeof(*m);
        if (len < required_len) { 
                RETURN(-EINVAL);
        }

        m->bufcount = NTOH__u32(m->bufcount); 

        required_len += m->bufcount * sizeof(__u32); 
        if (len < required_len) { 
                RETURN(-EINVAL);
        }

        for (i=0; i<m->bufcount; i++) { 
                m->buflens[i] = NTOH__u32(m->buflens[i]);
                required_len += size_round(m->buflens[i]);
        }

        if (len < required_len) { 
                RETURN(-EINVAL);
        }

        EXIT;
        return 0;
}

void *lustre_msg_buf(int n, struct lustre_msg *m)
{
        int i;
        int offset;

        if (n >= m->bufcount || n < 0) { 
                CERROR("referencing bad sub buffer!\n"); 
                return NULL;
        }

        if (m->buflens[n] == 0)
                return NULL;

        offset = sizeof(*m) + m->bufcount * sizeof(__u32);

        for (i=0; i < n;  i++ ) 
                offset += size_round(m->buflens[i]); 

        return (char *)m + offset;
}
