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

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/obd_support.h>
#include <linux/lustre_net.h>

int lustre_pack_msg(int count, int *lens, char **bufs, int *len,
                    struct lustre_msg **msg)
{
        char *ptr;
        struct lustre_msg *m;
        int size = 0, i;

        for (i = 0; i < count; i++)
                size += size_round(lens[i]);

        *len = size_round(sizeof(*m) + count * sizeof(__u32)) + size;

        OBD_ALLOC(*msg, *len);
        if (!*msg)
                RETURN(-ENOMEM);

        m = *msg;
        m->bufcount = HTON__u32(count);
        for (i = 0; i < count; i++)
                m->buflens[i] = HTON__u32(lens[i]);

        ptr = (char *)m + size_round(sizeof(*m) + count * sizeof(__u32));
        for (i = 0; i < count; i++) {
                char *tmp = NULL;
                if (bufs)
                        tmp = bufs[i];
                LOGL(tmp, lens[i], ptr);
        }

        return 0;
}

/* This returns the size of the buffer that is required to hold a lustre_msg
 * with the given sub-buffer lengths. */
int lustre_msg_size(int count, int *lengths)
{
        int size = 0, i;

        for (i = 0; i < count; i++)
                size += size_round(lengths[i]);

        size += size_round(sizeof(struct lustre_msg) + count * sizeof(__u32));

        return size;
}

int lustre_unpack_msg(struct lustre_msg *m, int len)
{
        int required_len, i;

        required_len = size_round(sizeof(*m));
        if (len < required_len)
                RETURN(-EINVAL);

        m->opc = NTOH__u32(m->opc);
        m->status = NTOH__u32(m->status);
        m->type = NTOH__u32(m->type);
        m->bufcount = NTOH__u32(m->bufcount);
        m->last_rcvd = NTOH__u64(m->last_rcvd);
        m->last_committed = NTOH__u64(m->last_committed);

        required_len = size_round(sizeof(*m) + m->bufcount * sizeof(__u32));
        if (len < required_len)
                RETURN(-EINVAL);

        for (i = 0; i < m->bufcount; i++) {
                m->buflens[i] = NTOH__u32(m->buflens[i]);
                required_len += size_round(m->buflens[i]);
        }

        if (len < required_len) {
                CERROR("len: %d, required_len %d\n", len, required_len);
                RETURN(-EINVAL);
        }

        RETURN(0);
}

void *lustre_msg_buf(struct lustre_msg *m, int n)
{
        int i, offset;

        if (!m) {
                CERROR("no message buffer!\n");
                LBUG();
                return NULL;
        }

        if (n < 0 || n >= m->bufcount) {
                CERROR("referencing bad sub buffer (requested %d, count is "
                       "%d)!\n", n, m->bufcount);
                LBUG();
                return NULL;
        }

        if (m->buflens[n] == 0)
                return NULL;

        offset = size_round(sizeof(*m) + m->bufcount * sizeof(__u32));

        for (i = 0; i < n; i++)
                offset += size_round(m->buflens[i]);

        return (char *)m + offset;
}
