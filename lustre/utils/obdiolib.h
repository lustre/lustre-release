/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   This file is part of Lustre, http://www.lustre.org
 */
#ifndef _OBDIOLIB_H_
#define _OBDIOLIB_H_

#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <lustre_lib.h>
#include <lustre/lustre_idl.h>
#include <obd_class.h>

struct obdio_conn {
        int                    oc_fd;
        uint32_t               oc_device;
        struct obd_ioctl_data  oc_data;
        char                   oc_buffer[8192];
};

struct obdio_barrier {
        uint64_t               ob_id;
        uint64_t               ob_oid;
        uint64_t               ob_npeers;
        uint64_t               ob_ordinal;
        uint64_t               ob_count;
};

extern struct obdio_conn *obdio_connect(int device);
extern void obdio_disconnect(struct obdio_conn *conn, int flags);
extern int obdio_open(struct obdio_conn *conn, uint64_t oid,
                      struct lustre_handle *fh);
extern int obdio_close(struct obdio_conn *conn, uint64_t oid,
                       struct lustre_handle *fh);
extern int obdio_pread(struct obdio_conn *conn, uint64_t oid,
                       void *buffer, uint32_t count, uint64_t offset);
extern int obdio_pwrite(struct obdio_conn *conn, uint64_t oid,
                        void *buffer, uint32_t count, uint64_t offset);
extern int obdio_enqueue(struct obdio_conn *conn, uint64_t oid,
                         int mode, uint64_t offset, uint32_t count,
                         struct lustre_handle *lh);
extern int obdio_cancel(struct obdio_conn *conn, struct lustre_handle *lh);
extern void *obdio_alloc_aligned_buffer(void **spacep, int size);
extern struct obdio_barrier *obdio_new_barrier(uint64_t oid, uint64_t id,
                                               int npeers);
extern int obdio_setup_barrier(struct obdio_conn *conn,struct obdio_barrier *b);
extern int obdio_barrier(struct obdio_conn *conn, struct obdio_barrier *b);

#endif
