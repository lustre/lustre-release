/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef OST_INTERNAL_H
#define OST_INTERNAL_H

#ifdef LPROCFS
extern void ost_print_req(void *seq_file, struct ptlrpc_request *req);
#else
# define ost_print_req NULL
#endif

#endif /* OST_INTERNAL_H */
