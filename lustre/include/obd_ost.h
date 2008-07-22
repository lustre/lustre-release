/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   This file is part of Lustre, http://www.lustre.org
 *
 * Data structures for object storage targets and client: OST & OSC's
 * 
 * See also lustre_idl.h for wire formats of requests.
 */

#ifndef _LUSTRE_OST_H
#define _LUSTRE_OST_H

#include <obd_class.h>

struct osc_brw_async_args {
        struct obdo     *aa_oa;
        int              aa_requested_nob;
        int              aa_nio_count;
        obd_count        aa_page_count;
        int              aa_resends;
        struct brw_page **aa_ppga;
        struct client_obd *aa_cli;
        struct list_head aa_oaps;
};

struct osc_async_args {
        struct obd_info   *aa_oi;
};

struct osc_enqueue_args {
        struct obd_export       *oa_exp;
        struct obd_info         *oa_oi;
        struct ldlm_enqueue_info*oa_ei;
};

int osc_extent_blocking_cb(struct ldlm_lock *lock,
                           struct ldlm_lock_desc *new, void *data,
                           int flag);

#endif
