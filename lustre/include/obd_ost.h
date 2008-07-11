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

static inline struct ldlm_res_id *osc_build_res_name(__u64 id, __u64 gr,
                                                     struct ldlm_res_id *name)
{
        memset(name, 0, sizeof *name);
        name->name[0] = id;
        name->name[2] = gr;
        return name;
}

static inline int osc_res_name_eq(__u64 id, __u64 gr, struct ldlm_res_id *name)
{
        return name->name[0] == id && name->name[2] == gr;
}

#endif
