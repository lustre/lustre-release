/*
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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2017, Intel Corporation.
 *
 * Copyright 2015 Cray Inc, all rights reserved.
 * Author: Ben Evans.
 *
 * We assume all nodes are either little-endian or big-endian, and we
 * always send messages in the sender's native format.  The receiver
 * detects the message format by checking the 'magic' field of the message
 * (see lustre_msg_swabbed() below).
 *
 * Each wire type has corresponding 'lustre_swab_xxxtypexxx()' routines
 * are implemented in ptlrpc/lustre_swab.c.  These 'swabbers' convert the
 * type from "other" endian, in-place in the message buffer.
 *
 * A swabber takes a single pointer argument.  The caller must already have
 * verified that the length of the message buffer >= sizeof (type).
 *
 * For variable length types, a second 'lustre_swab_v_xxxtypexxx()' routine
 * may be defined that swabs just the variable part, after the caller has
 * verified that the message buffer is large enough.
 */

#ifndef _LUSTRE_SWAB_H_
#define _LUSTRE_SWAB_H_

#include <uapi/linux/lustre/lustre_idl.h>

#ifdef HAVE_SERVER_SUPPORT
void lustre_swab_orphan_ent(struct lu_orphan_ent *ent);
void lustre_swab_orphan_ent_v2(struct lu_orphan_ent_v2 *ent);
void lustre_swab_orphan_ent_v3(struct lu_orphan_ent_v3 *ent);
void lustre_swab_gl_lquota_desc(struct ldlm_gl_lquota_desc *desc);
void lustre_swab_gl_barrier_desc(struct ldlm_gl_barrier_desc *desc);
void lustre_swab_object_update(struct object_update *ou);
int lustre_swab_object_update_request(struct object_update_request *our,
				      __u32 len);
void lustre_swab_out_update_header(struct out_update_header *ouh);
void lustre_swab_out_update_buffer(struct out_update_buffer *oub);
void lustre_swab_object_update_result(struct object_update_result *our);
int lustre_swab_object_update_reply(struct object_update_reply *our, __u32 len);
#endif /* HAVE_SERVER_SUPPORT */
void lustre_swab_ptlrpc_body(struct ptlrpc_body *pb);
void lustre_swab_connect(struct obd_connect_data *ocd);
void lustre_swab_hsm_user_state(struct hsm_user_state *hus);
void lustre_swab_hsm_state_set(struct hsm_state_set *hss);
void lustre_swab_obd_statfs(struct obd_statfs *os);
void lustre_swab_obd_ioobj(struct obd_ioobj *ioo);
void lustre_swab_niobuf_remote(struct niobuf_remote *nbr);
void lustre_swab_ost_lvb_v1(struct ost_lvb_v1 *lvb);
void lustre_swab_ost_lvb(struct ost_lvb *lvb);
int lustre_swab_obd_quotactl(struct obd_quotactl *q, __u32 len);
void lustre_swab_quota_body(struct quota_body *b);
void lustre_swab_lquota_lvb(struct lquota_lvb *lvb);
void lustre_swab_barrier_lvb(struct barrier_lvb *lvb);
void lustre_swab_generic_32s(__u32 *val);
void lustre_swab_mdt_body(struct mdt_body *b);
void lustre_swab_mdt_ioepoch(struct mdt_ioepoch *b);
void lustre_swab_mdt_rec_setattr(struct mdt_rec_setattr *sa);
void lustre_swab_mdt_rec_reint(struct mdt_rec_reint *rr);
void lustre_swab_lmv_desc(struct lmv_desc *ld);
void lustre_swab_lmv_mds_md(union lmv_mds_md *lmm);
void lustre_swab_lov_desc(struct lov_desc *ld);
void lustre_swab_ldlm_res_id(struct ldlm_res_id *id);
void lustre_swab_ldlm_policy_data(union ldlm_wire_policy_data *d);
void lustre_swab_ldlm_intent(struct ldlm_intent *i);
void lustre_swab_ldlm_resource_desc(struct ldlm_resource_desc *r);
void lustre_swab_ldlm_lock_desc(struct ldlm_lock_desc *l);
void lustre_swab_ldlm_request(struct ldlm_request *rq);
void lustre_swab_ldlm_reply(struct ldlm_reply *r);
void lustre_swab_mgs_target_info(struct mgs_target_info *oinfo);
void lustre_swab_mgs_nidtbl_entry(struct mgs_nidtbl_entry *oinfo);
void lustre_swab_mgs_config_body(struct mgs_config_body *body);
void lustre_swab_mgs_config_res(struct mgs_config_res *body);
void lustre_swab_lfsck_request(struct lfsck_request *lr);
void lustre_swab_lfsck_reply(struct lfsck_reply *lr);
void lustre_swab_obdo(struct obdo *o);
void lustre_swab_ost_body(struct ost_body *b);
void lustre_swab_ost_last_id(__u64 *id);
int lustre_swab_fiemap(struct fiemap *fiemap, __u32 len);
void lustre_swab_fiemap_info_key(struct ll_fiemap_info_key *fiemap_info);
void lustre_swab_lov_user_md_v1(struct lov_user_md_v1 *lum);
void lustre_swab_lov_user_md_v3(struct lov_user_md_v3 *lum);
void lustre_swab_lov_comp_md_v1(struct lov_comp_md_v1 *lum);
void lustre_swab_lov_user_md_objects(struct lov_user_ost_data *lod,
				     int stripe_count);
void lustre_swab_lov_user_md(struct lov_user_md *lum, size_t size);
void lustre_swab_lov_mds_md(struct lov_mds_md *lmm);
void lustre_swab_idx_info(struct idx_info *ii);
void lustre_swab_lip_header(struct lu_idxpage *lip);
void lustre_swab_fid2path(struct getinfo_fid2path *gf);
void lustre_swab_layout_intent(struct layout_intent *li);
void lustre_swab_hsm_user_state(struct hsm_user_state *hus);
void lustre_swab_hsm_current_action(struct hsm_current_action *action);
void lustre_swab_hsm_progress_kernel(struct hsm_progress_kernel *hpk);
void lustre_swab_hsm_user_state(struct hsm_user_state *hus);
void lustre_swab_hsm_user_item(struct hsm_user_item *hui);
void lustre_swab_hsm_request(struct hsm_request *hr);
void lustre_swab_batch_update_request(struct batch_update_request *bur);
void lustre_swab_but_update_header(struct but_update_header *buh);
void lustre_swab_but_update_buffer(struct but_update_buffer *bub);
void lustre_swab_batch_update_reply(struct batch_update_reply *bur);
void lustre_swab_swap_layouts(struct mdc_swap_layouts *msl);
void lustre_swab_close_data(struct close_data *data);
void lustre_swab_close_data_resync_done(struct close_data_resync_done *resync);
void lustre_swab_lmv_user_md(struct lmv_user_md *lum);
void lustre_swab_ladvise(struct lu_ladvise *ladvise);
void lustre_swab_ladvise_hdr(struct ladvise_hdr *ladvise_hdr);

/* Functions for dumping PTLRPC fields */
void dump_rniobuf(struct niobuf_remote *rnb);
void dump_ioo(struct obd_ioobj *nb);
void dump_ost_body(struct ost_body *ob);
void dump_rcs(__u32 *rc);

void lustre_print_user_md(unsigned int level, struct lov_user_md *lum,
			  const char *msg);

#endif
