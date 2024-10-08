/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 *
 * Copyright 2015 Cray Inc, all rights reserved.
 * Author: Ben Evans.
 *
 * We assume all nodes are either little-endian or big-endian, and we
 * always send messages in the sender's native format.  The receiver
 * detects the message format by checking the 'magic' field of the message
 * (see lustre_msg_swabbed() below).
 *
 * Each type has corresponding 'lustre_swab_xxxtypexxx()' routines
 * are implemented in ptlrpc/pack_generic.c.  These 'swabbers' convert the
 * type from "other" endian, in-place in the message buffer.
 *
 * A swabber takes a single pointer argument.  The caller must already have
 * verified that the length of the message buffer >= sizeof (type).
 *
 * For variable length types, a second 'lustre_swab_v_xxxtypexxx()' routine
 * may be defined that swabs just the variable part, after the caller has
 * verified that the message buffer is large enough.
 */

#ifndef _LLOG_SWAB_H_
#define _LLOG_SWAB_H_

#include <uapi/linux/lustre/lustre_idl.h>
struct lustre_cfg;

void lustre_swab_lu_fid(struct lu_fid *fid);
void lustre_swab_ost_id(struct ost_id *oid);
void lustre_swab_ll_fid(struct ll_fid *fid);
void lustre_swab_llogd_body(struct llogd_body *d);
void lustre_swab_llog_hdr(struct llog_log_hdr *h);
void lustre_swab_llogd_conn_body(struct llogd_conn_body *d);
void lustre_swab_llog_rec(struct llog_rec_hdr *rec);
void lustre_swab_llog_id(struct llog_logid *lid);
void lustre_swab_lu_seq_range(struct lu_seq_range *range);
#ifdef HAVE_SERVER_SUPPORT
void lustre_swab_update_ops(struct update_ops *uops, unsigned int op_count);
#endif
void lustre_swab_lustre_cfg(struct lustre_cfg *lcfg);
void lustre_swab_cfg_marker(struct cfg_marker *marker,
			    int swab, int size);

#endif
