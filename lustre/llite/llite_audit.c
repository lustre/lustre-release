/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
 *   
 *   osc_audit.c - audit code for client side.
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
 */

#define DEBUG_SUBSYSTEM S_LLITE
#include <linux/module.h>
#include <linux/types.h>
#include <linux/random.h>
#include <linux/version.h>

#include <linux/lustre_lite.h>
#include <linux/lustre_ha.h>
#include <linux/lustre_dlm.h>
#include <linux/lprocfs_status.h>
#include <linux/lustre_acl.h>
#include <linux/lustre_audit.h>
#include "llite_internal.h"

//audit is set via obd_set_info() on mds
int ll_set_audit(struct inode * inode, __u64 arg)
{
        struct audit_attr_msg msg;
        struct obd_export * exp = ll_i2mdexp(inode);
        int rc;

        msg.attr = arg;
        msg.id = ll_i2info(inode)->lli_id;
        //set audit on MDS (fs/dir/file)
        rc = obd_set_info(exp, 5, "audit", sizeof(msg), &msg);
        
        //if fs audit is being set for fs then pass attr to all OSS
        if (IS_AUDIT_OP(arg, AUDIT_FS)) {
                exp = ll_i2dtexp(inode);
                rc = obd_set_info(exp, 5, "audit", sizeof(msg), &msg);
        }
        return rc;
}

int ll_check_audit(struct inode * inode, audit_op op, int ret)
{
        __u64 mask = 0;

        LASSERT(op < AUDIT_MAX);
        //check fs audit        
        if (IS_AUDIT(ll_s2sbi(inode->i_sb)->ll_audit_mask)) {
                mask = ll_s2sbi(inode->i_sb)->ll_audit_mask;
        }
        else if (IS_AUDIT(ll_i2info(inode)->lli_audit_mask)) {
                mask = ll_i2info(inode)->lli_audit_mask;
        }
        else
                return 0;

        //if audit is only for failures?
        if (ret >= 0 && IS_AUDIT_OP(mask, AUDIT_FAIL))
                return 0;
        
        return (IS_AUDIT_OP(mask,op));
}
/*
 * this function send audit record data to selected OST
 * obd_set_info() RPC is using for this with key "auditlog"
 */

int ll_audit_log (struct inode * inode, audit_op code, int ret)
{
        struct audit_msg msg;
        struct obd_export * exp = ll_i2dtexp(inode);
        int rc = 0;
        
        if (ll_check_audit(inode, code, ret)) {
                msg.id = ll_i2info(inode)->lli_id;
                msg.code = code;
                msg.result = ret;
                msg.uid = current->uid;
                msg.gid = current->gid;
                msg.nid = 0;
                
                rc = obd_set_info(exp, 8, "auditlog", sizeof(msg), &msg);
        }
        
        RETURN(rc);
}

