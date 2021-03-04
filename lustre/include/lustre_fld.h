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
 * Copyright (c) 2011, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef __LINUX_FLD_H
#define __LINUX_FLD_H

/** \defgroup fld fld
 *
 * @{
 */

#include <uapi/linux/lustre/lustre_idl.h>
#include <libcfs/libcfs.h>
#include <seq_range.h>
#include <lustre_fid.h>

struct lu_env;
struct lu_client_fld;
struct lu_server_fld;
struct lu_fld_hash;
struct fld_cache;
struct thandle;
struct dt_device;
struct dt_object;

/*
 * FLD (Fid Location Database) interface.
 */
enum {
        LUSTRE_CLI_FLD_HASH_DHT = 0,
        LUSTRE_CLI_FLD_HASH_RRB
};

struct lu_fld_target {
	struct list_head	ft_chain;
	struct obd_export      *ft_exp;
	struct lu_server_fld   *ft_srv;
	__u64			ft_idx;
};

struct lu_server_fld {
	/**
	 * Fld dir debugfs entry.
	 */
	struct dentry		*lsf_debugfs_entry;

        /**
         * /fld file object device */
        struct dt_object        *lsf_obj;

        /**
         * super sequence controller export, needed to forward fld
         * lookup  request. */
        struct obd_export       *lsf_control_exp;

        /**
         * Client FLD cache. */
        struct fld_cache        *lsf_cache;

        /**
         * Protect index modifications */
	struct mutex		lsf_lock;

	/**
	 * Fld service name in form "fld-srv-lustre-MDTXXX"
	 */
	char			lsf_name[LUSTRE_MDT_MAXNAMELEN];

	int (*lsf_seq_lookup)(const struct lu_env *env,
			      struct lu_server_fld *fld, u64 seq,
			      struct lu_seq_range *range);

	/**
	 * Just reformatted or upgraded, and this flag is being
	 * used to check whether the local FLDB is needs to be
	 * synced with global FLDB(in MDT0), and it is only needed
	 * if the MDT is upgraded from < 2.6 to 2.6, i.e. when the
	 * local FLDB is being invited */
	unsigned int		 lsf_new:1;

};

struct lu_client_fld {
	/**
	 * Client side debugfs entry.
	 */
	struct dentry		*lcf_debugfs_entry;

	/**
	 * List of exports client FLD knows about. */
	struct list_head	lcf_targets;

        /**
         * Current hash to be used to chose an export. */
        struct lu_fld_hash      *lcf_hash;

        /**
         * Exports count. */
        int                      lcf_count;

        /**
         * Lock protecting exports list and fld_hash. */
	spinlock_t		 lcf_lock;

        /**
         * Client FLD cache. */
        struct fld_cache        *lcf_cache;

	/**
	 * Client fld debugfs entry name.
	 */
	char			lcf_name[LUSTRE_MDT_MAXNAMELEN];
};

/* Server methods */
int fld_server_init(const struct lu_env *env, struct lu_server_fld *fld,
		    struct dt_device *dt, const char *prefix, int type);

void fld_server_fini(const struct lu_env *env, struct lu_server_fld *fld);

int fld_declare_server_create(const struct lu_env *env,
			      struct lu_server_fld *fld,
			      const struct lu_seq_range *range,
			      struct thandle *th);

int fld_server_create(const struct lu_env *env,
		      struct lu_server_fld *fld,
		      const struct lu_seq_range *add_range,
		      struct thandle *th);

int fld_insert_entry(const struct lu_env *env,
		     struct lu_server_fld *fld,
		     const struct lu_seq_range *range);

int fld_server_lookup(const struct lu_env *env, struct lu_server_fld *fld,
		      u64 seq, struct lu_seq_range *range);

int fld_local_lookup(const struct lu_env *env, struct lu_server_fld *fld,
		     u64 seq, struct lu_seq_range *range);

int fld_update_from_controller(const struct lu_env *env,
			       struct lu_server_fld *fld);

/* Client methods */
int fld_client_init(struct lu_client_fld *fld,
                    const char *prefix, int hash);

void fld_client_fini(struct lu_client_fld *fld);

void fld_client_flush(struct lu_client_fld *fld);

int fld_client_lookup(struct lu_client_fld *fld, u64 seq, u32 *mds,
                      __u32 flags, const struct lu_env *env);

int fld_client_create(struct lu_client_fld *fld,
                      struct lu_seq_range *range,
                      const struct lu_env *env);

int fld_client_delete(struct lu_client_fld *fld, u64 seq,
                      const struct lu_env *env);

int fld_client_add_target(struct lu_client_fld *fld,
                          struct lu_fld_target *tar);

int fld_client_del_target(struct lu_client_fld *fld,
                          __u64 idx);

void fld_client_debugfs_fini(struct lu_client_fld *fld);

/** @} fld */

#endif
