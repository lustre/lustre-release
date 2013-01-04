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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2012, Intel Corporation.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osd-zfs/osd_oi.c
 * OI functions to map fid to dnode
 *
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 * Author: Mike Pershin <tappro@whamcloud.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_OSD

#include <lustre_ver.h>
#include <libcfs/libcfs.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_disk.h>
#include <lustre_fid.h>

#include "osd_internal.h"

#include <sys/dnode.h>
#include <sys/dbuf.h>
#include <sys/spa.h>
#include <sys/stat.h>
#include <sys/zap.h>
#include <sys/spa_impl.h>
#include <sys/zfs_znode.h>
#include <sys/dmu_tx.h>
#include <sys/dmu_objset.h>
#include <sys/dsl_prop.h>
#include <sys/sa_impl.h>
#include <sys/txg.h>

static char *oi_tag = "osd_mount, oi";

#define OSD_OI_FID_NR         (1UL << 7)
#define OSD_OI_FID_NR_MAX     (1UL << OSD_OI_FID_OID_BITS_MAX)
unsigned int osd_oi_count = OSD_OI_FID_NR;


/*
 * zfs osd maintains names for known fids in the name hierarchy
 * so that one can mount filesystem with regular ZFS stack and
 * access files
 */
struct named_oid {
	unsigned long	 oid;
	char		*name;
};

static const struct named_oid oids[] = {
	{ OFD_LAST_RECV_OID,		LAST_RCVD },
	{ OFD_LAST_GROUP_OID,		"LAST_GROUP" },
	{ LLOG_CATALOGS_OID,		"CATALOGS" },
	{ MGS_CONFIGS_OID,              NULL /*MOUNT_CONFIGS_DIR*/ },
	{ FID_SEQ_SRV_OID,              "seq_srv" },
	{ FID_SEQ_CTL_OID,              "seq_ctl" },
	{ MDD_CAPA_KEYS_OID,            NULL /*CAPA_KEYS*/ },
	{ FLD_INDEX_OID,                "fld" },
	{ MDD_LOV_OBJ_OID,		LOV_OBJID },
	{ MDT_LAST_RECV_OID,		LAST_RCVD },
	{ OFD_HEALTH_CHECK_OID,		HEALTH_CHECK },
	{ OFD_GROUP0_LAST_OID,		"LAST_ID" },
	{ ACCT_USER_OID,		"acct_usr_inode" },
	{ ACCT_GROUP_OID,		"acct_grp_inode" },
	{ MDD_ROOT_INDEX_OID,		NULL },
	{ MDD_ORPHAN_OID,		NULL },
	{ 0,				NULL }
};

static char *oid2name(const unsigned long oid)
{
	int i = 0;

	while (oids[i].oid) {
		if (oids[i].oid == oid)
			return oids[i].name;
		i++;
	}
	return NULL;
}

/*
 * objects w/o a natural reference (unlike a file on a MDS)
 * are put under a special hierarchy /O/<seq>/d0..dXX
 * this function returns a directory specific fid belongs to
 */
static uint64_t
osd_get_idx_for_ost_obj(const struct lu_env *env, struct osd_device *osd,
			const struct lu_fid *fid, char *buf)
{
	unsigned long	b;
	int		rc;

	rc = fid_ostid_pack(fid, &osd_oti_get(env)->oti_ostid);
	LASSERT(rc == 0); /* we should not get here with IGIF */
	b = osd_oti_get(env)->oti_ostid.oi_id % OSD_OST_MAP_SIZE;
	LASSERT(osd->od_ost_compat_dirs[b]);

	sprintf(buf, LPU64, osd_oti_get(env)->oti_ostid.oi_id);

	return osd->od_ost_compat_dirs[b];
}

/* XXX: f_ver is not counted, but may differ too */
static void osd_fid2str(char *buf, const struct lu_fid *fid)
{
	sprintf(buf, DFID_NOBRACE, PFID(fid));
}

/*
 * Determine the zap object id which is being used as the OI for the
 * given fid.  The lowest N bits in the sequence ID are used as the
 * index key.  On failure 0 is returned which zfs treats internally
 * as an invalid object id.
 */
static uint64_t
osd_get_idx_for_fid(struct osd_device *osd, const struct lu_fid *fid,
		    char *buf)
{
	struct osd_oi *oi;

	LASSERT(osd->od_oi_table != NULL);
	oi = osd->od_oi_table[fid_seq(fid) & (osd->od_oi_count - 1)];
	osd_fid2str(buf, fid);

	return oi->oi_zapid;
}

uint64_t osd_get_name_n_idx(const struct lu_env *env, struct osd_device *osd,
			    const struct lu_fid *fid, char *buf)
{
	uint64_t zapid;

	LASSERT(fid);
	LASSERT(buf);

	if (fid_is_idif(fid)) {
		zapid = osd_get_idx_for_ost_obj(env, osd, fid, buf);
	} else if (unlikely(fid_seq(fid) == FID_SEQ_LOCAL_FILE)) {
		/* special objects with fixed known fids get their name */
		char *name = oid2name(fid_oid(fid));

		if (name) {
			zapid = osd->od_root;
			strcpy(buf, name);
			if (fid_oid(fid) == OFD_GROUP0_LAST_OID)
				zapid = osd->od_ost_compat_grp0;
			else if (fid_is_acct(fid))
				zapid = MASTER_NODE_OBJ;
		} else {
			zapid = osd_get_idx_for_fid(osd, fid, buf);
		}
	} else {
		zapid = osd_get_idx_for_fid(osd, fid, buf);
	}

	return zapid;
}

static inline int fid_is_fs_root(const struct lu_fid *fid)
{
	/* Map root inode to special local object FID */
	return fid_seq(fid) == FID_SEQ_LOCAL_FILE &&
		fid_oid(fid) == OSD_FS_ROOT_OID;
}

int osd_fid_lookup(const struct lu_env *env, struct osd_device *dev,
		   const struct lu_fid *fid, uint64_t *oid)
{
	struct osd_thread_info	*info = osd_oti_get(env);
	char			*buf = info->oti_buf;
	uint64_t		zapid;
	int			rc = 0;
	ENTRY;

	if (OBD_FAIL_CHECK(OBD_FAIL_OST_ENOENT))
		RETURN(-ENOENT);

	if (unlikely(fid_is_acct(fid))) {
		if (fid_oid(fid) == ACCT_USER_OID)
			*oid = dev->od_iusr_oid;
		else
			*oid = dev->od_igrp_oid;
	} else if (unlikely(fid_is_fs_root(fid))) {
		*oid = dev->od_root;
	} else {
		zapid = osd_get_name_n_idx(env, dev, fid, buf);

		rc = -zap_lookup(dev->od_objset.os, zapid, buf,
				8, 1, &info->oti_zde);
		if (rc)
			RETURN(rc);
		*oid = info->oti_zde.lzd_reg.zde_dnode;
	}

	RETURN(rc);
}

/**
 * Lookup an existing OI by the given name.
 */
static int
osd_oi_lookup(const struct lu_env *env, struct osd_device *o,
	      uint64_t parent, const char *name, struct osd_oi *oi)
{
	struct zpl_direntry	*zde = &osd_oti_get(env)->oti_zde.lzd_reg;
	int			 rc;

	rc = -zap_lookup(o->od_objset.os, parent, name, 8, 1, (void *)zde);
	if (rc)
		return rc;

	strncpy(oi->oi_name, name, OSD_OI_NAME_SIZE - 1);
	oi->oi_zapid = zde->zde_dnode;

	return rc;
}

/**
 * Create a new OI with the given name.
 */
static int
osd_oi_create(const struct lu_env *env, struct osd_device *o,
	      uint64_t parent, const char *name, uint64_t *child)
{
	struct zpl_direntry	*zde = &osd_oti_get(env)->oti_zde.lzd_reg;
	struct lu_attr		*la = &osd_oti_get(env)->oti_la;
	dmu_buf_t		*db;
	dmu_tx_t		*tx;
	int			 rc;

	/* verify it doesn't already exist */
	rc = -zap_lookup(o->od_objset.os, parent, name, 8, 1, (void *)zde);
	if (rc == 0)
		return -EEXIST;

	/* create fid-to-dnode index */
	tx = dmu_tx_create(o->od_objset.os);
	if (tx == NULL)
		return -ENOMEM;

	dmu_tx_hold_zap(tx, DMU_NEW_OBJECT, 1, NULL);
	dmu_tx_hold_bonus(tx, parent);
	dmu_tx_hold_zap(tx, parent, TRUE, name);
	LASSERT(tx->tx_objset->os_sa);
	dmu_tx_hold_sa_create(tx, ZFS_SA_BASE_ATTR_SIZE);

	rc = -dmu_tx_assign(tx, TXG_WAIT);
	if (rc) {
		dmu_tx_abort(tx);
		return rc;
	}

	la->la_valid = LA_MODE | LA_UID | LA_GID;
	la->la_mode = S_IFDIR | S_IRUGO | S_IWUSR | S_IXUGO;
	la->la_uid = la->la_gid = 0;
	__osd_zap_create(env, &o->od_objset, &db, tx, la, oi_tag, 0);

	zde->zde_dnode = db->db_object;
	zde->zde_pad = 0;
	zde->zde_type = IFTODT(S_IFDIR);

	rc = -zap_add(o->od_objset.os, parent, name, 8, 1, (void *)zde, tx);

	dmu_tx_commit(tx);

	*child = db->db_object;
	sa_buf_rele(db, oi_tag);

	return rc;
}

static int
osd_oi_find_or_create(const struct lu_env *env, struct osd_device *o,
		      uint64_t parent, const char *name, uint64_t *child)
{
	struct osd_oi	oi;
	int		rc;

	rc = osd_oi_lookup(env, o, parent, name, &oi);
	if (rc == 0) {
		*child = oi.oi_zapid;
	} else if (rc == -ENOENT) {
		rc = osd_oi_create(env, o, parent, name, child);
	}

	return rc;
}

/**
 * Close an entry in a specific slot.
 */
static void
osd_oi_remove_table(const struct lu_env *env, struct osd_device *o, int key)
{
	struct osd_oi *oi;

	LASSERT(key < o->od_oi_count);

	oi = o->od_oi_table[key];
	if (oi) {
		OBD_FREE_PTR(oi);
		o->od_oi_table[key] = NULL;
	}
}

/**
 * Allocate and open a new entry in the specified unused slot.
 */
static int
osd_oi_add_table(const struct lu_env *env, struct osd_device *o,
		 char *name, int key)
{
	struct osd_oi *oi;
	int rc;

	LASSERT(key < o->od_oi_count);
	LASSERT(o->od_oi_table[key] == NULL);

	OBD_ALLOC_PTR(oi);
	if (oi == NULL)
		return -ENOMEM;

	rc = osd_oi_lookup(env, o, o->od_root, name, oi);
	if (rc) {
		OBD_FREE_PTR(oi);
		return rc;
	}

	o->od_oi_table[key] = oi;

	return 0;
}

/**
 * Depopulate the OI table.
 */
static void
osd_oi_close_table(const struct lu_env *env, struct osd_device *o)
{
	int i;

	for (i = 0; i < o->od_oi_count; i++)
		osd_oi_remove_table(env, o, i);
}

/**
 * Populate the OI table based.
 */
static int
osd_oi_open_table(const struct lu_env *env, struct osd_device *o, int count)
{
	char name[16];
	int  i, rc = 0;
	ENTRY;

	for (i = 0; i < count; i++) {
		sprintf(name, "%s.%d", DMU_OSD_OI_NAME_BASE, i);
		rc = osd_oi_add_table(env, o, name, i);
		if (rc) {
			osd_oi_close_table(env, o);
			break;
		}
	}

	RETURN(rc);
}

/**
 * Determine if the type and number of OIs used by this file system.
 */
static int
osd_oi_probe(const struct lu_env *env, struct osd_device *o, int *count)
{
	uint64_t	root_oid = o->od_root;
	struct osd_oi	oi;
	char		name[16];
	int		rc;
	ENTRY;

	/*
	 * Check for multiple OIs and determine the count.  There is no
	 * gap handling, if an OI is missing the wrong size can be returned.
	 * The only safeguard is that we know the number of OIs must be a
	 * power of two and this is checked for basic sanity.
	 */
	for (*count = 0; *count < OSD_OI_FID_NR_MAX; (*count)++) {
		sprintf(name, "%s.%d", DMU_OSD_OI_NAME_BASE, *count);
		rc = osd_oi_lookup(env, o, root_oid, name, &oi);
		if (rc == 0)
			continue;

		if (rc == -ENOENT) {
			if (*count == 0)
				break;

			if ((*count & (*count - 1)) != 0)
				RETURN(-EDOM);

			RETURN(0);
		}

		RETURN(rc);
	}

	/*
	 * No OIs exist, this must be a new filesystem.
	 */
	*count = 0;

	RETURN(0);
}

/**
 * Create /O subdirectory to map legacy OST objects for compatibility.
 */
static int
osd_oi_init_compat(const struct lu_env *env, struct osd_device *o)
{
	char		*key = osd_oti_get(env)->oti_buf;
	uint64_t	 odb, sdb;
	int		 i, rc;
	ENTRY;

	rc = osd_oi_find_or_create(env, o, o->od_root, "O", &sdb);
	if (rc)
		RETURN(rc);

	/* create /O/0 subdirectory to map legacy OST objects */
	rc = osd_oi_find_or_create(env, o, sdb, "0", &odb);
	if (rc)
		RETURN(rc);

	o->od_ost_compat_grp0 = odb;

	for (i = 0; i < OSD_OST_MAP_SIZE; i++) {
		sprintf(key, "d%d", i);
		rc = osd_oi_find_or_create(env, o, odb, key, &sdb);
		if (rc)
			RETURN(rc);

		o->od_ost_compat_dirs[i] = sdb;
	}

	/* Create on-disk indexes to maintain per-UID/GID inode usage.
	 * Those new indexes are created in the top-level ZAP outside the
	 * namespace in order not to confuse ZPL which might interpret those
	 * indexes as directories and assume the values are object IDs */
	rc = osd_oi_find_or_create(env, o, MASTER_NODE_OBJ,
			oid2name(ACCT_USER_OID), &odb);
	if (rc)
		RETURN(rc);
	o->od_iusr_oid = odb;

	rc = osd_oi_find_or_create(env, o, MASTER_NODE_OBJ,
			oid2name(ACCT_GROUP_OID), &odb);
	if (rc)
		RETURN(rc);
	o->od_igrp_oid = odb;

	RETURN(rc);
}

/**
 * Initialize the OIs by either opening or creating them as needed.
 */
int osd_oi_init(const struct lu_env *env, struct osd_device *o)
{
	char	*key = osd_oti_get(env)->oti_buf;
	int	 i, rc, count = 0;
	ENTRY;

	rc = osd_oi_probe(env, o, &count);
	if (rc)
		RETURN(rc);

	if (count == 0) {
		uint64_t odb, sdb;

		count = osd_oi_count;
		odb = o->od_root;

		for (i = 0; i < count; i++) {
			sprintf(key, "%s.%d", DMU_OSD_OI_NAME_BASE, i);
			rc = osd_oi_find_or_create(env, o, odb, key, &sdb);
			if (rc)
				RETURN(rc);
		}
	}

	rc = osd_oi_init_compat(env, o);
	if (rc)
		RETURN(rc);

	LASSERT((count & (count - 1)) == 0);
	o->od_oi_count = count;
	OBD_ALLOC(o->od_oi_table, sizeof(struct osd_oi *) * count);
	if (o->od_oi_table == NULL)
		RETURN(-ENOMEM);

	rc = osd_oi_open_table(env, o, count);
	if (rc) {
		OBD_FREE(o->od_oi_table, sizeof(struct osd_oi *) * count);
		o->od_oi_table = NULL;
	}

	RETURN(rc);
}

void osd_oi_fini(const struct lu_env *env, struct osd_device *o)
{
	ENTRY;

	if (o->od_oi_table != NULL) {
		(void) osd_oi_close_table(env, o);
		OBD_FREE(o->od_oi_table,
			 sizeof(struct osd_oi *) * o->od_oi_count);
		o->od_oi_table = NULL;
		o->od_oi_count = 0;
	}

	EXIT;
}

int osd_options_init(void)
{
	/* osd_oi_count - Default number of OIs, 128 works well for ZFS */
	if (osd_oi_count == 0 || osd_oi_count > OSD_OI_FID_NR_MAX)
		osd_oi_count = OSD_OI_FID_NR;

	if ((osd_oi_count & (osd_oi_count - 1)) != 0) {
		LCONSOLE_WARN("Round up osd_oi_count %d to power2 %d\n",
			osd_oi_count, size_roundup_power2(osd_oi_count));
		osd_oi_count = size_roundup_power2(osd_oi_count);
	}

	return 0;
}


