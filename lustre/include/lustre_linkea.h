/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2013, 2017, Intel Corporation.
 * Use is subject to license terms.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: di wang <di.wang@intel.com>
 */

/* There are several reasons to restrict the linkEA size:
 *
 * 1. Under DNE mode, if we do not restrict the linkEA size, and if there
 *    are too many cross-MDTs hard links to the same object, then it will
 *    casue the llog overflow.
 *
 * 2. Some backend has limited size for EA. For example, if without large
 *    EA enabled, the ldiskfs will make all EAs to share one (4K) EA block.
 *
 * 3. Too many entries in linkEA will seriously affect linkEA performance
 *    because we only support to locate linkEA entry consecutively.
 */
#define MAX_LINKEA_SIZE	4096

struct linkea_data {
	/**
	 * Buffer to keep link EA body.
	 */
	struct lu_buf		*ld_buf;
	/**
	 * The matched header, entry and its lenght in the EA
	 */
	struct link_ea_header	*ld_leh;
	struct link_ea_entry	*ld_lee;
	int			ld_reclen;
};

int linkea_data_new(struct linkea_data *ldata, struct lu_buf *buf);
int linkea_init(struct linkea_data *ldata);
int linkea_init_with_rec(struct linkea_data *ldata);
void linkea_entry_unpack(const struct link_ea_entry *lee, int *reclen,
			 struct lu_name *lname, struct lu_fid *pfid);
int linkea_entry_pack(struct link_ea_entry *lee, const struct lu_name *lname,
		      const struct lu_fid *pfid);
bool linkea_will_overflow(struct linkea_data *ldata,
			  const struct lu_name *lname);
int linkea_add_buf(struct linkea_data *ldata, const struct lu_name *lname,
		   const struct lu_fid *pfid, bool err_on_overflow);
void linkea_del_buf(struct linkea_data *ldata, const struct lu_name *lname,
		    bool is_encrypted);
int linkea_links_new(struct linkea_data *ldata, struct lu_buf *buf,
		     const struct lu_name *cname, const struct lu_fid *pfid);
int linkea_overflow_shrink(struct linkea_data *ldata);
int linkea_links_find(struct linkea_data *ldata, const struct lu_name *lname,
		      const struct lu_fid  *pfid);

static inline void linkea_first_entry(struct linkea_data *ldata)
{
	LASSERT(ldata != NULL);
	LASSERT(ldata->ld_leh != NULL);

	if (ldata->ld_leh->leh_reccount == 0)
		ldata->ld_lee = NULL;
	else
		ldata->ld_lee = (struct link_ea_entry *)(ldata->ld_leh + 1);
}

static inline void linkea_next_entry(struct linkea_data *ldata)
{
	LASSERT(ldata != NULL);
	LASSERT(ldata->ld_leh != NULL);

	if (ldata->ld_lee != NULL) {
		ldata->ld_lee = (struct link_ea_entry *)((char *)ldata->ld_lee +
							 ldata->ld_reclen);
		if ((char *)ldata->ld_lee >= ((char *)ldata->ld_leh +
					      ldata->ld_leh->leh_len))
			ldata->ld_lee = NULL;
	}
}
