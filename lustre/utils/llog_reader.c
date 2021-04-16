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
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */
/** \defgroup llog_reader Lustre Log Reader
 *
 * Interpret llogs used for storing configuration and changelog data
 *
 * @{
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_ENDIAN_H
# include <endian.h>
#endif
#include <unistd.h>
#include <fcntl.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <errno.h>
#include <time.h>
#include <linux/lnet/nidstr.h>
#include <linux/lustre/lustre_cfg.h>
#include <linux/lustre/lustre_fid.h>
#include <linux/lustre/lustre_ostid.h>
#include <linux/lustre/lustre_log_user.h>
#include <lustre/lustreapi.h>

static inline int ext2_test_bit(int nr, const void *addr)
{
#if __BYTE_ORDER == __BIG_ENDIAN
	const unsigned char *tmp = addr;

	return (tmp[nr >> 3] >> (nr & 7)) & 1;
#else
	const unsigned long *tmp = addr;

	return ((1UL << (nr & (__WORDSIZE - 1))) &
		((tmp)[nr / __WORDSIZE])) != 0;
#endif
}

int llog_pack_buffer(int fd, struct llog_log_hdr **llog_buf,
		     struct llog_rec_hdr ***recs, int *recs_number);

void print_llog_header(struct llog_log_hdr *llog_buf);
static void print_records(struct llog_rec_hdr **recs_buf,
			  int rec_number, int is_ext);
void llog_unpack_buffer(int fd, struct llog_log_hdr *llog_buf,
			struct llog_rec_hdr **recs_buf);

#define CANCELLED 0x678

#define PTL_CMD_BASE 100
char *portals_command[17] = {
	"REGISTER_PEER_FD",
	"CLOSE_CONNECTION",
	"REGISTER_MYNID",
	"PUSH_CONNECTION",
	"GET_CONN",
	"DEL_PEER",
	"ADD_PEER",
	"GET_PEER",
	"GET_TXDESC",
	"ADD_ROUTE",
	"DEL_ROUTE",
	"GET_ROUTE",
	"NOTIFY_ROUTER",
	"ADD_INTERFACE",
	"DEL_INTERFACE",
	"GET_INTERFACE",
	""
};

int is_fstype_ext(int fd)
{
	struct statfs st;
	int rc;

	rc = fstatfs(fd, &st);
	if (rc < 0) {
		llapi_error(LLAPI_MSG_ERROR, rc, "Got statfs error.");
		return -errno;
	}

	return (st.f_type == EXT4_SUPER_MAGIC);
}

/**
 * Attempt to display a path to the object (file) containing changelog entries,
 * referred to by this changelog_catalog record.
 *
 * This path depends on the implementation of the OSD device; zfs-osd and
 * ldiskfs-osd are different.
 *
 * Assumes that if the file system containing the changelog_catalog is
 * ext{2,3,4}, the backend is ldiskfs-osd; otherwise it is either zfs-osd or at
 * least names objects based on FID and the zfs-osd path (which includes the
 * FID) will be sufficient.
 *
 * The Object ID stored in the record is also displayed untranslated.
 */
#define OSD_OI_FID_NR         (1UL << 7)
static void print_log_path(struct llog_logid_rec *lid, int is_ext)
{
	char object_path[255];
	struct lu_fid fid_from_logid;

	logid_to_fid(&lid->lid_id, &fid_from_logid);

	if (is_ext)
		snprintf(object_path, sizeof(object_path),
			 "O/%ju/d%u/%u", (uintmax_t)fid_from_logid.f_seq,
			 fid_from_logid.f_oid % 32,
			 fid_from_logid.f_oid);
	else
		snprintf(object_path, sizeof(object_path),
			 "oi.%ju/"DFID_NOBRACE,
			 (uintmax_t)(fid_from_logid.f_seq &
				     (OSD_OI_FID_NR - 1)),
			 PFID(&fid_from_logid));

	printf("id="DFID":%x path=%s\n",
	       PFID(&lid->lid_id.lgl_oi.oi_fid), lid->lid_id.lgl_ogen,
	       object_path);
}

int main(int argc, char **argv)
{
	int rc = 0;
	int is_ext;
	int fd, rec_number;
	struct llog_log_hdr *llog_buf = NULL;
	struct llog_rec_hdr **recs_buf = NULL;

	setlinebuf(stdout);

	if (argc != 2) {
		printf("Usage: llog_reader filename\n");
		return -1;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "Could not open the file %s.",
			    argv[1]);
		goto out;
	}

	is_ext = is_fstype_ext(fd);
	if (is_ext < 0) {
		rc = is_ext;
		llapi_error(LLAPI_MSG_ERROR, -rc,
			    "Unable to determine filesystem type for %s",
		       argv[1]);
		goto out_fd;
	}

	rc = llog_pack_buffer(fd, &llog_buf, &recs_buf, &rec_number);
	if (rc < 0) {
		llapi_error(LLAPI_MSG_ERROR, rc, "Could not pack buffer.");
		goto out_fd;
	}

	if (llog_buf)
		print_llog_header(llog_buf);
	if (recs_buf)
		print_records(recs_buf, rec_number, is_ext);
	llog_unpack_buffer(fd, llog_buf, recs_buf);

out_fd:
	close(fd);
out:
	return rc;
}

int llog_pack_buffer(int fd, struct llog_log_hdr **llog,
		     struct llog_rec_hdr ***recs,
		     int *recs_number)
{
	int rc = 0, recs_num, rd = 0;
	long long file_size;
	struct stat st;
	char *file_buf = NULL, *recs_buf = NULL;
	struct llog_rec_hdr **recs_pr = NULL;
	char *ptr = NULL;
	int count;
	int i, last_idx;

	rc = fstat(fd, &st);
	if (rc < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "Got file stat error.");
		goto out;
	}

	file_size = st.st_size;
	if (file_size < sizeof(**llog)) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "File too small for llog header: want=%zd got=%lld",
			    sizeof(**llog), file_size);
		rc = -EIO;
		goto out;
	}

	file_buf = malloc(file_size);
	if (!file_buf) {
		rc = -ENOMEM;
		llapi_error(LLAPI_MSG_ERROR, rc, "Memory Alloc for file_buf.");
		goto out;
	}
	*llog = (struct llog_log_hdr *)file_buf;

	do {
		rc = read(fd, file_buf + rd, file_size - rd);
		if (rc > 0)
			rd += rc;
	} while (rc > 0 && rd < file_size);

	if (rd < file_size) {
		rc = rc < 0 ? -errno : -EIO;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "Error reading llog header: need %zd, got %d",
			    sizeof(**llog), rd);
		goto clear_file_buf;
	}

	count = __le32_to_cpu((*llog)->llh_count);
	if (count < 0) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "corrupted llog: negative record number %d",
			    count);
		goto clear_file_buf;
	} else if (count == 0) {
		llapi_printf(LLAPI_MSG_NORMAL,
			     "uninitialized llog: zero record number\n");
		*recs_number = 0;
		goto clear_file_buf;
	}
	/* the llog header not countable here.*/
	recs_num = count - 1;

	recs_buf = calloc(recs_num, sizeof(**recs_pr));
	if (!recs_buf) {
		rc = -ENOMEM;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "Error allocating %zd bytes for recs_buf",
			    recs_num * sizeof(**recs_pr));
		goto clear_file_buf;
	}
	recs_pr = (struct llog_rec_hdr **)recs_buf;

	ptr = file_buf + __le32_to_cpu((*llog)->llh_hdr.lrh_len);
	i = 0;

	last_idx = 0;
	while (ptr < (file_buf + file_size)) {
		struct llog_rec_hdr *cur_rec;
		int idx;
		unsigned long offset;

		if (ptr + sizeof(**recs_pr) > file_buf + file_size) {
			rc = -EINVAL;
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "The log is corrupt (too big at %d)", i);
			goto clear_recs_buf;
		}

		cur_rec = (struct llog_rec_hdr *)ptr;
		idx = __le32_to_cpu(cur_rec->lrh_index);
		recs_pr[i] = cur_rec;
		offset = (unsigned long)ptr - (unsigned long)file_buf;
		if (cur_rec->lrh_len == 0 ||
		    cur_rec->lrh_len > (*llog)->llh_hdr.lrh_len) {
			cur_rec->lrh_len = (*llog)->llh_hdr.lrh_len -
				offset % (*llog)->llh_hdr.lrh_len;
			printf("off %lu skip %u to next chunk.\n", offset,
			       cur_rec->lrh_len);
			i--;
		} else if (ext2_test_bit(idx, LLOG_HDR_BITMAP(*llog))) {
			printf("rec #%d type=%x len=%u offset %lu\n", idx,
			       cur_rec->lrh_type, cur_rec->lrh_len, offset);
		} else {
			cur_rec->lrh_id = CANCELLED;
			if (cur_rec->lrh_type == LLOG_PAD_MAGIC &&
			   ((offset + cur_rec->lrh_len) & 0x7) != 0)
				printf("rec #%d wrong padding len=%u offset %lu to 0x%lx\n",
				       idx, cur_rec->lrh_len, offset,
				       offset + cur_rec->lrh_len);
			/* The header counts only set records */
			i--;
		}
		if (last_idx + 1 != idx) {
			printf("Previous index is %d, current %d, offset %lu\n",
			       last_idx, idx, offset);
		}
		last_idx = idx;

		ptr += __le32_to_cpu(cur_rec->lrh_len);
		if ((ptr - file_buf) > file_size) {
			printf("The log is corrupt (too big at %d)\n", i);
			rc = -EINVAL;
			goto clear_recs_buf;
		}
		i++;
	}

	*recs = recs_pr;
	*recs_number = recs_num;

out:
	return rc;

clear_recs_buf:
	free(recs_buf);

clear_file_buf:
	free(file_buf);

	*llog = NULL;
	goto out;
}

void llog_unpack_buffer(int fd, struct llog_log_hdr *llog_buf,
			struct llog_rec_hdr **recs_buf)
{
	if (llog_buf)
		free(llog_buf);
	if (recs_buf)
		free(recs_buf);
}

void print_llog_header(struct llog_log_hdr *llog_buf)
{
	time_t t;
	unsigned int lrh_len = __le32_to_cpu(llog_buf->llh_hdr.lrh_len);
	struct llog_rec_tail *tail = ((struct llog_rec_tail *)((char *)llog_buf+
				 lrh_len - sizeof(llog_buf->llh_tail)));

	printf("Header size : %u\t llh_size : %u\n", lrh_len,
	       __le32_to_cpu(llog_buf->llh_size));

	t = __le64_to_cpu(llog_buf->llh_timestamp);
	printf("Time : %s", ctime(&t));

	printf("Number of records: %u\tcat_idx: %u\tlast_idx: %u\n",
	       __le32_to_cpu(llog_buf->llh_count)-1,
	       __le32_to_cpu(llog_buf->llh_cat_idx),
	       __le32_to_cpu(tail->lrt_index));

	printf("Target uuid : %s\n",
	       (char *)(&llog_buf->llh_tgtuuid));

	/* Add the other info you want to view here */

	printf("-----------------------\n");
}

static void print_1_cfg(struct lustre_cfg *lcfg)
{
	int i;

	if (lcfg->lcfg_nid)
		printf("nid=%s(%#jx)  ", libcfs_nid2str(lcfg->lcfg_nid),
		       (uintmax_t)lcfg->lcfg_nid);
	if (lcfg->lcfg_nal)
		printf("nal=%d ", lcfg->lcfg_nal);
	for (i = 0; i <  lcfg->lcfg_bufcount; i++)
		printf("%d:%.*s  ", i, lcfg->lcfg_buflens[i],
		       (char *)lustre_cfg_buf(lcfg, i));
}

static char *lustre_cfg_string(struct lustre_cfg *lcfg, __u32 index)
{
	char *s;

	if (lcfg->lcfg_buflens[index] == 0)
		return NULL;

	s = lustre_cfg_buf(lcfg, index);
	if (!s)
		return NULL;

	/*
	 * make sure it's NULL terminated, even if this kills a char
	 * of data. Try to use the padding first though.
	 */
	if (s[lcfg->lcfg_buflens[index] - 1] != '\0') {
		size_t last = __ALIGN_KERNEL(lcfg->lcfg_buflens[index], 8) - 1;
		char lost;

		/* Use the smaller value */
		if (last > lcfg->lcfg_buflens[index])
			last = lcfg->lcfg_buflens[index];

		lost = s[last];
		s[last] = '\0';
		if (lost != '\0') {
			fprintf(stderr,
				"Truncated buf %d to '%s' (lost '%c'...)\n",
				index, s, lost);
		}
	}
	return s;
}

static void print_setup_cfg(struct lustre_cfg *lcfg)
{
	struct lov_desc *desc;

	if ((lcfg->lcfg_bufcount == 2) &&
	    (lcfg->lcfg_buflens[1] == sizeof(*desc))) {
		printf("lov_setup ");
		printf("0:%s  ", lustre_cfg_string(lcfg, 0));
		printf("1:(struct lov_desc)\n");
		desc = (struct lov_desc *)(lustre_cfg_string(lcfg, 1));
		printf("\t\tuuid=%s  ", (char *)desc->ld_uuid.uuid);
		printf("stripe:cnt=%u ", desc->ld_default_stripe_count);
		printf("size=%ju ", (uintmax_t)desc->ld_default_stripe_size);
		printf("offset=%ju ",
		       (uintmax_t)desc->ld_default_stripe_offset);
		printf("pattern=%#x", desc->ld_pattern);
	} else {
		printf("setup     ");
		print_1_cfg(lcfg);
	}
}

void print_lustre_cfg(struct lustre_cfg *lcfg, int *skip)
{
	enum lcfg_command_type cmd = __le32_to_cpu(lcfg->lcfg_command);

	if (*skip > 0)
		printf("SKIP ");

	switch (cmd) {
	case(LCFG_ATTACH):{
		printf("attach    ");
		print_1_cfg(lcfg);
		break;
	}
	case(LCFG_SETUP):{
		print_setup_cfg(lcfg);
		break;
	}
	case(LCFG_DETACH):{
		printf("detach    ");
		print_1_cfg(lcfg);
		break;
	}
	case(LCFG_CLEANUP):{
		printf("cleanup   ");
		print_1_cfg(lcfg);
		break;
	}
	case(LCFG_ADD_UUID):{
		printf("add_uuid  ");
		print_1_cfg(lcfg);
		break;
	}
	case(LCFG_DEL_UUID):{
		printf("del_uuid  ");
		print_1_cfg(lcfg);
		break;
	}
	case(LCFG_ADD_CONN):{
		printf("add_conn  ");
		print_1_cfg(lcfg);
		break;
	}
	case(LCFG_DEL_CONN):{
		printf("del_conn  ");
		print_1_cfg(lcfg);
		break;
	}
	case(LCFG_LOV_ADD_OBD):{
		printf("lov_modify_tgts add ");
		print_1_cfg(lcfg);
		break;
	}
	case(LCFG_LOV_DEL_OBD):{
		printf("lov_modify_tgts del ");
		print_1_cfg(lcfg);
		break;
	}
	case(LCFG_ADD_MDC):{
		printf("modify_mdc_tgts add ");
		print_1_cfg(lcfg);
		break;
	}
	case(LCFG_DEL_MDC):{
		printf("modify_mdc_tgts del ");
		print_1_cfg(lcfg);
		break;
	}
	case(LCFG_MOUNTOPT):{
		printf("mount_option ");
		print_1_cfg(lcfg);
		break;
	}
	case(LCFG_DEL_MOUNTOPT):{
		printf("del_mount_option ");
		print_1_cfg(lcfg);
		break;
	}
	case(LCFG_SET_TIMEOUT):{
		printf("set_timeout=%d ", lcfg->lcfg_num);
		break;
	}
	case(LCFG_SET_LDLM_TIMEOUT):{
		printf("set_ldlm_timeout=%d ", lcfg->lcfg_num);
		break;
	}
	case(LCFG_SET_UPCALL):{
		printf("set_lustre_upcall ");
		print_1_cfg(lcfg);
		break;
	}
	case(LCFG_PARAM):{
		printf("param ");
		print_1_cfg(lcfg);
		break;
	}
	case(LCFG_SET_PARAM):{
		printf("set_param ");
		print_1_cfg(lcfg);
		break;
	}
	case(LCFG_SPTLRPC_CONF):{
		printf("sptlrpc_conf ");
		print_1_cfg(lcfg);
		break;
	}
	case(LCFG_MARKER):{
		struct cfg_marker *marker = lustre_cfg_buf(lcfg, 1);
		char createtime[26], canceltime[26] = "";
		time_t time_tmp;

		if (marker->cm_flags & CM_START &&
		    marker->cm_flags & CM_SKIP) {
			printf("SKIP START ");
			(*skip)++;
		} else if (marker->cm_flags & CM_END) {
			printf("END   ");
			*skip = 0;
		}

		if (marker->cm_flags & CM_EXCLUDE) {
			if (marker->cm_flags & CM_START)
				printf("EXCLUDE START ");
			else
				printf("EXCLUDE END   ");
		}

		/*
		 * Handle overflow of 32-bit time_t gracefully.
		 * The copy to time_tmp is needed in any case to
		 * keep the pointer happy, even on 64-bit systems.
		 */
		time_tmp = marker->cm_createtime;
		if (time_tmp == marker->cm_createtime) {
			ctime_r(&time_tmp, createtime);
			createtime[strlen(createtime) - 1] = 0;
		} else {
			strcpy(createtime, "in the distant future");
		}

		if (marker->cm_canceltime) {
			/*
			 * Like cm_createtime, we try to handle overflow of
			 * 32-bit time_t gracefully. The copy to time_tmp
			 * is also needed on 64-bit systems to keep the
			 * pointer happy, see bug 16771
			 */
			time_tmp = marker->cm_canceltime;
			if (time_tmp == marker->cm_canceltime) {
				ctime_r(&time_tmp, canceltime);
				canceltime[strlen(canceltime) - 1] = 0;
			} else {
				strcpy(canceltime, "in the distant future");
			}
		}

		printf("marker %3d (flags=%#04x, v%d.%d.%d.%d) %-15s '%s' %s-%s",
		       marker->cm_step, marker->cm_flags,
		       OBD_OCD_VERSION_MAJOR(marker->cm_vers),
		       OBD_OCD_VERSION_MINOR(marker->cm_vers),
		       OBD_OCD_VERSION_PATCH(marker->cm_vers),
		       OBD_OCD_VERSION_FIX(marker->cm_vers),
		       marker->cm_tgtname, marker->cm_comment,
		       createtime, canceltime);
		break;
	}
	case(LCFG_POOL_NEW):{
		printf("pool new ");
		print_1_cfg(lcfg);
		break;
	}
	case(LCFG_POOL_ADD):{
		printf("pool add ");
		print_1_cfg(lcfg);
		break;
	}
	case(LCFG_POOL_REM):{
		printf("pool remove ");
		print_1_cfg(lcfg);
		break;
	}
	case(LCFG_POOL_DEL):{
		printf("pool destroy ");
		print_1_cfg(lcfg);
		break;
	}
	default:
		printf("unsupported cmd_code = %x\n", cmd);
	}
	printf("\n");
}

static void print_hsm_action(struct llog_agent_req_rec *larr)
{
	char buf[12];
	int sz;

	sz = larr->arr_hai.hai_len - sizeof(larr->arr_hai);
	printf("lrh=[type=%X len=%d idx=%d] fid="DFID" compound/cookie=%#llx/%#llx status=%s action=%s archive#=%d flags=%#llx create=%llu change=%llu extent=%#llx-%#llx gid=%#llx datalen=%d data=[%s]\n",
	       larr->arr_hdr.lrh_type,
	       larr->arr_hdr.lrh_len, larr->arr_hdr.lrh_index,
	       PFID(&larr->arr_hai.hai_fid),
	       (unsigned long long)larr->arr_compound_id,
	       (unsigned long long)larr->arr_hai.hai_cookie,
	       agent_req_status2name(larr->arr_status),
	       hsm_copytool_action2name(larr->arr_hai.hai_action),
	       larr->arr_archive_id,
	       (unsigned long long)larr->arr_flags,
	       (unsigned long long)larr->arr_req_create,
	       (unsigned long long)larr->arr_req_change,
	       (unsigned long long)larr->arr_hai.hai_extent.offset,
	       (unsigned long long)larr->arr_hai.hai_extent.length,
	       (unsigned long long)larr->arr_hai.hai_gid, sz,
	       hai_dump_data_field(&larr->arr_hai, buf, sizeof(buf)));
}

void print_changelog_rec(struct llog_changelog_rec *rec)
{
	time_t secs;
	struct tm ts;

	secs = __le64_to_cpu(rec->cr.cr_time) >> 30;
	gmtime_r(&secs, &ts);
	printf("changelog record id:0x%x index:%llu cr_flags:0x%x cr_type:%s(0x%x) date:'%02d:%02d:%02d.%09d %04d.%02d.%02d' target:"DFID,
	       __le32_to_cpu(rec->cr_hdr.lrh_id),
	       (unsigned long long)__le64_to_cpu(rec->cr.cr_index),
	       __le32_to_cpu(rec->cr.cr_flags),
	       changelog_type2str(__le32_to_cpu(rec->cr.cr_type)),
	       __le32_to_cpu(rec->cr.cr_type),
	       ts.tm_hour, ts.tm_min, ts.tm_sec,
	       (int)(__le64_to_cpu(rec->cr.cr_time) & ((1 << 30) - 1)),
	       ts.tm_year + 1900, ts.tm_mon + 1, ts.tm_mday,
	       PFID(&rec->cr.cr_tfid));

	if (rec->cr.cr_flags & CLF_JOBID) {
		struct changelog_ext_jobid *jid =
			changelog_rec_jobid(&rec->cr);

		if (jid->cr_jobid[0] != '\0')
			printf(" jobid:%s", jid->cr_jobid);
	}

	if (rec->cr.cr_flags & CLF_EXTRA_FLAGS) {
		struct changelog_ext_extra_flags *ef =
			changelog_rec_extra_flags(&rec->cr);

		printf(" cr_extra_flags:0x%llx",
		       (unsigned long long)__le64_to_cpu(ef->cr_extra_flags));

		if (ef->cr_extra_flags & CLFE_UIDGID) {
			struct changelog_ext_uidgid *uidgid =
				changelog_rec_uidgid(&rec->cr);

			printf(" user:%u:%u",
			       __le32_to_cpu(uidgid->cr_uid),
			       __le32_to_cpu(uidgid->cr_gid));
		}
		if (ef->cr_extra_flags & CLFE_NID) {
			struct changelog_ext_nid *nid =
				changelog_rec_nid(&rec->cr);

			printf(" nid:%s",
			       libcfs_nid2str(nid->cr_nid));
		}

		if (ef->cr_extra_flags & CLFE_OPEN) {
			struct changelog_ext_openmode *omd =
				changelog_rec_openmode(&rec->cr);
			char mode[] = "---";

			/* exec mode must be exclusive */
			if (__le32_to_cpu(omd->cr_openflags) & MDS_FMODE_EXEC) {
				mode[2] = 'x';
			} else {
				if (__le32_to_cpu(omd->cr_openflags) &
				    MDS_FMODE_READ)
					mode[0] = 'r';
				if (__le32_to_cpu(omd->cr_openflags) &
			   (MDS_FMODE_WRITE | MDS_OPEN_TRUNC | MDS_OPEN_APPEND))
					mode[1] = 'w';
			}

			if (strcmp(mode, "---") != 0)
				printf(" mode:%s", mode);
		}

		if (ef->cr_extra_flags & CLFE_XATTR) {
			struct changelog_ext_xattr *xattr =
				changelog_rec_xattr(&rec->cr);

			if (xattr->cr_xattr[0] != '\0')
				printf(" xattr:%s", xattr->cr_xattr);
		}
	}

	if (rec->cr.cr_namelen)
		printf(" parent:"DFID" name:%.*s", PFID(&rec->cr.cr_pfid),
		       __le32_to_cpu(rec->cr.cr_namelen),
		       changelog_rec_name(&rec->cr));

	if (rec->cr.cr_flags & CLF_RENAME) {
		struct changelog_ext_rename *rnm =
			changelog_rec_rename(&rec->cr);

		if (!fid_is_zero(&rnm->cr_sfid))
			printf(" source_fid:"DFID" source_parent_fid:"DFID
			       " %.*s",
			       PFID(&rnm->cr_sfid),
			       PFID(&rnm->cr_spfid),
			       (int)__le32_to_cpu(
				       changelog_rec_snamelen(&rec->cr)),
			       changelog_rec_sname(&rec->cr));
	}
	printf("\n");
}

static void lustre_swab_lu_fid(struct lu_fid *fid)
{
	__swab64s(&fid->f_seq);
	__swab32s(&fid->f_oid);
	__swab32s(&fid->f_ver);
}

static inline size_t
update_op_size(unsigned int param_count)
{
	return offsetof(struct update_op, uop_params_off[param_count]);
}


static inline struct update_op *
update_op_next_op(const struct update_op *uop)
{
	return (struct update_op *)((char *)uop +
				update_op_size(uop->uop_param_count));
}

static void lustre_swab_update_ops(struct update_ops *uops,
				   unsigned int op_count)
{
	unsigned int i;
	unsigned int j;

	struct update_op *op =
	       (struct update_op *)((char *)&uops->uops_op[0]);

	for (i = 0; i < op_count; i++, op = update_op_next_op(op)) {
		lustre_swab_lu_fid(&op->uop_fid);
		__swab16s(&op->uop_type);
		__swab16s(&op->uop_param_count);
		for (j = 0; j < op->uop_param_count; j++)
			__swab16s(&op->uop_params_off[j]);
	}
}
static const char *update_op_str(__u16 opc)
{
	static const char *opc_str[] = {
		[OUT_START] = "start",
		[OUT_CREATE] = "create",
		[OUT_DESTROY] = "destroy",
		[OUT_REF_ADD] = "ref_add",
		[OUT_REF_DEL] = "ref_del",
		[OUT_ATTR_SET] = "attr_set",
		[OUT_ATTR_GET] = "attr_get",
		[OUT_XATTR_SET] = "xattr_set",
		[OUT_XATTR_GET] = "xattr_get",
		[OUT_XATTR_LIST] = "xattr_list",
		[OUT_INDEX_LOOKUP] = "lookup",
		[OUT_INDEX_INSERT] = "insert",
		[OUT_INDEX_DELETE] = "delete",
		[OUT_WRITE] = "write",
		[OUT_XATTR_DEL] = "xattr_del",
		[OUT_PUNCH] = "punch",
		[OUT_READ] = "read",
		[OUT_NOOP] = "noop",
	};

	if (opc < (sizeof(opc_str) / sizeof((opc_str)[0])) &&
	    opc_str[opc] != NULL)
		return opc_str[opc];
	else
		return "unknown";
}

char *buf2str(void *buf, unsigned int size)
{
	const char *hex = "0123456789ABCDEF";
	char *buf_c = buf;
	static char string[128];
	int i, j = 0;
	bool format_hex = false;

	if (size > 0 && buf_c[size - 1] == 0)
		size--;
	for (i = 0; i < size; i++) {
		if (buf_c[i] >= 0x20 && buf_c[i] <= 0x7E) {
			string[j++] = buf_c[i];
			format_hex = false;
		} else if (j < sizeof(string) - 6) {
			if (!format_hex) {
				string[j++] = '\\';
				string[j++] = 'x';
				format_hex = true;
			}
			string[j++] = hex[(buf_c[i] >> 4) & 0xF];
			string[j++] = hex[buf_c[i] & 0xF];
		} else {
			break;
		}
		if (j == sizeof(string) - 2)
			break;
	}
	string[j] = 0;
	return string;
}

void print_update_rec(struct llog_update_record *lur)
{
	struct update_records *rec = &lur->lur_update_rec;
	unsigned int i, j, up_count, pm_count;
	struct update_op *op;
	struct object_update_param *pm;

	up_count = __le32_to_cpu(rec->ur_update_count);
	pm_count = __le32_to_cpu(rec->ur_param_count);
	printf("updatelog record master_transno:%llu batchid:%llu flags:0x%x u_index:%d u_count:%d p_count:%d\n",
	       __le64_to_cpu(rec->ur_master_transno),
	       __le64_to_cpu(rec->ur_batchid),
	       __le32_to_cpu(rec->ur_flags),
	       __le32_to_cpu(rec->ur_index),
	       up_count,
	       pm_count);

	op = (struct update_op *)((char *)&rec->ur_ops.uops_op[0] + 0);
	if (op->uop_type != __le16_to_cpu(op->uop_type))
		lustre_swab_update_ops(&rec->ur_ops, up_count);

	for (i = 0; i < up_count; i++, op = update_op_next_op(op)) {
		printf("\t"DFID" type:%s/%d params:%d ",
		       PFID(&op->uop_fid), update_op_str(op->uop_type),
		       op->uop_type, op->uop_param_count);
		for (j = 0; j < op->uop_param_count; j++)
			printf("p_%d:%d ", j, op->uop_params_off[j]);
		printf("\n");
	}
	pm = (struct object_update_param *) op;
	for (i = 0; i < pm_count; i++) {
		printf("\tp_%d - %d/%s\n", i, pm->oup_len,
		       buf2str(pm->oup_buf, pm->oup_len));
		pm = (struct object_update_param *)((char *)(pm + 1) +
		     pm->oup_len);
	}
	printf("\n");

}

static void print_records(struct llog_rec_hdr **recs,
			  int rec_number, int is_ext)
{
	__u32 lopt;
	int i, skip = 0;

	for (i = 0; i < rec_number; i++) {
		if (!recs[i]) {
			llapi_printf(LLAPI_MSG_NORMAL,
				     "uninitialized llog record at index %d\n",
				     i);
			break;
		}
		printf("#%.2d (%.3d)", __le32_to_cpu(recs[i]->lrh_index),
		       __le32_to_cpu(recs[i]->lrh_len));

		lopt = __le32_to_cpu(recs[i]->lrh_type);

		if (recs[i]->lrh_id == CANCELLED)
			printf("NOT SET ");

		switch (lopt) {
		case OBD_CFG_REC:
			print_lustre_cfg(
				(struct lustre_cfg *)((char *)(recs[i]) +
				sizeof(struct llog_rec_hdr)), &skip);
			break;
		case LLOG_PAD_MAGIC:
			printf("padding\n");
			break;
		case LLOG_LOGID_MAGIC:
			print_log_path((struct llog_logid_rec *)recs[i],
				       is_ext);
			break;
		case HSM_AGENT_REC:
			print_hsm_action((struct llog_agent_req_rec *)recs[i]);
			break;
		case CHANGELOG_REC:
			print_changelog_rec((struct llog_changelog_rec *)
					    recs[i]);
			break;
		case CHANGELOG_USER_REC:
			printf("changelog_user record id:0x%x\n",
			       __le32_to_cpu(recs[i]->lrh_id));
			break;
		case UPDATE_REC:
			print_update_rec((struct llog_update_record *)recs[i]);
			break;
		default:
			printf("unknown type %x\n", lopt);
			break;
		}
	}
}

/** @} llog_reader */
