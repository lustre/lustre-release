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
 *
 * User-level tool to check iam files sanity.
 *
 * Author: Artem Blagodarenko <artem.blagodarenko@hpe.com>
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <endian.h>
#include <errno.h>

#include <sys/types.h>
#include <asm/byteorder.h>
#include <linux/lustre/lustre_user.h>
#include <linux/lustre/lustre_fid.h>
#include <linux/lustre/lustre_disk.h>
#include <linux/lnet/nidstr.h>
#include <lustre/libiam.h>

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(a) ((sizeof(a)) / (sizeof((a)[0])))
#endif /* !ARRAY_SIZE */

struct record_cb {
	int (*key)(const void *key, size_t size);
	int (*rec)(const void *rec, size_t size);
	int (*key_rec)(const void *key, size_t keys,
		       const void *rec, size_t recs);
};

struct record_type {
	char *type;
	char *filename;
	struct record_cb cb;
};

static int verbose;
static bool print_records;
static struct record_cb *print_cb;

static int hexdump(const void *buf, size_t size);
static int print_fid(const void *buf, size_t size);
static int print_oid(const void *buf, size_t size);
static int print_lfsck_namespace(const void *buf, size_t size);
static int print_dangling_rec_key(const void *buf, size_t size);
static int print_dangling_rec(const void *buf, size_t size);
static int print_nodemap_key(const void *buf, size_t size);
static int print_nodemap(const void *key, size_t keys,
			 const void *rec, size_t recs);

#define HEXDUMP_IDX 0
#define GUESS_START_IDX (HEXDUMP_IDX + 1)
static struct record_type record_type_array[] = {
	[HEXDUMP_IDX] {
		.type = "hexdump",
		.filename = NULL,
		.cb = {hexdump, hexdump},
	},
	{
		.type = "oi_map",
		.filename = "oi.",
		.cb = {print_fid, print_oid},
	},
	{
		.type = "lfsck_namespace",
		.filename = "lfsck_namespace_",
		.cb = {print_fid, print_lfsck_namespace},
	},
	{
		.type = "lfsck_dangling_rec",
		.filename = "lfsck_layout_",
		.cb = {print_dangling_rec_key, print_dangling_rec},
	},
	{
		.type = "nodemap",
		.filename = "nodemap",
		.cb = {print_nodemap_key, NULL, print_nodemap},
	},
	{ 0 }
};

static struct record_type *get_rec_type(const char *type)
{
	struct record_type *curr;

	for (curr = &record_type_array[0]; curr->type; curr++) {
		if (strcmp(type, curr->type) == 0)
			return curr;
	}

	fprintf(stderr, "Record type '%s' not found\n", type);

	return NULL;
}

static struct record_type *guess_rec_type(const char *filename)
{
	struct record_type *curr;
	struct record_type *start = &record_type_array[GUESS_START_IDX];

	for (curr = start; curr->type; curr++) {
		if (curr->filename && strstr(filename, curr->filename))
			return curr;
	}

	fprintf(stderr, "Failed to guess record type for '%s', fallback to hexdump\n",
		filename);

	return &record_type_array[HEXDUMP_IDX];
}

static void print_rec_types(void)
{
	struct record_type *curr;

	for (curr = &record_type_array[0]; curr->type; curr++)
		printf("%s%s", curr->type, curr[1].type ? ", " : "");
}

enum {
	ROOT_NODE,
	INDEX_NODE,
	LEAF_NODE,
	IDLE_NODE
};

struct node_info {
	int referenced;
	int recycled;
	int node_type;
};

static void usage(char *str)
{
	printf("Usage: %s [-hrv] [-t rec_type] iam_file\n", basename(str));
	fputs("\t-h: this help.\n"
	      "\t-r: print IAM keys and records.\n"
	      "\t-v: verbose mode to debug the file.\n"
	      "\t-t: type of record to print (", stdout);
	print_rec_types();
	puts(").\n"
	     "\t    If not specified, this will be guess with file name.");
}

struct iam_params {
	char *filename;
	int blocksize;
	int fmt;
	int keysize;
	int recsize;
	int ptrsize;
	int indirect_levels;
	int root_gap;
	int node_gap;
	unsigned long idle_blocks;
	unsigned long current_block;
	unsigned long long file_size;
	unsigned long blocks_count;
	struct node_info *node_info;
	int rc;
};

static int check_idle_blocks(char *buf, struct iam_params *params)
{
	struct iam_idle_head *idle;
	int i;

	idle = (struct iam_idle_head *)buf;

	if (idle->iih_magic != __cpu_to_le16(IAM_IDLE_HEADER_MAGIC)) {
		printf("Wrong magic 0x%x\n", idle->iih_magic);
		return -1;
	}

	if (verbose) {
		printf(", %i blocks, next table in block %i, idle blocks: ",
		       __le16_to_cpu(idle->iih_count),
		       __le32_to_cpu(idle->iih_next));
	}

	for (i = 0; i < __le32_to_cpu(idle->iih_count); i++) {
		unsigned int blk = __le32_to_cpu(idle->iih_blks[i]);

		if (verbose)
			printf("%i, ", blk);
		if (blk >= params->blocks_count) {
			printf("Pointer to the idle block (%i) outside the file\n",
			       blk);
			params->rc = -1;
		} else {
			if (params->node_info[blk].referenced && verbose)
				printf("Reference to recycled node (%i)\n",
				       blk);
			params->node_info[blk].recycled = 1;
		}
	}

	if (verbose)
		printf("\n");

	return 0;
}

static void print_record(int idx, void *entry, struct iam_params *params)
{
	void *key = entry;
	void *rec = entry + params->keysize;

	if (verbose)
		printf("%03d: ", idx);

	if (print_cb->key_rec) {
		if (print_cb->key_rec(key, params->keysize,
				      rec, params->recsize)) {
			fprintf(stderr, "Bad key or rec for idx %d\n", idx);
			params->rc = -1;
		}
		putchar('\n');

		return;
	}

	if (print_cb->key && print_cb->key(key, params->keysize)) {
		fprintf(stderr, "Bad key for idx %d\n", idx);
		params->rc = -1;
	}
	putchar('\t');
	if (print_cb->rec && print_cb->rec(rec, params->recsize)) {
		fprintf(stderr, "Bad record for idx %d\n", idx);
		params->rc = -1;
	}
	putchar('\n');
}

static int check_entries(unsigned char *entries, size_t size, int count,
			 struct iam_params *params, int block_type)
{
	unsigned int ptr;
	int i, rc;

	for (i = 0; i < count; i++) {
		rc = 0;
		size -= (params->keysize + params->ptrsize);

		if (size < 0) {
			if (verbose)
				printf("index outside of buffer\n");

			return -1;
		}

		if (block_type == INDEX_NODE) {

			if (verbose && print_cb->key) {
				printf("%03d: ", i);
				print_cb->key(entries, params->keysize);
			}

			entries += params->keysize;
			ptr = __le32_to_cpu(*((__le32 *)entries));

			if (ptr >= params->blocks_count) {
				params->rc = -1;
				rc = -1;
			}
			if (verbose)
				printf("\tptr: %u%s\n", ptr,
				       rc ? " wrong" : "");

			entries += params->ptrsize;

			if (rc)
				continue;

			if (params->node_info[ptr].recycled && verbose) {
				printf("Reference to recycled node (%u) from node %lu\n",
					ptr, params->current_block);
			}
			params->node_info[ptr].referenced = 1;
		} else if (block_type == LEAF_NODE) {
			if (print_records)
				print_record(i, entries, params);

			entries += params->keysize + params->recsize;
		}

	}

	return 0;
}

static int check_leaf(char *buf, struct iam_params *params)
{
	struct iam_leaf_head *leaf;
	int counted_limit;
	int leaf_count;

	leaf = (struct iam_leaf_head *)buf;

	params->node_info[params->current_block].node_type = LEAF_NODE;

	counted_limit = node_limit(sizeof(struct iam_leaf_head),
				   params->blocksize,
				   params->keysize + params->recsize);
	leaf_count = __le16_to_cpu(leaf->ill_count);

	if (verbose)
		printf("Leaf block, count %i, limit %i\n", leaf_count,
		       counted_limit);

	if (leaf_count > counted_limit) {
		printf("More elements (%i) then limit (%i)\n", leaf_count,
			counted_limit);
		return -1;
	}

	if (check_entries((unsigned char *)(buf + sizeof(struct iam_leaf_head)),
			  params->blocksize - sizeof(struct iam_leaf_head),
			  counted_limit < leaf_count ?
			  counted_limit : leaf_count, params, LEAF_NODE)) {
		printf("Broken entries\n");
		return -1;
	}

	return 0;
}

static int check_index(char *buf, struct iam_params *params)
{
	struct iam_index_head *index;
	int counted_limit;
	struct dx_countlimit *limit;
	int limit_count;

	index = (struct iam_index_head *)buf;
	limit = &index->limit;

	params->node_info[params->current_block].node_type = INDEX_NODE;

	limit_count = __le16_to_cpu(limit->count);
	if (verbose)
		printf("Index block, count %i, limit %i\n", limit_count,
		       __le16_to_cpu(limit->limit));

	counted_limit = node_limit(params->node_gap, params->blocksize,
				   params->keysize + params->ptrsize);

	if (__le16_to_cpu(limit->limit) != counted_limit) {
		fprintf(stderr, "Wrong limit %i, counted limit %i\n",
			__le16_to_cpu(limit->limit), counted_limit);
		return -1;
	}


	if (limit_count > __le16_to_cpu(limit->limit)) {
		printf("More elements (%i) then limit (%i)\n", limit_count,
			__le16_to_cpu(limit->limit));
		return -1;
	}

	 /* count - 1, because limit is entry itself */
	if (check_entries(index->entries,
			  params->blocksize - offsetof(struct iam_index_head,
						       entries),
			  limit_count - 1, params, INDEX_NODE)) {
		printf("Broken entries\n");
		return -1;
	}

	return 0;
}

static int check_root(void *buf, size_t size, struct iam_params *params)
{
	__le64 *magic = buf;
	unsigned int counted_limit;
	int min;
	struct dx_countlimit *limit;
	__u32 *idle_blocks;
	int root_entry_size;
	int entries_off;

	if (verbose)
		printf("Root format: ");

	switch (__le64_to_cpu(*magic)) {
	case IAM_LFIX_ROOT_MAGIC: {
		struct iam_lfix_root *root = buf;

		params->fmt = FMT_LFIX;
		params->keysize = __le16_to_cpu(root->ilr_keysize);
		params->recsize = __le16_to_cpu(root->ilr_recsize);
		params->ptrsize = __le16_to_cpu(root->ilr_ptrsize);
		params->indirect_levels = root->ilr_indirect_levels;
		params->root_gap = sizeof(*root);
		if (verbose)
			puts("LFIX");
		break;
	}
	case IAM_LVAR_ROOT_MAGIC: {
		struct lvar_root *root = buf;

		params->fmt = FMT_LVAR;
		params->keysize = sizeof(lvar_hash_t);
		params->recsize = __le16_to_cpu(root->vr_recsize);
		params->ptrsize = __le16_to_cpu(root->vr_ptrsize);
		params->indirect_levels = root->vr_indirect_levels;
		params->root_gap = sizeof(*root);
		if (verbose)
			puts("LVAR");
		break;
	}
	default:
		fprintf(stderr, "Bad magic %llu\n", __le64_to_cpu(*magic));
		return -1;
	}

	limit = buf + params->root_gap;
	idle_blocks = buf + params->root_gap + sizeof(*limit);
	params->idle_blocks = __le32_to_cpu(*idle_blocks);

	params->node_info[0].referenced = 1; //self referance
	params->node_info[0].node_type = ROOT_NODE;

	if (params->idle_blocks >= params->blocks_count) {
		printf("Idle blocks number (%lu) is out of blocks range (%lu)\n",
			params->idle_blocks, params->blocks_count);
		params->rc = -1;
	} else {
		params->node_info[params->idle_blocks].referenced = 1;
		params->node_info[params->idle_blocks].node_type = IDLE_NODE;
	}

	if (verbose) {
		printf("\tkeysize: %i\n"
		       "\trecsize: %i\n"
		       "\tptrsize: %i\n"
		       "\tindirect_levels: %i\n"
		       "\tidle_blocks: %lu\n",
		       params->keysize, params->recsize, params->ptrsize,
		       params->indirect_levels, params->idle_blocks);
	}

	if (params->ptrsize != 4 && params->ptrsize != 8) {
		printf("Invalid ptrsize (%i). Only 4 and 8 are supported\n",
		       params->ptrsize);
		return -1;
	}

	if (params->keysize < 1 || params->recsize < 0) {
		printf("Too small key(%i) or recorod(%i)\n",
			params->keysize, params->recsize);
		return -1;
	}

	if ((params->keysize + params->recsize +
	    (int)sizeof(struct iam_leaf_head)) > (params->blocksize / 3)) {
		printf("Too large record + key or too small block, %i, %i\n",
			(params->keysize + params->recsize +
			 (int)sizeof(struct iam_leaf_head)),
			params->blocksize);
		return -1;
	}

	root_entry_size = params->keysize + params->ptrsize;
	counted_limit = root_limit(params->root_gap, params->node_gap,
				   params->blocksize, root_entry_size);


	if (__le16_to_cpu(limit->limit) != counted_limit) {
		fprintf(stderr, "Wrong limit %i, counted limit %i\n",
			__le16_to_cpu(limit->limit), counted_limit);
		params->rc = -1;
	}

	min = (counted_limit < __le16_to_cpu(limit->limit)) ?
			counted_limit : __le16_to_cpu(limit->limit);

	if (__le16_to_cpu(limit->count) > __le16_to_cpu(limit->limit)) {
		printf("More elements (%i) then limit (%i)\n",
			__le16_to_cpu(limit->count),
			__le16_to_cpu(limit->limit));
		params->rc = -1;
	}

	min = (__le16_to_cpu(limit->count) < min) ?
			__le16_to_cpu(limit->count) : min;

	if (verbose)
		printf("Root entries: count %i, limit %i\n",
			__le16_to_cpu(limit->count),
			__le16_to_cpu(limit->limit));

	/* count - 1, because limit is entry itself */
	entries_off = params->root_gap + root_entry_size;
	if (check_entries(buf + entries_off, size - entries_off,
			  min - 1, params, INDEX_NODE)) {
		printf("Broken entries\n");
		return -1;
	}

	return 0;
}

static int check_block(char *buf, struct iam_params *params)
{
	struct iam_leaf_head *head;

	head = (struct iam_leaf_head *)buf;

	if (verbose)
		printf("Block %lu,", params->current_block);

	switch (head->ill_magic) {
	case __cpu_to_le16(IAM_LEAF_HEADER_MAGIC):
			if (verbose)
				printf("FIX leaf, ");
			if (check_leaf(buf, params)) {
				printf("Broken leaf block\n");
				params->rc = -1;
			}
			break;
	case __cpu_to_le16(IAM_LVAR_ROOT_MAGIC):
			if (verbose)
				printf("LVAR leaf,");
			break;
	case __cpu_to_le16(IAM_IDLE_HEADER_MAGIC):
			if (verbose)
				printf("IDLE block");

			params->node_info[params->current_block].referenced = 1;

			if (check_idle_blocks(buf, params)) {
				printf("Broken idle blocks\n");
				params->rc = -1;
			}
			break;
	default:
			if (check_index(buf, params)) {
				printf("Broken index node\n");
				params->rc = -1;
			}
			break;
	}
	if (verbose)
		printf("count %i\n", head->ill_count);

	return 0;
}

static void print_node_type(int type)
{
	switch (type) {
	case ROOT_NODE:
			printf("ROOT\n");
			break;
	case INDEX_NODE:
			printf("INDEX\n");
			break;
	case LEAF_NODE:
			printf("LEAF\n");
			break;
	case IDLE_NODE:
			printf("IDLE\n");
			break;
	default:
			printf("UNKNOWN %i\n", type);
			break;
	}
}

static int check_unconnected(struct iam_params *params)
{
	unsigned long i;
	int rc = 0;

	for (i = 0; i < params->blocks_count; i++) {
		if (params->node_info[i].referenced &&
		    params->node_info[i].recycled) {
			printf("Node %lu referenced and recycled. FAIL, ", i);
			print_node_type(params->node_info[i].node_type);
		}

		if (!params->node_info[i].referenced &&
		    !params->node_info[i].recycled) {
			printf("Unconnected node %lu. FAIL, ", i);
			print_node_type(params->node_info[i].node_type);
			rc = -1;
		}
	}
	return rc;
}


/*
 * print callbacks
 */

static int hexdump(const void *buf, size_t size)
{
	const __u8 *ptr = buf;
	int i;

	printf("0x");
	for (i = 0; i < size; i++)
		printf("%02x", ptr[i]);

	return 0;
}

static int print_fid(const void *buf, size_t size)
{
	struct lu_fid fid;

	if (size < sizeof(fid)) {
		putchar('-');
		return -1;
	}

	fid_be_to_cpu(&fid, buf);
	printf(DFID, PFID(&fid));

	return 0;
}

static int print_oid(const void *buf, size_t size)
{
	const struct osd_inode_id *oid = buf;

	if (size < sizeof(*oid)) {
		putchar('-');
		return -1;
	}

	printf("%u/%u", __be32_to_cpu(oid->oii_ino),
	       __be32_to_cpu(oid->oii_gen));

	return 0;
}

static int print_lfsck_namespace(const void *buf, size_t size)
{
	static const char * const fl2str[] = {
		"CHECK_LINKEA",		/* LNTF_CHECK_LINKEA */
		"CHECK_ORPHAN",		/* LNTF_CHECK_PARENT */
		"CHECK_ORPHAN",		/* LNTF_CHECK_ORPHAN */
		"UNCERTAIN_LMV",	/* LNTF_UNCERTAIN_LMV */
		"RECHECK_NAME_HASH",	/* LNTF_RECHECK_NAME_HASH */
		"CHECK_AGENT_ENTRY",	/* LNTF_CHECK_AGENT_ENTRY */
	};
	const __u8 *flags = buf;
	bool first = true;
	int i;

	if (size < sizeof(*flags)) {
		putchar('-');
		return -1;
	}

	printf("0x%x (", *flags);
	if (!*flags) {
		putchar(')');
		return 0;
	}

	for (i = 0; i < ARRAY_SIZE(fl2str); i++) {
		if (*flags & (1<<i)) {
			printf("%s%s", first ? "" : "|", fl2str[i]);
			first = false;
		}
	}

	putchar(')');

	return 0;
}

struct lfsck_layout_dangling_key {
	struct lu_fid	lldk_fid;
	__u32		lldk_comp_id;
	__u32		lldk_ea_off;
};

static inline void lldk_be_to_cpu(struct lfsck_layout_dangling_key *des,
				  const struct lfsck_layout_dangling_key *src)
{
	fid_be_to_cpu(&des->lldk_fid, &src->lldk_fid);
	des->lldk_comp_id = __be32_to_cpu(src->lldk_comp_id);
	des->lldk_ea_off = __be32_to_cpu(src->lldk_ea_off);
}

static int print_dangling_rec_key(const void *buf, size_t size)
{
	const struct lfsck_layout_dangling_key *src = buf;
	struct lfsck_layout_dangling_key key;

	if (size < sizeof(key)) {
		putchar('-');
		return -1;
	}

	lldk_be_to_cpu(&key, src);
	printf("{ parent: "DFID", comp_id: %u, ea_off: %u }",
	       PFID(&key.lldk_fid), key.lldk_comp_id, key.lldk_ea_off);

	return 0;
}

static int print_dangling_rec(const void *buf, size_t size)
{
	struct lu_fid fid;
	__u32 idx;

	if (size < sizeof(fid)) {
		putchar('-');
		return -1;
	}

	fid_be_to_cpu(&fid, buf);
	idx = fid.f_ver;
	fid.f_ver = 0x0;
	printf("{ cfid: "DFID", ost_idx: %d }", PFID(&fid), idx);

	return 0;
}

static inline enum nodemap_idx_type nm_idx_get_type(unsigned int id)
{
	return id >> NM_TYPE_SHIFT;
}

static enum nodemap_idx_type nodemap_get_key_type(const struct nodemap_key *key)
{
	__u32 nodemap_id;

	nodemap_id = __le32_to_cpu(key->nk_nodemap_id);
	return nm_idx_get_type(nodemap_id);
}

static int nodemap_get_key_subtype(const struct nodemap_key *key)
{
	enum nodemap_idx_type type = nodemap_get_key_type(key);

	return type == NODEMAP_CLUSTER_IDX ? key->nk_cluster_subid : -1;
}

static const char *nodemap_type2str(int type)
{
	static const char * const type2str[] = {
		[NODEMAP_EMPTY_IDX]	= "empty",
		[NODEMAP_CLUSTER_IDX]	= "cluster",
		[NODEMAP_RANGE_IDX]	= "range",
		[NODEMAP_UIDMAP_IDX]	= "uidmap",
		[NODEMAP_GIDMAP_IDX]	= "gidmap",
		[NODEMAP_PROJIDMAP_IDX]	= "projidmap",
		[NODEMAP_NID_MASK_IDX]	= "nid_mask",
		[NODEMAP_GLOBAL_IDX]	= "global",
	};

	if (type >= ARRAY_SIZE(type2str) || !type2str[type])
		return "unknown";

	return type2str[type];
}

static int print_nodemap_key(const void *buf, size_t size)
{
	const struct nodemap_key *nk = buf;
	int type;

	if (size < sizeof(*nk))
		return -1;

	type = nodemap_get_key_type(nk);
	printf("{ id: 0x%x, type: %s(%d) }",
	       __le32_to_cpu(nk->nk_nodemap_id) & NM_TYPE_MASK,
	       nodemap_type2str(type), type);

	return 0;
}

static int print_nodemap(const void *key, size_t keys,
			 const void *rec, size_t recs)
{
	const struct nodemap_key *nk = key;
	const union nodemap_rec *nr = rec;
	int type;

	if (keys < sizeof(*nk) || recs < sizeof(*nr))
		return -1;

	type = nodemap_get_key_type(nk);
	printf("{ id: 0x%x, type: %s(%d)",
	       __le32_to_cpu(nk->nk_nodemap_id) & NM_TYPE_MASK,
	       nodemap_type2str(type), type);

	switch (type) {
	case NODEMAP_EMPTY_IDX:
		fputs(" }\t{}", stdout);
		if (nk->nk_nodemap_id)
			return -1;
		break;
	case NODEMAP_CLUSTER_IDX:
		fputs(", subtype: ", stdout);

		switch (nodemap_get_key_subtype(nk)) {
		case NODEMAP_CLUSTER_REC:
			printf("cluster }\t{ name: %s, flag: 0x%hhx, flag2: 0x%hhx, squash_uid: %u, squash_gid: %u, squash_projid: %u}",
			       nr->ncr.ncr_name,
			       nr->ncr.ncr_flags, nr->ncr.ncr_flags2,
			       __le32_to_cpu(nr->ncr.ncr_squash_uid),
			       __le32_to_cpu(nr->ncr.ncr_squash_gid),
			       __le32_to_cpu(nr->ncr.ncr_squash_projid));
			break;
		case NODEMAP_CLUSTER_ROLES:
			printf("roles }\t{ roles: 0x%llx}",
			       __le64_to_cpu(nr->ncrr.ncrr_roles));
			break;
		default:
			printf("unknown(%d) }\t{}",
				nodemap_get_key_subtype(nk));
			break;
		}
		break;
	case NODEMAP_RANGE_IDX:
		printf(" }\t{ start_nid: %s, end_nid: %s }",
		       libcfs_nid2str(__le64_to_cpu(nr->nrr.nrr_start_nid)),
		       libcfs_nid2str(__le64_to_cpu(nr->nrr.nrr_end_nid)));
		break;
	case NODEMAP_NID_MASK_IDX:
		printf(" }\t{ subnet: %s/%hhd }",
		       libcfs_nidstr(&nr->nrr2.nrr_nid_prefix),
		       nr->nrr2.nrr_netmask);
		break;
	case NODEMAP_UIDMAP_IDX:
	case NODEMAP_GIDMAP_IDX:
	case NODEMAP_PROJIDMAP_IDX:
		printf(", id_client: %u }\t{ id_fs: %u }",
		       __le32_to_cpu(nk->nk_id_client),
		       __le32_to_cpu(nr->nir.nir_id_fs));
		break;
	case NODEMAP_GLOBAL_IDX:
		printf(" }\t{ is_active: %hhu }",
		       nr->ngr.ngr_is_active);

		if (nk->nk_unused)
			return -1;
		break;
	default:
		fputs(" }\t{}", stdout);
		break;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct iam_params params;
	int rc = 0;
	int opt;
	void *buf;
	int fd;
	struct stat sb;
	struct record_type *rec_type = NULL;

	params.rc = 0;
	print_records = false;
	do {
		opt = getopt(argc, argv, "hvrt:");
		switch (opt) {
		case 'v':
				verbose++;
				break;
		case 't':
				rec_type = get_rec_type(optarg);
		case 'r':
				print_records = true;
		case -1:
				break;
		default:
				fprintf(stderr, "Unable to parse options.");
		case 'h':
				usage(argv[0]);
				return 0;
		}
	} while (opt != -1);

	if (optind >= argc) {
		fprintf(stderr, "Expected filename after options\n");
		return -1;
	}

	if (!rec_type)
		rec_type = guess_rec_type(argv[optind]);

	print_cb = &rec_type->cb;
	if (verbose && print_records)
		printf("Record type to print: %s\n", rec_type->type);

	params.filename = argv[optind];
	params.blocksize = 4096;
	params.current_block = 0;
	params.node_gap = 0;

	fd = open(params.filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Can not open file %s, %s\n",
			params.filename, strerror(errno));
		return -1;
	}

	if (fstat(fd, &sb) == -1) {
		fprintf(stderr, "Error stat file.\n");
		close(fd);
		return -1;
	}
	params.file_size = (unsigned long long)sb.st_size;
	params.blocks_count = params.file_size / params.blocksize +
				((params.file_size % params.blocksize) ? 1 : 0);

	if (verbose)
		printf("Filesize %llu, blocks count %lu\n", params.file_size,
		       params.blocks_count);
	buf = malloc(params.blocksize);
	if (buf == NULL) {
		fprintf(stderr, "Can't allocate buffer\n");
		close(fd);
		return -1;
	}
	params.node_info = malloc(params.blocks_count *
				  sizeof(struct node_info));
	memset(params.node_info, 0,
	       params.blocks_count * sizeof(struct node_info));

	/* Read root block */
	if (read(fd, buf, params.blocksize) < params.blocksize) {
		fprintf(stderr, "Can't read root block\n");
		params.rc = -1;
		goto err;
	}

	rc = check_root(buf, params.blocksize, &params);
	if (rc) {
		printf("Root node is insane\n");
		goto err;
	}

	params.current_block++;

	/* Read all another blocks */
	while (read(fd, buf, params.blocksize)) {
		rc = check_block(buf, &params);
		if (rc) {
			printf("Node with offset 0x%lx in %s is broken\n",
				params.current_block * params.blocksize,
				params.filename);
			params.rc = rc;
		}
		params.current_block++;
	}

	rc = check_unconnected(&params);
	if (rc)
		printf("There are unconnected nodes\n");
err:
	if (!(rc ? rc : params.rc))
		printf("NO ERRORS\n");
	else
		printf("FINISHED WITH ERRORS\n");

	free(params.node_info);
	free(buf);
	close(fd);

	return rc ?: params.rc;
}
