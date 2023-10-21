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
#include <linux/lustre/lustre_user.h>
#include <linux/lustre/lustre_fid.h>
#include <asm/byteorder.h>
#include <lustre/libiam.h>

static int verbose;
static bool print_records;

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

void usage(char *str)
{
	printf("Usage: %s [-hrv] iam_file\n", str);
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

int check_idle_blocks(char *buf, struct iam_params *params)
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

static int check_entries(unsigned char *entries, size_t size, int count,
			 struct iam_params *params, int block_type)
{
	unsigned int ptr;
	int i, j, rc;

	for (i = 0; i < count; i++) {
		rc = 0;
		size -= (params->keysize + params->ptrsize);

		if (size < 0) {
			if (verbose)
				printf("index outside of buffer\n");

			return -1;
		}

		if (block_type == INDEX_NODE) {

			if (verbose)
				printf("key:");

			for (j = 0; j < params->keysize; j++, entries++)
				if (verbose)
					printf("%02x", *entries);

			ptr = __le32_to_cpu(*((__le32 *)entries));

			if (ptr >= params->blocks_count) {
				params->rc = -1;
				rc = -1;
			}
			if (verbose)
				printf(", ptr: %u%s\n", ptr,
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
			struct lu_fid fid;
			struct osd_inode_id *inode;

			fid_be_to_cpu(&fid, (struct lu_fid *)entries);
			inode = (struct osd_inode_id *)(entries + sizeof(fid));
			entries += params->keysize + params->recsize;

			if (print_records)
				printf(DFID" %u/%u\n", PFID(&fid),
				       __be32_to_cpu(inode->oii_ino),
				       __be32_to_cpu(inode->oii_gen));
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

static int check_root(char *buf, size_t size, struct iam_params *params)
{
	struct iam_lfix_root *root;
	unsigned int counted_limit;
	int min;
	struct dx_countlimit *limit;

	if (verbose)
		printf("Root format ");

	root = (struct iam_lfix_root *)buf;
	if (root->ilr_magic == __cpu_to_le64(IAM_LFIX_ROOT_MAGIC)) {
		params->fmt = FMT_LFIX;
		if (verbose)
			printf("LFIX,");
	} else if (root->ilr_magic == __cpu_to_le64(IAM_LVAR_ROOT_MAGIC)) {
		params->fmt = FMT_LVAR;
		if (verbose)
			printf("LVAR,");
	} else {
		printf("Bad magic %llu\n", __le64_to_cpu(root->ilr_magic));
		params->rc = -1;
	}

	limit = &root->limit;

	params->keysize = __le16_to_cpu(root->ilr_keysize);
	params->recsize = __le16_to_cpu(root->ilr_recsize);
	params->ptrsize = __le16_to_cpu(root->ilr_ptrsize);
	params->indirect_levels = root->ilr_indirect_levels;

	params->node_info[0].referenced = 1; //self referance
	params->node_info[0].node_type = ROOT_NODE;

	params->idle_blocks = __le32_to_cpu(root->idle_blocks);
	if (params->idle_blocks >= params->blocks_count) {
		printf("Idle blocks number (%lu) is out of blocks range (%lu)\n",
			params->idle_blocks, params->blocks_count);
		params->rc = -1;
	} else {
		params->node_info[params->idle_blocks].referenced = 1;
		params->node_info[params->idle_blocks].node_type = IDLE_NODE;
	}

	if (verbose) {
		printf("Idle blocks block number %lu\n", params->idle_blocks);
		printf("keysize %i, recsize %i, ptrsize %i, indirect_levels %i\n",
		       params->keysize, params->recsize, params->ptrsize,
		       params->indirect_levels);
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

	counted_limit = root_limit(params->root_gap, params->node_gap,
				   params->blocksize,
				   params->keysize + params->ptrsize);


	if (__le16_to_cpu(limit->limit) != counted_limit) {
		fprintf(stderr, "Wrong limit %i, counted limit %i\n",
			__le16_to_cpu(limit->limit), counted_limit);
		params->rc = -1;
	}

	min = (counted_limit < __le16_to_cpu(limit->limit)) ?
			counted_limit : __le16_to_cpu(limit->limit);

	if (__le16_to_cpu(limit->count) > __le16_to_cpu(limit->limit)) {
		printf("More elements (%i) then limit (%i)\n",
			__le16_to_cpu(root->limit.count),
			__le16_to_cpu(root->limit.limit));
		params->rc = -1;
	}

	min = (__le16_to_cpu(limit->count) < min) ?
			__le16_to_cpu(limit->count) : min;


	if (verbose)
		printf("count %i, limit %i\n",
			__le16_to_cpu(root->limit.count),
			__le16_to_cpu(root->limit.limit));

	/* cound - 1, because limit is entry itself */
	if (check_entries(root->entries,
			  size - offsetof(struct iam_lfix_root, entries),
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
				printf("FIX leaf,");
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
int main(int argc, char **argv)
{
	struct iam_params params;
	int rc = 0;
	int opt;
	void *buf;
	int fd;
	struct stat sb;

	params.rc = 0;
	print_records = false;
	do {
		opt = getopt(argc, argv, "hvr");
		switch (opt) {
		case 'v':
				verbose++;
				break;
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

	params.filename = argv[optind];
	params.blocksize = 4096;
	params.current_block = 0;
	params.root_gap = sizeof(struct iam_lfix_root);
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
