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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/tests/it_test.c
 *
 * Unit test tool for interval tree.
 *
 * Author: jay <jxiong@clusterfs.com>
 */
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <libcfs/util/list.h>

#include <linux/types.h>

/*
 * it_test.c is built against one of the lustre kernel
 * files (interval_tree.c). This pulls in kernel specific
 * definitions which are not of interest for user land.
 */
#define EXPORT_SYMBOL(s)
#define LASSERT assert

#include <../ldlm/interval_tree.c>

#define dprintf(fmt, args...) //printf(fmt, ##args)
#define error(fmt, args...) do {                        \
        fflush(stdout), fflush(stderr);                 \
        fprintf(stderr, "\nError:" fmt, ##args);        \
        abort();                                        \
} while(0)

#define ALIGN_SIZE       4096
#define ALIGN_MASK       (~(ALIGN_SIZE - 1))

static struct it_node {
        struct interval_node node;
	struct list_head list;
        int hit, valid;
} *it_array;
static int it_count;
static struct list_head header = LIST_HEAD_INIT(header);
static unsigned long max_count = ULONG_MAX & ALIGN_MASK;
static int have_wide_lock = 0;

static void it_test_clear(void)
{
        int i = 0;
        for (i = 0; i < it_count; i++)
                it_array[i].hit = 0;
}

static enum interval_iter cb(struct interval_node *n, void *args)
{
        struct it_node *node = (struct it_node *)n;
        static int count = 1;

        if (node->hit == 1) {
		error("A duplicate node [%#jx:%#jx] access found\n",
		      (uintmax_t)n->in_extent.start,
		      (uintmax_t)n->in_extent.end);
                return INTERVAL_ITER_CONT;
        }

        if (node->valid == 0) {
		error("A deleted node [%#jx:%#jx] being accessed\n",
		      (uintmax_t)n->in_extent.start,
		      (uintmax_t)n->in_extent.end);
                return INTERVAL_ITER_STOP;
        }

        if (count++ == 8) {
                dprintf("\n");
                count = 1;
        }
	dprintf("[%#jx:%#jx] ", (uintmax_t)n->in_extent.start,
		(uintmax_t)n->in_extent.end);
        fflush(stdout);

        node->hit = 1;
        return INTERVAL_ITER_CONT;
}

static int it_test_search(struct interval_node *root)
{
        struct it_node *n;
        struct interval_node_extent ext;
        int times = 10, i, err = 0;

        while (times--) {
                it_test_clear();
                ext.start = (random() % max_count) & ALIGN_MASK;
                ext.end = random() % (max_count - ext.start + 2) + ext.start;
                ext.end &= ALIGN_MASK;
                if (ext.end > max_count)
                        ext.end = max_count;

		dprintf("\n\nSearching the node overlapped [%#jx:%#jx] ..\n",
			(uintmax_t)ext.start, (uintmax_t)ext.end);

                interval_search(root, &ext, cb, NULL);

                dprintf("\nverifing ...");

                /* verify */
                for (i = 0; i < it_count; i++) {
                        n = &it_array[i];
                        if (n->valid == 0)
                                continue;

                        if (extent_overlapped(&ext, &n->node.in_extent) &&
                            n->hit == 0)
				error("node [%#jx:%#jx] overlaps [%#jx:%#jx],"
                                      "but never to be hit.\n",
				      (uintmax_t)n->node.in_extent.start,
				      (uintmax_t)n->node.in_extent.end,
				      (uintmax_t)ext.start, (uintmax_t)ext.end);

                        if (!extent_overlapped(&ext, &n->node.in_extent) &&
                            n->hit)
				error("node [%#jx:%#jx] overlaps [%#jx:%#jx], but hit.\n",
				      (uintmax_t)n->node.in_extent.start,
				      (uintmax_t)n->node.in_extent.end,
				      (uintmax_t)ext.start, (uintmax_t)ext.end);
                }
                if (err) error("search error\n");
                dprintf("ok.\n");
        }

        return 0;
}

static int it_test_iterate(struct interval_node *root)
{
        int i;

        dprintf("\n\nIterate testing start..\n");

        it_test_clear();
        interval_iterate(root, cb, NULL);

        /* verify */
        for (i = 0; i < it_count; i++) {
                if (it_array[i].valid == 0)
                        continue;
		if (it_array[i].hit == 0) {
			error("Node [%#jx:%#jx] is not accessed\n",
			      (uintmax_t)it_array[i].node.in_extent.start,
			      (uintmax_t)it_array[i].node.in_extent.end);
		}
	}
        return 0;
}

static int it_test_iterate_reverse(struct interval_node *root)
{
        int i;

        dprintf("\n\niterate reverse testing start..\n");
        it_test_clear();
        interval_iterate_reverse(root, cb, NULL);

        /* verify */
        for (i = 0; i < it_count; i++) {
                if (it_array[i].valid == 0)
                        continue;
                if (it_array[i].hit == 0)
                        error("Not every extent is accessed\n");
        }

        return 0;
}

static int it_test_find(struct interval_node *root)
{
        int idx;
        struct interval_node_extent *ext;

        dprintf("\ninterval_find testing start ..\n");
        for (idx = 0; idx < it_count; idx++) {
                if (it_array[idx].valid == 0)
                        continue;

                ext = &it_array[idx].node.in_extent;
		dprintf("Try to find [%#jx:%#jx]\n", (uintmax_t)ext->start,
			(uintmax_t)ext->end);
		if (!interval_find(root, ext)) {
			error("interval_find, try to find [%#jx:%#jx]\n",
			      (uintmax_t)ext->start, (uintmax_t)ext->end);
		}
	}
	return 0;
}

/* sanity test is tightly coupled with implementation, so when you changed
 * the interval tree implementation, change this code also. */
static enum interval_iter sanity_cb(struct interval_node *node, void *args)
{
        __u64 max_high = node->in_max_high;
        struct interval_node *tmp, *parent;
        int left = 1, has = 0, nr = 0;

        parent = node->in_parent;
        node->in_parent = NULL;
        interval_for_each(tmp, node) {
                if ((left && node_compare(tmp, node) > 0) ||
                    (!left && node_compare(tmp, node) < 0))
                        error("interval tree sanity test\n");

                if (tmp->in_max_high > max_high) {
                        dprintf("max high sanity check, max_high is %llu,"
				"child max_high: %llu[%#jx:%#jx]\n",
                                max_high, tmp->in_max_high,
                                __F(&tmp->in_extent));
                        goto err;
                } else if (tmp->in_max_high == max_high) {
                        has = 1;
                }

                if (tmp == node) {
                        left = 0;
                        continue;
                }
        }

        if (!has) {
                int count;
err:
                count = 1;
		dprintf("node[%#jx:%#jx]:%llu Child list:\n",
                        node->in_extent.start,
                        node->in_extent.end,
                        node->in_max_high);

                interval_for_each(tmp, node) {
			dprintf("[%#jx:%#jx]:%llu ",
                                __F(&tmp->in_extent),
                                tmp->in_max_high);
                        if (count++ == 8) {
                                dprintf("\n");
                                count = 1;
                        }
                }

                error("max high sanity check, has == %d\n", has);
        }
        node->in_parent = parent;

        tmp = node;
        while (tmp) {
                if (node_is_black(tmp))
                        nr++;
                else if ((tmp->in_left && node_is_red(tmp->in_left)) ||
                         (tmp->in_right && node_is_red(tmp->in_right)))
                        error("wrong tree, a red node has red child\n");
                tmp = tmp->in_left;
        }

        tmp = node;
        while (tmp) {
                if (node_is_black(tmp))
                        nr--;
                tmp = tmp->in_right;
        }
        if (nr)
                error("wrong tree, unbalanced!\n");

        return 0;
}

static int it_test_sanity(struct interval_node *root)
{
        it_test_clear();
        interval_iterate(root, sanity_cb, NULL);
        return 0;
}

static int it_test_search_hole(struct interval_node *root)
{
        int i, count = 10;
        struct interval_node_extent ext, ext2;
        struct it_node *n;
        __u64 low = 0, high = ~0;

        do {
                if (--count == 0)
                        return 0;

                ext.start = random() % max_count;
                ext.end = ext.start;
        } while (interval_is_overlapped(root, &ext));
        ext2 = ext;

        interval_expand(root, &ext, NULL);
	dprintf("Extending [%#jx:%#jx] to ..[%#jx:%#jx]\n",
		(uintmax_t)ext2.start, (uintmax_t)ext2.end,
		(uintmax_t)ext.start, (uintmax_t)ext.end);
        for (i = 0; i < it_count; i++) {
                n = &it_array[i];
                if (n->valid == 0)
                        continue;

                if (extent_overlapped(&ext, &n->node.in_extent)) {
			error("Extending [%#jx:%#jx] to ..[%#jx:%#jx] overlaps node[%#jx:%#jx]\n",
			      (uintmax_t)ext2.start, (uintmax_t)ext2.end,
			      (uintmax_t)ext.start, (uintmax_t)ext.end,
			      (uintmax_t)n->node.in_extent.start,
			      (uintmax_t)n->node.in_extent.end);
                }

                if (n->node.in_extent.end < ext2.start)
                        low = max_u64(n->node.in_extent.end + 1, low);

                if (n->node.in_extent.start > ext2.end)
                        high = min_u64(n->node.in_extent.start - 1, high);
        }

        /* only expanding high right now */
        if (ext2.start != ext.start || high != ext.end) {
                ext2.start = low, ext2.end = high;
		error("Real extending result:[%#jx:%#jx], expected:[%#jx:%#jx]\n",
		      (uintmax_t)ext.start, (uintmax_t)ext.end,
		      (uintmax_t)ext2.start, (uintmax_t)ext2.end);
        }

        return 0;
}

static int contended_count = 0;
#define LOOP_COUNT 1000
static enum interval_iter perf_cb(struct interval_node *n, void *args)
{
        unsigned long count = LOOP_COUNT;
        while (count--);
        contended_count++;
        return INTERVAL_ITER_CONT;
}

static inline long tv_delta(struct timeval *s, struct timeval *e)
{
        long c = e->tv_sec - s->tv_sec;
        c *= 1000;
        c += (long int)(e->tv_usec - s->tv_usec) / 1000;
        dprintf("\tStart: %lu:%lu -> End: %lu:%lu\n",
                s->tv_sec, s->tv_usec, e->tv_sec, e->tv_usec);
        return c;
}

static int it_test_performance(struct interval_node *root, unsigned long len)
{
        int i = 0, interval_time, list_time;
        struct interval_node_extent ext;
        struct it_node *n;
        struct timeval start, end;
        unsigned long count;

        ext.start = (random() % (max_count - len)) & ALIGN_MASK;
        ext.end = (ext.start + len) & ALIGN_MASK;
        if (have_wide_lock) {
                ext.start = (max_count - len) & ALIGN_MASK;
                ext.end = max_count;
        }

	dprintf("Extent search[%#jx:%#jx]\n", (uintmax_t)ext.start,
		(uintmax_t)ext.end);

        /* list */
        contended_count = 0;
        gettimeofday(&start, NULL);
	list_for_each_entry(n, &header, list) {
                if (extent_overlapped(&ext, &n->node.in_extent)) {
                        count = LOOP_COUNT;
                        while (count--);
                        contended_count++;
                }
        }
        gettimeofday(&end, NULL);
        list_time = tv_delta(&start, &end);
        i = contended_count;

        /* interval */
        contended_count = 0;
        gettimeofday(&start, NULL);
        interval_search(root, &ext, perf_cb, &contended_count);
        gettimeofday(&end, NULL);
        interval_time = tv_delta(&start, &end);

        if (i != contended_count)
                error("count of contended lock don't match(%d: %d)\n",
                      i, contended_count);

        printf("\tList vs Int. search: \n\t\t"
               "(%d vs %d)ms, %d contended lock.\n",
                list_time, interval_time, contended_count);

        return 0;
}

static struct interval_node *it_test_helper(struct interval_node *root)
{
        int idx, count = 0;
        struct it_node *n;

        count = random() % it_count;
        while (count--) {
                idx = random() % it_count;
                n = &it_array[idx];
                if (n->valid) {
                        if (!interval_find(root, &n->node.in_extent))
                                error("Cannot find an existent node\n");
			dprintf("Erasing a node [%#jx:%#jx]\n",
				(uintmax_t)n->node.in_extent.start,
				(uintmax_t)n->node.in_extent.end);
                        interval_erase(&n->node, &root);
                        n->valid = 0;
			list_del_init(&n->list);
                } else {
                        __u64 low, high;
                        low = (random() % max_count) & ALIGN_MASK;
                        high = ((random() % max_count + 1) & ALIGN_MASK) + low;
                        if (high > max_count)
                                high = max_count;
                        interval_set(&n->node, low, high);
                        while (interval_insert(&n->node, &root))
                                interval_set(&n->node, low, ++high);
			dprintf("Adding a node [%#jx:%#jx]\n",
				(uintmax_t)n->node.in_extent.start,
				(uintmax_t)n->node.in_extent.end);
                        n->valid = 1;
			list_add(&n->list, &header);
                }
        }

        return root;
}

static struct interval_node *it_test_init(int count)
{
        int i;
        uint64_t high, low, len;
        struct it_node *n;
        struct interval_node *root = NULL;

        it_count = count;
        it_array = (struct it_node *)malloc(sizeof(struct it_node) * count);
        if (it_array == NULL)
                error("it_array == NULL, no memory\n");

        have_wide_lock = 0;
        for (i = 0; i < count; i++) {
                n = &it_array[i];
                do {
                        low = (random() % max_count + 1) & ALIGN_MASK;
                        len = (random() % 256 + 1) * ALIGN_SIZE;
                        if (!have_wide_lock && !(random() % count)) {
                                low = 0;
                                len = max_count;
                                have_wide_lock = 1;
                        }
                        high = low + (len & ALIGN_MASK);

                        interval_set(&n->node, low, high);
                } while (interval_insert(&n->node, &root));
                n->hit = 0;
                n->valid = 1;
                if (i == 0)
			list_add_tail(&n->list, &header);
                else
			list_add_tail(&n->list, &it_array[rand()%i].list);
        }

        return root;
}

static void it_test_fini(void)
{
        free(it_array);
        it_array = NULL;
        it_count = 0;
        max_count = 0;
}

int main(int argc, char *argv[])
{
        int count = 5, perf = 0;
        struct interval_node *root;
        struct timeval tv;

        gettimeofday(&tv, NULL);
        srandom(tv.tv_usec);

        if (argc == 2) {
                if (strcmp(argv[1], "-p"))
                        error("Unknow options, usage: %s [-p]\n", argv[0]);
                perf = 1;
                count = 1;
        }

        if (perf) {
                int M = 1024 * 1024;
                root = it_test_init(1000000);
                printf("1M locks with 4K request size\n");
                it_test_performance(root, 4096);
                printf("1M locks with 128K request size\n");
                it_test_performance(root, 128 * 1024);
                printf("1M locks with 256K request size\n");
                it_test_performance(root, 256 * 1024);
                printf("1M locks with 1M request size\n");
                it_test_performance(root, 1 * M);
                printf("1M locks with 16M request size\n");
                it_test_performance(root, 16 * M);
                printf("1M locks with 32M request size\n");
                it_test_performance(root, 32 * M);
                printf("1M locks with 64M request size\n");
                it_test_performance(root, 64 * M);
                printf("1M locks with 128M request size\n");
                it_test_performance(root, 128 * M);
                printf("1M locks with 256M request size\n");
                it_test_performance(root, 256 * M);
                printf("1M locks with 512M request size\n");
                it_test_performance(root, 512 * M);
                printf("1M locks with 1G request size\n");
                it_test_performance(root, 1024 * M);
                printf("1M locks with 2G request size\n");
                it_test_performance(root, 2048 * M);
                printf("1M locks with 3G request size\n");
                it_test_performance(root, 3072 * M);
                printf("1M locks with 4G request size\n");
                it_test_performance(root, max_count - 1);
                it_test_fini();
                return 0;
        }

        root = it_test_init(random() % 100000 + 1000);
        while (count--) {
                it_test_sanity(root);
                it_test_iterate(root);
                it_test_iterate_reverse(root);
                it_test_find(root);
                it_test_search_hole(root);
                it_test_search(root);
                root = it_test_helper(root);
        }
        it_test_fini();

        return 0;
}
