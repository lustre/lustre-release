// SPDX-License-Identifier: GPL-2.0

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Userspace test of the LOD round-robin target allocator.
 *
 * lustre/obdclass/lu_tgt_alloc.c is built directly into this program with stubs
 * for the few kernel interfaces it uses.  For each OST count, OSS count
 * and stripe count, allocate layouts from one round-robin state per MDT
 * the way lod_ost_alloc_rr() does, and check that every OST gets about
 * the same number of objects, and with -f also of first (#0) objects.
 */

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>

/* stubs for the kernel interfaces used by lu_tgt_alloc.c */
typedef struct { int counter; } atomic_t;

static inline int atomic_read(const atomic_t *v)
{
	return v->counter;
}

static inline void atomic_set(atomic_t *v, int i)
{
	v->counter = i;
}

static inline void atomic_sub(int i, atomic_t *v)
{
	v->counter -= i;
}

static inline int atomic_inc_return(atomic_t *v)
{
	return ++v->counter;
}

static inline __u32 get_random_u32_below(__u32 ceil)
{
	return random() % ceil;
}

static unsigned long gcd(unsigned long a, unsigned long b)
{
	while (b) {
		unsigned long r = a % b;

		a = b;
		b = r;
	}

	return a;
}

static inline void spin_lock(int *lock)
{
}

static inline void spin_unlock(int *lock)
{
}

#define max(a, b)	((a) > (b) ? (a) : (b))

/* the fields of the kernel structures used by lu_tgt_alloc.c */
struct lu_tgt_pool {
	__u32		*op_array;
	unsigned int	 op_count;
};

struct lu_qos_rr_stream {
	__u64			 lqrs_key;
	atomic_t		 lqrs_start_idx;
	__u32			 lqrs_offset_idx;
	__u32			 lqrs_layouts;
	__u32			 lqrs_stride;
	__u32			 lqrs_used;
};

#define LQR_STREAMS	16

struct lu_qos_rr {
	int			 lqr_alloc;
	struct lu_qos_rr_stream	 lqr_streams[LQR_STREAMS];
	__u32			 lqr_clock;
	int			 lqr_start_count;
	struct lu_tgt_pool	 lqr_pool;
};

#define EXPORT_SYMBOL(sym)

#include "../include/lu_tgt_alloc.h"
#include "../obdclass/lu_tgt_alloc.c"

#define MAX_OSTS 1024
#define MAX_MDTS 64
#define MAX_PATTERN 16

static const char *progname;
static bool verbose;
static unsigned int unusable;
static unsigned int unbalanced_first;
static int pattern[MAX_PATTERN];
static unsigned int npattern;
static bool mirrors;
static unsigned int parity;

struct rr_test {
	unsigned int	ost_count;
	unsigned int	oss_count;
	unsigned int	stripes;
	unsigned int	stripes_per_ost;
	bool		skip[MAX_OSTS];
	unsigned int	objs[MAX_OSTS];
	unsigned int	objs0[MAX_OSTS];
	unsigned int	objs0c[MAX_PATTERN][MAX_OSTS];
	unsigned int	oss_of[MAX_OSTS];
	unsigned int	mirror_same_oss;
	bool		no_first;
};

/* like lod_qos_calc_rr(), with OSTs split evenly and in order among OSSs */
static void rr_fill(struct lu_tgt_pool *rr, unsigned int ost_count,
		    unsigned int oss_count)
{
	unsigned int oss, i;

	rr->op_count = ost_count;
	for (i = 0; i < ost_count; i++)
		rr->op_array[i] = LU_RR_EMPTY;

	for (oss = 0; oss < oss_count; oss++) {
		unsigned int first = oss * ost_count / oss_count;
		unsigned int last = (oss + 1) * ost_count / oss_count;

		for (i = first; i < last; i++)
			lu_rr_place_tgt(rr, i, i - first, last - first);
	}
}

/*
 * Like lod_ost_alloc_rr() for layout component @comp when every OST is
 * usable, avoiding the OSTs in @used that the file already uses.
 */
static void rr_alloc(struct rr_test *rt, struct lu_qos_rr *lqr,
		     unsigned int comp, __u64 key, bool cont,
		     unsigned int *used)
{
	struct lu_qos_rr_stream *lqrs;
	unsigned int found = 0;
	unsigned int i;

	lqrs = lu_rr_start(lqr, rt->ost_count, rt->stripes, key, cont);
	for (i = 0; i < rt->ost_count * rt->stripes_per_ost &&
		    found < rt->stripes; i++) {
		__u32 ost = lqr->lqr_pool.op_array[lu_rr_next(lqrs) %
						   rt->ost_count];

		if (ost == LU_RR_EMPTY || rt->skip[ost] ||
		    used[ost] >= rt->stripes_per_ost)
			continue;

		used[ost]++;
		if (found++ == 0 && !rt->no_first) {
			rt->objs0[ost]++;
			rt->objs0c[comp][ost]++;
		}
		rt->objs[ost]++;
	}
}

/*
 * Check that every usable OST has less than 3/2 the first objects of any
 * other, the limit that sanity test_51d uses for adjacent OSTs.
 */
static int rr_check_first(struct rr_test *rt, const unsigned int *objs0,
			  unsigned int stripes, bool check_first)
{
	unsigned int min0 = 0, max0 = 0;
	bool found = false;
	unsigned int i;

	for (i = 0; i < rt->ost_count; i++) {
		if (rt->skip[i])
			continue;
		if (!found) {
			min0 = max0 = i;
			found = true;
		}
		if (objs0[i] < objs0[min0])
			min0 = i;
		if (objs0[i] > objs0[max0])
			max0 = i;
	}

	if (objs0[max0] == objs0[min0] || objs0[max0] * 2 < objs0[min0] * 3)
		return 0;

	if (check_first || verbose)
		printf("ost=%u oss=%u stripes=%u: OST%u has %u #0 objects, OST%u has %u\n",
		       rt->ost_count, rt->oss_count, stripes,
		       max0, objs0[max0], min0, objs0[min0]);
	if (check_first)
		return -EDOM;

	unbalanced_first++;
	return 0;
}

static unsigned int comp_stripes(unsigned int comp, unsigned int ost_count)
{
	return pattern[comp] < 0 || pattern[comp] > (int)ost_count ?
	       ost_count : pattern[comp];
}

/*
 * Check that every usable OST has less than 5/4 the objects of any other,
 * like sanity test_51d, and with @check_first the first objects as well,
 * separately for each component of a stripe count pattern.
 */
static int rr_check(struct rr_test *rt, bool check_first)
{
	unsigned int min = 0, max = 0;
	bool found = false;
	unsigned int i;
	int rc = 0;

	for (i = 0; i < rt->ost_count; i++) {
		if (rt->skip[i])
			continue;
		if (!found) {
			min = max = i;
			found = true;
		}
		if (rt->objs[i] < rt->objs[min])
			min = i;
		if (rt->objs[i] > rt->objs[max])
			max = i;
	}

	if (rt->objs[max] * 4 >= rt->objs[min] * 5) {
		printf("ost=%u oss=%u stripes=%u: OST%u has %u objects, OST%u has %u\n",
		       rt->ost_count, rt->oss_count, rt->stripes,
		       max, rt->objs[max], min, rt->objs[min]);
		rc = -EDOM;
	}
	if (!npattern) {
		if (rr_check_first(rt, rt->objs0, rt->stripes, check_first))
			rc = -EDOM;
	}
	for (i = 0; i < npattern; i++)
		if (rr_check_first(rt, rt->objs0c[i],
				   comp_stripes(i, rt->ost_count),
				   check_first))
			rc = -EDOM;
	if (rt->mirror_same_oss) {
		printf("ost=%u oss=%u stripes=%u: %u files have both mirrors on one OSS\n",
		       rt->ost_count, rt->oss_count, rt->stripes,
		       rt->mirror_same_oss);
		rc = -EDOM;
	}

	if (rc || verbose) {
		for (i = 0; i < rt->ost_count; i++)
			printf("  OST%u has %u objects, %u are index 0\n",
			       i, rt->objs[i], rt->objs0[i]);
	}

	return rc;
}

static int rr_test_one(unsigned int ost_count, unsigned int oss_count,
		       unsigned int stripes, unsigned int mdt_count,
		       unsigned int per_ost, bool check_first)
{
	static struct lu_qos_rr lqr[MAX_MDTS];
	static __u32 rr_array[MAX_OSTS];
	struct lu_tgt_pool rr = { .op_array = rr_array };
	struct rr_test rt = {
		.ost_count = ost_count,
		.oss_count = oss_count,
		.stripes = stripes,
		.stripes_per_ost = (stripes - 1) / ost_count + 1,
	};
	unsigned int i;

	/* spread the unusable OSTs, which still use up an RR index */
	for (i = 0; i < unusable; i++)
		rt.skip[i * ost_count / unusable] = true;

	rr_fill(&rr, ost_count, oss_count);
	for (i = 0; i < ost_count; i++)
		while ((rt.oss_of[i] + 1) * ost_count / oss_count <= i)
			rt.oss_of[i]++;
	memset(lqr, 0, sizeof(lqr));
	for (i = 0; i < mdt_count; i++)
		lqr[i].lqr_pool = rr;

	/* files in a striped directory are spread over the MDTs by hash */
	for (i = 0; i < per_ost * ost_count; i++) {
		struct lu_qos_rr *m = &lqr[mdt_count > 1 ?
					  random() % mdt_count : 0];
		unsigned int used[MAX_OSTS] = { 0 };
		unsigned int c;

		if (mirrors) {
			/* mirrors of one extent share a key, like EC parity,
			 * with -P each file has the next stripe count
			 */
			unsigned int per_oss[MAX_OSTS] = { 0 };
			unsigned int j;

			c = npattern ? i % npattern : 0;
			if (npattern) {
				rt.stripes = comp_stripes(c, ost_count);
				rt.stripes_per_ost = 1;
			}
			rr_alloc(&rt, m, c, rt.stripes, false, used);
			rr_alloc(&rt, m, c, rt.stripes, true, used);
			/* with enough equal OSSs, none should have two OSTs */
			for (j = 0; j < ost_count; j++)
				if (used[j] && ++per_oss[rt.oss_of[j]] > 1 &&
				    2 * rt.stripes <= oss_count &&
				    ost_count % oss_count == 0) {
					rt.mirror_same_oss++;
					break;
				}
			continue;
		}
		if (!npattern) {
			rr_alloc(&rt, m, 0, stripes, false, used);
			/* EC parity continues from the data stripes */
			if (parity) {
				rt.stripes = parity;
				rt.no_first = true;
				rr_alloc(&rt, m, 0, stripes, true, used);
				rt.stripes = stripes;
				rt.no_first = false;
			}
			continue;
		}
		/* each component of a PFL-like layout in turn */
		for (c = 0; c < npattern; c++) {
			rt.stripes = comp_stripes(c, ost_count);
			rt.stripes_per_ost = (rt.stripes - 1) / ost_count + 1;
			memset(used, 0, sizeof(used));
			rr_alloc(&rt, m, c, ((__u64)(c + 1) << 32) + rt.stripes,
				 false, used);
		}
	}

	return rr_check(&rt, check_first);
}

static int parse_range(const char *arg, unsigned int *lo, unsigned int *hi,
		       unsigned int limit)
{
	char *end;

	*lo = strtoul(arg, &end, 0);
	*hi = *lo;
	if (*end == '-')
		*hi = strtoul(end + 1, &end, 0);
	if (*end != '\0' || *lo == 0 || *hi < *lo || *hi > limit) {
		fprintf(stderr, "%s: invalid range '%s', need 1-%u\n",
			progname, arg, limit);
		return -EINVAL;
	}

	return 0;
}

static void print_usage(void)
{
	printf("usage: %s [-f] [-v] [-C MULT] [-c STRIPES[-MAX]] [-m MDTS]\n"
	       "\t\t[-n PER_OST] [-o OSTS[-MAX]] [-r SEED] [-s OSSS[-MAX]]\n"
	       "\t\t[-e PARITY] [-M] [-P STRIPES,...] [-x UNUSABLE]\n"
	       "\t-C: overstripe up to MULT stripes per OST (default 1)\n"
	       "\t-c: stripe counts to test (default 1-OSTS)\n"
	       "\t-e: allocate PARITY more stripes after each layout, like EC\n"
	       "\t-f: fail if first (#0) objects are unbalanced\n"
	       "\t-M: allocate two mirrors of each layout\n"
	       "\t-m: MDTs allocating layouts independently (default 1)\n"
	       "\t-n: layouts to allocate per OST (default 100)\n"
	       "\t-o: OST counts to test (default 3-32)\n"
	       "\t-P: stripe counts of each layout's components, -1 all OSTs\n"
	       "\t-r: random seed (default 1)\n"
	       "\t-s: OSS counts to test (default 1-4)\n"
	       "\t-v: print object counts for every OST\n"
	       "\t-x: number of unusable OSTs (default 0)\n", progname);
}

int main(int argc, char **argv)
{
	unsigned int sc_min = 1, sc_max = MAX_OSTS;
	unsigned int ost_min = 3, ost_max = 32;
	unsigned int oss_min = 1, oss_max = 4;
	unsigned int mdt_count = 1;
	unsigned int ost_mult = 1;
	unsigned int per_ost = 100;
	unsigned int ost, oss, sc;
	bool check_first = false;
	int failed = 0;
	int tested = 0;
	int c;

	progname = argv[0];
	srandom(1);
	while ((c = getopt(argc, argv, "C:c:e:fhMm:n:o:P:r:s:vx:")) != -1) {
		switch (c) {
		case 'C':
			ost_mult = strtoul(optarg, NULL, 0);
			if (ost_mult < 1 || ost_mult > MAX_OSTS) {
				fprintf(stderr, "%s: invalid overstriping '%s', need 1-%u\n",
					progname, optarg, MAX_OSTS);
				return 1;
			}
			break;
		case 'c':
			if (parse_range(optarg, &sc_min, &sc_max, MAX_OSTS))
				return 1;
			break;
		case 'e':
			parity = strtoul(optarg, NULL, 0);
			break;
		case 'f':
			check_first = true;
			break;
		case 'm':
			mdt_count = strtoul(optarg, NULL, 0);
			if (mdt_count < 1 || mdt_count > MAX_MDTS) {
				fprintf(stderr, "%s: invalid MDT count '%s', need 1-%u\n",
					progname, optarg, MAX_MDTS);
				return 1;
			}
			break;
		case 'n':
			per_ost = strtoul(optarg, NULL, 0);
			if (per_ost < 1) {
				fprintf(stderr, "%s: invalid layouts per OST '%s'\n",
					progname, optarg);
				return 1;
			}
			break;
		case 'o':
			if (parse_range(optarg, &ost_min, &ost_max, MAX_OSTS))
				return 1;
			break;
		case 'M':
			mirrors = true;
			break;
		case 'P': {
			char *tok, *save = NULL;

			for (tok = strtok_r(optarg, ",", &save);
			     tok && npattern < MAX_PATTERN;
			     tok = strtok_r(NULL, ",", &save))
				pattern[npattern++] = strtol(tok, NULL, 0);
			break;
		}
		case 'r':
			srandom(strtoul(optarg, NULL, 0));
			break;
		case 's':
			if (parse_range(optarg, &oss_min, &oss_max, MAX_OSTS))
				return 1;
			break;
		case 'v':
			verbose = true;
			break;
		case 'x':
			unusable = strtoul(optarg, NULL, 0);
			break;
		case 'h':
			print_usage();
			return 0;
		default:
			print_usage();
			return 1;
		}
	}

	for (ost = ost_min; ost <= ost_max; ost++) {
		for (oss = oss_min; oss <= oss_max && oss <= ost; oss++) {
			/* with -P, each layout has all of its stripe counts,
			 * and with -M, the mirrors need different OSTs
			 */
			for (sc = npattern ? 1 : sc_min; sc <= sc_max &&
			     sc + parity + unusable <=
			     ost * ost_mult / (mirrors + 1);
			     sc++) {
				tested++;
				if (rr_test_one(ost, oss, sc, mdt_count,
						per_ost, check_first))
					failed++;
				if (npattern)
					break;
			}
		}
	}

	printf("%s: %d of %d combinations failed", progname, failed, tested);
	if (unbalanced_first)
		printf(", %u have unbalanced first stripes", unbalanced_first);
	printf("\n");

	return failed ? 1 : 0;
}
