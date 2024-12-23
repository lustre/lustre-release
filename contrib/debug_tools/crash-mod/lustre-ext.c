// SPDX-License-Identifier: GPL-v2.0+
/*
 * Copyright (C) 2007, Lawrence Livermore National Labs
 * Author: Brian Behlendorf
 * Copyright (C) 2017-2023, Cray Inc.
 * Author: Alexey Lyashkov
 */

#include "defs.h"

#define UINT32_LEN   10		/* ceil(log10(UINT_MAX)) */
#define UINT64_LEN   20		/* ceil(log10(ULONG_MAX)) */

/* three types of trace_data in linux */
enum {
	TCD_TYPE_PROC = 0,
	TCD_TYPE_SOFTIRQ,
	TCD_TYPE_IRQ,
	TCD_TYPE_MAX
};

struct cfs_trace_page {
	/*
	 * page itself
	 */
	struct page *page;
	/*
	 * linkage into one of the lists in trace_data_union or
	 * page_collection
	 */
	struct kernel_list_head linkage;
	/*
	 * number of bytes used within this page
	 */
	unsigned int used;
	/*
	 * cpu that owns this page
	 */
	unsigned short cpu;
	/*
	 * type(context) of this page
	 */
	unsigned short type;
};

#define LUSTRE_PAGES		1
#define LUSTRE_DAEMON_PAGES	2
#define LUSTRE_STOCK_PAGES	3

#define FMT_PAGE_COUNT		"$%*d = %d"

static const char fmt_page_list_head[] =
    "$%*d = (struct list_head *) %lx";
static const char lustre2_pfx[] = "cfs_";
static const char *name_prefix = lustre2_pfx;

void cmd_lustre(void);
char *help_lustre[];
int global_daemon_pages;
/* not all crash tools have  OFFSET(page_private) */
unsigned int pg_private_off;

static struct command_table_entry command_table[] = {
	{ "lustre", cmd_lustre, help_lustre, 0 },
	{ NULL }
};

void _init(void)
{
	if (symbol_exists("daemon_pages"))
		global_daemon_pages = 1;

	pg_private_off = MEMBER_OFFSET("page", "private");

	register_extension(command_table);
}

void _fini(void)
{
}

/* Given a pointer to a page frame append the assoicated linear
 * address range to the passed file descriptor.
 */
static int
lustre_write_page_frame(int fd, ulong tp_addr, ulong kvaddr, int used)
{
	char buf[PAGESIZE()];
	physaddr_t kpaddr;
	int retry = 0;
	ssize_t rc, count = 0;

	if (!is_page_ptr(kvaddr, &kpaddr)) {
		error(WARNING,
		      "Skipping trace page %p which references an invalid page pointer (%#x)\n",
		      tp_addr, kvaddr);
		return -EADDRNOTAVAIL;
	}

	if (!readmem(kpaddr, PHYSADDR, buf, used,
		     "trace page data", RETURN_ON_ERROR)) {
		error(WARNING,
		      "Skipping trace page %p, unable to read data from physical address (%#x)\n",
		      tp_addr, kpaddr);
		return -EIO;
	}

	while (count < used) {
		rc = write(fd, buf + count, used - count);
		if (rc >= 0) {
			count += rc;

			if ((rc == 0) && (retry++ > 5)) {
				error(WARNING,
				      "Partial trace page %#lx written to output file (%d/%d bytes)\n",
				      tp_addr, count, used);
				return count;
			}
		} else {
			error(WARNING,
			      "Unable to write to output file: %s (%d)\n",
			      strerror(errno), errno);
			return -rc;
		}
	}

	return count;
}

static int lustre_walk_trace_pages(int cpu, int fd, ulong lh_addr)
{
	static const char *name = "cfs_trace_page";
	struct list_data ld;
	int count, rc, i = 0, ret = 0;
	struct cfs_trace_page buf;


	BZERO(&ld, sizeof(struct list_data));
	ld.end = lh_addr;
	ld.list_head_offset = MEMBER_OFFSET((char *) name, "linkage");
	ld.member_offset = ld.list_head_offset;

	readmem(lh_addr + ld.member_offset, KVADDR, &ld.start,
		sizeof(void *), "LIST_HEAD contents", FAULT_ON_ERROR);
	ld.structname_args = 1;
	ld.structname =
	    (char **) GETBUF(sizeof(char *) * ld.structname_args);
	ld.structname[0] = (char *) name;
	ld.flags |= LIST_ALLOCATE | LIST_HEAD_FORMAT | LIST_HEAD_POINTER;

	hq_open();
	count = do_list(&ld);
	hq_close();

	printf("%s(%d, %d, %#lx) = %d\n", __func__, cpu, fd, lh_addr, count);
	/* count include a list_head itself for empty */
	if (count <= 1)
		return 0;

	for (i = 0; i < count; ++i) {
#if 0
		printf("i = %d, count = %d, tp_addr = %#lx, tp_page = %p, tp_next = %p, tp_prev = %p, tp_used = %d tcpu = %d\n",
		     i, count, ld.list_ptr[i], buf.page,
		     buf.linkage.next, buf.linkage.prev, buf.used, buf.cpu);
#endif

		readmem(ld.list_ptr[i], KVADDR, (char *) &buf, sizeof(buf),
			"cfs_trace_page buffer", FAULT_ON_ERROR);

		/* Validate the list heads for some sanity */
		if ((buf.linkage.next == 0) || (buf.linkage.prev == 0)) {
			error(WARNING,
			      "Trace page %p has bogus next (%#p) or prev (%#p) pointers\n",
			      buf.page, buf.linkage.next, buf.linkage.prev);
			continue;
		}

		if ((buf.used < 0) || (buf.used > PAGESIZE())) {
			error(WARNING,
			      "Trace page %#p has bogus used size (%d)\n",
			      buf.page, buf.used);
			continue;
		}

		rc = lustre_write_page_frame(fd, ld.list_ptr[i],
					     (ulong) buf.page, buf.used);
		if (rc >= 0)
			ret += 1;
	}
	FREEBUF(ld.list_ptr);

	return ret;
}

/* Aquire the debug page list head pointer for this CPU and walk them */
static int lustre_walk_cpus(int type, int cpu, int fd, int mode)
{
	static const char cmd_head_fmt[] =
	    "p &((*%strace_data[%i])[%i].tcd.tcd_%s)";
	static const char cmd_count_fmt[] =
	    "p (*%strace_data[%i])[%i].tcd.tcd_%s";
	char cmd_head[sizeof(cmd_head_fmt) + 40];
	char cmd_count[sizeof(cmd_count_fmt) + 40];
	int count, count1;
	int rc;
	ulong lh_addr;

	printf("%s(%d, %d, %d)\n", __func__, cpu, fd, mode);

	if (global_daemon_pages && (mode == LUSTRE_DAEMON_PAGES))
		return 0;

	switch (mode) {
	case LUSTRE_PAGES:
		snprintf(cmd_head, sizeof(cmd_head), cmd_head_fmt, name_prefix,
			 type, cpu, "pages");
		snprintf(cmd_count, sizeof(cmd_head), cmd_count_fmt,
			 name_prefix, type, cpu, "cur_pages");
		break;
	case LUSTRE_DAEMON_PAGES:
		snprintf(cmd_head, sizeof(cmd_head), cmd_head_fmt, name_prefix,
			 type, cpu, "daemon_pages");
		snprintf(cmd_count, sizeof(cmd_head), cmd_count_fmt,
			 name_prefix, type, cpu, "cur_daemon_pages");
		break;
	case LUSTRE_STOCK_PAGES:
		snprintf(cmd_head, sizeof(cmd_head), cmd_head_fmt, name_prefix,
			 type, cpu, "stock_pages");
		snprintf(cmd_count, sizeof(cmd_head), cmd_count_fmt,
			 name_prefix, type, cpu, "cur_stock_pages");

		break;
	default:
		return -EINVAL;
	}
	printf("cmd:\t%s\n\t%s\n", cmd_head, cmd_count);

	/* Aquire the expected number of debug pages */
	open_tmpfile();
	if (!gdb_pass_through(cmd_count, pc->tmpfile, GNU_RETURN_ON_ERROR)) {
		close_tmpfile();
		error(FATAL, "gdb request failed: '%s'\n", cmd_count);
		return -EINVAL;
	}

	rewind(pc->tmpfile);
	rc = fscanf(pc->tmpfile, FMT_PAGE_COUNT, &count);
	if (rc != 1) {
		close_tmpfile();
		error(FATAL, "gdb unexpected result: '%s', rc = %d\n",
		      cmd_count, rc);
		return -EINVAL;
	}
	close_tmpfile();

	/* Skip CPUs with no debug pages */
	if (count == 0)
		return count;


	/* Aquire the list head address for the tage list */
	open_tmpfile();
	if (!gdb_pass_through(cmd_head, pc->tmpfile, GNU_RETURN_ON_ERROR)) {
		close_tmpfile();
		error(FATAL, "gdb request failed: '%s'\n", cmd_head);
		return -EINVAL;
	}

	rewind(pc->tmpfile);
	rc = fscanf(pc->tmpfile, fmt_page_list_head, &lh_addr);

	if (rc != 1) {
		close_tmpfile();
		error(FATAL, "gdb unexpected result: '%s', rc = %d\n",
		      cmd_head, rc);
		return -EINVAL;
	}
	close_tmpfile();

	count1 = lustre_walk_trace_pages(cpu, fd, lh_addr);
	if (count1 != count)
		printf("Unexpected write size %d != %d\n", count1, count);
	return count1;
}

static int lustre_walk_daemon_pages(int fd)
{
	struct list_data ld;
	int count, rc, i = 0, ret = 0;
	unsigned long pg_private;

	BZERO(&ld, sizeof(struct list_data));
	get_symbol_data("daemon_pages", sizeof(void *), &ld.start);
	ld.end = ld.start;
	ld.list_head_offset = MEMBER_OFFSET("page", "page_lru");
	ld.flags |= LIST_ALLOCATE | LIST_HEAD_FORMAT | LIST_HEAD_POINTER;

	hq_open();
	count = do_list(&ld);
	hq_close();

	printf("%s(%p:%d)\n", __func__, (void *)ld.start,
	       count);
	/* count include a list_head itself for empty */
	if (count <= 1)
		return 0;

	for (i = 0; i < count; ++i) {
		readmem(ld.list_ptr[i] + pg_private_off, KVADDR,
			(char *) &pg_private, sizeof(void *),
			"daemon page private", FAULT_ON_ERROR);

		if ((pg_private < 0) || (pg_private > PAGESIZE())) {
			error(WARNING,
			      "Trace page %p has bogus used size (%d)\n",
			      ld.list_ptr[i], pg_private);
			continue;
		}

		rc = lustre_write_page_frame(fd, ld.list_ptr[i],
					     ld.list_ptr[i], pg_private);
		if (rc >= 0)
			ret += 1;
	}
	FREEBUF(ld.list_ptr);

	return ret;
}

void cmd_lustre_log(char *name)
{
	int i, rc, count, total = 0, fd;
	int type;

	fd = open(name, O_CREAT | O_EXCL | O_APPEND | O_WRONLY,
		  S_IRUSR | S_IWUSR);
	if (fd == -1) {
		error(FATAL, "Unable to open log file '%s': %s (%d)\n",
		      name, strerror(errno), errno);
		return;
	}

	for (type = 0; type < TCD_TYPE_MAX; type++) {
		for (i = 0; i < kt->cpus; i++) {
			count = 0;

			rc = lustre_walk_cpus(type, i, fd, LUSTRE_PAGES);
			if (rc >= 0)
				count += rc;

			rc = lustre_walk_cpus(type, i, fd,
					      LUSTRE_DAEMON_PAGES);
			if (rc >= 0)
				count += rc;

			rc = lustre_walk_cpus(type, i, fd,
					      LUSTRE_STOCK_PAGES);
			if (rc >= 0)
				count += rc;

			error(INFO,
			      "Dumped %d debug pages from type %d - CPU %d\n",
			      count, type, i);
			total += count;
		}
	}

	if (global_daemon_pages)
		lustre_walk_daemon_pages(fd);

	if (fsync(fd) == -1)
		error(WARNING,
		      "Unable to sync log file '%s' it may be incomplete: %s (%d)\n",
		      name, strerror(errno), errno);

	if (close(fd) == -1)
		error(WARNING, "Unable to close log file '%s': %s %d\n",
		      name, strerror(errno), errno);

	error(INFO, "Dumped %d total debug pages from %d CPUs to '%s'\n",
	      total, kt->cpus, name);
}


void cmd_lustre(void)
{
	int c;

	while ((c = getopt(argcnt, args, "l:")) != EOF) {
		switch (c) {
		case 'l':
			if (strlen(optarg) == 0)
				argerrs++;
			else
				cmd_lustre_log(optarg);

			break;
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	fprintf(fp, "\n");
}

char *help_lustre[] = {
	"lustre",		/* command name */
	"lustre specific debug commands",	/* short description */
	"[-l <file>]",		/* argument synopsis */
	"  This command displays lustre specific data.\n",
	"       -l  Extract lustre kernel debug data to <file>",
	"           (use 'lctl df <file>' for ascii text)",
	"\nEXAMPLE",
	"    crash> lustre -l /tmp/lustre.log",
	NULL
};

/*
 * Local Variables:
 * mode: C
 * c-file-style: "stroustrup"
 * indent-tabs-mode: nil
 * c-basic-offset: 8
 * End:
 *
 * end of lustre-ext.c
 */
