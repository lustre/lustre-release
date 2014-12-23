/*
 * 2003, Copyright, Hewlett-Packard Development Compnay, LP.
 *
 * Developed under the sponsorship of the U.S. Government
 *     under Subcontract No. B514193
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2014, Intel Corporation.
 */

#include <stdio.h>
#include <getopt.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <dirent.h>

#include "mpi.h"

/* lustre */
#include <lustre/lustreapi.h>        /* for O_LOV_DELAY_CREATE */

#define CHECK_COUNT 10000
#define DISPLAY_COUNT (CHECK_COUNT * 10)
#define DISPLAY_TIME 100

enum {
        CREATE   = 'c',
        LOOKUP   = 'l',
        MKNOD    = 'm',
        OPEN     = 'o',
        STAT     = 's',
        UNLINK   = 'u',
        BEGIN    = 'b',
        ITERS    = 'i',
        TIME     = 't',
        DIRFMT   = 'd',
        NDIRS    = 'D',
        FILEFMT  = 'f',
        NFILES   = 'F',
        NOEXCL   = 'X',
        STRIPES  = 'S',
        SEED     = 'r',
        SEEDFILE = 'R',
        RANDOM   = 'A',
        READDIR  = 'B',
        RECREATE = 'C',
        IGNORE   = 'E',
        VERBOSE  = 'V',
        DEBUG    = 'v',
        HELP     = 'h',
	MNT	 = 'M',
	MNTCOUNT = 'N',
	MDTCOUNT = 'T',
};

struct option longOpts[] = {
        {"create",        0, NULL, CREATE     },
        {"lookup",        0, NULL, LOOKUP     },
        {"mknod",         0, NULL, MKNOD      },
        {"open",          0, NULL, OPEN       },
        {"stat",          0, NULL, STAT       },
        {"unlink",        0, NULL, UNLINK     },
        {"begin",         1, NULL, BEGIN      },
        {"iters",         1, NULL, ITERS      },
        {"time",          1, NULL, TIME       },   /* seconds */
        {"dirfmt",        1, NULL, DIRFMT     },
        {"ndirs",         1, NULL, NDIRS      },
        {"filefmt",       1, NULL, FILEFMT    },
        {"nfiles",        1, NULL, NFILES     },
        {"noexcl",        0, NULL, NOEXCL     },
        {"stripes",       1, NULL, STRIPES    },
        {"seed",          1, NULL, SEED       },
        {"seedfile",      1, NULL, SEEDFILE   },
        {"random_order",  0, NULL, RANDOM     },
        {"readdir_order", 0, NULL, READDIR    },
        {"recreate",      0, NULL, RECREATE   },
        {"ignore",        0, NULL, IGNORE     },
        {"verbose",       0, NULL, VERBOSE    },
        {"debug",         0, NULL, DEBUG      },
        {"help",          0, NULL, HELP       },
	{"mdtcount",      1, NULL, MDTCOUNT   },
	{"mntcount",      1, NULL, MNTCOUNT   },
	{"mntfmt",        1, NULL, MNT        },
	{ 0,              0, NULL, 0          }
};

int foo1, foo2;

char   shortOpts[128];
int    myrank = -1;
int    nthreads = -1;
char * prog;
char   hostname[512] = "unknown";
char   mode;
char * cmd;
int    openflags = O_RDWR|O_CREAT|O_EXCL;
int    ndirs = 1;
char * dirfmt;
char   dir[PATH_MAX];
char   mkdir_cmd[PATH_MAX+14];
int    dirthreads;
int    dirnum;
DIR *  directory;
struct dirent *dir_entry;
int    nfiles;
char   filefmt[PATH_MAX];
char   filename[PATH_MAX];
char   path[PATH_MAX];
int    stripes = -1;
int    begin;
int    beginsave;
int    end;
int    iters;
int    seconds;
int    alarm_caught;
struct sigaction act;
int    order = RANDOM;
int    seed;
int    recreate;
int    ignore;
int    verbose;
int    debug;
struct stat statbuf;
int    mnt_count = -1;
int    mdt_count = 1;
char  *mntfmt;

#define dmesg if (debug) printf

#define DISPLAY_PROGRESS() {                                                \
        if (verbose && (nops % CHECK_COUNT == 0)) {                         \
                curTime = MPI_Wtime();                                      \
                interval = curTime - lastTime;                              \
                if (interval > DISPLAY_TIME || nops % DISPLAY_COUNT == 0) { \
                        rate = (double)(nops - lastOps)/interval;           \
                        printf("Rank %d: %.2f %ss/sec %.2f secs "           \
                               "(total: %d %ss %.2f secs)\n",               \
                               myrank, rate, cmd, interval,                 \
                               nops, cmd, curTime - startTime);             \
                        lastOps = nops;                                     \
                        lastTime = curTime;                                 \
                }                                                           \
        }                                                                   \
}

char *usage_msg = "usage: %s\n"
                  "    { --create [ --noexcl ] | --lookup | --mknod |\n"
                  "      --open | --stat | --unlink  [ --recreate ] [ --ignore ] }\n"
                  "    [ --help ] [ --verbose ] [ --debug ]\n"
                  "    { [ --begin <num> ] --nfiles <num> }\n"
                  "    [ --iters <num> ] [ --time <secs> ]\n"
                  "    [ --dirfmt <str> ] [ --ndirs  <num> ]\n"
                  "    [ --filefmt <str> ] [ --stripes <num> ]\n"
                  "    [ --random_order [--seed <num> | --seedfile <file>] ]\n"
		  "    [ --readdir_order ] [ --mntfmt <str> ]\n"
		  "    [ --mntcount <num> ] [ --mdtcount <num> ]\n";

static void
usage(FILE *stream, char *fmt, ...)
{
        if (myrank == 0) {
                if (fmt != NULL) {
                        va_list       ap;

                        fprintf(stream, "%s: ", prog);
                        va_start(ap, fmt);
                        vfprintf(stderr, fmt, ap);
                        va_end(ap);
                }
                fprintf(stream, usage_msg, prog);
        }

        MPI_Finalize();
        exit(stream == stderr);
}

/* Print process myrank and message, and exit (i.e. a fatal error) */
static int
fatal(int rank, const char *fmt, ...)
{
        if (rank == myrank) {
                va_list       ap;

                fprintf(stderr, "rank %d: ", rank);
                va_start(ap, fmt);
                vfprintf(stderr, fmt, ap);
                va_end(ap);
        }

        MPI_Abort(MPI_COMM_WORLD, 1);
        exit(1);
}

static void
sigalrm_handler(int signum)
{
        alarm_caught++;
}

/* HAVE_LLAPI_FILE_LOOKUP is defined by liblustreapi.h if this function is
 * defined therein.  Otherwise we can do the equivalent operation via ioctl
 * if we have access to a complete lustre build tree to get the various
 * definitions - then compile with USE_MDC_LOOKUP defined. */
#if defined(HAVE_LLAPI_FILE_LOOKUP)
#define HAVE_MDC_LOOKUP
#elif defined(USE_MDC_LOOKUP)
#include <config.h>
#include <libcfs/libcfs.h>
#include <lustre_ioctl.h>

int llapi_file_lookup(int dirfd, const char *name)
{
        struct obd_ioctl_data data = { 0 };
        char rawbuf[8192];
        char *buf = rawbuf;
        int rc;

        if (dirfd < 0 || name == NULL)
                return -EINVAL;

        data.ioc_version = OBD_IOCTL_VERSION;
        data.ioc_len = sizeof(data);
        data.ioc_inlbuf1 = name;
        data.ioc_inllen1 = strlen(name) + 1;

        rc = obd_ioctl_pack(&data, &buf, sizeof(rawbuf));
        if (rc) {
                fatal(myrank, "ioctl_pack failed: rc = %d\n", rc);
                return rc;
        }

        return ioctl(fd, IOC_MDC_LOOKUP, buf);
}
#define HAVE_MDC_LOOKUP
#endif

static void
process_args(int argc, char *argv[])
{
        char   *cp, *endptr;
        int    i, index, offset, tmpend, rc;
        char   tmp[16];
        FILE * seed_file;
        struct option *opt;

        setbuf(stdout, 0);
        setbuf(stderr, 0);
        prog = basename(argv[0]);
        strcpy(filefmt, "f%d");
        gethostname(hostname, sizeof(hostname));

        /* auto create shortOpts rather than maintaining a static string. */
        for (opt = longOpts, cp = shortOpts; opt->name != NULL; opt++, cp++) {
                *cp = opt->val;
                if (opt->has_arg)
                        *++cp = ':';
        }

        while ((rc = getopt_long(argc,argv, shortOpts, longOpts,&index)) != -1) {
                switch (rc) {
                case OPEN:
                        openflags &= ~(O_CREAT|O_EXCL);
                case CREATE:
#ifdef HAVE_MDC_LOOKUP
                case LOOKUP:
#endif
                case MKNOD:
                case STAT:
                case UNLINK:
                        if (cmd != NULL) {
                                fatal(0, "Invalid - more than one operation "
                                           "specified: --%s\n",
                                        longOpts[index].name);
                        }
                        mode = rc;
                        cmd = (char *)longOpts[index].name;
                        break;
                case NOEXCL:
                        if (mode != CREATE && mode != MKNOD) {
                                usage(stderr, "--noexcl only applies to "
                                              "--create or --mknod.\n");
                        }
                        openflags &= ~O_EXCL;
                        break;
                case RECREATE:
                        if (mode != UNLINK) {
                                usage(stderr, "--recreate only makes sense"
                                              "with --unlink.\n");
                        }
                        recreate++;
                        break;
                case BEGIN:
                        begin = strtol(optarg, &endptr, 0);
                        if ((*endptr != 0) || (begin < 0)) {
                                fatal(0, "Invalid --start value.\n");
                        }
                        break;
                case ITERS:
                        iters = strtol(optarg, &endptr, 0);
                        if ((*endptr != 0) || (iters <= 0)) {
                                fatal(0, "Invalid --iters value.\n");
                        }
                        if (mode != LOOKUP && mode != OPEN) {
                                usage(stderr, "--iters only makes sense with "
                                              "--lookup or --open.\n");
                        }
                        break;
                case TIME:
                        seconds = strtol(optarg, &endptr, 0);
                        if ((*endptr != 0) || (seconds <= 0)) {
                                fatal(0, "Invalid --time value.\n");
                        }
                        break;
                case DIRFMT:
                        if (strlen(optarg) > (PATH_MAX - 16)) {
                                fatal(0, "--dirfmt too long\n");
                        }
                        dirfmt = optarg;
                        break;
                case NDIRS:
                        ndirs = strtol(optarg, &endptr, 0);
                        if ((*endptr != 0) || (ndirs <= 0)) {
                                fatal(0, "Invalid --ndirs value.\n");
                        }
                        if ((ndirs > nthreads) &&
                            ((mode == CREATE) || (mode == MKNOD))) {
                                fatal(0, "--ndirs=%d must be less than or "
                                      "equal to the number of threads (%d).\n",
                                      ndirs, nthreads);
                        }
                        break;
                case FILEFMT:
                        if (strlen(optarg) > 4080) {
                                fatal(0, "--filefmt too long\n");
                        }

                        /* Use %%d where you want the file # in the name. */
                        sprintf(filefmt, optarg, myrank);
                        break;
                case NFILES:
                        nfiles = strtol(optarg, &endptr, 0);
                        if ((*endptr != 0) || (nfiles <= 0)) {
                                fatal(0, "Invalid --nfiles value.\n");
                        }
                        break;
                case STRIPES:
                        stripes = strtol(optarg, &endptr, 0);
                        if ((*endptr != 0) || (stripes < 0)) {
                                fatal(0, "Invalid --stripes value.\n");
                        }

                        if (stripes == 0) {
                                openflags |= O_LOV_DELAY_CREATE;
                        } else {
                                fatal(0, "non-zero --stripes value "
                                         "not yet supported.\n");
                        }

                        break;
                case SEED:
                        seed = strtoul(optarg, &endptr, 0);
                        if (*endptr) {
                                fatal(0, "bad --seed option %s\n", optarg);
                        }
                        break;
                case SEEDFILE:
                        seed_file = fopen(optarg, "r");
                        if (!seed_file) {
                              fatal(myrank, "fopen(%s) error: %s\n",
                                      optarg, strerror(errno));
                        }

                        for (i = -1; fgets(tmp, 16, seed_file) != NULL;) {
                                if (++i == myrank)
                                        break;
                        }

                        if (i == myrank) {
                                rc = sscanf(tmp, "%d", &seed);
                                if ((rc != 1) || (seed < 0)) {
                                        fatal(myrank, "Invalid seed value '%s' "
                                              "at line %d in %s.\n",
                                              tmp, i, optarg);
                                }
                        } else {
                                fatal(myrank, "File '%s' too short. Does not "
                                      "contain a seed for thread %d.\n",
                                      optarg, myrank);
                        }

                        fclose(seed_file);
                        break;
                case RANDOM:
                case READDIR:
                        if (mode != LOOKUP && mode != OPEN)  {
                                fatal(0, "--%s can only be specified with "
                                         "--lookup, or --open.\n",
                                      (char *)longOpts[index].name);
                        }
                        order = rc;
                        break;
                case IGNORE:
                        ++ignore;
                        break;
                case DEBUG:
                        ++debug;
                case VERBOSE:
                        ++verbose;
                        break;
                case HELP:
                        usage(stdout, NULL);
			break;
		case MNT:
			if (strlen(optarg) > (PATH_MAX - 16))
				fatal(0, "--mnt too long\n");
			mntfmt = optarg;
			break;
		case MNTCOUNT:
			mnt_count = strtol(optarg, &endptr, 0);
			if ((*endptr != 0) || (mnt_count <= 0)) {
				fatal(0, "Invalid --mnt_count value %s.\n",
				      optarg);
			}
			break;
		case MDTCOUNT:
			mdt_count = strtol(optarg, &endptr, 0);
			if ((*endptr != 0) || (mdt_count <= 0)) {
				fatal(0, "Invalid --mdt_count value %s.\n",
				      optarg);
			}
			break;
                default:
                        usage(stderr, "unrecognized option: '%c'.\n", optopt);
                }
        }

        if (optind < argc) {
                usage(stderr, "too many arguments %d >= %d.\n", optind, argc);
        }

	if ((mnt_count != -1 && mntfmt == NULL) ||
	    (mnt_count == -1 && mntfmt != NULL)) {
		usage(stderr, "mnt_count and mntfmt must be specified at the "
			     "same time\n");
	}

        if (mode == CREATE || mode == MKNOD || mode == UNLINK || mode == STAT) {
                if (seconds != 0) {
                        if (nfiles == 0)
                                nfiles = INT_MAX;
                } else if (nfiles == 0) {
                        usage(stderr, "--nfiles or --time must be specified "
                                      "with %s.\n", cmd);
                }
        } else if (mode == LOOKUP || mode == OPEN) {
                if (seconds != 0) {
                        if (iters == 0)
                                iters = INT_MAX;
                } else if (iters == 0) {
                        usage(stderr, "--iters or --time must be specifed "
                                      "with %s.\n", cmd);
                }

                if (nfiles == 0) {
                        usage(stderr, "--nfiles must be specifed with --%s.\n",
                              cmd);
                }

                if (seed == 0) {
                        int fd = open("/dev/urandom", O_RDONLY);

                        if (fd >= 0) {
                                if (read(fd, &seed, sizeof(seed)) <
                                    sizeof(seed))
                                        seed = time(0);
                                close(fd);
                        } else {
                                seed = time(0);
                        }
                }

                srand(seed);

                dmesg("%s: rank %d seed %d (%s).\n", prog, myrank, seed,
                      (order == RANDOM) ? "random_order" : "readdir_order");
        } else {
                usage(stderr, "one --create, --mknod, --open, --stat,"
#ifdef HAVE_MDC_LOOKUP
                      " --lookup,"
#endif
                      " or --unlink must be specifed.");
        }

        /* support for multiple threads in a dir, set begin/end appropriately.*/
        dirnum = myrank % ndirs;
        dirthreads = nthreads / ndirs;
        if (nthreads > (ndirs * dirthreads + dirnum))
                ++dirthreads;

        offset = myrank / ndirs;

        tmpend = begin + nfiles - 1;
        if (tmpend <= 0)
                tmpend = INT_MAX;

        end = begin + (nfiles / dirthreads) * dirthreads + offset;
        if ((end > tmpend) || (end <= 0))
                end -= dirthreads;

	/* make sure mnt_count <= nthreads, otherwise it might div 0 in
	 * the following test */
	if (mnt_count > nthreads)
		mnt_count = nthreads;

        begin += offset;
        if (begin < 0)
                begin = INT_MAX;

	beginsave = begin;

        dmesg("%d: iters %d nfiles %d time %d begin %d end %d dirthreads %d."
              "\n", myrank, iters, nfiles, seconds, begin, end, dirthreads);

        if (dirfmt == NULL) {
                strcpy(dir, ".");
        } else {
		int dir_len = 0;

		if (mntfmt != NULL) {
			sprintf(dir, mntfmt, (myrank / (nthreads/mnt_count)));
			strcat(dir, "/");
			dir_len = strlen(dir);
		}
		sprintf(dir + dir_len, dirfmt, dirnum);

		if (mdt_count > 1) {
			struct stat sb;
			if (stat(dir, &sb) == 0) {
				if (!S_ISDIR(sb.st_mode))
					fatal(myrank, "'%s' is not dir\n", dir);
			} else if (errno == ENOENT) {
				sprintf(mkdir_cmd, "lfs mkdir -i %d %s",
					myrank % mdt_count, dir);
			} else {
				fatal(myrank, "'%s' stat failed\n", dir);
			}
		} else {
			sprintf(mkdir_cmd, "mkdir -p %s", dir);
		}

		dmesg("%d: %s\n", myrank, mkdir_cmd);
#ifdef _LIGHTWEIGHT_KERNEL
		printf("NOTICE: not running system(%s)\n", mkdir_cmd);
#else
		rc = system(mkdir_cmd);
		if (rc)
			fatal(myrank, "'%s' failed.\n", mkdir_cmd);
#endif

                rc = chdir(dir);
                if (rc) {
                        fatal(myrank, "unable to chdir to '%s'.\n", dir);
                }
        }
}

static inline char *next_file()
{
        if (order == RANDOM) {
                sprintf(filename, filefmt, random() % nfiles);
                return(filename);
        }

        /* readdir order */

        dir_entry = readdir(directory);
        if (dir_entry == NULL) {
                rewinddir(directory);
                while ((dir_entry = readdir(directory)) != NULL) {
                        if (dir_entry->d_name[0] != '.')
                                return(dir_entry->d_name);
                }

                fatal(myrank, "unable to read directory %s (%s).\n",
                      dir, strerror(errno));
        }

        return(dir_entry->d_name);
}

int
main(int argc, char *argv[])
{
        int    i, j, fd, rc, nops, lastOps;
        int ag_ops = 0;
        double ag_interval = 0;
        double ag_rate = 0;
        double rate, avg_rate, effective_rate;
        double startTime, curTime, lastTime, interval;
        time_t timestamp;
        char * file;

        rc = MPI_Init(&argc, &argv);
        if (rc != MPI_SUCCESS)
                fatal(myrank, "MPI_Init failed: %d\n", rc);

        rc = MPI_Comm_size(MPI_COMM_WORLD, &nthreads);
        if (rc != MPI_SUCCESS)
                fatal(myrank, "MPI_Comm_size failed: %d\n", rc);

        rc = MPI_Comm_rank(MPI_COMM_WORLD, &myrank);
        if (rc != MPI_SUCCESS)
                fatal(myrank, "MPI_Comm_rank failed: %d\n", rc);

        process_args(argc, argv);

        timestamp = time(0);
        if ((myrank == 0) || debug) {
        	printf("%d: %s starting at %s",
		       myrank, hostname, ctime(&timestamp));
	}

        /* if we're not measuring creation rates then precreate
         * the files we're operating on. */
        if ((mode != CREATE) && (mode != MKNOD) && !ignore &&
            (mode != UNLINK || recreate)) {
                /* create the files in reverse order. When we encounter
                 * a file that already exists, assume the remainder of 
                 * the files exist to save time. The timed performance
                 * test scripts make use of this behavior. */
                for (i = end, j = 0; i >= begin; i -= dirthreads) {
                        sprintf(filename, filefmt, i);
                        fd = open(filename, openflags, 0644);
                        if (fd < 0) {
                                if (errno == EEXIST)
                                        break;
                                rc = errno;
                                fatal(myrank, "precreate open(%s) error: %s\n",
                                      filename, strerror(rc));
                        }
                        j++;
                        close(fd);
                }
                dmesg("%d: %s pre-created %d files.\n",myrank,hostname,j);

                rc = MPI_Barrier(MPI_COMM_WORLD);
                if (rc != MPI_SUCCESS)
                        fatal(myrank, "prep MPI_Barrier failed: %d\n", rc);
        }

        if (order == READDIR) {
                directory = opendir(dir);
                if (directory == NULL) {
                        rc = errno;
                        fatal(myrank, "opendir(%s) error: %s\n",
                              dir, strerror(rc));
                }

                timestamp = time(0);
                j = random() % nfiles;
                dmesg("%d: %s initializing dir offset %u: %s",
                      myrank, hostname, j, ctime(&timestamp));

                for (i = 0; i <= j; i++) {
                        if ((dir_entry = readdir(directory)) == NULL) {
                                fatal(myrank, "could not read entry number %d "
                                      "in directory %s.\n", i, dir);
                        }
                }

                timestamp = time(0);
                dmesg("%d: index %d, filename %s, offset %ld: "
                      "%s initialization complete: %s",
                      myrank, i, dir_entry->d_name, telldir(directory),
                      hostname, ctime(&timestamp));
        }

        if (seconds) {
                act.sa_handler = sigalrm_handler;
                (void)sigemptyset(&act.sa_mask);
                act.sa_flags = 0;
                sigaction(SIGALRM, &act, NULL);
                alarm(seconds);
        }

        rc = MPI_Barrier(MPI_COMM_WORLD);
        if (rc != MPI_SUCCESS)
                fatal(myrank, "prep MPI_Barrier failed: %d\n", rc);

        startTime = lastTime = MPI_Wtime();
        nops = lastOps = 0;

        switch (mode) {
        case CREATE:
                for (; begin <= end && !alarm_caught; begin += dirthreads) {
                        sprintf(filename, filefmt, begin);
                        if ((fd = open(filename, openflags, 0644)) < 0) {
                                if (((rc = errno) == EINTR) && alarm_caught)
                                        break;
                                fatal(myrank, "open(%s) error: %s\n",
                                      filename, strerror(rc));
                        }

                        close(fd);
                        nops++;
                        DISPLAY_PROGRESS();
                }

                dmesg("%d: created %d files, last file '%s'.\n",
                      myrank, nops, filename);
                break;
#ifdef HAVE_MDC_LOOKUP
        case LOOKUP:
                fd = open(dir, O_RDONLY);
                if (fd < 0) {
                        fatal(myrank, "open(dir == '%s') error: %s\n",
                              dir, strerror(errno));
                }

                for (; nops < iters && !alarm_caught;) {
                        char *filename = next_file();
                        rc = llapi_file_lookup(fd, filename);
                        if (rc < 0) {
                                if (((rc = errno) == EINTR) && alarm_caught)
                                        break;
                                fatal(myrank, "llapi_file_lookup(%s) "
                                      "error: %s\n", filename, strerror(rc));
                        }

                        nops++;
                        DISPLAY_PROGRESS();
                }
                break;
#endif
        case MKNOD:
                for (; begin <= end && !alarm_caught; begin += dirthreads) {
                        sprintf(filename, filefmt, begin);
                        rc = mknod(filename, S_IFREG| 0644, 0);
                        if (rc) {
                                if (((rc = errno) == EINTR) && alarm_caught)
                                        break;
                                fatal(myrank, "mknod(%s) error: %s\n",
                                      filename, strerror(rc));
                        }

                        nops++;
                        DISPLAY_PROGRESS();
                }
                break;
        case OPEN:
                for (; nops < iters && !alarm_caught;) {
                        file = next_file();
                        if ((fd = open(file, openflags, 0644)) < 0) {
                                if (((rc = errno) == EINTR) && alarm_caught)
                                        break;
                                fatal(myrank, "open(%s) error: %s\n",
                                      file, strerror(rc));
                        }

                        close(fd);

                        nops++;
                        DISPLAY_PROGRESS();
                }
                break;
        case STAT:
                for (; begin <= end && !alarm_caught; begin += dirthreads) {
                        sprintf(filename, filefmt, begin);
                        rc = stat(filename, &statbuf);
                        if (rc) {
                                if (((rc = errno) == EINTR) && alarm_caught)
                                        break;
                                if (((rc = errno) == ENOENT) && ignore)
                                        continue;
                                fatal(myrank, "stat(%s) error: %s\n",
                                      filename, strerror(rc));
                        }

                        nops++;
                        DISPLAY_PROGRESS();
                }
                break;
        case UNLINK:
                for (; begin <= end && !alarm_caught; begin += dirthreads) {
                        sprintf(filename, filefmt, begin);
                        rc = unlink(filename);
                        if (rc) {
                                if (((rc = errno) == EINTR) && alarm_caught)
                                        break;
                                if ((rc = errno) == ENOENT) {
                                        if (ignore)
                                                continue;
                                        /* no more files to unlink */
                                        break;
                                }
                                fatal(myrank, "unlink(%s) error: %s\n",
                                      filename, strerror(rc));
                        }

                        nops++;
                        DISPLAY_PROGRESS();
                }
                break;
        }

        rc = MPI_Barrier(MPI_COMM_WORLD);
        if (rc != MPI_SUCCESS)
               fatal(myrank, "prep MPI_Barrier failed: %d\n", rc);
        curTime = MPI_Wtime();
        interval = curTime - startTime;
        rate = (double) (nops) / interval;

        rc = MPI_Reduce(&nops, &ag_ops, 1, MPI_INT, MPI_SUM, 0,
                        MPI_COMM_WORLD);
        if (rc != MPI_SUCCESS) {
                fatal(myrank, "Failure in MPI_Reduce of total ops.\n");
        }

        rc = MPI_Reduce(&interval, &ag_interval, 1, MPI_DOUBLE, MPI_SUM, 0,
                        MPI_COMM_WORLD);
        if (rc != MPI_SUCCESS) {
                fatal(myrank, "Failure in MPI_Reduce of total interval.\n");
        }

        rc = MPI_Reduce(&rate, &ag_rate, 1, MPI_DOUBLE, MPI_SUM, 0,
                        MPI_COMM_WORLD);
        if (rc != MPI_SUCCESS) {
                fatal(myrank, "Failure in MPI_Reduce of aggregated rate.\n");
        }

        if (myrank == 0) {

                curTime = MPI_Wtime();
                interval = curTime - startTime;
                effective_rate = (double) ag_ops / interval;
                avg_rate = (double) ag_ops / ag_interval;

                printf("Rate: %.2f eff %.2f aggr %.2f avg client %ss/sec "
                       "(total: %d threads %d %ss %d dirs %d threads/dir %.2f secs)\n",
                       effective_rate, ag_rate, avg_rate, cmd, nthreads, ag_ops,
                       cmd, ndirs, dirthreads, interval);
                if (mode == UNLINK && !recreate && !ignore && ag_ops != nfiles)
                        printf("Warning: only unlinked %d files instead of %d"
                               "\n", ag_ops, nfiles);
        }

        if (recreate) {
                for (begin = beginsave; begin <= end; begin += dirthreads) {
                        sprintf(filename, filefmt, begin);
                        if ((fd = open(filename, openflags, 0644)) < 0) {
                                rc = errno;
				if (rc == EEXIST)
					break;
                                fatal(myrank, "recreate open(%s) error: %s\n",
                                      filename, strerror(rc));
                        }

                        close(fd);
                }
        }

        timestamp = time(0);
        if ((myrank == 0) || debug) {
        	printf("%d: %s finished at %s",
		       myrank, hostname, ctime(&timestamp));
	}

        MPI_Finalize();
        return(0);
}
