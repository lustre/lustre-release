/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Compile with:
 * cc -I../../portals/include -o mkdirdeep mkdirdeep.c
 *    -L../../portals/linux/utils -lptlctl
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/limits.h>
#include <portals/lltrace.h>

static int opt_depth = 1;
static int opt_mknod = 0;
static int opt_verbose = 0;
static int opt_trace = 1;
static char* basepathname = 0;
static char mycwd[PATH_MAX];
static char* pname = 0;
static char* outputfilename = 0;

void usage()
{
        fprintf(stderr, "Usage: %s --depth <d> --output <outputtracefilename>"
                "[--mknod] [--verbose] [--notrace] <basepath>\n", pname);
        exit(1);
}

int do_mkdir(char* path)
{
        int rc = mkdir(path, 0755);
        if (rc!=0)
                fprintf(stderr, "mkdir(%s) failed: %s\n",
                        path, strerror(errno));
        if (opt_verbose)
                printf("mkdir %s\n", path);
        return rc;
}


int do_mknod(char* path)
{
        int rc = mknod(path, 0755, S_IFIFO);
        if (rc!=0)
                fprintf(stderr, "mkdir(%s) failed: %s\n",
                        path, strerror(errno));
        if (opt_verbose)
                printf("mknod %s\n", path);
        return rc;
}

int do_chdir(char* path)
{
        int rc = chdir(path);
        if (rc!=0)
                fprintf(stderr, "chdir(%s) failed: %s\n",
                        path, strerror(errno));
        if (opt_verbose)
                printf("chdir %s\n", path);

        return rc;
}


int do_stat(char* path)
{
        char mark_buf[PATH_MAX];
        struct stat mystat;
        int rc = stat(path, &mystat);
        if (rc!=0)
                fprintf(stderr, "stat(%s) failed: %s\n",
                        path, strerror(errno));
        if (opt_verbose)
                printf("stat %s = inode %lu\n", path, mystat.st_ino);

        if (opt_trace) {
                snprintf(mark_buf, PATH_MAX, "stat %s = inode %lu",
                         path, mystat.st_ino);
                ltrace_mark(0, mark_buf);
        }

        return rc;
}

int main(int argc, char** argv)
{
        int c, opt_index, i, mypid;

        static struct option long_options[] = {
                {"depth", 1, 0, 0 },
                {"help", 0, 0, 0 },
                {"mknod", 0, 0, 0 },
                {"verbose", 0, 0, 0 },
                {"notrace", 0, 0, 0 },
                {"output", 1, 0, 0 },
                {0,0,0,0}
        };

        char full_pathname[PATH_MAX];
        char rel_pathname[PATH_MAX];
        char mark_buf[PATH_MAX];

        pname = strdup(argv[0]);

        while (1) {
                c = getopt_long(argc, argv, "d:mhv", long_options, &opt_index);
                if (c == -1)
                        break;
                if (c==0) {
                        if (!strcmp(long_options[opt_index].name, "notrace")) {
                                opt_trace = 0;
                                continue;
                        }
                        c = long_options[opt_index].name[0];
                }
                switch (c) {
                case 'd':
                        opt_depth = atoi(optarg);
                        if ((opt_depth == 0) || (opt_depth > 100))
                                usage();
                        break;
                case 'm':
                        opt_mknod = 1;
                        break;
                case 'v':
                        opt_verbose = 1;
                        break;
                case 'o':
                        outputfilename = optarg;
                        break;
                case 'h':
                case '?':
                case ':':
                default:
                        usage();
                        break;
                }
        }

        if (optind != (argc-1))
                usage();

        if (outputfilename == NULL)
                usage();

        basepathname = argv[optind];
        mypid = getpid();

        printf("%s(pid=%d) depth=%d mknod=%d, basepathname=%s, "
               "trace=%d, outputfilename=%s\n",
               pname, mypid, opt_depth, opt_mknod, basepathname, opt_trace,
               outputfilename);

        if (!getcwd(&mycwd[0], sizeof(mycwd))) {
                fprintf(stderr, "%s: unable to getcwd()\n", pname);
                exit(1);
        }

        if (opt_trace) {
                ltrace_start();
                ltrace_clear();
                snprintf(mark_buf, PATH_MAX,
                         "Initialize - mkdir %s; chdir %s",
                         basepathname, basepathname);
                ltrace_mark(2, mark_buf);
        }

        if (do_mkdir(basepathname)!=0)
                exit(1);
        if (do_chdir(basepathname)!=0)
                exit(1);

        /* Create directory tree with depth level of subdirectories */

        if (opt_trace) {
                snprintf(mark_buf, PATH_MAX,
                         "Create Directory Tree (depth %d)", opt_depth);
                ltrace_mark(2, mark_buf);
        }

        for (i=0; i<opt_depth; i++) {

                snprintf(rel_pathname, sizeof(rel_pathname),"%d", i+1);

                 if (i == (opt_depth-1)) {
                         /* Last Iteration */

                         if (opt_trace) {
                                 snprintf(mark_buf, PATH_MAX,
                                          "Tree Leaf (%d) %s/stat", i,
                                          (opt_mknod ? "mknod" : "mkdir"));
                                 ltrace_mark(3, mark_buf);
                         }

                         if (opt_mknod)
                                 do_mknod(rel_pathname);
                         else
                                 do_mkdir(rel_pathname);
                         /* Now stat it */
                         do_stat(rel_pathname);
                 }
                else {
                        /* Not Leaf */

                        if (opt_trace) {
                                snprintf(mark_buf, PATH_MAX,
                                         "Tree Level (%d) mkdir/stat/chdir",
                                         i);
                                ltrace_mark(3, mark_buf);
                        }

                        do_mkdir(rel_pathname);
                        do_stat(rel_pathname);
                        do_chdir(rel_pathname);
                }
        }

        /* Stat through directory tree with fullpaths */

        if (opt_trace) {
                snprintf(mark_buf, PATH_MAX, "Walk Directory Tree");
                ltrace_mark(2, mark_buf);
        }

        do_chdir(basepathname);

        strncpy(full_pathname, basepathname, sizeof(full_pathname));

        for (i=0; i<opt_depth; i++) {
                snprintf(rel_pathname, sizeof(rel_pathname),"%d", i+1);
                strcat(full_pathname, "/");
                strcat(full_pathname, rel_pathname);

                if (opt_trace) {
                        snprintf(mark_buf, PATH_MAX, "stat %s",
                                 full_pathname);
                        ltrace_mark(2, mark_buf);
                }

                do_stat(full_pathname);
        }

        /* Cleanup */

        if (opt_trace) {
                snprintf(mark_buf, PATH_MAX, "Cleanup");
                ltrace_mark(2, mark_buf);
        }

        if (opt_trace) {
                    ltrace_write_file(outputfilename);
                    ltrace_add_processnames(outputfilename);
                    ltrace_stop();
        }

        do_chdir(basepathname);

        snprintf(full_pathname, sizeof(full_pathname),
                 "rm -rf %s\n", basepathname);
        if (opt_verbose)
                printf("Cleanup: %s", full_pathname);

        system(full_pathname);

        printf("%s (pid=%d) done.\n", pname, mypid);
        return 0;
}
