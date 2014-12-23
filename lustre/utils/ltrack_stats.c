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
 *
 * Copyright (c) 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/utils/ltrack_stats.c
 *
 * Author: Milind Dumbare <milind@clusterfs.com>
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <glob.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define TRACK_BY_GID 0
#define TRACK_BY_PPID 1
#define TRACK_BY_PID 2
#define TRACK_FOR_ALL 3

/* We can have at the most 1024 llstats monitoring 1024 lustre clients
 * at a time */
#define NO_OF_CLIENTS 1024

/* length of absolute path of vfs_ops_stats */
#define LEN_STATS 1024

/* Length of llstat command with all its switches and command line options */
#define LEN_LLSTAT (25 + LEN_STATS)

/* strlen of each lustre client entry in /proc/fs/lustre/llite/ */
#define LEN_CLIENT 1024

/* size of output of llstat command we read at a time */
#define LLSTAT_READ_SIZE 1024

/* Length of command given on command line */
#define COMM_LEN 4096

/* print usage */
void print_usage()
{
        printf("Usage:\n\n");
        printf("ltrack_stats runs command given and does one of the "
                "following:\n"
                "\t1. Writes its pid to "
                "/proc/fs/lustre/llite/.../stats_track_pid\n"
                " to collects stats for that process.\n"
                "\t2. Writes its ppid to "
                "/proc/fs/lustre/llite/.../stats_track_ppid\n"
                " to collect stats of that process and all its children \n"
                "\t3. Sets gid of process to some random gid (444) and also\n"
                " writes that to/proc/fs/lustre/llite/.../stats_track_gid to"
                " collect stats \nof all processes in that group\n\n"
                " It also uses llstat to generate output with interval of 1 "
                " second and duration\n of run of command for plot-llstat to "
                "generate a graph\n\n");
        printf("ltrack_stats [-l filename] [-g <gid> | -a | -i | -c | -h ]\n"
               "\t<command with arguments ...>\n\n");
        printf("-l: outputs the llstat.pl's output to given <filename>"
               "with interval of 1 second \nbetween each output and flag for"
               "graphable output. If -l flag is not given llstat \nwont be"
               "executed\n\n");

        printf("-g: for displaying VFS operation statistics collected"
               "for all processes having \ngroup id as given <gid> \n\n");

        printf("-a: for displaying VFS operations statistics collected"
               "for all processes\n\n");

        printf("-i: for displaying VFS operation statistics collected"
               "for only given <command's> \nPID.\n\n");

        printf("-c: for displaying VFS operation statistics collected"
               " for all processes whose \nparents' PID is same as pid of "
               "<command> to be executed\n\n");

        printf("-h: for showing this help\n");
}

/* - type: to which file data should be written to track VFS operations
 * statistics
 * - id: we either need to write gid which is given on command line or pid
 * to collect statistics of that process or its children. */

void write_track_xid(int type, unsigned short id, char* stats_path)
{
        FILE *fp;

        /* for loop is used if we have more than one lustre clients on same
         * machine. glob() return /proc entry for each lustre client */

        switch(type) {
                case TRACK_BY_GID:
                        strcat(stats_path, "/stats_track_gid");
                        break;
                case TRACK_BY_PPID:
                        strcat(stats_path, "/stats_track_ppid");
                        break;
                case TRACK_BY_PID:
                        strcat(stats_path, "/stats_track_pid");
                        break;
        }

        fp = fopen(stats_path, "w+");
        if (!fp) {
                fprintf(stderr, "Error: Couldn't open /proc entry file: %s\n",
                        stats_path);
                exit(1);
        }
        if (fprintf(fp, "%d", id) < 0) {
                fprintf(stderr, "Error: Couldn't write id to tracking /proc"
                        "entry file: %s\n", stats_path);
                exit(1);
        }
        if (fclose(fp)) {
                fprintf(stderr, "Error: Couldn't close tracking /proc entry"
                        " file: %s\n", stats_path);
                exit(1);
        }
}

/* Get extra command lines concatenated to "command Function getopt scans
 *  one switch and its optional argument. So if command line is 
 * "-g 1234 make bzImage" 1234 is optarg and "make bzImage" will be collected
 *  with following function to exec it. */
char* get_command_from_argv(int optind, int argc, char** argv,char* optarg,
                            char* command)
{
        int index = 0;

        strcpy(command, optarg);
        strcat(command, " ");
        for (index = optind; index < argc; index++) {
                strcat(command, argv[index]);
                strcat(command, " ");
        }
        if (strlen(command) == 1) {
                fprintf(stderr,"Error: command missing \n");
                print_usage();
                exit(1);
        } else if (strlen(command) > COMM_LEN) {
                fprintf(stderr,"Error: Too long command \n");
                print_usage();
                exit(1);
        }

        return command;
}

/* Check for the llstat command in $PATH env variable. */
void check_llstat()
{
        int status;

        status = system("which llstat.pl &> /dev/null");
        if (status) {
                fprintf(stderr,"Error: llstat.pl not found in PATH\n");
                exit(1);
        }
}

pid_t fork_llstat_command(char* llstat_file,char* stats_path)
{
	char truncate_command[100];
	char llstat_command[LEN_LLSTAT];
	pid_t pid_llstat_command;
	FILE *fp_popen, *fp_out;
	char buffer[LLSTAT_READ_SIZE];
	int ret;
        
        /* Truncating llstat output file as it will be opened in while
         * loop to append output */
        sprintf(truncate_command,"> %s",llstat_file);
        if ((ret = system(truncate_command)) != 0) {
                ret = WEXITSTATUS(ret);
                printf("error excuting truncate command: %d\n", ret);
                exit(ret);
        }

        strcat(stats_path, "/stats");

        /* creating a string of llstat command to give to
         * popen */
        sprintf(llstat_command, "llstat -i 1 -g %s ",
                stats_path);

        /* fork for llstat */
        if ((pid_llstat_command = fork()) < 0)
                fprintf(stderr, "Error: Fork error\n");

        /* in child (llstat) */
        if (pid_llstat_command == 0) {
                /* Doing popen for llstat command */
                fp_popen = popen(llstat_command, "r");
                if (fp_popen == NULL) {
                        fprintf(stderr,"Couldn't popen the llstat command:"
                                "\"%s\"n", llstat_command);
                        exit(1);
                }
		while (fgets(buffer, LLSTAT_READ_SIZE, fp_popen) != NULL) {
			/* Following code should be in while loop as llstat
			 * will keep on sending output each second and will
			 * not exit on itself. It will be killed when we finsh
			 * with our command so we must make the output file
			 * consistent after writing each 1024 bytes chunk */

			/* opening file where llstat will write its output */
			fp_out = fopen(llstat_file, "a");
			if (!fp_out) {
				fprintf(stderr, "Error: Couldn't open llstat"
					"outfile file: %s\n",
					llstat_file);
				exit(1);
			}
			/* fgets reads the popen output and fprintf writes it to
			 * output file */

			if (fputs(buffer, fp_out) == EOF) {
				fprintf(stderr, "Error: Couldn't write output"
					"of llstat to out file\n");
				exit(1);
			}

			/* closing file opened for storing llstat's output */
			if (fclose(fp_out)) {
				fprintf(stderr, "Error: Couldn't close llstat"
					"outfile: %s\n", llstat_file);
				exit(1);
			}
		}
                /* closing popen for llstat */
                if (pclose(fp_popen) < 0) {
                        fprintf(stderr, "Error: Couldn't pclos"
                                " llstat popen call\n");
                        exit(1);
                }
        } /* child ends */
        return pid_llstat_command;
}

pid_t fork_actual_command(int type, unsigned short id, char* stats_path,
                          char* command)
{
        pid_t pid;

        /* starting ltrack_stats functionality here */
        if ((pid = fork()) < 0)
                fprintf(stderr, "Error: Fork error\n");

        /* fork for executing command */
        if (pid == 0) {
                switch(type) {
                        case TRACK_BY_GID:
                                if (setgid(id) < 0) {
                                        fprintf(stderr, "Error: failed to"
                                               " setgid\n");
                                        exit(1);
                                }
                                pid = id;
                                break;

                        case TRACK_BY_PID:
                        case TRACK_BY_PPID:
                                pid = getpid();
                                break;

                        /* 0 has to be written to vfs_track_pid to collect 
                         * statistics of all processes */
                        case TRACK_FOR_ALL:
                                pid = 0;
                                type = TRACK_BY_PID;
                                break;
                }
                write_track_xid(type, pid, stats_path);
                execl("/bin/sh", "sh", "-c", command, (char *)0);
                exit(0);
        } /* child ends */

        return(pid);
}

char* get_path_stats(int with_llstat, char* stats_path)
{
        glob_t stats_glob_buffer;
        int choice;
        char error = 0;
        int i;

        /* No slots reserved in gl_pathv. Store the found path at 0 location */
        stats_glob_buffer.gl_offs = 0;

        /* doing glob() for attaching llstat to monitor each vfs_ops_stat for
         * mulitiple lustre clients */
        if (glob("/proc/fs/lustre/llite/*", GLOB_DOOFFS, NULL,
                 &stats_glob_buffer) != 0) {
                fprintf(stderr,"Error: Couldn't find /proc entry for "
                        "lustre\n");
                exit(1);
        }

        /* If multiple client entries found in /proc/fs/lustre/llite user will
         * be prompted with choice of all */
        if (stats_glob_buffer.gl_pathc > 1 && with_llstat) {
                check_llstat(); 
                printf("Multiple lustre clients found, continuing... \n");
                do {
                        /* If flow is here again it means there was an error
                         * and notifying that to user */
                        if (error) {
                                int ret;
                                if ((ret = system("clear")) != 0) {
                                        ret = WEXITSTATUS(ret);
                                        printf("error excuting clear command: %d\n", ret);
                                        exit(ret);
                                }
                                fprintf(stderr, "Error: Please give correct "
                                        "choice.\n");
                        }
                        /* Simple menu based interface to avoid possible
                         * spelling mistakes */
                        printf("\t\tMenu.\n");
                        for (i = 0; i < stats_glob_buffer.gl_pathc; i++)
                                printf("\t\t%d. %s\n", i+1, 
                                       stats_glob_buffer.gl_pathv[i]);

                        printf("\nEnter the lustre client number you want to "
                               "use:");
                        if (scanf(" %d", &choice) == EOF && ferror(stdin)) {
                                perror("reading from stdin");
                                exit(-1);
                        }
                        error++;
                } while (choice > stats_glob_buffer.gl_pathc || choice < 1);
                strcpy(stats_path, stats_glob_buffer.gl_pathv[choice - 1]);
        } else {
                /*if only one client then simply copying the path from glob */
                strcpy(stats_path, stats_glob_buffer.gl_pathv[0]);
        }
        /* this frees dynamically allocated space by glob() for storing found
         * paths */
        globfree(&stats_glob_buffer);

        return stats_path;
}

/* Writes the id (gid/ pid/ ppid) value in appropriate tracking proc entry file
 * and EXECs the command given */
void fork_command(int type, unsigned short id, char* command, char* llstat_file)
{
        pid_t pid_actual_command = 0;
        pid_t pid_llstat_command = 0;

        /* counters */
        int with_llstat = 1;
        int status;
        char stats_path[1024];
	char stats_path_temp[1024 + 6]; /* 6=strlen("/stats") */

        if (strlen(llstat_file) == 0)
                with_llstat = 0;

        get_path_stats(with_llstat, stats_path);
        strcpy(stats_path_temp, stats_path);

        /* llstat process attached to monitor given command */
        if (with_llstat)
                pid_llstat_command = fork_llstat_command(llstat_file,
                                                         stats_path_temp);

        /* forking a process which will exec command given */
        pid_actual_command = fork_actual_command(type, id, stats_path,
                                                 command);

        if (waitpid(pid_actual_command, NULL, 0) != pid_actual_command)
                fprintf(stderr, "Error: waitpid error\n");

        if (with_llstat) {
                /* comment #25 of BUG 10968 */
		sleep(2);

                /* sending kill to all llstat commands created for each
                 * lustre-client respectively */
                kill(pid_llstat_command, 9);
                waitpid(pid_llstat_command, &status, 0);

                /* if llstat child is killed by KILL only then print note for
                 * plotting graph and if its exited normally with errornous
                 * status then it means there were some error and llstat was
                 * aborted*/
                if (!WIFEXITED(status))
                        printf("\n\t[Note: Do \"$plot-llstat %s\" to plot a graph"
                               " using GNU plot]\n", llstat_file);

        }
}

/* main */
int main(int argc, char **argv)
{
        char gid_string[5] = "";
        gid_t gid;
        int c;
        char command[COMM_LEN] = "";
        char llstat_file[100] = "";

        /* Checking for root*/
        if (getuid()) {
                fprintf(stderr, "Error: You need to be root\n");
                exit(1);
        }

        opterr = 0;
        /* Parsing command line switches */
        while ((c = getopt(argc, argv, "l:g:c:i:a:h")) != 1)
                switch (c) {
                        case 'l':
				if (strlen(optarg) > sizeof(llstat_file)-1) {
                                        fprintf(stderr, "length of outfile file"
                                                " is too long\n");
                                        exit(1);
				}
				strncpy(llstat_file, optarg,
					sizeof(llstat_file));
                                break;

                        /* When any value is written to vfs_track_gid, then VFS
                         * operation statistics are collected for all
                         * processes of that group ID.
                         * write_track_xid writes given <gid> in vfs_track_gid
                         * here. */
                        case 'g':
				if (strlen(optarg) > sizeof(gid_string)-1)
					return -E2BIG;
				strncpy(gid_string, optarg, sizeof(gid_string));
                                get_command_from_argv(optind, argc, argv, "",
                                                      command);
                                gid = atoi(gid_string);

                                fork_command(TRACK_BY_GID, gid, command,
                                             llstat_file); 
                                return(0);

                        /* When any value is written to vfs_track_ppid, then VFS
                         * operation statistics are collected for all processes
                         * whose parents' PID is same as track_ppid.
                         *- write_track_xid writes pid to vfs_track_ppid here */
                        case 'c':
                                get_command_from_argv(optind, argc, argv,
                                                      optarg, command);
                                fork_command(TRACK_BY_PPID, 0, command,
                                             llstat_file);
                                return(0);

                        /* When a non-zero value is written to vfs_track_pid,
                         * then VFS operation statistics are collected for only
                         * that PID.Write_track_xid writes pid to vfs_track_pid
                         * here.Wei need to FORK a new process and EXEC it with
                         * given <command>. */
                        case 'i':
                                get_command_from_argv(optind, argc, argv,
                                                      optarg, command);
                                fork_command(TRACK_BY_PID, 0, command,
                                             llstat_file);
                                return(0);

                        /* When VFS operation statistics for all processes are
                         * to be collected, "0" is written to vfs_track_pid. */
                        case 'a':
                                get_command_from_argv(optind, argc, argv,
                                                      optarg, command);
                                fork_command(TRACK_FOR_ALL, 0, command,
                                             llstat_file);
                                return(0);

                        /* Help */
                        case 'h':
                                print_usage();
                                return(0);

                        default:
                                print_usage();
                                return(1);
                }
        return(0);
} /* main ends */
