/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Robert Read <rread@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */


#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/mount.h>
#include <mntent.h>
#include <getopt.h>

#include "obdctl.h"
#include <portals/ptlctl.h>

int verbose;
int nomtab;
int fake;
int force;
static char *progname = NULL;

typedef struct {
        ptl_nid_t gw;
        ptl_nid_t lo;
        ptl_nid_t hi;
} llmount_route_t;

#define MAX_ROUTES  1024
int route_index;
ptl_nid_t lmd_cluster_id = 0;
llmount_route_t routes[MAX_ROUTES];

void usage(FILE *out)
{
        fprintf(out, "usage: %s <mdsnode>:/<mdsname>/<cfgname> <mountpt> "
                "[-fhnv] [-o mntopt]\n", progname);
        fprintf(out, "\t<mdsnode>: hostname or nid of MDS (config) node\n"
                "\t<mdsname>: name of MDS service (e.g. mds1)\n"
                "\t<cfgname>: name of client config (e.g. client)\n"
                "\t<mountpt>: filesystem mountpoint (e.g. /mnt/lustre)\n"
                "\t-f|--fake: fake mount (updates /etc/mtab)\n"
                "\t--force: force mount even if already in /etc/mtab\n"
                "\t-h|--help: print this usage message\n"
                "\t-n|--nomtab: do not update /etc/mtab after mount\n"
                "\t-v|--verbose: print verbose config settings\n"
                "\t-o: filesystem mount options:\n"
                "\t\tnettype={tcp,elan,iibnal,lonal}: network type\n"
                "\t\tcluster_id=0xNNNN: cluster this node is part of\n"
                "\t\tlocal_nid=0xNNNN: client ID (default ipaddr or nodenum)\n"
                "\t\tserver_nid=0xNNNN: server node ID (default mdsnode)\n"
                "\t\tport=NNN: server port (default 988 for tcp)\n"
                "\t\troute=<gw>[-<gw>]:<low>[-<high>]: portal route to MDS\n");
        exit(out != stdout);
}

static int check_mtab_entry(char *spec, char *mtpt, char *type)
{
        FILE *fp;
        struct mntent *mnt;

        if (!force) {
                fp = setmntent(MOUNTED, "r");
                if (fp == NULL)
                        return(0);

                while ((mnt = getmntent(fp)) != NULL) {
                        if (strcmp(mnt->mnt_fsname, spec) == 0 &&
                            strcmp(mnt->mnt_dir, mtpt) == 0 &&
                            strcmp(mnt->mnt_type, type) == 0) {
                                fprintf(stderr, "%s: according to %s %s is "
                                        "already mounted on %s\n",
                                        progname, MOUNTED, spec, mtpt);
                                return(1); /* or should we return an error? */
                        }
                }
                endmntent(fp);
        }
        return(0);
}

static int
update_mtab_entry(char *spec, char *mtpt, char *type, char *opts,
                  int flags, int freq, int pass)
{
        FILE *fp;
        struct mntent mnt;
        int rc = 0;

        mnt.mnt_fsname = spec;
        mnt.mnt_dir = mtpt;
        mnt.mnt_type = type;
        mnt.mnt_opts = opts ? opts : "";
        mnt.mnt_freq = freq;
        mnt.mnt_passno = pass;

        fp = setmntent(MOUNTED, "a+");
        if (fp == NULL) {
                fprintf(stderr, "%s: setmntent(%s): %s:",
                        progname, MOUNTED, strerror (errno));
                rc = 16;
        } else {
                if ((addmntent(fp, &mnt)) == 1) {
                        fprintf(stderr, "%s: addmntent: %s:",
                                progname, strerror (errno));
                        rc = 16;
                }
                endmntent(fp);
        }

        return rc;
}

int
init_options(struct lustre_mount_data *lmd)
{
        memset(lmd, 0, sizeof(*lmd));
        lmd->lmd_magic = LMD_MAGIC;
        lmd->lmd_server_nid = PTL_NID_ANY;
        lmd->lmd_local_nid = PTL_NID_ANY;
        lmd->lmd_port = 988;    /* XXX define LUSTRE_DEFAULT_PORT */
        lmd->lmd_nal = SOCKNAL;
        return 0;
}

int
print_options(struct lustre_mount_data *lmd)
{
        int i;

        printf("mds:             %s\n", lmd->lmd_mds);
        printf("profile:         %s\n", lmd->lmd_profile);
        printf("server_nid:      "LPX64"\n", lmd->lmd_server_nid);
        printf("local_nid:       "LPX64"\n", lmd->lmd_local_nid);
        printf("nal:             %x\n", lmd->lmd_nal);
        printf("server_ipaddr:   0x%x\n", lmd->lmd_server_ipaddr);
        printf("port:            %d\n", lmd->lmd_port);

        for (i = 0; i < route_index; i++)
                printf("route:           "LPX64" : "LPX64" - "LPX64"\n",
                       routes[i].gw, routes[i].lo, routes[i].hi);

        return 0;
}

static int parse_route(char *opteq, char *opttgts)
{
        char *gw_lo_ptr, *gw_hi_ptr, *tgt_lo_ptr, *tgt_hi_ptr;
        ptl_nid_t gw_lo, gw_hi, tgt_lo, tgt_hi;

        opttgts[0] = '\0';
        gw_lo_ptr = opteq + 1;
        if (!(gw_hi_ptr = strchr(gw_lo_ptr, '-'))) {
                gw_hi_ptr = gw_lo_ptr;
        } else {
                gw_hi_ptr[0] = '\0';
                gw_hi_ptr++;
        }

        if (ptl_parse_nid(&gw_lo, gw_lo_ptr) != 0) {
                fprintf(stderr, "%s: can't parse NID %s\n", progname,gw_lo_ptr);
                return(1);
        }

        if (ptl_parse_nid(&gw_hi, gw_hi_ptr) != 0) {
                fprintf(stderr, "%s: can't parse NID %s\n", progname,gw_hi_ptr);
                return(1);
        }

        tgt_lo_ptr = opttgts + 1;
        if (!(tgt_hi_ptr = strchr(tgt_lo_ptr, '-'))) {
                tgt_hi_ptr = tgt_lo_ptr;
        } else {
                tgt_hi_ptr[0] = '\0';
                tgt_hi_ptr++;
        }

        if (ptl_parse_nid(&tgt_lo, tgt_lo_ptr) != 0) {
                fprintf(stderr, "%s: can't parse NID %s\n",progname,tgt_lo_ptr);
                return(1);
        }

        if (ptl_parse_nid(&tgt_hi, tgt_hi_ptr) != 0) {
                fprintf(stderr, "%s: can't parse NID %s\n",progname,tgt_hi_ptr);
                return(1);
        }

        while (gw_lo <= gw_hi) {
                if (route_index >= MAX_ROUTES) {
                        fprintf(stderr, "%s: to many routes %d\n",
                                progname, MAX_ROUTES);
                        return(-1);
                }

                routes[route_index].gw = gw_lo;
                routes[route_index].lo = tgt_lo;
                routes[route_index].hi = tgt_hi;
                route_index++;
                gw_lo++;
        }

        return(0);
}

/*****************************************************************************
 *
 * This part was cribbed from util-linux/mount/mount.c.  There was no clear
 * license information, but many other files in the package are identified as
 * GNU GPL, so it's a pretty safe bet that was their intent.
 *
 ****************************************************************************/
struct opt_map {
        const char *opt;        /* option name */
        int skip;               /* skip in mtab option string */
        int inv;                /* true if flag value should be inverted */
        int mask;               /* flag mask value */
};

static const struct opt_map opt_map[] = {
  { "defaults", 0, 0, 0         },      /* default options */
  { "rw",       1, 1, MS_RDONLY },      /* read-write */
  { "ro",       0, 0, MS_RDONLY },      /* read-only */
  { "exec",     0, 1, MS_NOEXEC },      /* permit execution of binaries */
  { "noexec",   0, 0, MS_NOEXEC },      /* don't execute binaries */
  { "suid",     0, 1, MS_NOSUID },      /* honor suid executables */
  { "nosuid",   0, 0, MS_NOSUID },      /* don't honor suid executables */
  { "dev",      0, 1, MS_NODEV  },      /* interpret device files  */
  { "nodev",    0, 0, MS_NODEV  },      /* don't interpret devices */
  { "async",    0, 1, MS_SYNCHRONOUS},  /* asynchronous I/O */
  { "auto",     0, 0, 0         },      /* Can be mounted using -a */
  { "noauto",   0, 0, 0         },      /* Can  only be mounted explicitly */
  { "nousers",  0, 1, 0         },      /* Forbid ordinary user to mount */
  { "nouser",   0, 1, 0         },      /* Forbid ordinary user to mount */
  { "noowner",  0, 1, 0         },      /* Device owner has no special privs */
  { "_netdev",  0, 0, 0         },      /* Device accessible only via network */
  { NULL,       0, 0, 0         }
};
/****************************************************************************/

static int parse_one_option(const char *check, int *flagp)
{
        const struct opt_map *opt;

        for (opt = &opt_map[0]; opt->opt != NULL; opt++) {
                if (strcmp(check, opt->opt) == 0) {
                        if (opt->inv)
                                *flagp &= ~(opt->mask);
                        else
                                *flagp |= opt->mask;
                        return 1;
                }
        }
        return 0;
}

int parse_options(char *options, struct lustre_mount_data *lmd, int *flagp)
{
        ptl_nid_t nid = 0, cluster_id = 0;
        int val;
        char *opt, *opteq, *opttgts;

        *flagp = 0;
        /* parsing ideas here taken from util-linux/mount/nfsmount.c */
        for (opt = strtok(options, ","); opt; opt = strtok(NULL, ",")) {
                if ((opteq = strchr(opt, '='))) {
                        val = atoi(opteq + 1);
                        *opteq = '\0';
                        if (!strcmp(opt, "nettype")) {
                                lmd->lmd_nal = ptl_name2nal(opteq + 1);
                                if (lmd->lmd_nal < 0) {
                                        fprintf(stderr, "%s: can't parse NET "
                                                "%s\n", progname, opteq + 1);
                                        return (1);
                                }
                        } else if(!strcmp(opt, "cluster_id")) {
                                if (ptl_parse_nid(&cluster_id, opteq+1) != 0) {
                                        fprintf(stderr, "%s: can't parse NID "
                                                "%s\n", progname, opteq+1);
                                        return (1);
                                }
                                lmd_cluster_id = cluster_id;
                        } else if(!strcmp(opt, "route")) {
                                if (!(opttgts = strchr(opteq + 1, ':'))) {
                                        fprintf(stderr, "%s: Route must be "
                                                "of the form: route="
                                                "<gw>[-<gw>]:<low>[-<high>]\n",
                                                progname);
                                        return(1);
                                }
                                parse_route(opteq, opttgts);
                        } else if (!strcmp(opt, "local_nid")) {
                                if (ptl_parse_nid(&nid, opteq + 1) != 0) {
                                        fprintf(stderr, "%s: "
                                                "can't parse NID %s\n",
                                                progname,
                                                opteq+1);
                                        return (1);
                                }
                                lmd->lmd_local_nid = nid;
                        } else if (!strcmp(opt, "server_nid")) {
                                if (ptl_parse_nid(&nid, opteq + 1) != 0) {
                                        fprintf(stderr, "%s: "
                                                "can't parse NID %s\n",
                                                progname, opteq + 1);
                                        return (1);
                                }
                                lmd->lmd_server_nid = nid;
                        } else if (!strcmp(opt, "port")) {
                                lmd->lmd_port = val;
                        } else {
                                fprintf(stderr, "%s: unknown option '%s'\n",
                                        progname, opt);
                                usage(stderr);
                        }
                } else {
                        if (parse_one_option(opt, flagp))
                                continue;

                        fprintf(stderr, "%s: unknown option '%s'\n",
                                progname, opt);
                        usage(stderr);
                }
        }
        return 0;
}

int
get_local_elan_id(char *fname, char *buf)
{
        FILE *fp = fopen(fname, "r");
        int   rc;

        if (fp == NULL)
                return 1;

        rc = fscanf(fp, "NodeId %255s", buf);

        fclose(fp);

        return (rc == 1) ? 0 : -1;
}

int
set_local(struct lustre_mount_data *lmd)
{
        /* XXX ClusterID?
         * XXX PtlGetId() will be safer if portals is loaded and
         * initialised correctly at this time... */
        char buf[256], *ptr = buf;
        ptl_nid_t nid;
        int rc;

        if (lmd->lmd_local_nid != PTL_NID_ANY)
                return 0;

        memset(buf, 0, sizeof(buf));

        switch (lmd->lmd_nal) {
        default:
                fprintf(stderr, "%s: Unknown network type: %d\n",
                        progname, lmd->lmd_nal);
                return 1;

        case SOCKNAL:
                /* We need to do this before the mount is started if routing */
                system("/sbin/modprobe ksocknal");
        case TCPNAL:
        case OPENIBNAL:
        case IIBNAL:
        case VIBNAL:
        case RANAL:
                rc = gethostname(buf, sizeof(buf) - 1);
                if (rc) {
                        fprintf (stderr, "%s: can't get local buf: %d\n",
                                 progname, rc);
                        return rc;
                }
                break;
        case QSWNAL: {
                char *pfiles[] = {"/proc/qsnet/elan3/device0/position",
                                  "/proc/qsnet/elan4/device0/position",
                                  "/proc/elan/device0/position",
                                  NULL};
                int   i = 0;

                /* We need to do this before the mount is started if routing */
                system("/sbin/modprobe kqswnal");
                do {
                        rc = get_local_elan_id(pfiles[i], buf);
                } while (rc != 0 && pfiles[++i] != NULL);

                if (rc != 0) {
                        rc = gethostname(buf, sizeof(buf) - 1);
                        if (rc == 0) {
                                char *tmp = ptr;
                                while ((*tmp >= 'a' && *tmp <= 'z') ||
                                       (*tmp >= 'A' && *tmp <= 'Z'))
                                        tmp++;
                                ptr = strsep(&tmp, ".");
                        } else {
                                fprintf(stderr,
                                        "%s: can't read Elan ID from /proc\n",
                                        progname);
                                return 1;
                        }
                }
                break;
        }
        }

        if (ptl_parse_nid (&nid, ptr) != 0) {
                fprintf (stderr, "%s: can't parse NID %s\n", progname, buf);
                return (1);
        }

        lmd->lmd_local_nid = nid + lmd_cluster_id;
        return 0;
}

int
set_peer(char *hostname, struct lustre_mount_data *lmd)
{
        ptl_nid_t nid = 0;
        int rc;

        switch (lmd->lmd_nal) {
        default:
                fprintf(stderr, "%s: Unknown network type: %d\n",
                        progname, lmd->lmd_nal);
                return 1;

        case IIBNAL:
                if (lmd->lmd_server_nid != PTL_NID_ANY)
                        break;
                if (ptl_parse_nid (&nid, hostname) != 0) {
                        fprintf (stderr, "%s: can't parse NID %s\n",
                                 progname, hostname);
                        return (1);
                }
                lmd->lmd_server_nid = nid;
                break;

        case SOCKNAL:
        case TCPNAL:
        case OPENIBNAL:
        case VIBNAL:
        case RANAL:
                if (lmd->lmd_server_nid == PTL_NID_ANY) {
                        if (ptl_parse_nid (&nid, hostname) != 0) {
                                fprintf (stderr, "%s: can't parse NID %s\n",
                                         progname, hostname);
                                return (1);
                        }
                        lmd->lmd_server_nid = nid;
                }

                if (ptl_parse_ipaddr(&lmd->lmd_server_ipaddr, hostname) != 0) {
                        fprintf (stderr, "%s: can't parse host %s\n",
                                 progname, hostname);
                        return (1);
                }
                break;
        case QSWNAL: {
                char buf[64];

                if (lmd->lmd_server_nid != PTL_NID_ANY)
                        break;

                rc = sscanf(hostname, "%*[^0-9]%63[0-9]", buf);
                if (rc != 1) {
                        fprintf (stderr, "%s: can't get elan id from host %s\n",
                                 progname, hostname);
                        return 1;
                }
                if (ptl_parse_nid (&nid, buf) != 0) {
                        fprintf (stderr, "%s: can't parse NID %s\n",
                                 progname, hostname);
                        return (1);
                }
                lmd->lmd_server_nid = nid;

                break;
        }
        }

        return 0;
}

int
build_data(char *source, char *options, struct lustre_mount_data *lmd,
           int *flagp)
{
        char buf[1024];
        char *hostname = NULL, *mds = NULL, *profile = NULL, *s;
        int rc;

        if (lmd_bad_magic(lmd))
                return -EINVAL;

        if (strlen(source) >= sizeof(buf)) {
                fprintf(stderr, "%s: host:/mds/profile argument too long\n",
                        progname);
                return -EINVAL;
        }
        strcpy(buf, source);
        if ((s = strchr(buf, ':'))) {
                hostname = buf;
                *s = '\0';

                while (*++s == '/')
                        ;
                mds = s;
                if ((s = strchr(mds, '/'))) {
                        *s = '\0';
                        profile = s + 1;
                } else {
                        fprintf(stderr, "%s: directory to mount not in "
                                "host:/mds/profile format\n",
                                progname);
                        return(1);
                }
        } else {
                fprintf(stderr, "%s: "
                        "directory to mount not in host:/mds/profile format\n",
                        progname);
                return(1);
        }

        rc = parse_options(options, lmd, flagp);
        if (rc)
                return rc;

        rc = set_local(lmd);
        if (rc)
                return rc;

        rc = set_peer(hostname, lmd);
        if (rc)
                return rc;
        if (strlen(mds) > sizeof(lmd->lmd_mds) + 1) {
                fprintf(stderr, "%s: mds name too long\n", progname);
                return(1);
        }
        strcpy(lmd->lmd_mds, mds);

        if (strlen(profile) > sizeof(lmd->lmd_profile) + 1) {
                fprintf(stderr, "%s: profile name too long\n", progname);
                return(1);
        }
        strcpy(lmd->lmd_profile, profile);

        if (verbose)
                print_options(lmd);
        return 0;
}

static int set_routes(struct lustre_mount_data *lmd) {
       struct portals_cfg pcfg;
       struct portal_ioctl_data data;
       int i, j, route_exists, rc, err = 0;

       register_ioc_dev(PORTALS_DEV_ID, PORTALS_DEV_PATH);

       for (i = 0; i < route_index; i++) {

               /* Check for existing routes so as not to add duplicates */
              for (j = 0; ; j++) {
                      PCFG_INIT(pcfg, NAL_CMD_GET_ROUTE);
                      pcfg.pcfg_nal = ROUTER;
                      pcfg.pcfg_count = j;

                      PORTAL_IOC_INIT(data);
                      data.ioc_pbuf1 = (char*)&pcfg;
                      data.ioc_plen1 = sizeof(pcfg);
                      data.ioc_nid = pcfg.pcfg_nid;

                      rc = l_ioctl(PORTALS_DEV_ID, IOC_PORTAL_NAL_CMD, &data);
                      if (rc != 0) {
                              route_exists = 0;
                              break;
                      }

                      if ((pcfg.pcfg_gw_nal == lmd->lmd_nal) &&
                          (pcfg.pcfg_nid    == routes[i].gw) &&
                          (pcfg.pcfg_nid2   == routes[i].lo) &&
                          (pcfg.pcfg_nid3   == routes[i].hi)) {
                              route_exists = 1;
                              break;
                      }
              }

              if (route_exists)
                      continue;

              PCFG_INIT(pcfg, NAL_CMD_ADD_ROUTE);
              pcfg.pcfg_nid = routes[i].gw;
              pcfg.pcfg_nal = ROUTER;
              pcfg.pcfg_gw_nal = lmd->lmd_nal;
              pcfg.pcfg_nid2 = MIN(routes[i].lo, routes[i].hi);
              pcfg.pcfg_nid3 = MAX(routes[i].lo, routes[i].hi);

              PORTAL_IOC_INIT(data);
              data.ioc_pbuf1 = (char*)&pcfg;
              data.ioc_plen1 = sizeof(pcfg);
              data.ioc_nid = pcfg.pcfg_nid;

              rc = l_ioctl(PORTALS_DEV_ID, IOC_PORTAL_NAL_CMD, &data);
              if (rc != 0) {
                      fprintf(stderr, "%s: Unable to add route "
                              LPX64" : "LPX64" - "LPX64"\n[%d] %s\n",
                              progname, routes[i].gw, routes[i].lo,
                              routes[i].hi, errno, strerror(errno));
                      err = 2;
                      break;
              }
       }

       unregister_ioc_dev(PORTALS_DEV_ID);
       return err;
}

int main(int argc, char *const argv[])
{
        char *source, *target, *options = "";
        int i, nargs = 3, opt, rc, flags;
        struct lustre_mount_data lmd;
        static struct option long_opt[] = {
                {"fake", 0, 0, 'f'},
                {"force", 0, 0, 1},
                {"help", 0, 0, 'h'},
                {"nomtab", 0, 0, 'n'},
                {"options", 1, 0, 'o'},
                {"verbose", 0, 0, 'v'},
                {0, 0, 0, 0}
        };

        progname = strrchr(argv[0], '/');
        progname = progname ? progname + 1 : argv[0];

        while ((opt = getopt_long(argc, argv, "fhno:v", long_opt,NULL)) != EOF){
                switch (opt) {
                case 1:
                        ++force;
                        printf("force: %d\n", force);
                        nargs++;
                        break;
                case 'f':
                        ++fake;
                        printf("fake: %d\n", fake);
                        nargs++;
                        break;
                case 'h':
                        usage(stdout);
                        break;
                case 'n':
                        ++nomtab;
                        printf("nomtab: %d\n", nomtab);
                        nargs++;
                        break;
                case 'o':
                        options = optarg;
                        nargs++;
                        break;
                case 'v':
                        ++verbose;
                        printf("verbose: %d\n", verbose);
                        nargs++;
                        break;
                default:
                        fprintf(stderr, "%s: unknown option '%c'\n",
                                progname, opt);
                        usage(stderr);
                        break;
                }
        }

        if (optind + 2 > argc) {
                fprintf(stderr, "%s: too few arguments\n", progname);
                usage(stderr);
        }

        source = argv[optind];
        target = argv[optind + 1];

        if (verbose) {
                for (i = 0; i < argc; i++)
                        printf("arg[%d] = %s\n", i, argv[i]);
                printf("source = %s, target = %s\n", source, target);
        }

        if (!force && check_mtab_entry(source, target, "lustre"))
                exit(32);

        init_options(&lmd);
        rc = build_data(source, options, &lmd, &flags);
        if (rc) {
                exit(1);
        }

        if (!fake) {
                rc = set_routes(&lmd);
                if (rc)
                        exit(2);
        }

        rc = access(target, F_OK);
        if (rc) {
                rc = errno;
                fprintf(stderr, "%s: %s inaccessible: %s\n", progname, target,
                        strerror(errno));
                return 1;
        }

        if (!fake)
                rc = mount(source, target, "lustre", flags, (void *)&lmd);
        if (rc) {
                fprintf(stderr, "%s: mount(%s, %s) failed: %s\n", source,
                        target, progname, strerror(errno));
                if (errno == ENODEV)
                        fprintf(stderr, "Are the lustre modules loaded?\n"
                             "Check /etc/modules.conf and /proc/filesystems\n");
                rc = 32;
        } else if (!nomtab) {
                rc = update_mtab_entry(source, target, "lustre", options,0,0,0);
        }
        return rc;
}
