/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

/* for O_DIRECTORY */
#define _GNU_SOURCE

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <dirent.h>
#include <linux/unistd.h>
#include <string.h>

#include <liblustre.h>
#include <linux/obd.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_lite.h>
#include <linux/obd_lov.h>

/* XXX Max obds per lov currently hardcoded to 1000 in lov/lov_obd.c */
#define MAX_LOV_UUID_COUNT	1000
#define OBD_NOT_FOUND		(-1)

char		*cmd;
struct option	 longOpts[] = {
			{"help", 0, 0, 'h'},
			{"obd", 1, 0, 'o'},
			{"quiet", 0, 0, 'q'},
                        {"recursive", 0, 0, 'r'},
			{"verbose", 0, 0, 'v'},
			{0, 0, 0, 0}
		 };
int		 quiet;
int		 verbose;
char		 shortOpts[] = "ho:qrv";
char		 usageMsg[] =
        "[--obd <uuid>] [--quiet | --verbose] [--recursive] <dir|file> ...";

int		 max_ost_count = MAX_LOV_UUID_COUNT;
struct obd_uuid *obduuid;
char		*buf;
int		 buflen;
struct obd_uuid *uuids;
struct obd_ioctl_data data;
struct lov_desc  desc;
int		 uuidslen;
int		 cfglen;
struct lov_mds_md *lmm;
int		 lmmlen;
int              got_uuids;
int              recursive;
int              obdindex = OBD_NOT_FOUND;


void	init();
void	usage(FILE *stream);
void	errMsg(char *fmt, ...);
void    processDir(DIR *dir, char *dname);
void    processFile(DIR *dir, char *dname, char *fname);
void	processPath(char *path);
void    get_obd_uuids(DIR *dir, char *dname);

int main (int argc, char **argv) {
	int c;

	cmd = basename(argv[0]);

	while ((c = getopt_long(argc, argv, shortOpts, longOpts, NULL)) != -1) {
		switch (c) {
		case 'o':
			if (obduuid) {
				fprintf(stderr, "only one obduuid allowed");
				exit(1);
			}

			obduuid = (struct obd_uuid *)optarg;
			break;
		case 'h':
			usage(stdout);
			exit(0);
		case 'q':
			quiet++;
			verbose = 0;
			break;
                case 'r':
                        recursive = 1;
                        break;
		case 'v':
			verbose++;
			quiet = 0;
			break;
		case '?':
			usage(stderr);
			exit(1);
		default:
			printf("option '%s' unrecognized\n", argv[optind - 1]);
			usage(stderr);
			exit(1);
		}
	}

	if (optind >= argc) {
		usage(stderr);
		exit(1);
	}

	init();

	do {
		processPath(argv[optind]);
	} while (++optind < argc);

	exit (0);
}

void init()
{
	int datalen, desclen;

	datalen = size_round(sizeof(data));
	desclen = size_round(sizeof(desc));
	uuidslen = size_round(max_ost_count * sizeof(*uuids));
	cfglen = datalen + desclen + uuidslen;
	lmmlen = lov_mds_md_size(max_ost_count);
	if (cfglen > lmmlen)
		buflen = cfglen;
	else
		buflen = lmmlen;

	/* XXX max ioctl buffer size currently hardcoded to 8192 */
	if (buflen > 8192) {
		int nuuids, remaining, nluoinfos;

		buflen = 8192;
		nuuids = (buflen - datalen - desclen) / sizeof(*uuids);
		uuidslen = size_round(nuuids * sizeof(*uuids));
		remaining = nuuids * sizeof(*uuids);
		if (uuidslen > remaining)
			nuuids--;
		nluoinfos = (buflen - sizeof(*lmm)) / sizeof(*lmm->lmm_objects);
		if (nuuids > nluoinfos)
			max_ost_count = nluoinfos;
		else
			max_ost_count = nuuids;

		cfglen = datalen + desclen + uuidslen;
		lmmlen = lov_mds_md_size(max_ost_count);
	}

	if ((buf = malloc(buflen)) == NULL) {
		errMsg("Unable to allocate %d bytes of memory for ioctl's");
		exit(1);
	}

	lmm = (struct lov_mds_md *)buf;
	uuids = (struct obd_uuid *)buf;
}

void usage(FILE *stream)
{
	fprintf(stream, "usage: %s %s\n", cmd, usageMsg);
}

void errMsg(char *fmt, ...)
{
	va_list args;
	int tmp_errno = errno;

	fprintf(stderr, "%s: ", cmd);
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fprintf(stderr, ": %s (%d)\n", strerror(tmp_errno), tmp_errno);
}

void processPath(char *path)
{
        char *fname, *dname;
        DIR *dir;

        fname = strrchr(path, '/');
        if (fname != NULL && fname[1] == '\0') {
                /* Trailing '/', it must be a dir */
                *fname = '\0';
                dir = opendir(path);
                if (dir == NULL) {
                        errMsg("\"%.40s\" opendir failed", path);
                } else {
                        processDir(dir, path);
                        closedir(dir);
                }
        } else if ((dir = opendir(path)) != NULL) {
                /* No trailing '/', but it is still a dir */
                processDir(dir, path);
                closedir(dir);
        } else {
                /* It must be a file (or other non-directory) */
                if (fname == NULL) {
                        dname = ".";
                        fname = path;
                } else {
                        *fname = '\0';
                        fname++;
                        dname = path;
                }
                dir = opendir(dname);
                if (dir == NULL) {
                        errMsg("\"%.40s\" opendir failed", dname);
                } else {
                        if (!got_uuids)
                                get_obd_uuids(dir, dname);
                        processFile(dir, dname, fname);
                        closedir(dir);
                }
        }
}


void processDir(DIR *dir, char *dname)
{
	struct dirent64 *dirp;
        DIR *subdir;
	char path[1024];

	if (!got_uuids)
                get_obd_uuids(dir, dname);

	/* Handle the contents of the directory */
        while ((dirp = readdir64(dir)) != NULL) {
                if (!strcmp(dirp->d_name, ".") || !strcmp(dirp->d_name, ".."))
                        continue;

                switch (dirp->d_type) {
                case DT_UNKNOWN:
                        errMsg("\"%s\" is UNKNOWN type %d", dirp->d_name,
                               dirp->d_type);
                        /* If we cared we could stat the file to determine
                         * type and continue on here, but we don't since we
                         * know d_type should be valid for lustre and this
                         * tool only makes sense for lustre filesystems. */
                        exit(1);
                        break;
                case DT_DIR:
                        if (!recursive)
                                break;
                        strcpy(path, dname);
                        strcat(path, "/");
                        strcat(path, dirp->d_name);
                        subdir = opendir(path);
                        if (subdir == NULL) {
                                errMsg("\"%.40s\" opendir failed", path);
                                break;
                        }
                        processDir(subdir, path);
                        closedir(subdir);
                        break;
                case DT_REG:
                        processFile(dir, dname, dirp->d_name);
                        break;
                default:
                        /*errMsg("type of \"%s\" is unsupported",
                                dirp->d_name);*/
                        break;
                }
        }
}

void processFile(DIR *dir, char *dname, char *fname)
{
	int rc, i;

	strncpy((char *)lmm, fname, buflen);

	rc = ioctl(dirfd(dir), IOC_MDC_GETSTRIPE, (void *)lmm);
	if (rc) {
		if (errno == ENODATA) {
			if (!obduuid && !quiet)
				fprintf(stderr,
                                        "%s: %s/%s has no stripe info\n",
					cmd, dname, fname);
		} else if (errno == EISDIR) {
			fprintf(stderr, "%s: processFile on directory %s/%s!\n",
				cmd, dname, fname);
			/*
			  add fname to directory list;
                        */
                } else {
			errMsg("IOC_MDC_GETSTRIPE ioctl failed");
		}
		return;
	}

	if ((obduuid && lmm->lmm_objects[obdindex].l_object_id) ||
	    (!obduuid && !quiet))
                printf("%s/%s\n", dname, fname);

        if (verbose) {
                printf("lmm_magic:          0x%x\n", lmm->lmm_magic);
                printf("lmm_object_id:      "LPX64"\n", lmm->lmm_object_id);
                printf("lmm_stripe_offset:  %u\n", (int)lmm->lmm_stripe_offset);
                printf("lmm_stripe_count:   %u\n", (int)lmm->lmm_stripe_count);
                printf("lmm_stripe_size:    %u\n", (int)lmm->lmm_stripe_size);
                printf("lmm_ost_count:      %u\n", lmm->lmm_ost_count);
                printf("lmm_stripe_pattern: %d\n", lmm->lmm_magic & 0xf);
        }

	if (verbose || !obduuid) {
		long long oid;
		int ost = lmm->lmm_stripe_offset;
		int header = !quiet;

		/* FIXME: temporary fix for bug 1612 */
		if (lmm->lmm_ost_count == 0) {
			oid = lmm->lmm_object_id;
			if (header)
				printf("\tobdidx\t\t objid\t\tobjid\n");
			printf("\t%6u\t%14llu\t%13llx\n", 0, oid, oid);
		} else
		for (i = 0; i < lmm->lmm_ost_count; i++, ost++) {
			ost %= lmm->lmm_ost_count;
			if ((oid = lmm->lmm_objects[ost].l_object_id)) {
				if (header) {
					printf("\tobdidx\t\t objid\t\tobjid\n");
					header = 0;
				}
				printf("\t%6u\t%14llu\t%13llx%s\n", ost,
				       oid, oid, obdindex == ost ? " *" : "");
			}
		}
		printf("\n");
	}
}

void get_obd_uuids(DIR *dir, char *dname)
{
	int obdcount;
	struct obd_uuid *uuidp;
	int rc, i;

        got_uuids = 1;
        memset(&data, 0, sizeof(data));
        data.ioc_inllen1 = sizeof(desc);
        data.ioc_inlbuf1 = (char *)&desc;
        data.ioc_inllen2 = uuidslen;
        data.ioc_inlbuf2 = (char *)uuids;

        memset(&desc, 0, sizeof(desc));
        desc.ld_tgt_count = max_ost_count;

        if (obd_ioctl_pack(&data, &buf, buflen)) {
                fprintf(stderr, "%s: internal buffer error from %s\n",
                        cmd, dname);
                return;
        }

        rc = ioctl(dirfd(dir), OBD_IOC_LOV_GET_CONFIG, buf);
        if (rc) {
                errMsg("error getting LOV config from %s", dname);
                return;
        }

        if (obd_ioctl_unpack(&data, buf, buflen)) {
                errMsg("invalid reply from ioctl from %s", dname);
                return;
        }

        obdcount = desc.ld_tgt_count;
        if (obdcount == 0)
                return;

        if (obduuid) {
                for (i = 0, uuidp = uuids; i < obdcount; i++, uuidp++) {
                        if (strncmp(obduuid->uuid, uuidp->uuid,
                                    sizeof(*uuidp)) == 0) {
                                obdindex = i;
                                break;
                        }
                }

                if (obdindex == OBD_NOT_FOUND)
                        return;
        } else if (!quiet) {
                printf("OBDS:\n");
                for (i = 0, uuidp = uuids; i < obdcount; i++, uuidp++)
                        printf("%4d: %s\n", i, uuidp->uuid);
        }
}
