#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdarg.h>
#include <libgen.h>
#include <ftw.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>


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
			{"query", 0, 0, 'q'},
			{"verbose", 0, 0, 'v'},
			{0, 0, 0, 0}
		 };
int		 query;
int		 verbose;
char		 shortOpts[] = "ho:qv";
char		 usageMsg[] = "[ --obd <obd uuid> | --query ] <dir|file> ...";

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
int		 printed_UUIDs;

void	init();
void	usage(FILE *stream);
void	errMsg(char *fmt, ...);
void	processPath(char *path);

int main (int argc, char **argv) {
	int c;

	cmd = basename(argv[0]);

	while ((c = getopt_long(argc, argv, shortOpts, longOpts, NULL)) != -1) {
		switch (c) {
		case 'o':
			if (obduuid) {
				printf("obd '%s' already specified: '%s'\n",
					obduuid->uuid, optarg);
				exit(1);
			}

			obduuid = (struct obd_uuid *)optarg;
			break;
		case 'h':
			usage(stdout);
			exit(0);
		case 'q':
			query++;
			break;
		case 'v':
			verbose++;
			break;
		case '?':
			usage(stderr);
			exit(1);
		default:
			printf("Internal error. Valid '%s' unrecognized\n",
				argv[optind - 1]);
			usage(stderr);
			exit(1);
		}
	}

	if (optind >= argc) {
		usage(stderr);
		exit(1);
	}

	if (obduuid == NULL)
		query++;

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
	int fd;
	int rc;
	int i;
	int obdindex = OBD_NOT_FOUND;
	int obdcount;
	struct obd_uuid *uuidp;
	char *fname, *dirname;

	if ((query || verbose) && !obduuid) {
		printf("%s\n", path);
	}

	fname = strrchr(path, '/');
	if (fname != NULL && fname[1] != '\0') {
		*fname = '\0';
		fname++;
		dirname = path;
	} else if (fname != NULL && fname[1] == '\0') {
		printf("need getdents support\n");
		return;
	} else {
		dirname = ".";
		fname = path;
	}

	if ((fd = open(dirname, O_RDONLY)) < 0) {
		errMsg("open \"%.20s\" failed", dirname);
		return;
	}

	if (!printed_UUIDs) {
		memset(&data, 0, sizeof(data));
		data.ioc_inllen1 = sizeof(desc);
		data.ioc_inlbuf1 = (char *)&desc;
		data.ioc_inllen2 = uuidslen;
		data.ioc_inlbuf2 = (char *)uuids;

		memset(&desc, 0, sizeof(desc));
		desc.ld_tgt_count = max_ost_count;

		if (obd_ioctl_pack(&data, &buf, buflen)) {
			errMsg("internal buffering error");
			exit(1);
		}

		rc = ioctl(fd, OBD_IOC_LOV_GET_CONFIG, buf);
		if (rc) {
			if (errno == ENOTTY) {
				if (!obduuid) {
					errMsg("error getting LOV config");
				}
				return;
			}
			errMsg("OBD_IOC_LOV_GET_CONFIG ioctl failed: %s");
			exit(1);
		}

		if (obd_ioctl_unpack(&data, buf, buflen)) {
			errMsg("Invalid reply from ioctl");
			exit(1);
		}

		obdcount = desc.ld_tgt_count;
		if (obdcount == 0)
			return;

		obdindex = OBD_NOT_FOUND;

		if (obduuid) {
			for (i = 0, uuidp = uuids; i < obdcount; i++, uuidp++) {
				if (strncmp((char *)obduuid, (char *)uuidp,
					sizeof(*uuidp)) == 0) {
					obdindex = i;
				}
			}

			if (obdindex == OBD_NOT_FOUND)
				return;
		} else if (query || verbose) {
			printf("OBDS:\n");
			for (i = 0, uuidp = uuids; i < obdcount; i++, uuidp++)
				printf("%4d: %s\n", i, (char *)uuidp);
		}
		printed_UUIDs = 1;
	}

	strcpy((char *)lmm, fname);
	rc = ioctl(fd, IOC_MDC_GETSTRIPE, (void *)lmm);
	if (rc) {
		if (errno == ENODATA) {
			if (!obduuid)
				printf("Has no stripe information.\n");
		}
		else {
			errMsg("IOC_MDC_GETSTRIPE ioctl failed");
		}
		return;
	}

	close(fd);

	if (obduuid && lmm->lmm_objects[obdindex].l_object_id)
		printf("%s\n", path);

	if (verbose) {
		printf("lmm_magic:          0x%x\n", lmm->lmm_magic);
		printf("lmm_object_id:      "LPX64"\n", lmm->lmm_object_id);
		printf("lmm_stripe_offset:  %u\n", (int)lmm->lmm_stripe_offset);
		printf("lmm_stripe_count:   %u\n", (int)lmm->lmm_stripe_count);
		printf("lmm_stripe_size:    %u\n", (int)lmm->lmm_stripe_size);
		printf("lmm_ost_count:      %u\n", lmm->lmm_ost_count);
		printf("lmm_stripe_pattern: %d\n", lmm->lmm_magic & 0xf);
	}

	if (query || verbose) {
		long long oid;
		int ost = lmm->lmm_stripe_offset;
		int header = 1;

		/* FIXME: temporary fix for bug 1612 */
		if (lmm->lmm_ost_count == 0) {
			oid = lmm->lmm_object_id;
			printf("\tobdidx\t         objid\t       objid\n"
			       "\t%6u\t%14llu\t%12llx\n", 0, oid, oid);
		} else
		for (i = 0; i < lmm->lmm_ost_count; i++, ost++) {
			ost %= lmm->lmm_ost_count;
			if ((oid = lmm->lmm_objects[ost].l_object_id)) {
				if (header) {
					printf("\tobdidx\t   objid\t   objid\n");
					header = 0;
				}
				printf("\t%6u\t%14llu\t%12llx%s\n",
				       ost, oid, oid, obdindex == ost ? " *" : "");
			}
		}
		printf("\n");
	}
}
