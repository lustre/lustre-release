#define _XOPEN_SOURCE 500

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
#define	printk printf
#include <linux/lustre_lib.h>
#include <linux/lustre_lite.h>

#warning Max obds per lov currently hardcoded to 1000 in lov/lov_obd.c
#define MAX_LOV_UUID_COUNT	1000
#define OBD_NOT_FOUND		((__u32)-1)
#define	debugMsg		if (debug) printf

char *		cmd;
int		debug;
struct option	longOpts[] = {
			{"debug", 0, 0, 'd'},
			{"help", 0, 0, 'h'},
			{"obd", 1, 0, 'o'},
			{"query", 0, 0, 'o'},
			{0, 0, 0, 0}
		};
int		query;
char *		shortOpts = "dho:qv";
char *		usageMsg = "[ --obd <obd uuid> | --query ] <dir|file> ...";

int		max_stripe_count = MAX_LOV_UUID_COUNT;
obd_uuid_t *	obduuid;
__u32		obdcount;
__u32		obdindex;
char *		buf;
int		buflen;
struct obd_ioctl_data data;
struct lov_desc desc;
obd_uuid_t *	uuids;
int		uuidslen;
int		cfglen;
struct lov_user_md *lum;
int		lumlen;

void	init();
void	usage(FILE *stream);
void	errMsg(char *fmt, ...);
void	processPath(char *path);
int	processFile(
		const char *path,
		const struct stat *sp,
		int flag,
		struct FTW *ftwp
	);
__u32	getobdindex(const char *path);

int
main (int argc, char **argv) {
	int c;

	cmd = basename(argv[0]);

	while ((c = getopt_long(argc, argv, shortOpts, longOpts, NULL)) != -1) {
		switch (c) {
		case 'd':
			debug++;
			break;
		case 'o':
			if (obduuid) {
				errMsg("obd '%s' already specified: '%s'.",
					obduuid, optarg);
				exit(1);
			}

			obduuid = (obd_uuid_t *)optarg;
			break;
		case 'h':
			usage(stdout);
			exit(0);
		case 'q':
			query++;
			break;
		case '?':
			usage(stderr);
			exit(1);
		default:
			errMsg("Internal error. Valid '%s' unrecognized.",
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

void
init()
{
	int datalen, desclen;

	datalen = size_round(sizeof(data));
	desclen = size_round(sizeof(desc));
	uuidslen = size_round(max_stripe_count * sizeof(*uuids));
	cfglen = datalen + desclen + uuidslen;
	lumlen = sizeof(*lum) + max_stripe_count * sizeof(*lum->lum_luoinfo);
	if (cfglen > lumlen)
		buflen = cfglen;
	else
		buflen = lumlen;

#warning max ioctl buffer size currently hardcoded to 8192
	if (buflen > 8192) {
		int nuuids, remaining, nluoinfos;

		buflen = 8192;
		nuuids = (buflen - datalen - desclen) / sizeof(*uuids);
		uuidslen = size_round(nuuids * sizeof(*uuids));
		remaining = nuuids * sizeof(*uuids);
		if (uuidslen > remaining)
			nuuids--;
		nluoinfos = (buflen - sizeof(*lum)) / sizeof(*lum->lum_luoinfo);
		if (nuuids > nluoinfos)
			max_stripe_count = nluoinfos;
		else
			max_stripe_count = nuuids;

		cfglen = datalen + desclen + uuidslen;
		lumlen = sizeof(*lum) + max_stripe_count *
				sizeof(*lum->lum_luoinfo);
	}

	if ((buf = malloc(buflen)) == NULL) {
		errMsg("Unable to allocate %d bytes of memory for ioctl's.",
			buflen);
		exit(1);
	}

	lum = (struct lov_user_md *)buf;
	uuids = (obd_uuid_t *)buf;
}

void
usage(FILE *stream)
{
	fprintf(stream, "usage: %s %s\n", cmd, usageMsg);
}

void
errMsg(char *fmt, ...)
{
	va_list args;

	fprintf(stderr, "%s: ", cmd);
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fprintf(stderr, "\n");
}

void
processPath(char *path)
{
	obdindex = OBD_NOT_FOUND;
	nftw((const char *)path, processFile, 128, FTW_PHYS|FTW_MOUNT);
}

int
processFile(const char *path,
	const struct stat *sp,
	int flag,
	struct FTW *ftwp
) {
	struct lov_user_oinfo *luoinfo;
	int fd;
	int count;
	int rc;
	int i;

	if (flag != FTW_F)
		return 0;

	if ((obdcount == 0) && (getobdindex(path) == OBD_NOT_FOUND)) {
		/* terminate nftw walking this tree */
		return(1);
	}

	if ((fd = open(path, O_RDONLY)) < 0) {
		errMsg("open \"%.20s\" failed.", path);
		perror("open");
		exit(1);
	}

	memset((void *)buf, 0, buflen);
        lum->lum_stripe_count = max_stripe_count;

	if ((rc = ioctl(fd, LL_IOC_LOV_GETSTRIPE, (void *)lum)) < 0) {
		errMsg("LL_IOC_LOV_GETSTRIPE ioctl failed.");
		perror("ioctl");
		exit(1);
	}

	close(fd);

	count = lum->lum_stripe_count;
	luoinfo = lum->lum_luoinfo;

	if (query) {
		printf("%s\n", path);
		for (i = 0; i < count; i++, luoinfo++) {
			printf("%4d: obdindex: %-4d objid: %lld\n",
				i, luoinfo->luo_idx, luoinfo->luo_id);
		}
		return(0);
	}

	debugMsg("LL_IOC_LOV_GETSTRIPE:%s: obdindex: %d count: %d\n",
		path, obdindex, count);

	for (i = 0; i < count; i++, luoinfo++) {
		debugMsg("%-4d: obdidx: %-4d objid: %lld\n",
			i, luoinfo->luo_idx, luoinfo->luo_id);
		if (luoinfo->luo_idx == obdindex) {
			printf("%s\n", path);
			return 0;
		}
	}

	return(0);
}

__u32
getobdindex(const char *path)
{
	obd_uuid_t *uuidp;
	int fd;
	int rc;
	int i;

	if ((fd = open(path, O_RDONLY)) < 0) {
		errMsg("open \"%.20s\" failed.", path);
		perror("open");
		exit(1);
	}

        data.ioc_inllen1 = sizeof(desc);
        data.ioc_inlbuf1 = (char *)&desc;
        data.ioc_inllen2 = uuidslen;
        data.ioc_inlbuf2 = (char *)uuids;
        data.ioc_inllen3 = 0;

        memset(&desc, 0, sizeof(desc));
        desc.ld_tgt_count = max_stripe_count;

        if (obd_ioctl_pack(&data, &buf, buflen)) {
                errMsg("internal buffering error.");
		exit(1);
        }

        rc = ioctl(fd, OBD_IOC_LOV_GET_CONFIG, buf);
        if (rc) {
		errMsg("OBD_IOC_LOV_GET_CONFIG ioctl failed: %d.", errno);
		perror("ioctl");
                exit(1);
        }

	if (obd_ioctl_unpack(&data, buf, buflen)) {
		errMsg("Invalid reply from ioctl.");
                exit(1);
	}

	close(fd);

        obdcount = desc.ld_tgt_count;

	if (query) {
		printf("OBDS:\n");
		for (i = 0, uuidp = uuids; i < obdcount; i++, uuidp++)
			printf("%4d: %s\n", i, (char *)uuidp);

		return(0);
	}

        for (i = 0, uuidp = uuids; i < obdcount; i++, uuidp++) {
		rc = strncmp((const char *)obduuid, (const char *)uuidp,
				sizeof(*uuidp));
		if (rc == 0) {
			obdindex = i;
			break;
		}
	}

	if (obdindex == OBD_NOT_FOUND) {
		errMsg("obd UUID '%s' not found.", obduuid);
		return(OBD_NOT_FOUND);
	}

	return(0);
}
