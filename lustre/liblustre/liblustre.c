#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/queue.h>
#include <sys/statvfs.h>

#include <sysio.h>
#include <mount.h>

#define ENV_LUSTRE_MNTPNT "LUSTRE_MOUNT_POINT"
#define ENV_PORTALS_MYNID "PORTALS_MYNID"

extern int lllib_init(char *arg);

static char	*root_driver = "native";
static char	*lustre_driver = "llite";
static char	*root_path = "/";
static char	*lustre_path = NULL;
static char     *portals_mynid = NULL;
static unsigned mntflgs = 0;

extern int portal_debug;
extern int portal_subsystem_debug;

extern int _sysio_native_init();

void __liblustre_setup_(void)
{
	int err;

	lustre_path = getenv(ENV_LUSTRE_MNTPNT);
	if (!lustre_path) {
		printf("lislustre: env %s didn't set!\n", ENV_LUSTRE_MNTPNT);
		exit(1);
	}

	portals_mynid = getenv("PORTALS_MYNID");
	if (!portals_mynid) {
		printf("lislustre: env %s didn't set!\n", ENV_PORTALS_MYNID);
		exit(1);
	}

	if (_sysio_init() != 0) {
		perror("init sysio");
		exit(1);
	}

        _sysio_native_init();

	err = _sysio_mount_root(root_path, root_driver, mntflgs, NULL);
	if (err) {
		perror(root_driver);
		exit(1);
	}

#if 1
	portal_debug = 0;
	portal_subsystem_debug = 0;
#endif
	err = lllib_init(portals_mynid);
	if (err) {
		perror("init llite driver");
		exit(1);
	}	

        err = mount("/", lustre_path, lustre_driver, mntflgs, NULL);
	if (err) {
		errno = -err;
		perror(lustre_driver);
		exit(1);
	}
}

void __liblustre_cleanup_(void)
{
	printf("about shutdown\n");
	_sysio_shutdown();
	printf("finish shutdown\n");
}
