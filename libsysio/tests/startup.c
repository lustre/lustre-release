#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/queue.h>

#include "xtio.h"
#include "test.h"

#include "sysio.h"

int
_test_sysio_startup()
{
	int	err;
	const char *s;

	err = _sysio_init();
	if (err)
		return err;
	err = drv_init_all();
	if (err)
		return err;
	s = getenv("SYSIO_NAMESPACE");
	if (s)
		err = _sysio_boot(s);
	else if (!(s = getenv("SYSIO_MANUAL"))) {
		/*
		 * Assume a native mount at root.
		 */
		err = _sysio_boot("{mnt,dev=\"native:/\",dir=/,fl=0}");
	}
	if (err)
		return err;

	s = getenv("SYSIO_CWD");
	if (s) {
		err = chdir(s);
		if (err)
			return err;
	}

	return 0;
}

void
_test_sysio_shutdown()
{

	_sysio_shutdown();
}
