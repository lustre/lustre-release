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
	const char *cwd;
	const char *s;

	err = _sysio_init();
	if (err)
		return err;
	err = drv_init_all();
	if (err)
		return err;
	s = getenv("SYSIO_NAMESPACE");
	if (!(s || (s = getenv("SYSIO_MANUAL")))) {
		/*
		 * Assume a native mount at root.
		 */
		s = "{mnt,dev=\"native:/\",dir=/,fl=0}";
	}
	cwd = getenv("SYSIO_CWD");
#if DEFER_INIT_CWD
	err = _sysio_boot(s, cwd ? cwd : "/");
#else
	err = _sysio_boot(s);
#endif
	if (err)
		return err;

#if !DEFER_INIT_CWD
	if (!cwd)
		s = "/";
	err = chdir(s);
	if (err)
		return err;
#endif

	return 0;
}

void
_test_sysio_shutdown()
{

	_sysio_shutdown();
}
