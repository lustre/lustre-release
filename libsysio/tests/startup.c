#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/queue.h>

#include "sysio.h"

#include "test.h"

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
	err = s ? _sysio_boot(s) : -ENOTTY;
	if (err)
		return err;
	return 0;
}
