#define DEBUG_SUBSYSTEM S_FILTER

#include <libcfs/libcfs.h>
#include <obd.h>
#include <lvfs.h>
#include <lustre_lib.h>

atomic_t obd_memory;
int obd_memmax;

/* XXX currently ctxt functions should not be used ?? */
void push_ctxt(struct lvfs_run_ctxt *save, struct lvfs_run_ctxt *new_ctx,
	       struct lvfs_ucred *cred)
{
	LBUG();
}

void pop_ctxt(struct lvfs_run_ctxt *saved, struct lvfs_run_ctxt *new_ctx,
              struct lvfs_ucred *cred)
{
	LBUG();
}

static int __init lvfs_init(void)
{
	int ret = 0;
	ENTRY;

	RETURN(ret);
}

static void __exit lvfs_exit(void)
{
	int leaked;
	ENTRY;
	
	leaked = atomic_read(&obd_memory);
	CDEBUG(leaked ? D_ERROR : D_INFO,
	       "obd mem max: %d leaked: %d\n", obd_memmax, leaked);

	return;
}

cfs_module(lvfs, "1.0.0", lvfs_init, lvfs_exit);

