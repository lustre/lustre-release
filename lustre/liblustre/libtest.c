#include <stdio.h>

#include <portals/api-support.h> /* needed for ptpctl.h */
#include <portals/ptlctl.h>	/* needed for parse_dump */

#include <liblustre.h>
#include <../user/procbridge/procbridge.h>

ptl_handle_ni_t         tcpnal_ni;

struct pingcli_args {
        ptl_nid_t mynid;
        ptl_nid_t nid;
	ptl_pid_t port;
        int count;
        int size;
};

struct task_struct *current;

/* portals interfaces */
inline const ptl_handle_ni_t *
kportal_get_ni (int nal)
{
        return &tcpnal_ni;
}

inline void
kportal_put_ni (int nal)
{
        return;
}

void init_current(int argc, char **argv)
{ 
        current = malloc(sizeof(*current));
        strncpy(current->comm, argv[0], sizeof(current->comm));
        current->pid = getpid();

}

int init_lib_portals(struct pingcli_args *args)
{
        int rc;

        PtlInit();

        rc = PtlNIInit(procbridge_interface, 0, 0, args->mynid, &tcpnal_ni);
        if (rc != 0) {
                CERROR("ksocknal: PtlNIInit failed: error %d\n", rc);
                PtlFini();
                RETURN (rc);
        }
        PtlNIDebug(tcpnal_ni, ~0);
        return rc;
}

int lib_ioctl(int dev_id, int opc, void * ptr)
{
	if (dev_id == OBD_DEV_ID) {
		struct obd_ioctl_data *ioc = ptr;
		/* call class_obd_ioctl function here */
		/* class_obd_ioctl(inode, filp, opc, (unsigned long) ioc); */

		/* you _may_ need to call obd_ioctl_unpack or some
		   other verification function if you want to use ioc
		   directly here */
		printf ("processing ioctl cmd: %x buf len: %d\n", 
			opc,  ioc->ioc_len);
	}
	return (0);
}

int main(int arc, char **argv) 
{
        struct pingcli_args *args;
	args= malloc(sizeof(*args));
        if (!args) { 
                printf("Malloc error\n");
                exit(1);
        }

        args->mynid = atoi(argv[1]);
        args->nid = atoi(argv[2]);
	args->port = 9999;
	args->count = atoi(argv[3]);
	args->size = atoi(argv[4]);

        init_obdclass();
        init_lib_portals(args);
        ptlrpc_init();
        ldlm_init();
        osc_init();
        echo_client_init();
        /* XXX  lov and mdc are next */

	parse_dump("DUMP_FILE", lib_ioctl);

        printf("Hello\n");
        return 0;
}

