#include <stdio.h>

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

        /* XXX RR parse an lctl dump file here */
        /* XXX RR parse dumpfile here with obdclass/class_obd.c ioct command */

        printf("Hello\n");
        return 0;
}

