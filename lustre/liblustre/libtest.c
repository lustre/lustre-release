#include <stdio.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <portals/api-support.h> /* needed for ptpctl.h */
#include <portals/ptlctl.h>	/* needed for parse_dump */


#include <liblustre.h>
#include <linux/obd.h>
#include <linux/obd_class.h>
#include <procbridge.h>

#define LIBLUSTRE_TEST 1
#include "../utils/lctl.c"

struct ldlm_namespace;
struct ldlm_res_id;
struct obd_import;

void *inter_module_get(char *arg)
{
        if (!strcmp(arg, "tcpnal_ni"))
                return &tcpnal_ni;
        else if (!strcmp(arg, "ldlm_cli_cancel_unused"))
                return ldlm_cli_cancel_unused;
        else if (!strcmp(arg, "ldlm_namespace_cleanup"))
                return ldlm_namespace_cleanup;
        else if (!strcmp(arg, "ldlm_replay_locks"))
                return ldlm_replay_locks;
        else
                return NULL;
}

/* XXX move to proper place */
char *portals_nid2str(int nal, ptl_nid_t nid, char *str)
{
        switch(nal){
        case TCPNAL:
                /* userspace NAL */
        case SOCKNAL:
                sprintf(str, "%u:%d.%d.%d.%d", (__u32)(nid >> 32),
                        HIPQUAD(nid));
                break;
        case QSWNAL:
        case GMNAL:
        case IBNAL:
        case TOENAL:
        case SCIMACNAL:
                sprintf(str, "%u:%u", (__u32)(nid >> 32), (__u32)nid);
                break;
        default:
                return NULL;
        }
        return str;
}

ptl_handle_ni_t         tcpnal_ni;

struct pingcli_args {
        ptl_nid_t mynid;
        ptl_nid_t nid;
	ptl_pid_t port;
        int count;
        int size;
};

struct task_struct *current;

struct obd_class_user_state ocus;

/* portals interfaces */
ptl_handle_ni_t *
kportal_get_ni (int nal)
{
        switch (nal)
        {
        case SOCKNAL:
                return &tcpnal_ni;
        default:
                return NULL;
        }
}

inline void
kportal_put_ni (int nal)
{
        return;
}

int
kportal_nal_cmd(struct portals_cfg *pcfg)
{
#if 0
        __u32 nal = pcfg->pcfg_nal;
        int rc = -EINVAL;

        ENTRY;

        down(&nal_cmd_sem);
        if (nal > 0 && nal <= NAL_MAX_NR && nal_cmd[nal].nch_handler) {
                CDEBUG(D_IOCTL, "calling handler nal: %d, cmd: %d\n", nal, 
                       pcfg->pcfg_command);
                rc = nal_cmd[nal].nch_handler(pcfg, nal_cmd[nal].nch_private);
        }
        up(&nal_cmd_sem);
        RETURN(rc);
#else
        CERROR("empty function!!!\n");
        return 0;
#endif
}

int init_current(int argc, char **argv)
{ 
        current = malloc(sizeof(*current));
        strncpy(current->comm, argv[0], sizeof(current->comm));
        current->pid = getpid();
	return 0;
}

ptl_nid_t tcpnal_mynid;

int init_lib_portals()
{
        int rc;

        PtlInit();
        rc = PtlNIInit(procbridge_interface, 0, 0, 0, &tcpnal_ni);
        if (rc != 0) {
                CERROR("ksocknal: PtlNIInit failed: error %d\n", rc);
                PtlFini();
                RETURN (rc);
        }
        PtlNIDebug(tcpnal_ni, ~0);
        return rc;
}

extern int class_handle_ioctl(struct obd_class_user_state *ocus, unsigned int cmd, unsigned long arg);


int lib_ioctl_nalcmd(int dev_id, int opc, void * ptr)
{
        struct portal_ioctl_data *ptldata;

        if (opc == IOC_PORTAL_NAL_CMD) {
                ptldata = (struct portal_ioctl_data *) ptr;

                if (ptldata->ioc_nal_cmd == NAL_CMD_REGISTER_MYNID) {
                        tcpnal_mynid = ptldata->ioc_nid;
                        printf("mynid: %u.%u.%u.%u\n",
                                (unsigned)(tcpnal_mynid>>24) & 0xFF,
                                (unsigned)(tcpnal_mynid>>16) & 0xFF,
                                (unsigned)(tcpnal_mynid>>8) & 0xFF,
                                (unsigned)(tcpnal_mynid) & 0xFF);
                }
        }

	return (0);
}

int lib_ioctl(int dev_id, int opc, void * ptr)
{

	if (dev_id == OBD_DEV_ID) {
		class_handle_ioctl(&ocus, opc, (unsigned long)ptr);

		/* you _may_ need to call obd_ioctl_unpack or some
		   other verification function if you want to use ioc
		   directly here */
#if 0
		printf ("processing ioctl cmd: %x buf len: %d\n", 
			opc,  ioc->ioc_len);
#endif
	}
	return (0);
}

int liblustre_ioctl(int dev_id, int opc, void *ptr)
{
	int   rc = -EINVAL;
	
	switch (dev_id) {
	default:
		fprintf(stderr, "Unexpected device id %d\n", dev_id);
		abort();
		break;
		
	case OBD_DEV_ID:
		rc = class_handle_ioctl(&ocus, opc, (unsigned long)ptr);
		break;
	}

	return rc;
}

extern int time_ptlwait1;
extern int time_ptlwait2;
extern int time_ptlselect;
int main(int argc, char **argv) 
{
        char *config_file;

        if (argc > 2) {
                printf("Usage: %s [config_file]\n", argv[0]);
                return 1;
        }

        if (argc == 2) {
                config_file = argv[1];
		argc--;
		argv++;
	} else
                config_file = "/tmp/DUMP_FILE";

        srand(time(NULL));

        INIT_LIST_HEAD(&ocus.ocus_conns);
#if 1
	portal_debug = 0;
	portal_subsystem_debug = 0;
#endif
	parse_dump(config_file, lib_ioctl_nalcmd);

        if (init_current(argc, argv) ||
	    init_obdclass() || init_lib_portals() ||
	    ptlrpc_init() ||
	    ldlm_init() ||
	    mdc_init() ||
	    lov_init() ||
	    osc_init() ||
	    echo_client_init()) {
		printf("error\n");
		return 1;
	}

	parse_dump(config_file, lib_ioctl);

	set_ioc_handler(liblustre_ioctl);
#if 0	
	portal_debug = -1;
	portal_subsystem_debug = -1;
#endif
	return lctl_main(argc, argv);
}

