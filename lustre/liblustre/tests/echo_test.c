#include <stdio.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

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

unsigned int portal_subsystem_debug = ~0 - (S_PORTALS | S_QSWNAL | S_SOCKNAL |
                                            S_GMNAL | S_IBNAL);
                                                                                                                        
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

int
libcfs_nal_cmd(struct portals_cfg *pcfg)
{
        CERROR("empty function!!!\n");
        return 0;
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
	int max_interfaces;
        int rc;

        rc = PtlInit(&max_interfaces);
        if (rc != 0) {
                CERROR("ksocknal: PtlNIInit failed: error %d\n", rc);
                RETURN (rc);
        }
        return rc;
}

extern int class_handle_ioctl(unsigned int cmd, unsigned long arg);

int liblustre_ioctl(int dev_id, int opc, void *ptr)
{
	int   rc = -EINVAL;
	
	switch (dev_id) {
	default:
		fprintf(stderr, "Unexpected device id %d\n", dev_id);
		abort();
		break;
		
	case OBD_DEV_ID:
		rc = class_handle_ioctl(opc, (unsigned long)ptr);
		break;
	}

	return rc;
}

static void generate_random_uuid(unsigned char uuid_out[16])
{
        int *arr = (int*)uuid_out;
        int i;

        for (i = 0; i < sizeof(uuid_out)/sizeof(int); i++)
                arr[i] = rand();
}

static char *echo_server_nid = NULL;
static char *echo_server_ostname = "obd1";
static char *osc_dev_name = "OSC_DEV_NAME";
static char *echo_dev_name = "ECHO_CLIENT_DEV_NAME";

static int connect_echo_client(void)
{
	struct lustre_cfg lcfg;
	ptl_nid_t nid;
	char *peer = "ECHO_PEER_NID";
	class_uuid_t osc_uuid, echo_uuid;
	struct obd_uuid osc_uuid_str, echo_uuid_str;
	int nal, err;
	ENTRY;

        generate_random_uuid(osc_uuid);
        class_uuid_unparse(osc_uuid, &osc_uuid_str);
        generate_random_uuid(echo_uuid);
        class_uuid_unparse(echo_uuid, &echo_uuid_str);

        if (ptl_parse_nid(&nid, echo_server_nid)) {
                CERROR("Can't parse NID %s\n", echo_server_nid);
                RETURN(-EINVAL);
        }
        nal = ptl_name2nal("tcp");
        if (nal <= 0) {
                CERROR("Can't parse NAL tcp\n");
                RETURN(-EINVAL);
        }

	/* add uuid */
        LCFG_INIT(lcfg, LCFG_ADD_UUID, NULL);
        lcfg.lcfg_nid = nid;
        lcfg.lcfg_inllen1 = strlen(peer) + 1;
        lcfg.lcfg_inlbuf1 = peer;
        lcfg.lcfg_nal = nal;
        err = class_process_config(&lcfg);
        if (err < 0) {
		CERROR("failed add_uuid\n");
                RETURN(-EINVAL);
	}

	/* attach osc */
        LCFG_INIT(lcfg, LCFG_ATTACH, osc_dev_name);
        lcfg.lcfg_inlbuf1 = "osc";
        lcfg.lcfg_inllen1 = strlen(lcfg.lcfg_inlbuf1) + 1;
        lcfg.lcfg_inlbuf2 = osc_uuid_str.uuid;
        lcfg.lcfg_inllen2 = strlen(lcfg.lcfg_inlbuf2) + 1;
        err = class_process_config(&lcfg);
        if (err < 0) {
		CERROR("failed attach osc\n");
                RETURN(-EINVAL);
	}

	/* setup osc */
        LCFG_INIT(lcfg, LCFG_SETUP, osc_dev_name);
        lcfg.lcfg_inlbuf1 = echo_server_ostname;
        lcfg.lcfg_inllen1 = strlen(lcfg.lcfg_inlbuf1) + 1;
        lcfg.lcfg_inlbuf2 = peer;
        lcfg.lcfg_inllen2 = strlen(lcfg.lcfg_inlbuf2) + 1;
        err = class_process_config(&lcfg);
        if (err < 0) {
		CERROR("failed setup osc\n");
                RETURN(-EINVAL);
	}

	/* attach echo_client */
        LCFG_INIT(lcfg, LCFG_ATTACH, echo_dev_name);
        lcfg.lcfg_inlbuf1 = "echo_client";
        lcfg.lcfg_inllen1 = strlen(lcfg.lcfg_inlbuf1) + 1;
        lcfg.lcfg_inlbuf2 = echo_uuid_str.uuid;
        lcfg.lcfg_inllen2 = strlen(lcfg.lcfg_inlbuf2) + 1;
        err = class_process_config(&lcfg);
        if (err < 0) {
		CERROR("failed attach echo_client\n");
                RETURN(-EINVAL);
	}

	/* setup echo_client */
        LCFG_INIT(lcfg, LCFG_SETUP, echo_dev_name);
        lcfg.lcfg_inlbuf1 = osc_dev_name;
        lcfg.lcfg_inllen1 = strlen(lcfg.lcfg_inlbuf1) + 1;
        lcfg.lcfg_inlbuf2 = NULL;
        lcfg.lcfg_inllen2 = 0;
        err = class_process_config(&lcfg);
        if (err < 0) {
		CERROR("failed setup echo_client\n");
                RETURN(-EINVAL);
	}

	RETURN(0);
}

static int disconnect_echo_client(void)
{
	struct lustre_cfg lcfg;
	int err;
	ENTRY;

	/* cleanup echo_client */
        LCFG_INIT(lcfg, LCFG_CLEANUP, echo_dev_name);
        err = class_process_config(&lcfg);
        if (err < 0) {
		CERROR("failed cleanup echo_client\n");
                RETURN(-EINVAL);
	}

	/* detach echo_client */
        LCFG_INIT(lcfg, LCFG_DETACH, echo_dev_name);
        err = class_process_config(&lcfg);
        if (err < 0) {
		CERROR("failed detach echo_client\n");
                RETURN(-EINVAL);
	}

	/* cleanup osc */
        LCFG_INIT(lcfg, LCFG_CLEANUP, osc_dev_name);
        err = class_process_config(&lcfg);
        if (err < 0) {
		CERROR("failed cleanup osc device\n");
                RETURN(-EINVAL);
	}

	/* detach osc */
        LCFG_INIT(lcfg, LCFG_DETACH, osc_dev_name);
        err = class_process_config(&lcfg);
        if (err < 0) {
		CERROR("failed detach osc device\n");
                RETURN(-EINVAL);
	}

	RETURN(0);
}

static void usage(const char *s)
{
	printf("Usage: %s -s ost_host_name [-n ost_name]\n", s);
	printf("    ost_host_name: the host name of echo server\n");
	printf("    ost_name: ost name, default is \"obd1\"\n");
}

extern int time_ptlwait1;
extern int time_ptlwait2;
extern int time_ptlselect;

int main(int argc, char **argv) 
{
	int c, rc;

	while ((c = getopt(argc, argv, "s:n:")) != -1) {
		switch (c) {
		case 's':
			echo_server_nid = optarg;
			break;
		case 'n':
			echo_server_ostname = optarg;
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

        if (optind != argc)
                usage(argv[0]);

	if (!echo_server_nid) {
		usage(argv[0]);
		return 1;
	}

        srand(time(NULL));

	tcpnal_mynid = rand();
#if 1
	portal_debug = 0;
	portal_subsystem_debug = 0;
#endif

        if (init_current(argc, argv) ||
	    init_obdclass() || init_lib_portals() ||
	    ptlrpc_init() ||
	    mdc_init() ||
	    lov_init() ||
	    osc_init() ||
	    echo_client_init()) {
		printf("error\n");
		return 1;
	}

	rc = connect_echo_client();
	if (rc)
		return rc;

	set_ioc_handler(liblustre_ioctl);

	rc = lctl_main(1, &argv[0]);

	rc |= disconnect_echo_client();

	return rc;
}
