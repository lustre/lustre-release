#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <sys/socket.h>
#include "lnetconfig/cyaml.h"
#include "lutf_listener.h"
#include "lutf_message.h"
#include "lutf_python.h"
#include "lutf.h"

#define HB_TIMEOUT	2

struct in_addr g_local_ip;
FILE *out;
char *outlog;

/*externs needed by getopt lib*/
extern char *optarg;
extern int optind;

static void
lutf_help_usage(const struct option *long_options, const char *description[])
{
	int i = 0;

	fprintf(stderr, BOLDCYAN "LUTF Runs in two modes: "
		RESET BOLDMAGENTA "Master" RESET BOLDCYAN " or " BOLDRED "Agent\n\n"
		BOLDMAGENTA
		"Master Mode\n"
		"    . Runs on the Test Master node and controls all agents\n"
		BOLDRED
		"Agent Mode:\n"
		"    . Runs on the Nodes Under Test\n\n"
		BOLDGREEN
		"Look at lutf/python/config/lutf_cfg_sample.yaml for a sample "
		"LUTF configuration\n\n"
		RESET
		"Options:\n");

	while ((long_options[i].name != NULL) && (description[i] != NULL)) {
		fprintf(stderr, "\t-%c or --%s %s\n",
			(char) long_options[i].val,
			long_options[i].name,
			description[i]);
		i++;
	}

	fprintf(stderr, "\n");
}

static struct cYAML *get_value(struct cYAML *head, char *key)
{
	struct cYAML *child = head;

	while (child != NULL) {
		if (strcmp(child->cy_string, key) == 0)
			return child;
		child = child->cy_next;
	}

	return NULL;
}

static
lutf_rc_t hostname_to_ip(char *hostname, char *ip, int len)
{
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_in *h;
	int rv;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(hostname, "http", &hints, &servinfo)) != 0) {
		PERROR("getaddrinfo: %s\n", gai_strerror(rv));
		return EN_LUTF_RC_BAD_ADDR;
	}

	// loop through all the results and connect to the first we can
	memset(ip, 0, len);
	for (p = servinfo; p != NULL; p = p->ai_next) {
		h = (struct sockaddr_in *) p->ai_addr;
		strncpy(ip, inet_ntoa(h->sin_addr), len-1);
	}

	freeaddrinfo(servinfo); // all done with this structure
	return EN_LUTF_RC_OK;
}

static
lutf_rc_t extract_config_parameters(struct cYAML *config_tree,
				    lutf_config_params_t *cfg,
				    char **elem)
{
	struct in_addr addr;
	struct cYAML *head;
	struct cYAML *tmp;
	char maddr[24];
	lutf_rc_t rc;

	head = config_tree->cy_child;

	if (strcmp(head->cy_string, "lutf") != 0) {
		*elem = "lutf";
		return EN_LUTF_RC_BAD_PARAM;
	}

	/* go  to the list of elements we need to browse */
	head = head->cy_child;

	tmp = get_value(head, "shell");
	if (tmp) {
		if (tmp->cy_type == CYAML_TYPE_STRING) {
			if (strcmp(tmp->cy_valuestring,
				   INTERACTIVE) == 0) {
				cfg->shell = EN_LUTF_RUN_INTERACTIVE;
			} else if (strcmp(tmp->cy_valuestring,
					BATCH) == 0) {
				cfg->shell = EN_LUTF_RUN_BATCH;
			} else if (strcmp(tmp->cy_valuestring,
					DAEMON) == 0) {
				cfg->shell = EN_LUTF_RUN_DAEMON;
			} else {
				*elem = "shell";
				return EN_LUTF_RC_BAD_PARAM;
			}
		} else {
			*elem = "shell";
			return EN_LUTF_RC_BAD_PARAM;
		}
	} else {
		*elem = "shell";
		return EN_LUTF_RC_MISSING_PARAM;
	}

	tmp = get_value(head, "agent");
	if (tmp) {
		if (tmp->cy_type == CYAML_TYPE_FALSE)
			cfg->l_info.type = EN_LUTF_MASTER;
		else if (tmp->cy_type == CYAML_TYPE_TRUE)
			cfg->l_info.type = EN_LUTF_AGENT;
		else {
			*elem = "agent";
			return EN_LUTF_RC_BAD_PARAM;
		}
	} else {
		cfg->l_info.type = EN_LUTF_MASTER;
	}

	tmp = get_value(head, "telnet-port");
	if (tmp) {
		if (tmp->cy_type == CYAML_TYPE_NUMBER)
			cfg->l_info.hb_info.agent_telnet_port = tmp->cy_valueint;
		else {
			*elem = "telnet-port";
			return EN_LUTF_RC_BAD_PARAM;
		}
	} else {
		cfg->l_info.hb_info.agent_telnet_port = -1;
	}

	tmp = get_value(head, "master-address");
	if (tmp) {
		if (tmp->cy_type == CYAML_TYPE_STRING) {
			if (!inet_aton(tmp->cy_valuestring, &addr)) {
				/* maybe it's a host name so let's try
				 * that out
				 */
				rc = EN_LUTF_RC_BAD_ADDR;
				if ((rc = hostname_to_ip(tmp->cy_valuestring, maddr,
							 sizeof(maddr)))
				    != EN_LUTF_RC_OK) {
					*elem = "master-address";
					return rc;
				} else if (!inet_aton(maddr, &addr)) {
					*elem = "master-address";
					return rc;
				}
			}
			cfg->l_info.hb_info.master_address.sin_addr = addr;
		} else {
			*elem = "master-address";
			return EN_LUTF_RC_BAD_PARAM;
		}
	} else if (cfg->l_info.type == EN_LUTF_AGENT) {
		*elem = "master-address";
		return EN_LUTF_RC_MISSING_PARAM;
	}

	tmp = get_value(head, "master-port");
	if (tmp) {
		if (tmp->cy_type == CYAML_TYPE_NUMBER) {
			cfg->l_info.hb_info.master_address.sin_port = tmp->cy_valueint;
			cfg->l_info.listen_port = tmp->cy_valueint;
		} else {
			*elem = "master-port";
			return EN_LUTF_RC_BAD_PARAM;
		}
	} else {
		cfg->l_info.hb_info.master_address.sin_port = DEFAULT_MASTER_PORT;
		cfg->l_info.listen_port = DEFAULT_MASTER_PORT;
	}
	cfg->l_info.hb_info.master_address.sin_family = AF_INET;

	tmp = get_value(head, "lutf-path");
	if (tmp) {
		if (tmp->cy_type == CYAML_TYPE_STRING)
			cfg->lutf_path = tmp->cy_valuestring;
		else {
			*elem = "lutf-path";
			return EN_LUTF_RC_BAD_PARAM;
		}
	} else {
		*elem = "lutf-path";
		return EN_LUTF_RC_MISSING_PARAM;
	}

	tmp = get_value(head, "py-path");
	if (tmp) {
		if (tmp->cy_type == CYAML_TYPE_STRING)
			cfg->py_path = tmp->cy_valuestring;
		else {
			*elem = "py-path";
			return EN_LUTF_RC_BAD_PARAM;
		}
	}

	tmp = get_value(head, "node-name");
	if (tmp) {
		if (tmp->cy_type == CYAML_TYPE_STRING) {
			strncpy(cfg->l_info.hb_info.node_name, tmp->cy_valuestring,
				MAX_STR_LEN);
			cfg->l_info.hb_info.node_name[MAX_STR_LEN - 1] = '\0';
		} else {
			*elem = "node-name";
			return EN_LUTF_RC_BAD_PARAM;
		}
	} else {
		strncpy(cfg->l_info.hb_info.node_name, TEST_ROLE_GRC,
			MAX_STR_LEN);
		cfg->l_info.hb_info.node_name[MAX_STR_LEN - 1] = '\0';
	}

	tmp = get_value(head, "master-name");
	if (tmp) {
		if (tmp->cy_type == CYAML_TYPE_STRING)
			cfg->master_name = tmp->cy_valuestring;
		else
			return EN_LUTF_RC_BAD_PARAM;
	} else if (cfg->l_info.type == EN_LUTF_AGENT) {
		*elem = "master-name";
		return EN_LUTF_RC_MISSING_PARAM;
	}

	tmp = get_value(head, "suite");
	if (tmp && cfg->l_info.type == EN_LUTF_MASTER) {
		if (tmp->cy_type == CYAML_TYPE_STRING)
			if (strlen(tmp->cy_valuestring) > 0)
				cfg->suite = tmp->cy_valuestring;
			else
				cfg->suite = NULL;
		else {
			*elem = "suite";
			return EN_LUTF_RC_BAD_PARAM;
		}
	}

	tmp = get_value(head, "script");
	if (tmp && cfg->l_info.type == EN_LUTF_MASTER) {
		if (tmp->cy_type == CYAML_TYPE_STRING)
			if (strlen(tmp->cy_valuestring) > 0)
				cfg->script = tmp->cy_valuestring;
			else
				cfg->script = NULL;
		else {
			*elem = "script";
			return EN_LUTF_RC_BAD_PARAM;
		}
	}

	if (!cfg->suite && cfg->script) {
		*elem = "suite";
		return EN_LUTF_RC_BAD_PARAM;
	}

	tmp = get_value(head, "pattern");
	if (tmp) {
		if (tmp->cy_type == CYAML_TYPE_STRING)
			if (strlen(tmp->cy_valuestring) > 0)
				cfg->pattern = tmp->cy_valuestring;
			else
				cfg->pattern = "*";
		else {
			*elem = "pattern";
			return EN_LUTF_RC_BAD_PARAM;
		}
	} else {
		cfg->pattern = "*";
	}

	tmp = get_value(head, "results");
	if (tmp) {
		if (tmp->cy_type == CYAML_TYPE_STRING)
			cfg->results_file = tmp->cy_valuestring;
		else {
			*elem = "results";
			return EN_LUTF_RC_BAD_PARAM;
		}
	} else {
		cfg->results_file = "lutf_def_results";
	}

	tmp = get_value(head, "agent-list");
	if (tmp) {
		if (cYAML_is_sequence(tmp))
			cfg->agents = tmp;
		else {
			*elem = "agent-list";
			return EN_LUTF_RC_BAD_PARAM;
		}
	} else {
		cfg->agents = NULL;
	}

	tmp = get_value(head, "tmp-dir");
	if (tmp) {
		if (tmp->cy_type == CYAML_TYPE_STRING)
			cfg->tmp_dir = tmp->cy_valuestring;
		else {
			*elem = "tmp-dir";
			return EN_LUTF_RC_BAD_PARAM;
		}
	} else {
		cfg->tmp_dir = "/tmp/lutf/";
	}

	return EN_LUTF_RC_OK;
}

int
main(int argc, char *argv[])
{
	int cOpt;
	pthread_t l_thread_id;
	lutf_rc_t rc;
	int trc;
	char *config_file = NULL;
	char *elem = NULL;
	struct cYAML *config_tree;
	struct cYAML *err_rc = NULL;

	out = stdout;

	memset(&g_lutf_cfg, 0, sizeof(g_lutf_cfg));

	/* If followed by a ':', the option requires an argument*/
	const char *const short_options = "c:h";
	const struct option long_options[] = {
		{.name = "config", .has_arg = required_argument, .val = 'c'},
		{.name = "help", .has_arg = no_argument, .val = 'h'},
		{NULL, 0, NULL, 0}
	};

	const char *description[] = {
		/*'c'*/":\n\t\tYAML config file",
		/*'h'*/":\n\t\tPrint this help",
		NULL
	};

	/* sanity check */
	if (argc < 1) {
		lutf_help_usage(long_options, description);
		exit(LUTF_EXIT_ERR_STARTUP);
	}

	/*now process command line arguments*/
	if (argc > 1) {
		while ((cOpt = getopt_long(argc, argv,
					   short_options,
					   long_options,
					   NULL)) != -1) {
			switch (cOpt) {
			case 'c':
				config_file = optarg;
				break;
			case 'h':
				lutf_help_usage(long_options, description);
				exit(LUTF_EXIT_NORMAL);
			default:
				PERROR("Bad parameter");
				exit(LUTF_EXIT_ERR_BAD_PARAM);
				break;
			}
		}
	}

	if (!config_file) {
		lutf_help_usage(long_options, description);
		exit(LUTF_EXIT_ERR_BAD_PARAM);
	}

	g_lutf_cfg.cfg_path = config_file;

	config_tree = cYAML_build_tree(config_file, NULL, 0, &err_rc, false);
	if (!config_tree) {
		PERROR("Failed to parse config file: %s", config_file);
		exit(LUTF_EXIT_ERR_BAD_PARAM);
	}

	rc = extract_config_parameters(config_tree, &g_lutf_cfg, &elem);
	if (rc != EN_LUTF_RC_OK) {
		PERROR("Parsing configuration failed on %s with %s",
		       elem, lutf_rc2str(rc));
		exit(LUTF_EXIT_ERR_BAD_PARAM);
	}

	outlog = calloc(strlen(g_lutf_cfg.tmp_dir) + strlen(OUT_LOG_NAME) + 2, 1);

	if (!outlog) {
		PERROR("out of memory");
		exit(LUTF_EXIT_ERR_STARTUP);
	}

	sprintf(outlog, "%s/%s", g_lutf_cfg.tmp_dir, OUT_LOG_NAME);

	out = fopen(outlog, "w");

	if (!out) {
		fprintf(stderr, "Failed to open log files: %s\n",
			outlog);
		exit(LUTF_EXIT_ERR_STARTUP);
	}

	if (g_lutf_cfg.shell == EN_LUTF_RUN_DAEMON) {
		pid_t process_id = 0;
		pid_t sid = 0;

		/* create the child process */
		process_id = fork();
		if (process_id < 0) {
			PERROR("Failed to run lutf as deamon");
			exit(LUTF_EXIT_ERR_DEAMEON_STARTUP);
		}

		if (process_id > 0) {
			/*
			 * We're in the parent process so let's kill it
			 * off
			 */
			PDEBUG("Shutting down parent process");
			exit(LUTF_EXIT_NORMAL);
		}

		umask(0);
		sid = setsid();
		if (sid < 0) {
			PERROR("forking child failed");
			exit(LUTF_EXIT_ERR_DEAMEON_STARTUP);
		}

		rc = chdir("/");
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		if (rc) {
			PERROR("chdir failed");
			exit(LUTF_EXIT_ERR_DEAMEON_STARTUP);
		}
	}

	/*
	 * Spawn the listener thread if we are in Master Mode.
	 * The listener thread listens for Heart beats and deals
	 * with maintaining the health of the agents. If an agent
	 * dies and comes back again, then we know how to deal
	 * with it.
	 */
	trc = pthread_create(&l_thread_id, NULL,
			     lutf_listener_main,
			     &g_lutf_cfg.l_info);
	if (trc) {
		PERROR("Failed to start thread");
		exit(LUTF_EXIT_ERR_THREAD_STARTUP);
	}

	/* spawn listener thread iff running in Master mode */
	rc = python_init();
	if (rc) {
		PERROR("Failed to initialize Python Module");
		if (rc == EN_LUTF_RC_ERR_THREAD_STARTUP)
			exit(LUTF_EXIT_ERR_THREAD_STARTUP);
		else
			exit(LUTF_EXIT_ERR_STARTUP);
	}

	pthread_join(l_thread_id, NULL);

	fclose(out);

	cYAML_free_tree(config_tree);

	return 0;
}
