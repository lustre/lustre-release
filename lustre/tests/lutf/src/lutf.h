#ifndef LUTF_H
#define LUTF_H

#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <sys/stat.h>
#include "lutf_common.h"
#include "lutf_agent.h"
#include "lutf_message.h"

extern FILE *out;
extern char *outlog;

#define OUT_LOG_NAME "lutf_out.log"
#define OUT_PY_LOG "lutf_py.log"
#define LARGE_LOG_FILE 400000000 /* 400 MB */

time_t debugnow;
int di;
char debugtimestr[30];

static inline void lutf_log_print(bool error, char *color1, char *color2,
				  char *file, int line, char *fmt, ...)
{
	time_t debugnow;
	int di;
	char debugtimestr[30];
	struct stat st;
	va_list args;

	/* check if the log file has grown too large */
	stat(outlog, &st);
	if (st.st_size > LARGE_LOG_FILE)
		out = freopen(outlog, "w", out);

	time(&debugnow);
	ctime_r(&debugnow, debugtimestr);
	for (di = 0; di < 30; di++) {
		if (debugtimestr[di] == '\n')
			debugtimestr[di] = '\0';
	}

	fprintf(out, "%s%s %s:%s:%d " RESET "%s- ", color1,
		(error) ? "ERROR" : "", debugtimestr, file, line, color2);
	va_start(args, fmt);
	vfprintf(out, fmt, args);
	va_end(args);
	fprintf(out, RESET"\n");
	fflush(out);
}

#define PERROR(fmt, args...) lutf_log_print(true, BOLDRED, RED, __FILE__, __LINE__, fmt, ## args)
#define PDEBUG(fmt, args...) lutf_log_print(false, BOLDGREEN, GREEN, __FILE__, __LINE__, fmt, ## args)

typedef struct hb_info_s {
	struct sockaddr_in master_address;
	int agent_telnet_port;
	char node_name[MAX_STR_LEN];
} hb_info_t;

typedef struct lutf_listener_info_s {
	lutf_type_t type;
	int listen_port;
	hb_info_t hb_info;
} lutf_listener_info_t;

typedef struct lutf_config_params_s {
	lutf_listener_info_t l_info;
	lutf_run_mode_t shell; /* run in [non]-interactive or daemon mode */
	char *cfg_path; /* path to config file */
	char *lutf_path; /* path to lutf */
	char *py_path; /* other python specific paths */
	char *master_name; /* name of master. Important if I'm an agent */
	char *suite; /* name of suite to run. Run all if not present */
	char *script; /* name of script to run. Suite must be specified */
	char *pattern; /* file match pattern */
	char *results_file; /* path to results file */
	char *tmp_dir; /* directory to put temporary files */
	struct cYAML *agents; /* list of agents to wait for before
			       * starting the test
			       */
} lutf_config_params_t;

lutf_config_params_t g_lutf_cfg;

static inline char *lutf_rc2str(lutf_rc_t rc)
{
	char *str[] = {
		[EN_LUTF_RC_OK] = "RC_OK",
		[EN_LUTF_RC_FAIL*-1] = "RC_FAIL",
		[EN_LUTF_RC_SYS_ERR*-1] = "RC_SYSTEM_ERROR",
		[EN_LUTF_RC_BAD_VERSION*-1] = "RC_BAD_VERSION",
		[EN_LUTF_RC_SOCKET_FAIL*-1] = "RC_SOCKET_FAIL",
		[EN_LUTF_RC_BIND_FAILED*-1] = "RC_BIND_FAIL",
		[EN_LUTF_RC_LISTEN_FAILED*-1] = "RC_LISTEN_FAIL",
		[EN_LUTF_RC_CLIENT_CLOSED*-1] = "RC_CLIENT_CLOSED",
		[EN_LUTF_RC_ERR_THREAD_STARTUP*-1] = "RC_ERR_THREAD_START",
		[EN_LUTF_RC_AGENT_NOT_FOUND*-1] = "RC_AGENT_NOT_FOUND",
		[EN_LUTF_RC_PY_IMPORT_FAIL*-1] = "RC_PY_IMPORT_FAIL",
		[EN_LUTF_RC_PY_SCRIPT_FAIL*-1] = "RC_PY_SCRIPT_FAIL",
		[EN_LUTF_RC_RPC_FAIL*-1] = "RC_RPC_FAIL",
		[EN_LUTF_RC_OOM*-1] = "RC_OOM",
		[EN_LUTF_RC_BAD_PARAM*-1] = "RC_BAD_PARAM",
		[EN_LUTF_RC_BAD_ADDR*-1] = "RC_BAD_ADDR",
		[EN_LUTF_RC_MISSING_PARAM*-1] = "RC_MISSING_PARAM",
		[EN_LUTF_RC_TIMEOUT*-1] = "RC_TIMEOUT",
	};

	if (rc <= EN_LUTF_RC_MAX)
		return "BAD RC";

	rc *= -1;

	return str[rc];
}

int establishTCPConnection(unsigned long uiAddress,
			   int iPort,
			   bool b_non_block,
			   bool endian);


lutf_rc_t sendTcpMessage(int iTcpSocket, char *pcBody, int iBodySize);

lutf_rc_t lutf_send_msg(int fd, char *msg, size_t msg_size,
			lutf_msg_type_t type);

lutf_rc_t populateMsgHdr(int rsocket, char *msg_hdr,
			 int msg_type, int msg_size,
			 int lutf_version_number);

lutf_rc_t readTcpMessage(int iFd, char *pcBuffer,
			 int iBufferSize, int iTimeout);

lutf_rc_t closeTcpConnection(int iTcpSocket);

#endif /* LUTF_H */
