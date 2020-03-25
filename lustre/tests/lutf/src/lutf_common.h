#ifndef LUTF_COMMON_H
#define LUTF_COMMON_H

#define RESET   "\033[0m"
#define BLACK   "\033[30m"      /* Black */
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */
#define BLUE    "\033[34m"      /* Blue */
#define MAGENTA "\033[35m"      /* Magenta */
#define CYAN    "\033[36m"      /* Cyan */
#define WHITE   "\033[37m"      /* White */
#define BOLDBLACK   "\033[1m\033[30m"      /* Bold Black */
#define BOLDRED     "\033[1m\033[31m"      /* Bold Red */
#define BOLDGREEN   "\033[1m\033[32m"      /* Bold Green */
#define BOLDYELLOW  "\033[1m\033[33m"      /* Bold Yellow */
#define BOLDBLUE    "\033[1m\033[34m"      /* Bold Blue */
#define BOLDMAGENTA "\033[1m\033[35m"      /* Bold Magenta */
#define BOLDCYAN    "\033[1m\033[36m"      /* Bold Cyan */
#define BOLDWHITE   "\033[1m\033[37m"      /* Bold White */

#define LUTF_VERSION_NUMBER		 1

#define MAX_STR_LEN			 1024
#define MAX_MSG_SIZE			 2048

#define LUTF_EXIT_NORMAL		 0
#define LUTF_EXIT_ERR_STARTUP		-1
#define LUTF_EXIT_ERR_BAD_PARAM		-2
#define LUTF_EXIT_ERR_THREAD_STARTUP	-3
#define LUTF_EXIT_ERR_DEAMEON_STARTUP	-4

#define SYSTEMIPADDR			0x7f000001
#define INVALID_TCP_SOCKET		-1
#define SOCKET_TIMEOUT_USEC		900000
#define SOCKET_CONN_TIMEOUT_SEC		2
#define TCP_READ_TIMEOUT_SEC		20

/* default names */
#define TEST_ROLE_GRC		"GENERIC"
#define TEST_ROLE_MGS		"MGS"
#define TEST_ROLE_MDT		"MDT"
#define TEST_ROLE_OSS		"OSS"
#define TEST_ROLE_OST		"OST"
#define TEST_ROLE_RTR		"RTR"
#define TEST_ROLE_CLI		"CLI"

#define DEFAULT_MASTER_PORT	8282

typedef enum {
	EN_LUTF_RC_OK = 0,
	EN_LUTF_RC_FAIL = -1,
	EN_LUTF_RC_SYS_ERR = -2,
	EN_LUTF_RC_BAD_VERSION = -3,
	EN_LUTF_RC_SOCKET_FAIL = -4,
	EN_LUTF_RC_BIND_FAILED = -5,
	EN_LUTF_RC_LISTEN_FAILED = -6,
	EN_LUTF_RC_CLIENT_CLOSED = -7,
	EN_LUTF_RC_ERR_THREAD_STARTUP = -8,
	EN_LUTF_RC_AGENT_NOT_FOUND = -9,
	EN_LUTF_RC_PY_IMPORT_FAIL = -10,
	EN_LUTF_RC_PY_SCRIPT_FAIL = -11,
	EN_LUTF_RC_RPC_FAIL = -12,
	EN_LUTF_RC_OOM = -13,
	EN_LUTF_RC_BAD_PARAM = -14,
	EN_LUTF_RC_BAD_ADDR = -15,
	EN_LUTF_RC_MISSING_PARAM = -16,
	EN_LUTF_RC_TIMEOUT = -17,
	EN_LUTF_RC_MAX = -18,
} lutf_rc_t;

typedef enum lutf_type {
	EN_LUTF_MASTER = 1,
	EN_LUTF_AGENT = 2,
	EN_LUTF_INVALID,
} lutf_type_t;

#define INTERACTIVE "interactive"
#define BATCH "batch"
#define DAEMON "daemon"

typedef enum lutf_run_mode {
	EN_LUTF_RUN_INTERACTIVE = 1,
	EN_LUTF_RUN_BATCH = 2,
	EN_LUTF_RUN_DAEMON = 3,
	EN_LUTF_RUN_INVALID,
} lutf_run_mode_t;

#endif /* LUTF_COMMON_H */
