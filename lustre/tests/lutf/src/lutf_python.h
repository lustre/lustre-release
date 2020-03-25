#ifndef LUTF_PYTHON_H
#define LUTF_PYTHON_H

#include <pthread.h>
#include "lutf.h"

typedef struct python_thread_data_s {
	char **argv;
} python_thread_data_t;

/*
 * python_init
 *   Initialize the python interpreter.
 */
lutf_rc_t python_init(void);

/*
 * python_collect_agent_core
 *   Collect core information from the specified agent
 */
lutf_rc_t python_collect_agent_core(char *ip);

/*
 * python_handle_rpc_request
 *   Received an RPC now execute the operation in the python interpreter
 */
lutf_rc_t python_handle_rpc_request(char *rpc);

#endif /* LUTF_PYTHON_H */
