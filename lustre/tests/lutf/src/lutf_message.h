#ifndef LUTF_MESSAGE_H
#define LUTF_MESSAGE_H

#include "lutf_common.h"

typedef enum {
	EN_MSG_TYPE_HB = 0,
	EN_MSG_TYPE_GET_NUM_AGENTS,
	EN_MSG_TYPE_RPC_REQUEST,
	EN_MSG_TYPE_RPC_RESPONSE,
	EN_MSG_TYPE_MAX
} lutf_msg_type_t;

typedef struct lutf_message_hdr_s {
	lutf_msg_type_t type;
	unsigned int len;
	struct in_addr ip;
	unsigned int version;
} lutf_message_hdr_t;

typedef struct lutf_msg_hb_s {
	unsigned int telnet_port;
	lutf_type_t node_type;
	char node_name[MAX_STR_LEN];
	char node_hostname[MAX_STR_LEN];
} lutf_msg_hb_t;

typedef struct lutf_msg_num_agents_query_s {
	int num_agents;
} lutf_msg_num_agents_query_t;

#endif /* LUTF_MESSAGE_H */
