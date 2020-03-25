#ifndef LUTF_AGENTS_H
#define LUTF_AGENTS_H

#include "lutf_common.h"

#define MAX_NUM_AGENTS		1024
#define HB_TO			2

struct cYAML;

#define LUTF_AGENT_STATE_ALIVE (1 << 0)
#define LUTF_AGENT_HB_CHANNEL_CONNECTED (1 << 1)
#define LUTF_AGENT_RPC_CHANNEL_CONNECTED (1 << 2)
#define LUTF_AGENT_WORK_IN_PROGRESS (1 << 3)
#define LUTF_AGENT_ZOMBIE (1 << 4)

typedef struct lutf_agent_blk_s {
	pthread_mutex_t mutex;
	unsigned int id;
	unsigned int version;
	unsigned int telnet_port;
	unsigned int listen_port;
	char name[MAX_STR_LEN];
	char hostname[MAX_STR_LEN];
	int iFileDesc;
	int iRpcFd;
	struct timeval time_stamp;
	struct sockaddr_in addr;
	unsigned int state;
	unsigned int ref_count;
	lutf_type_t node_type;
} lutf_agent_blk_t;

/* lutf_agent_get_highest_fd
 *	Find the highest connected FD in all connected agents.
 */
int lutf_agent_get_highest_fd(void);

/* agent_state2str
 *	print agent state
 */
char *agent_state2str(lutf_agent_blk_t *agent);

/* get_local_ip
 *   gets the local IP address being used to send messages to the master
 */
char *get_local_ip();

/*
 * get_next_active_agent
 *	given an index start searching from that point on to find an
 *	active agent.
 *	To reset the loop start the index from 0
 */
int get_next_active_agent(int idx, lutf_agent_blk_t **out);

/*
 * find_agent_blk_by_id
 *	Find the agent blk given an internal ID
 *	Agent ref-count is incremented
 */
lutf_agent_blk_t *find_agent_blk_by_id(int idx);

/*
 * find_agent_blk_by_ip
 *	Find the agent blk given its IP address
 *	Agent ref-count is incremented
 */
lutf_agent_blk_t *find_agent_blk_by_ip(char *ip);

/*
 * find_agent_blk_by_name
 *	Find the agent blk given its name
 *	Agent ref-count is incremented
 */
lutf_agent_blk_t *find_agent_blk_by_name(char *name);

/*
 * find_create_agent_blk_by_addr
 *	return an agent block with this address or create a new one
 */
lutf_agent_blk_t *find_create_agent_blk_by_addr(struct sockaddr_in *addr);

/*
 * find_free_agent_blk
 *	Find a free agent block
 */
lutf_agent_blk_t *find_free_agent_blk(struct sockaddr_in *addr);

/*
 * free_agent_blk
 *	Free an agent blk that no longer is needed
 */
void free_agent_blk(int id);

/*
 * acquire_agent_blk
 *	acquire the agent for work
 */
void acquire_agent_blk(lutf_agent_blk_t *agent);

/*
 * release_agent_blk
 *	Release the agent blk
 */
void release_agent_blk(lutf_agent_blk_t *agent);

/*
 * agent_ip2str
 *	Returns the ip string representation
 */
char *agent_ip2str(lutf_agent_blk_t *agent);

/*
 * agent_hb_check
 *	Given a time struct insure that the agent doesn't exceed the HB
 *	time.
 */
void agent_hb_check(struct timeval *t, lutf_type_t whoami);

/*
 * agent_disable_hb
 *	Disables the HB
 */
void agent_disable_hb(void);

/*
 * agent_enable_hb
 *	Enables the HB
 */
void agent_enable_hb(void);

/*
 * get the number of registered agents
 */
int get_num_agents(void);

/*
 * Connect to masterIP:masterPort and get the number of agents connected
 * to the master
 */
int get_num_agents_remote(char *masterIP, int masterPort);

/*
 * wait for the agents specified to be connected. If we don't get the full
 * list within the time specified then fail
 */
lutf_rc_t wait_for_agents(struct cYAML *agents, int timeout);

/*
 * set_agent_state
 *
 * convenience function to set the agent state
 */
void set_agent_state(lutf_agent_blk_t *agent, unsigned int state);

/*
 * unset_agent_state
 *
 * unset the state and check if the agent is a zombie and
 * it has not pending work. If so then free it
 */
void unset_agent_state(lutf_agent_blk_t *agent, unsigned int state);

/*
 * lutf_send_rpc
 *   send an RPC message and wait for the RPC response
 *   RPCs always come in request/response pairs. This function will send
 *   the request and will block until it gets the response. If it doesn't
 *   get a response in the specified timeout it'll fail.
 *   Parameters:
 *	target: name of the agent to send to
 *	yaml: NULL terminated string to send to the target
 *	timeout: to wait for response
 *	rsp: rpc response
 *
 *  Return:
 *     Returns a string YAML block
 */
lutf_rc_t lutf_send_rpc(char *agent, char *yaml, int timeout, char **rsp);

/*
 * lutf_send_rpc_rsp
 *   send a response to the RPC origin.
 *   Parameters:
 *      target: name of the agent to send to
 *      yaml: NULL terminated string to send to the target
 */
lutf_rc_t lutf_send_rpc_rsp(char *agent, char *yaml);

/*
 * agent_init
 *	Initialize the agent module
 */
void agent_init(void);

#endif /* LUTF_AGENTS_H */
