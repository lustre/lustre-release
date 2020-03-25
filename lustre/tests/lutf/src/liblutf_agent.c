#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "cyaml.h"
#include "lutf_agent.h"
#include "lutf.h"
#include "lutf_python.h"

static pthread_mutex_t agent_array_mutex;
static lutf_agent_blk_t *agent_live_list[MAX_NUM_AGENTS];
/* TODO: this is probably not thread safe */
static char agent_state_str[128];

extern bool g_agent_enable_hb;
extern struct in_addr g_local_ip;

#define DEFAULT_RPC_RSP "rpc:\n   src: %s\n   dst: %s\n   type: failure\n"

#define MUTEX_LOCK(x) \
  pthread_mutex_lock(x)

#define MUTEX_UNLOCK(x) \
  pthread_mutex_unlock(x)

char *get_local_ip()
{
	return inet_ntoa(g_local_ip);
}

void release_agent_blk(lutf_agent_blk_t *agent)
{
	/* release the agent blk mutex */
	MUTEX_LOCK(&agent->mutex);
	if (agent) {
		assert(agent->ref_count != 0);
		agent->ref_count--;
	}
	MUTEX_UNLOCK(&agent->mutex);
}

void acquire_agent_blk(lutf_agent_blk_t *agent)
{
	/* acquire the agent blk mutex */
	MUTEX_LOCK(&agent->mutex);
	if (agent)
		agent->ref_count++;
	MUTEX_UNLOCK(&agent->mutex);
}

char *agent_state2str(lutf_agent_blk_t *agent)
{
	if (!agent)
		return "NULL PARAMETER";

	sprintf(agent_state_str, "%s%s%s%s",
		(agent->state & LUTF_AGENT_STATE_ALIVE) ? "alive " : "dead ",
		(agent->state & LUTF_AGENT_HB_CHANNEL_CONNECTED) ? " HB" : "",
		(agent->state & LUTF_AGENT_RPC_CHANNEL_CONNECTED) ? " RPC" : "",
		(agent->state & LUTF_AGENT_WORK_IN_PROGRESS) ? " WIP" : "");

	return agent_state_str;
}

static lutf_agent_blk_t *find_agent_blk_by_addr(lutf_agent_blk_t **list,
						struct sockaddr_in *addr)
{
	int i;
	lutf_agent_blk_t *agent;

	if (!addr)
		return NULL;

	MUTEX_LOCK(&agent_array_mutex);
	for (i = 0; i < MAX_NUM_AGENTS; i++) {
		agent = list[i];
		if ((agent) &&
		    (agent->addr.sin_addr.s_addr ==
		     addr->sin_addr.s_addr)) {
			MUTEX_UNLOCK(&agent_array_mutex);
			return agent;
		}
	}
	MUTEX_UNLOCK(&agent_array_mutex);

	return NULL;
}

int get_next_active_agent(int idx, lutf_agent_blk_t **out)
{
	int i = idx;
	lutf_agent_blk_t *agent = NULL;

	if (idx >= MAX_NUM_AGENTS)
		goto out;

	MUTEX_LOCK(&agent_array_mutex);
	for (i = idx; i < MAX_NUM_AGENTS; i++) {
		agent = agent_live_list[i];
		if (agent) {
			i++;
			acquire_agent_blk(agent);
			break;
		}
	}
	MUTEX_UNLOCK(&agent_array_mutex);

out:
	*out = agent;

	return i;
}

lutf_agent_blk_t *find_create_agent_blk_by_addr(struct sockaddr_in *addr)
{
	lutf_agent_blk_t *agent;
	agent = find_agent_blk_by_addr(agent_live_list, addr);
	if (!agent)
		return find_free_agent_blk(addr);

	MUTEX_LOCK(&agent_array_mutex);
	acquire_agent_blk(agent);
	MUTEX_UNLOCK(&agent_array_mutex);

	return agent;
}

int lutf_agent_get_highest_fd(void)
{
	lutf_agent_blk_t *agent;
	int iMaxFd = INVALID_TCP_SOCKET;
	int i;

	MUTEX_LOCK(&agent_array_mutex);
	for (i = 0; i < MAX_NUM_AGENTS; i++) {
		agent = agent_live_list[i];
		if (agent) {
			if (agent->iFileDesc > iMaxFd)
				iMaxFd = agent->iFileDesc;
			if (agent->iRpcFd > iMaxFd)
				iMaxFd = agent->iRpcFd;
		}
	}
	MUTEX_UNLOCK(&agent_array_mutex);

	return iMaxFd;
}

void agent_disable_hb(void)
{
	g_agent_enable_hb = false;
}

void agent_enable_hb(void)
{
	g_agent_enable_hb = true;
}

lutf_agent_blk_t *find_free_agent_blk(struct sockaddr_in *addr)
{
	int i = 0;
	lutf_agent_blk_t *agent;

	/* grab the lock for the array */
	MUTEX_LOCK(&agent_array_mutex);

	/* iterate through the array to find a free entry */
	while (agent_live_list[i] != NULL)
		i++;

	if (i >= MAX_NUM_AGENTS) {
		MUTEX_UNLOCK(&agent_array_mutex);
		return NULL;
	}

	/* allocate a new agent blk and assign it to that entry */
	agent = calloc(sizeof(char),
		sizeof(lutf_agent_blk_t));
	if (!agent) {
		MUTEX_UNLOCK(&agent_array_mutex);
		return NULL;
	}

	gettimeofday(&agent->time_stamp, NULL);
	agent->id = i;
	agent->iFileDesc = INVALID_TCP_SOCKET;
	agent->iRpcFd = INVALID_TCP_SOCKET;
	agent->addr = *addr;
	set_agent_state(agent, LUTF_AGENT_STATE_ALIVE);

	pthread_mutex_init(&agent->mutex, NULL);
	acquire_agent_blk(agent);

	/* assign to array */
	agent_live_list[i] = agent;

	/* release the array mutex */
	MUTEX_UNLOCK(&agent_array_mutex);

	/* return the agent blk */
	return agent;
}

lutf_agent_blk_t *find_agent_blk_by_id(int idx)
{
	lutf_agent_blk_t *agent;

	if ((idx < 0) || (idx >= MAX_NUM_AGENTS))
		return NULL;

	/* grab the array mutex */
	MUTEX_LOCK(&agent_array_mutex);

	/* if the blk is non null grab the mutex.
	 * possibly block until previous user is done
	 */
	if (agent_live_list[idx] == NULL) {
		MUTEX_UNLOCK(&agent_array_mutex);
		return NULL;
	}

	agent = agent_live_list[idx];

	acquire_agent_blk(agent);

	/* release the array mutex */
	MUTEX_UNLOCK(&agent_array_mutex);

	/* return the agent blk */
	return agent;
}

void set_agent_state(lutf_agent_blk_t *agent, unsigned int state)
{
	MUTEX_LOCK(&agent->mutex);
	agent->state |= state;
	MUTEX_UNLOCK(&agent->mutex);
}

void unset_agent_state(lutf_agent_blk_t *agent, unsigned int state)
{
	bool zombie = false;

	MUTEX_LOCK(&agent->mutex);
	agent->state &= ~state;
	if (!(agent->state & LUTF_AGENT_WORK_IN_PROGRESS) &&
	    (agent->state & LUTF_AGENT_ZOMBIE))
		zombie = true;
	MUTEX_UNLOCK(&agent->mutex);

	if (zombie)
		free_agent_blk(agent->id);
}

void free_agent_blk(int id)
{
	lutf_agent_blk_t *agent;

	/* grab the array mutex */
	MUTEX_LOCK(&agent_array_mutex);

	/* if the blk is non null grab the mutex.
	 * possibly block until previous user is done
	 */
	if (agent_live_list[id] == NULL) {
		MUTEX_UNLOCK(&agent_array_mutex);
		return;
	}

	agent = agent_live_list[id];

	MUTEX_LOCK(&agent->mutex);
	if (agent->state & LUTF_AGENT_WORK_IN_PROGRESS) {
		MUTEX_UNLOCK(&agent->mutex);
		MUTEX_UNLOCK(&agent_array_mutex);
		PDEBUG("delay deleting agent %s\n", agent->name);
		set_agent_state(agent, LUTF_AGENT_ZOMBIE);
		return;
	}
	MUTEX_UNLOCK(&agent->mutex);

	agent_live_list[id] = NULL;

	/* release the array mutex */
	MUTEX_UNLOCK(&agent_array_mutex);

	/* free the block */
	free(agent);
}

char *agent_ip2str(lutf_agent_blk_t *agent)
{
	if (!agent)
		return NULL;

	return inet_ntoa(agent->addr.sin_addr);
}

int get_num_agents(void)
{
	int i;
	int num = 0;
	for (i = 0; i < MAX_NUM_AGENTS; i++) {
		if (agent_live_list[i] != NULL)
			num++;
	}

	return num;
}

/* no lock version of the function */
static lutf_agent_blk_t *find_agent_blk_by_name_nl(char *name)
{
	lutf_agent_blk_t *agent;
	int i;

	if (!name)
		return NULL;

	MUTEX_LOCK(&agent_array_mutex);

	for (i = 0; i < MAX_NUM_AGENTS; i++) {
		agent = agent_live_list[i];
		if ((agent) &&
		    ((strcmp(agent->name, name) == 0) ||
		     (strcmp(name, TEST_ROLE_GRC) == 0))) {
			break;
		}
	}

	MUTEX_UNLOCK(&agent_array_mutex);

	/* return the agent blk */
	return agent;
}

lutf_agent_blk_t *find_agent_blk_by_name(char *name)
{
	lutf_agent_blk_t *agent;

	agent = find_agent_blk_by_name_nl(name);
	if (agent)
		acquire_agent_blk(agent);

	/* return the agent blk */
	return agent;
}

lutf_agent_blk_t *find_agent_blk_by_ip(char *ip)
{
	lutf_agent_blk_t *agent;
	int i;
	struct sockaddr_in addr;

	if (!ip)
		return NULL;

	inet_aton(ip, &addr.sin_addr);

	/* grab the array mutex */
	MUTEX_LOCK(&agent_array_mutex);

	for (i = 0; i < MAX_NUM_AGENTS; i++) {
		agent = agent_live_list[i];
		if ((agent) && (agent->addr.sin_addr.s_addr ==
				addr.sin_addr.s_addr))
			break;
	}

	if (agent)
		acquire_agent_blk(agent);

	/* release the array mutex */
	MUTEX_UNLOCK(&agent_array_mutex);

	/* return the agent blk */
	return agent;
}

void agent_hb_check(struct timeval *t, lutf_type_t me)
{
	lutf_agent_blk_t *agent;
	int i;

	/* grab the array mutex */
	MUTEX_LOCK(&agent_array_mutex);

	for (i = 0; i < MAX_NUM_AGENTS; i++) {
		agent = agent_live_list[i];
		if (agent && agent->node_type != me) {
			acquire_agent_blk(agent);
			if (t->tv_sec - agent->time_stamp.tv_sec >= HB_TO*100) {
				int agent_id = agent->id;
				/* agent didn't send a HB move to dead
				 * list
				 */
				PERROR("agent %s presumed dead", agent->name);
				release_agent_blk(agent);
				MUTEX_UNLOCK(&agent_array_mutex);
				/* free_agent_blk() grabs the mutex */
				free_agent_blk(agent_id);
				MUTEX_LOCK(&agent_array_mutex);
				continue;
			}
			release_agent_blk(agent);
		}
	}

	/* release the array mutex */
	MUTEX_UNLOCK(&agent_array_mutex);
}

lutf_rc_t wait_for_agents(struct cYAML *agents, int timeout)
{
	struct timeval start;
	struct timeval now;
	struct cYAML *a;
	bool found = false;
	lutf_agent_blk_t *agent;

	gettimeofday(&start, NULL);
	gettimeofday(&now, NULL);

	if (!agents) {
		PDEBUG("No agent to wait for");
		return EN_LUTF_RC_OK;
	}

	PDEBUG("Start waiting for Agents");

	while (now.tv_sec - start.tv_sec < timeout && !found) {
		found = true;
		PDEBUG("Waiting for Agents");
		while (cYAML_get_next_seq_item(agents, &a) != NULL) {
			PDEBUG("Looking up: %s", a->cy_valuestring);
			if (!(agent = find_agent_blk_by_name(a->cy_valuestring))) {
				found = false;
				break;
			} else {
				PDEBUG("agent %s found\n", agent->name);
				release_agent_blk(agent);
			}
		}
		if (!found)
			sleep(1);
		gettimeofday(&now, NULL);
	}

	return found ? EN_LUTF_RC_OK : EN_LUTF_RC_TIMEOUT;
}

int get_num_agents_remote(char *masterIP, int masterPort)
{
	lutf_rc_t rc;
	lutf_msg_num_agents_query_t msg;
	lutf_msg_num_agents_query_t *msg_p;
	lutf_message_hdr_t hdr;
	lutf_message_hdr_t *hdr_p;
	int remoteSocket = INVALID_TCP_SOCKET;
	struct in_addr addr;
	char *recvBuf = calloc(1, sizeof(hdr) + sizeof(hdr));

	if (!recvBuf) {
		PERROR("out of memory");
		rc = EN_LUTF_RC_FAIL;
		goto out;
	}

	if (!inet_aton(masterIP, &addr)) {
		PERROR("bad master IP = %s", masterIP);
		rc = EN_LUTF_RC_FAIL;
		goto out;
	}

	/* in network byte order, convert so we can have a
	 * uniform API
	 */
	remoteSocket = establishTCPConnection(addr.s_addr,
						htons(masterPort),
						false, false);
	if (remoteSocket < 0) {
		PERROR("establishTCPConnection failure: %s", lutf_rc2str(remoteSocket));
		rc = remoteSocket;
		goto out;
	}

	rc = lutf_send_msg(remoteSocket, NULL, 0, EN_MSG_TYPE_GET_NUM_AGENTS);
	if (rc)
		goto out;

	rc = readTcpMessage(remoteSocket, recvBuf, sizeof(hdr) + sizeof(msg),
			    TCP_READ_TIMEOUT_SEC);
	if (rc) {
		PERROR("failed to receive response");
		goto out;
	}

	hdr_p = (lutf_message_hdr_t *)recvBuf;
	msg_p = (lutf_msg_num_agents_query_t *)(recvBuf + sizeof(hdr));

	if (hdr_p->type != EN_MSG_TYPE_GET_NUM_AGENTS) {
		PERROR("Unexpected message. Waiting for num agents received %d",
		       hdr_p->type);
		rc = EN_LUTF_RC_FAIL;
		goto out;
	}

	rc = msg_p->num_agents;

out:
	closeTcpConnection(remoteSocket);
	free(recvBuf);
	return rc;
}

lutf_rc_t lutf_send_rpc(char *agent, char *yaml, int timeout, char **rsp)
{
	lutf_rc_t rc = EN_LUTF_RC_RPC_FAIL;
	lutf_agent_blk_t *agent_blk;
	char *default_rsp;
	lutf_message_hdr_t hdr;
	char *recvBuf = NULL;
	int msg_size;

	if (!agent || !yaml || !rsp)
		goto fail_rpc;

	msg_size = strlen(yaml) + 1;

	PDEBUG("sending rpc request\n%s", yaml);

	agent_blk = find_agent_blk_by_name(agent);
	if (!agent_blk) {
		PERROR("Can't find agent with name: %s", agent);
		goto fail_rpc_no_agent;
	}

	MUTEX_LOCK(&agent_blk->mutex);
	if (!(agent_blk->state & LUTF_AGENT_RPC_CHANNEL_CONNECTED)) {
		MUTEX_UNLOCK(&agent_blk->mutex);
		PDEBUG("Establishing an RPC channel to agent %s:%s:%d",
		       agent_blk->name,
		       inet_ntoa(agent_blk->addr.sin_addr),
		       agent_blk->listen_port);
		/* in network byte order, convert so we can have a uniform API */
		agent_blk->iRpcFd = establishTCPConnection(
				agent_blk->addr.sin_addr.s_addr,
				htons(agent_blk->listen_port),
				false, false);
		if (agent_blk->iRpcFd < 0)
			goto fail_rpc;
		set_agent_state(agent_blk,
				LUTF_AGENT_RPC_CHANNEL_CONNECTED);
	} else {
		MUTEX_UNLOCK(&agent_blk->mutex);
	}

	set_agent_state(agent_blk, LUTF_AGENT_WORK_IN_PROGRESS);

	rc = lutf_send_msg(agent_blk->iRpcFd, yaml, msg_size,
			   EN_MSG_TYPE_RPC_REQUEST);
	if (rc != EN_LUTF_RC_OK) {
		PERROR("Failed to send rpc message: %s", yaml);
		goto fail_rpc;
	}

	/* wait for the response */
	rc = readTcpMessage(agent_blk->iRpcFd, (char *)&hdr,
			    sizeof(hdr), timeout);
	if (rc != EN_LUTF_RC_OK) {
		PERROR("Failed to recv rpc header in timeout %d",
		       timeout);
		goto fail_rpc;
	}

	if (ntohl(hdr.type) != EN_MSG_TYPE_RPC_RESPONSE ||
	    ntohl(hdr.version) != LUTF_VERSION_NUMBER) {
		PERROR("Bad response. version %d, type:%d\n",
		       hdr.type, hdr.version);
		goto fail_rpc;
	}

	recvBuf = calloc(ntohl(hdr.len), 1);
	if (!recvBuf) {
		PERROR("Failed to allocate buffer to recv rpc response");
		goto fail_rpc;
	}

	rc = readTcpMessage(agent_blk->iRpcFd, recvBuf, ntohl(hdr.len), timeout);
	if (rc != EN_LUTF_RC_OK) {
		PERROR("Failed to recv rpc body in timeout %d", timeout);
		goto fail_rpc;
	}

	/*
	 * once recvBuf is given back to the caller, it's expected that
	 * the caller will manage the memory and free when done. This is
	 * mainly called from python. The SWIG wrapper frees the memory
	 * appropriately.
	 */
	*rsp = recvBuf;
	release_agent_blk(agent_blk);

	unset_agent_state(agent_blk, LUTF_AGENT_WORK_IN_PROGRESS);

	return EN_LUTF_RC_OK;

fail_rpc:
	release_agent_blk(agent_blk);
	unset_agent_state(agent_blk, LUTF_AGENT_WORK_IN_PROGRESS);
	if (recvBuf)
		free(recvBuf);
	msg_size = strlen(DEFAULT_RPC_RSP)+strlen(agent_blk->name)+
		strlen(g_lutf_cfg.l_info.hb_info.node_name) + 1;
fail_rpc_no_agent:
	default_rsp = calloc(msg_size, 1);
	if (!default_rsp) {
		PERROR("Failed to allocate buffer for default response");
		*rsp = NULL;
	} else {
		/* the source for the response would be the agent we sent
		 * to and the destination is me
		 */
		snprintf(default_rsp, msg_size,
			 DEFAULT_RPC_RSP, agent,
			 g_lutf_cfg.l_info.hb_info.node_name);
		*rsp = default_rsp;
	}

	return rc;
}

lutf_rc_t lutf_send_rpc_rsp(char *agent, char *yaml)
{
	lutf_rc_t rc = EN_LUTF_RC_RPC_FAIL;
	lutf_agent_blk_t *agent_blk;
	int msg_size;

	if (!agent || !yaml)
		goto out;

	msg_size = strlen(yaml) + 1;

	agent_blk = find_agent_blk_by_name_nl(agent);
	if (!agent_blk) {
		PERROR("Can't find agent with name: %s", agent);
		goto out;
	}

	MUTEX_LOCK(&agent_blk->mutex);
	if (!(agent_blk->state & LUTF_AGENT_RPC_CHANNEL_CONNECTED)) {
		MUTEX_UNLOCK(&agent_blk->mutex);
		PERROR("agent_blk %s doesn't have an RPC channel",
		       agent_blk->name);
		goto out;
	}
	MUTEX_UNLOCK(&agent_blk->mutex);

	PDEBUG("sending rpc response\n%s", yaml);
	rc = lutf_send_msg(agent_blk->iRpcFd, yaml, msg_size,
			   EN_MSG_TYPE_RPC_RESPONSE);

out:
	return rc;
}

void agent_init(void)
{
	pthread_mutex_init(&agent_array_mutex, NULL);
}
