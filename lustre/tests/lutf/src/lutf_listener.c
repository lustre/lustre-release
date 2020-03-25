#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <pthread.h>
#include <string.h>
#include <signal.h>
#include "lutf.h"
#include "lutf_python.h"
#include "lutf_agent.h"
#include "lutf_message.h"
#include "lutf_listener.h"

static fd_set g_tAllSet;
static bool g_bShutdown = false;
static int g_iListenFd = INVALID_TCP_SOCKET;
bool g_agent_enable_hb = true;

typedef lutf_rc_t (*msg_process_fn_t)(char *msg, lutf_agent_blk_t *agent);

static lutf_rc_t process_msg_hb(char *msg, lutf_agent_blk_t *agent);
static lutf_rc_t process_msg_get_num_agents(char *msg, lutf_agent_blk_t *agent);
static lutf_rc_t process_msg_rpc_request(char *msg, lutf_agent_blk_t *agent);

static msg_process_fn_t msg_process_tbl[EN_MSG_TYPE_MAX] = {
	[EN_MSG_TYPE_HB] = process_msg_hb,
	[EN_MSG_TYPE_GET_NUM_AGENTS] = process_msg_get_num_agents,
	[EN_MSG_TYPE_RPC_REQUEST] = process_msg_rpc_request,
};

void lutf_listener_shutdown(void)
{
	g_bShutdown = true;
}

int get_highest_fd(void)
{
	int iAgentFd = lutf_agent_get_highest_fd();
	int iMaxFd;

	if (iAgentFd > g_iListenFd)
		iMaxFd = iAgentFd;
	else
		iMaxFd = g_iListenFd;
	PDEBUG("Current highest FD = %d", iMaxFd);

	return iMaxFd;
}

static lutf_rc_t process_msg_rpc_request(char *msg, lutf_agent_blk_t *agent)
{
	lutf_rc_t rc;

	agent->state |= LUTF_AGENT_WORK_IN_PROGRESS;
	rc = python_handle_rpc_request(msg);
	agent->state &= ~LUTF_AGENT_WORK_IN_PROGRESS;

	return rc;
}

static lutf_rc_t process_msg_hb(char *msg, lutf_agent_blk_t *agent)
{
	lutf_msg_hb_t *hb = (lutf_msg_hb_t *)msg;
	//PERROR("Procesing HB message");

	/* endian convert message */
	hb->telnet_port = ntohl(hb->telnet_port);
	hb->node_type = ntohl(hb->node_type);

	/* update the agent with the information */
	agent->telnet_port = hb->telnet_port;
	agent->node_type = hb->node_type;
	strncpy(agent->hostname, hb->node_hostname, MAX_STR_LEN);
	agent->hostname[MAX_STR_LEN-1] = '\0';
	strncpy(agent->name, hb->node_name, MAX_STR_LEN);
	agent->name[MAX_STR_LEN-1] = '\0';
	gettimeofday(&agent->time_stamp, NULL);

	return EN_LUTF_RC_OK;
}

static lutf_rc_t process_msg_get_num_agents(char *msg, lutf_agent_blk_t *agent)
{
	lutf_rc_t rc;
	lutf_msg_num_agents_query_t query;

	query.num_agents = get_num_agents();
	rc = sendTcpMessage(agent->iFileDesc, (char *)&query, sizeof(query));
	if (rc) {
		PERROR("failed to send tcp message to get num agents query");
		return rc;
	}

	return EN_LUTF_RC_OK;
}

static lutf_rc_t process_agent_message(lutf_agent_blk_t *agent, int fd)
{
	lutf_rc_t rc = EN_LUTF_RC_OK;
	lutf_message_hdr_t hdr;
	char *buffer;
	msg_process_fn_t proc_fn;

	/* get the header first */
	rc = readTcpMessage(fd, (char *)&hdr, sizeof(hdr),
			    TCP_READ_TIMEOUT_SEC);

	if (rc)
		return rc;

	hdr.version = ntohl(hdr.version);
	if (hdr.version != LUTF_VERSION_NUMBER) {
		PERROR("version %d != %d", hdr.version,
		       LUTF_VERSION_NUMBER);
		return EN_LUTF_RC_BAD_VERSION;
	}

	/* if the ips don't match ignore the message */
	if (memcmp(&agent->addr.sin_addr, &hdr.ip, sizeof(hdr.ip)))
		return rc;

	hdr.type = ntohl(hdr.type);
	hdr.len = ntohl(hdr.len);

	buffer = calloc(hdr.len, 1);
	if (!buffer)
		return EN_LUTF_RC_OOM;

	/* get the rest of the message */
	rc = readTcpMessage(fd, buffer, hdr.len,
			    TCP_READ_TIMEOUT_SEC);

	if (rc) {
		free(buffer);
		return rc;
	}

	/* call the appropriate processing function */
	proc_fn = msg_process_tbl[hdr.type];
	if (proc_fn)
		rc = proc_fn(buffer, agent);

	free(buffer);
	return rc;
}

static lutf_rc_t init_comm(unsigned short server_port)
{
	int iFlags;
	struct sockaddr_in sServAddr;

	signal(SIGPIPE, SIG_IGN);

	/*  Create a socket to listen to.  */
	g_iListenFd = socket(AF_INET, SOCK_STREAM, 0);
	if (g_iListenFd < 0) {
		/*  Cannot create a listening socket.  */
		return EN_LUTF_RC_SOCKET_FAIL;
	}

	/* Set a socket option which will allow us to be quickly restarted
	 * if necessary.
	 */
	iFlags = 1;
	if (setsockopt(g_iListenFd, SOL_SOCKET, SO_REUSEADDR, (void *) &iFlags,
		       sizeof(iFlags)) < 0) {
		/*  Cannot change the socket options.  */
		closeTcpConnection(g_iListenFd);
		return EN_LUTF_RC_FAIL;
	}

	/*  Bind to our listening socket.  */
	bzero((char *) &sServAddr, sizeof(sServAddr));
	sServAddr.sin_family = AF_INET;
	sServAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	sServAddr.sin_port = htons(server_port);

	if (bind(g_iListenFd, (struct sockaddr *) &sServAddr, sizeof(sServAddr)) < 0) {
		/*  Cannot bind our listening socket.  */
		closeTcpConnection(g_iListenFd);
		return EN_LUTF_RC_BIND_FAILED;
	}

	/*  Let the system know we wish to listen to this port for
	 *  connections. */
	if (listen(g_iListenFd, 2) < 0) {
		/*  Cannot listen to socket, close and fail  */
		closeTcpConnection(g_iListenFd);
		return EN_LUTF_RC_LISTEN_FAILED;
	}

	/* We want this socket to be non-blocking even though it will be used
	 * in a blocking select call. This is to avoid a problem identified by
	 * Richard Stevens.
	 */
	iFlags = fcntl(g_iListenFd, F_GETFL, 0);
	fcntl(g_iListenFd, F_SETFL, iFlags | O_NONBLOCK);

	/*  Add the listening socket to our select() mask.  */
	FD_ZERO(&g_tAllSet);
	FD_SET(g_iListenFd, &g_tAllSet);

	return EN_LUTF_RC_OK;
}

static inline int close_agent_connection(lutf_agent_blk_t *agent)
{
	FD_CLR(agent->iFileDesc, &g_tAllSet);
	FD_CLR(agent->iRpcFd, &g_tAllSet);
	closeTcpConnection(agent->iRpcFd);
	closeTcpConnection(agent->iFileDesc);
	agent->state &=
		~LUTF_AGENT_RPC_CHANNEL_CONNECTED;
	agent->state &=
		~LUTF_AGENT_HB_CHANNEL_CONNECTED;
	return get_highest_fd();
}

lutf_rc_t send_hb(lutf_agent_blk_t *agent, char *name, int telnet_port,
		  int type)
{
	lutf_msg_hb_t hb;
	int rc;

	hb.telnet_port = htonl(telnet_port);
	hb.node_type = htonl(type);
	strncpy(hb.node_name, name, MAX_STR_LEN);
	hb.node_name[MAX_STR_LEN-1] = '\0';
	gethostname(hb.node_hostname, MAX_STR_LEN);

	/* send the heart beat */
	rc = lutf_send_msg(agent->iFileDesc, (char *)&hb,
			   sizeof(hb), EN_MSG_TYPE_HB);
	if (rc != EN_LUTF_RC_OK) {
		PERROR("Failed to send heart beat %s\n",
			lutf_rc2str(rc));
	}

	return rc;
}

lutf_rc_t complete_agent_connection(lutf_agent_blk_t *agent, int fd)
{
	/* we assume the first connection is an HB connection */
	if (!(agent->state & LUTF_AGENT_HB_CHANNEL_CONNECTED)) {
		if (agent->iFileDesc != INVALID_TCP_SOCKET) {
			PERROR("agent in unexpected state. "
			       "state is %s, but HB FD is %d",
			       agent_state2str(agent), fd);
			return EN_LUTF_RC_SYS_ERR;
		} else {
			PDEBUG("HB Channel Connected: %d", fd);
			agent->iFileDesc = fd;
			agent->state |= LUTF_AGENT_HB_CHANNEL_CONNECTED;
			return EN_LUTF_RC_OK;
		}
	} else if (!(agent->state & LUTF_AGENT_RPC_CHANNEL_CONNECTED)) {
		if (agent->iRpcFd != INVALID_TCP_SOCKET) {
			PERROR("agent in unexpected state. "
			       "state is %s, but RPC FD is %d",
			       agent_state2str(agent), fd);
			return EN_LUTF_RC_SYS_ERR;
		} else {
			PDEBUG("RPC Channel Connected: %d", fd);
			agent->iRpcFd = fd;
			agent->state |= LUTF_AGENT_RPC_CHANNEL_CONNECTED;
			return EN_LUTF_RC_OK;
		}
	}

	PERROR("agent is in an unexpected state on connection %s",
	       agent_state2str(agent));
	return EN_LUTF_RC_SYS_ERR;
}

/*
 * lutf_listener_main
 *   main loop.  Listens for incoming agent connections, and for agent
 *   messages.  Every period of time it triggers a walk through the agent
 *   list to see if any of the HBs stopped
 *
 *   If I am an Agent, then attempt to connect to the master and add an
 *   agent block on the list of agents. After successful connection send
 *   a regular heart beat.
 *
 *   Since the master's agent block is on the list of agents and its FD is
 *   on the select FD set, then if the master sends the agent a message
 *   the agent should be able to process it.
 */
void *lutf_listener_main(void *usr_data)
{
	int iConnFd;
	struct sockaddr_in sCliAddr;
	socklen_t  tCliLen;
	fd_set tReadSet;
	int iNReady;
	int iMaxSelectFd;
	int i;
	lutf_rc_t rc;
	lutf_agent_blk_t *agent = NULL, *master = NULL;
	struct timeval time_1, time_2, select_to;
	lutf_listener_info_t *info;
	bool master_connected = false;

	info = (lutf_listener_info_t *)usr_data;
	if ((!info) ||
	    ((info) && (info->listen_port == 0))) {
		PERROR("No liston port provided");
		return NULL;
	}

	rc = init_comm(info->listen_port);
	if (rc) {
		PERROR("init_comm failed: %s", lutf_rc2str(rc));
		return NULL;
	}

	agent_init();

	iMaxSelectFd = g_iListenFd;

	gettimeofday(&time_1, NULL);


	/*  Main Processing Loop: Keep going until we have reason to shutdown. */
	while (!g_bShutdown) {
		/*  Wait on our select mask for an event to occur.  */
		tReadSet = g_tAllSet;

		select_to.tv_sec = HB_TO;
		select_to.tv_usec = 0;

		iNReady = select(iMaxSelectFd + 1, &tReadSet, NULL, NULL, &select_to);

		/*  Determine if we failed the select call */
		if (iNReady < 0) {
			/*  Check to see if we were interrupted by a signal.  */
			if ((errno == EINTR) || (errno == EAGAIN)) {
				PERROR("Select failure: errno = %d", errno);
			} else {
				/*  If this is an ECONNABORTED error, just ignore it.  */
				if (errno != ECONNABORTED) {
					/* Raise a fatal alarm.  */
					/* Shut down */
					PERROR("Shutting down Listener thread. errno: %d", errno);
					g_bShutdown = true;
				}
			}
		} else {
			if (FD_ISSET(g_iListenFd, &tReadSet)) {
				/*  A new client is trying to connect.  */
				tCliLen = sizeof(sCliAddr);
				iConnFd = accept(g_iListenFd, (struct sockaddr *) &sCliAddr,
						 &tCliLen);
				if (iConnFd < 0) {
					/*  Cannot accept new connection...just ignore.  */
					if (errno != EWOULDBLOCK)
						PERROR("Error on accept(), errno = %d", errno);
				} else {
					/* Try to see if we have an agent
					 * with the same address, since
					 * agents can have multiple tcp
					 * connections open
					 */
					agent = find_create_agent_blk_by_addr(&sCliAddr);
					if (!agent) {
						/*  Cannot support more clients...just ignore.  */
						PERROR("Cannot accept more clients");
						closeTcpConnection(iConnFd);
					} else {
						int iOption, iFlags;

						rc = complete_agent_connection(agent,
								iConnFd);
						if (rc != EN_LUTF_RC_OK) {
							int agent_id = agent->id;
							iMaxSelectFd = close_agent_connection(agent);
							release_agent_blk(agent);
							free_agent_blk(agent_id);
							continue;
						}

						/* all nodes listen on the
						 * same port
						 */
						agent->listen_port = info->listen_port;

						/*  Add new client to our select mask.  */
						FD_SET(iConnFd, &g_tAllSet);
						iMaxSelectFd = get_highest_fd();

						/* Ok, it seems that the connected socket gains
						 * the same flags as the listen socket.  We want
						 * to make it blocking here.
						 */
						iFlags = fcntl(iConnFd, F_GETFL, 0);
						fcntl(iConnFd, F_SETFL, iFlags & (~O_NONBLOCK));

						/*  And, we want to turn off Nagle's algorithm to
						 *  reduce latency
						 */
						iOption = 1;
						setsockopt(iConnFd, IPPROTO_TCP, TCP_NODELAY,
							   (void *)&iOption,
							   sizeof(iOption));

						PDEBUG("Received a connection from %s on FD %d\n",
						       inet_ntoa(agent->addr.sin_addr), iConnFd);

						release_agent_blk(agent);
					}
				}

				/*  See if there are other messages waiting.  */
				iNReady--;
			}

			/* need to iterate through the clients and see if a
			 * message was sent to any of them
			 */
			for (i = 0; ((i < MAX_NUM_AGENTS) && (iNReady > 0)); i++) {
				/* reset the return code to avoid misbehaving on previous
				 * returns
				 */
				rc = EN_LUTF_RC_OK;

				if ((agent = find_agent_blk_by_id(i))) {
					int hb_fd = INVALID_TCP_SOCKET;
					int rpc_fd = INVALID_TCP_SOCKET;

					if (FD_ISSET(agent->iFileDesc, &tReadSet))
						hb_fd = agent->iFileDesc;
					if (FD_ISSET(agent->iRpcFd, &tReadSet))
						rpc_fd = agent->iRpcFd;

					if (hb_fd == INVALID_TCP_SOCKET &&
					    rpc_fd == INVALID_TCP_SOCKET)
						continue;

					/* process heart beat */
					if (hb_fd != INVALID_TCP_SOCKET) {
						/* process the message */
						rc = process_agent_message(agent, hb_fd);
						if (rc)
							PERROR("msg failure: %s",
							       lutf_rc2str(rc));
					}
					if (rc == EN_LUTF_RC_SOCKET_FAIL) {
						int agent_id = agent->id;
						if (agent->id == master->id) {
							PERROR("Disconnected from master. Will attempt to reconnect");
							master_connected = false;
						}
						iMaxSelectFd = close_agent_connection(agent);
						release_agent_blk(agent);
						free_agent_blk(agent_id);
						continue;
					}

					/* process rpc */
					if (rpc_fd != INVALID_TCP_SOCKET) {
						/* process the message */
						rc = process_agent_message(agent, rpc_fd);
						if (rc)
							PERROR("msg failure: %s",
							       lutf_rc2str(rc));
					}
					if (rc == EN_LUTF_RC_SOCKET_FAIL) {
						int agent_id = agent->id;
						if (agent->id == master->id) {
							PERROR("Disconnected from master. Will attempt to reconnect");
							master_connected = false;
						}
						iMaxSelectFd = close_agent_connection(agent);
						release_agent_blk(agent);
						free_agent_blk(agent_id);
						continue;
					}
					release_agent_blk(agent);
				}
			}

			/* establish connection with the master if I'm an agent
			 * and I have not connected to the master yet.
			 * Otherwise send a heart beat
			 */
			if (!master_connected &&
			    strlen(g_lutf_cfg.master_name) != 0) {
				PDEBUG("Attempting a connection on master %s",
				       g_lutf_cfg.master_name);
				master = find_free_agent_blk(&info->hb_info.master_address);
				if (!master) {
					PERROR("Failed to allocate agent block");
					continue;
				}

				iConnFd = establishTCPConnection(
					info->hb_info.master_address.sin_addr.s_addr,
					htons(info->hb_info.master_address.sin_port),
					true, false);

				if (iConnFd < 0) {
					int master_id = master->id;

					PERROR("establishTCPConnection failure: %s. Clearing set",
						lutf_rc2str(iConnFd));
					iMaxSelectFd = close_agent_connection(master);
					release_agent_blk(master);
					free_agent_blk(master_id);
					PERROR("Disconnected from master. Will attempt to reconnect");
					master_connected = false;
					continue;
				}

				master->iFileDesc = iConnFd;
				memcpy(&master->addr,
				       &info->hb_info.master_address,
				       sizeof(master->addr));
				strncpy(master->name, g_lutf_cfg.master_name,
					MAX_STR_LEN);
				master->name[MAX_STR_LEN-1] = '\0';
				master->node_type = EN_LUTF_MASTER;
				gethostname(master->hostname, MAX_STR_LEN);
				master->telnet_port = info->hb_info.agent_telnet_port;
				release_agent_blk(master);

				PDEBUG("Connected to master %s on fd %d",
				       master->name, master->iFileDesc);

				/*
				 * add the master FD to the select FD set
				 * to be able to process master messages
				 */
				FD_SET(iConnFd, &g_tAllSet);
				iMaxSelectFd = get_highest_fd();

				master_connected = true;
				master->state |= LUTF_AGENT_HB_CHANNEL_CONNECTED;
			}
/*
			if (info->type == EN_LUTF_AGENT) {
				rc = send_hb(master, info->hb_info.node_name,
					     info->hb_info.agent_telnet_port,
					     info->type);
				if (rc != EN_LUTF_RC_OK) {
					master_connected = false;
					iMaxSelectFd = get_highest_fd();
				}
			}
*/
			/*
			 * Get the time stamp and go through each agent
			 * and see if it's still healthy.  For agents which
			 * aren't healthy move off to the dead_list.
			 * This operation is only valid if I'm a master
			 */
			gettimeofday(&time_2, NULL);
			if (g_agent_enable_hb && info->type == EN_LUTF_MASTER) {
				/* check if HB_TO seconds has passed since the last
				 * time we collected the time */
				if (time_2.tv_sec - time_1.tv_sec >= HB_TO * 100) {

					/* do the heartbeat check */
					agent_hb_check(&time_1, info->type);
				}
			}

			if (time_2.tv_sec - time_1.tv_sec >= HB_TO) {
				lutf_agent_blk_t *agent = NULL;
				int idx = 0;

				do {
					idx = get_next_active_agent(idx, &agent);
					/* A master doesn't send a heart
					 * beat to himself */
					if (agent) {
						if (info->type == EN_LUTF_MASTER &&
						    agent->id == master->id)
							continue;
						int agent_id = agent->id;
						rc = send_hb(agent, info->hb_info.node_name,
							     info->hb_info.agent_telnet_port,
							     info->type);
						if (rc != EN_LUTF_RC_OK) {
							if (agent->id == master->id) {
								PERROR("Disconnected from master. Will attempt to reconnect");
								master_connected = false;
							}
							iMaxSelectFd = close_agent_connection(agent);
							release_agent_blk(agent);
							free_agent_blk(agent_id);
						} else {
							release_agent_blk(agent);
						}
					}
				} while (agent);
			}
		}
		/* store the current time */
		time_1 = time_2;
	}

	/* Zero out the g_tAllSet */
	FD_ZERO(&g_tAllSet);

	return NULL;
}
