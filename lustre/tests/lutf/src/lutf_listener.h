// SPDX-License-Identifier: GPL-2.0

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/tests/lutf/lutf_listener.h
 *
 * Author: Amir Shehata <ashehata@whamcloud.com>
 *
 */

#ifndef LUTF_LISTENER_H
#define LUTF_LISTENER_H

#include "lutf_common.h"
#include "lutf_agent.h"

/*
 * lutf_listener_main
 *   Main loop of the listener thread
 */
void *lutf_listener_main(void *usr_data);

void lutf_listener_shutdown(void);

void close_agent_connection(lutf_agent_blk_t *agent);

void release_dead_list_agents(void);

#endif /* LUTF_LISTENER_H */
