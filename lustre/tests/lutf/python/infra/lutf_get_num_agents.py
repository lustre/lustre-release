from clutf_agent import *

def get_num_agents():
	i = 0
	for x in range(0, MAX_NUM_AGENTS):
		agent = find_agent_blk_by_id(x)
		if agent:
			i = i + 1
			release_agent_blk(agent, False)
	return i
