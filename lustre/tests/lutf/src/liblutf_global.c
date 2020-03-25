#include <pthread.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lutf.h"

char *get_lutf_path(void)
{
	return g_lutf_cfg.lutf_path;
}

char *get_py_path(void)
{
	return g_lutf_cfg.py_path;
}

char *get_master_name(void)
{
	return g_lutf_cfg.master_name;
}

char *get_suite_name(void)
{
	return g_lutf_cfg.suite;
}

char *get_script_name(void)
{
	return g_lutf_cfg.script;
}

char *get_matching_pattern(void)
{
	return g_lutf_cfg.pattern;
}

int get_master_listen_port(void)
{
	return g_lutf_cfg.l_info.listen_port;
}

char *get_node_name(void)
{
	return g_lutf_cfg.l_info.hb_info.node_name;
}

int get_agent_telnet_port(void)
{
	return g_lutf_cfg.l_info.hb_info.agent_telnet_port;
}

char *get_master_address(void)
{
	return inet_ntoa(g_lutf_cfg.l_info.hb_info.master_address.sin_addr);
}

int get_master_port(void)
{
	return g_lutf_cfg.l_info.hb_info.master_address.sin_port;
}

lutf_run_mode_t get_lutf_mode(void)
{
	return g_lutf_cfg.shell;
}

lutf_type_t get_lutf_type(void)
{
	return g_lutf_cfg.l_info.type;
}

char *get_lutf_results_file_path(void)
{
	return g_lutf_cfg.results_file;
}

char *get_lutf_cfg_file_path(void)
{
	return g_lutf_cfg.cfg_path;
}

char *get_lutf_tmp_dir(void)
{
	return g_lutf_cfg.tmp_dir;
}
