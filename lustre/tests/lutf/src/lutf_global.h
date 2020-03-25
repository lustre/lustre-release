#ifndef LUTF_CONNECT_H
#define LUTF_CONNECT_H

#include "lutf_common.h"

/* accessor functions to get global information */

char *get_lutf_path(void);
char *get_py_path(void);
char *get_master_name(void);
char *get_suite_name(void);
char *get_script_name(void);
char *get_matching_pattern(void);
int get_master_listen_port(void);
char *get_node_name(void);
int get_agent_telnet_port(void);
char *get_master_address(void);
int get_master_port(void);
lutf_run_mode_t get_lutf_mode(void);
lutf_type_t get_lutf_type(void);
char *get_lutf_results_file_path(void);
char *get_lutf_cfg_file_path(void);
char *get_lutf_tmp_dir(void);

#endif /* LUTF_CONNECT_H */
