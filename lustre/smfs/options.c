/*
 *  snapfs/options.c
 */
#define DEBUG_SUBSYSTEM S_SM

#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include "smfs_internal.h" 


static struct list_head option_list;
char  *options = NULL;
char  *opt_left = NULL;

int init_option(char *data)
{
	INIT_LIST_HEAD(&option_list);
	SM_ALLOC(options, strlen(data) + 1);
	if (!options) {
		CERROR("Can not allocate memory \n");
		return -ENOMEM;
	}
	memcpy(options, data, strlen(data));
	opt_left = options;
	return 0;
}
/*cleanup options*/
void cleanup_option(void)
{
	struct option *option;
	while (!list_empty(&option_list)) {
		option = list_entry(option_list.next, struct option, list);
		list_del(&option->list);
		SM_FREE(option->opt, strlen(option->opt) + 1);
		SM_FREE(option->value, strlen(option->value) + 1);
		SM_FREE(option, sizeof(struct option));
	}
	SM_FREE(options, strlen(options) + 1);
}
int get_opt(struct option **option, char **pos)
{
	char  *name, *value, *left;
	struct option *tmp_opt;
	int  length;

	*pos = opt_left;

	if (! *opt_left)
		return -ENODATA;

	left = strchr(opt_left, '=');

	if (left == opt_left || !left) 
		return -EINVAL;

	SM_ALLOC(tmp_opt, sizeof(struct option));   	
		
	length = left - opt_left + 1;
	SM_ALLOC(name, length);
	tmp_opt->opt = name;
	memset(name, 0, length);
	while (opt_left != left) *name++ = *opt_left++;

	opt_left ++; /*after '='*/

	left = strchr(opt_left, ',');
	if (left == opt_left) {
		SM_FREE(tmp_opt->opt, length);
		SM_FREE(tmp_opt, sizeof(struct option));
		opt_left = *pos;
		return -EINVAL;
	}
	if (!left) 
		left = opt_left + strlen(opt_left); 
	length = left - opt_left + 1;
	SM_ALLOC(value, length);
	tmp_opt->value = value;
	memset(value, 0, length);
	while (opt_left != left) *value++ = *opt_left++;

	list_add(&tmp_opt->list, &option_list);
	
	if (*opt_left == ',') opt_left ++; /*after ','*/	

	*option = tmp_opt;
	return 0;
}
