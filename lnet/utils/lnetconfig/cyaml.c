/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <http://www.gnu.org/licenses/>.
 *
 * LGPL HEADER END
 *
 * Copyright (c) 2014, 2017, Intel Corporation.
 *
 * Author:
 *   Amir Shehata <amir.shehata@intel.com>
 */

/*
 *  The cYAML tree is constructed as an n-tree.
 *  root -> cmd 1
 *          ||
 *          \/
 *          cmd 2 -> attr1 -> attr2
 *				||
 *				\/
 *			      attr2.1 -> attr2.1.1 -> attr2.1.2
 */

#include <yaml.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <errno.h>
#include <float.h>
#include <limits.h>
#include <ctype.h>
#include "libcfs/util/list.h"
#include <cyaml.h>

#define INDENT		4
#define EXTRA_IND	2
#define LEAD_ROOM	128
#define PRINT_BUF_LEN	2048

/*
 * cYAML_print_info
 *   This structure contains print information
 *   required when printing the node
 */
struct cYAML_print_info {
	int level;
	int array_first_elem;
	int extra_ind;
};

/*
 *  cYAML_ll
 *  Linked list of different trees representing YAML
 *  documents.
 */
struct cYAML_ll {
	struct list_head list;
	struct cYAML *obj;
	struct cYAML_print_info *print_info;
};

static void print_value(char **out, struct list_head *stack);

enum cYAML_handler_error {
	CYAML_ERROR_NONE = 0,
	CYAML_ERROR_UNEXPECTED_STATE = -1,
	CYAML_ERROR_NOT_SUPPORTED = -2,
	CYAML_ERROR_OUT_OF_MEM = -3,
	CYAML_ERROR_BAD_VALUE = -4,
	CYAML_ERROR_PARSE = -5,
};

enum cYAML_tree_state {
	TREE_STATE_COMPLETE = 0,
	TREE_STATE_INITED,
	TREE_STATE_TREE_STARTED,
	TREE_STATE_BLK_STARTED,
	TREE_STATE_KEY,
	TREE_STATE_KEY_FILLED,
	TREE_STATE_VALUE,
	TREE_STATE_SEQ_START,
};

struct cYAML_tree_node {
	struct cYAML *root;
	/* cur is the current node we're operating on */
	struct cYAML *cur;
	enum cYAML_tree_state state;
	int from_blk_map_start;
	/* represents the tree depth */
	struct list_head ll;
};

typedef enum cYAML_handler_error (*yaml_token_handler)(yaml_token_t *token,
						struct cYAML_tree_node *);

static enum cYAML_handler_error yaml_no_token(yaml_token_t *token,
					struct cYAML_tree_node *tree);
static enum cYAML_handler_error yaml_stream_start(yaml_token_t *token,
					struct cYAML_tree_node *tree);
static enum cYAML_handler_error yaml_stream_end(yaml_token_t *token,
					struct cYAML_tree_node *tree);
static enum cYAML_handler_error yaml_not_supported(yaml_token_t *token,
						struct cYAML_tree_node *tree);
static enum cYAML_handler_error yaml_document_start(yaml_token_t *token,
						struct cYAML_tree_node *tree);
static enum cYAML_handler_error yaml_document_end(yaml_token_t *token,
					       struct cYAML_tree_node *tree);
static enum cYAML_handler_error yaml_blk_seq_start(yaml_token_t *token,
						struct cYAML_tree_node *tree);
static enum cYAML_handler_error yaml_blk_mapping_start(yaml_token_t *token,
						struct cYAML_tree_node *tree);
static enum cYAML_handler_error yaml_block_end(yaml_token_t *token,
					struct cYAML_tree_node *tree);
static enum cYAML_handler_error yaml_key(yaml_token_t *token,
				struct cYAML_tree_node *tree);
static enum cYAML_handler_error yaml_value(yaml_token_t *token,
					struct cYAML_tree_node *tree);
static enum cYAML_handler_error yaml_scalar(yaml_token_t *token,
					struct cYAML_tree_node *tree);
static enum cYAML_handler_error yaml_entry_token(yaml_token_t *token,
					struct cYAML_tree_node *tree);

/* dispatch table */
static yaml_token_handler dispatch_tbl[] = {
	[YAML_NO_TOKEN] = yaml_no_token,
	[YAML_STREAM_START_TOKEN] = yaml_stream_start,
	[YAML_STREAM_END_TOKEN] = yaml_stream_end,
	[YAML_VERSION_DIRECTIVE_TOKEN] = yaml_not_supported,
	[YAML_TAG_DIRECTIVE_TOKEN] = yaml_not_supported,
	[YAML_DOCUMENT_START_TOKEN] = yaml_document_start,
	[YAML_DOCUMENT_END_TOKEN] = yaml_document_end,
	[YAML_BLOCK_SEQUENCE_START_TOKEN] = yaml_blk_seq_start,
	[YAML_BLOCK_MAPPING_START_TOKEN] = yaml_blk_mapping_start,
	[YAML_BLOCK_END_TOKEN] = yaml_block_end,
	[YAML_FLOW_SEQUENCE_START_TOKEN] = yaml_not_supported,
	[YAML_FLOW_SEQUENCE_END_TOKEN] = yaml_not_supported,
	[YAML_FLOW_MAPPING_START_TOKEN] = yaml_not_supported,
	[YAML_FLOW_MAPPING_END_TOKEN] = yaml_not_supported,
	[YAML_BLOCK_ENTRY_TOKEN] = yaml_entry_token,
	[YAML_FLOW_ENTRY_TOKEN] = yaml_not_supported,
	[YAML_KEY_TOKEN] = yaml_key,
	[YAML_VALUE_TOKEN] = yaml_value,
	[YAML_ALIAS_TOKEN] = yaml_not_supported,
	[YAML_ANCHOR_TOKEN] = yaml_not_supported,
	[YAML_TAG_TOKEN] = yaml_not_supported,
	[YAML_SCALAR_TOKEN] = yaml_scalar,
};

/* dispatch table */
static const char * const token_type_string[] = {
	[YAML_NO_TOKEN] = "YAML_NO_TOKEN",
	[YAML_STREAM_START_TOKEN] = "YAML_STREAM_START_TOKEN",
	[YAML_STREAM_END_TOKEN] = "YAML_STREAM_END_TOKEN",
	[YAML_VERSION_DIRECTIVE_TOKEN] = "YAML_VERSION_DIRECTIVE_TOKEN",
	[YAML_TAG_DIRECTIVE_TOKEN] = "YAML_TAG_DIRECTIVE_TOKEN",
	[YAML_DOCUMENT_START_TOKEN] = "YAML_DOCUMENT_START_TOKEN",
	[YAML_DOCUMENT_END_TOKEN] = "YAML_DOCUMENT_END_TOKEN",
	[YAML_BLOCK_SEQUENCE_START_TOKEN] = "YAML_BLOCK_SEQUENCE_START_TOKEN",
	[YAML_BLOCK_MAPPING_START_TOKEN] = "YAML_BLOCK_MAPPING_START_TOKEN",
	[YAML_BLOCK_END_TOKEN] = "YAML_BLOCK_END_TOKEN",
	[YAML_FLOW_SEQUENCE_START_TOKEN] = "YAML_FLOW_SEQUENCE_START_TOKEN",
	[YAML_FLOW_SEQUENCE_END_TOKEN] = "YAML_FLOW_SEQUENCE_END_TOKEN",
	[YAML_FLOW_MAPPING_START_TOKEN] = "YAML_FLOW_MAPPING_START_TOKEN",
	[YAML_FLOW_MAPPING_END_TOKEN] = "YAML_FLOW_MAPPING_END_TOKEN",
	[YAML_BLOCK_ENTRY_TOKEN] = "YAML_BLOCK_ENTRY_TOKEN",
	[YAML_FLOW_ENTRY_TOKEN] = "YAML_FLOW_ENTRY_TOKEN",
	[YAML_KEY_TOKEN] = "YAML_KEY_TOKEN",
	[YAML_VALUE_TOKEN] = "YAML_VALUE_TOKEN",
	[YAML_ALIAS_TOKEN] = "YAML_ALIAS_TOKEN",
	[YAML_ANCHOR_TOKEN] = "YAML_ANCHOR_TOKEN",
	[YAML_TAG_TOKEN] = "YAML_TAG_TOKEN",
	[YAML_SCALAR_TOKEN] = "YAML_SCALAR_TOKEN",
};

static const char * const state_string[] = {
	[TREE_STATE_COMPLETE] = "COMPLETE",
	[TREE_STATE_INITED] = "INITED",
	[TREE_STATE_TREE_STARTED] = "TREE_STARTED",
	[TREE_STATE_BLK_STARTED] = "BLK_STARTED",
	[TREE_STATE_KEY] = "KEY",
	[TREE_STATE_KEY_FILLED] = "KEY_FILLED",
	[TREE_STATE_VALUE] = "VALUE",
	[TREE_STATE_SEQ_START] = "SEQ_START",
};

static void cYAML_ll_free(struct list_head *ll)
{
	struct cYAML_ll *node, *tmp;

	list_for_each_entry_safe(node, tmp, ll, list) {
		free(node->print_info);
		free(node);
	}
}

static int cYAML_ll_push(struct cYAML *obj,
			 const struct cYAML_print_info *print_info,
			 struct list_head *list)
{
	struct cYAML_ll *node = calloc(1, sizeof(*node));
	if (node == NULL)
		return -1;

	INIT_LIST_HEAD(&node->list);

	if (print_info) {
		node->print_info = calloc(1, sizeof(*print_info));
		if (node->print_info == NULL) {
			free(node);
			return -1;
		}
		*node->print_info = *print_info;
	}
	node->obj = obj;

	list_add(&node->list, list);

	return 0;
}

static struct cYAML *cYAML_ll_pop(struct list_head *list,
				  struct cYAML_print_info **print_info)
{
	struct cYAML_ll *pop;
	struct cYAML *obj = NULL;

	if (!list_empty(list)) {
		pop = list_entry(list->next, struct cYAML_ll, list);

		obj = pop->obj;
		if (print_info != NULL)
			*print_info = pop->print_info;
		list_del(&pop->list);

		if (print_info == NULL)
			free(pop->print_info);

		free(pop);
	}
	return obj;
}

static int cYAML_ll_count(struct list_head *ll)
{
	int i = 0;
	struct list_head *node;

	list_for_each(node, ll)
		i++;

	return i;
}

static int cYAML_tree_init(struct cYAML_tree_node *tree)
{
	struct cYAML *obj = NULL, *cur = NULL;

	if (tree == NULL)
		return -1;

	obj = calloc(1, sizeof(*obj));
	if (obj == NULL)
		return -1;

	if (tree->root) {
		/* append the node */
		cur = tree->root;
		while (cur->cy_next != NULL)
			cur = cur->cy_next;
		cur->cy_next = obj;
	} else {
		tree->root = obj;
	}

	obj->cy_type = CYAML_TYPE_OBJECT;

	tree->cur = obj;
	tree->state = TREE_STATE_COMPLETE;

	/* free it and start anew */
	if (!list_empty(&tree->ll))
		cYAML_ll_free(&tree->ll);

	return 0;
}

static struct cYAML *create_child(struct cYAML *parent)
{
	struct cYAML *obj;

	if (parent == NULL)
		return NULL;

	obj = calloc(1, sizeof(*obj));
	if (obj == NULL)
		return NULL;

	/* set the type to OBJECT and let the value change that */
	obj->cy_type = CYAML_TYPE_OBJECT;

	parent->cy_child = obj;

	return obj;
}

static struct cYAML *create_sibling(struct cYAML *sibling)
{
	struct cYAML *obj;

	if (sibling == NULL)
		return NULL;

	obj = calloc(1, sizeof(*obj));
	if (obj == NULL)
		return NULL;

	/* set the type to OBJECT and let the value change that */
	obj->cy_type = CYAML_TYPE_OBJECT;

	sibling->cy_next = obj;
	obj->cy_prev = sibling;

	return obj;
}

/* Parse the input text to generate a number,
 * and populate the result into item. */
static bool parse_number(struct cYAML *item, const char *input)
{
	double n = 0, sign = 1, scale = 0;
	int subscale = 0, signsubscale = 1;
	const char *num = input;

	if (*num == '-') {
		sign = -1;
		num++;
	}

	if (*num == '0')
		num++;

	if (*num >= '1' && *num <= '9') {
		do {
			n = (n * 10.0) + (*num++ - '0');
		} while (*num >= '0' && *num <= '9');
	}

	if (*num == '.' && num[1] >= '0' && num[1] <= '9') {
		num++;
		do {
			n = (n * 10.0) + (*num++ - '0');
			scale--;
		} while (*num >= '0' && *num <= '9');
	}

	if (*num == 'e' || *num == 'E') {
		num++;
		if (*num == '+') {
			num++;
		} else if (*num == '-') {
			signsubscale = -1;
			num++;
		}
		while (*num >= '0' && *num <= '9')
			subscale = (subscale * 10) + (*num++ - '0');
	}

	/* check to see if the entire string is consumed.  If not then
	 * that means this is a string with a number in it */
	if (num != (input + strlen(input)))
		return false;

	/* number = +/- number.fraction * 10^+/- exponent */
	n = sign * n * pow(10.0, (scale + subscale * signsubscale));

	item->cy_valuedouble = n;
	item->cy_valueint = (int)n;
	item->cy_type = CYAML_TYPE_NUMBER;

	return true;
}

static int assign_type_value(struct cYAML *obj, const char *value)
{
	if (value == NULL)
		return -1;

	if (strcmp(value, "null") == 0)
		obj->cy_type = CYAML_TYPE_NULL;
	else if (strcmp(value, "false") == 0) {
		obj->cy_type = CYAML_TYPE_FALSE;
		obj->cy_valueint = 0;
	} else if (strcmp(value, "true") == 0) {
		obj->cy_type = CYAML_TYPE_TRUE;
		obj->cy_valueint = 1;
	} else if (*value == '-' || (*value >= '0' && *value <= '9')) {
		if (parse_number(obj, value) == 0) {
			obj->cy_valuestring = strdup(value);
			obj->cy_type = CYAML_TYPE_STRING;
		}
	} else {
		obj->cy_valuestring = strdup(value);
		obj->cy_type = CYAML_TYPE_STRING;
	}

	return 0;
}

/*
 * yaml_handle_token
 *  Builds the YAML tree rpresentation as the tokens are passed in
 *
 *  if token == STREAM_START && tree_state != COMPLETE
 *    something wrong. fail.
 *  else tree_state = INITIED
 *  if token == DOCUMENT_START && tree_state != COMPLETE || INITED
 *    something wrong, fail.
 *  else tree_state = TREE_STARTED
 *  if token == DOCUMENT_END
 *    tree_state = INITED if no STREAM START, else tree_state = COMPLETE
 *    erase everything on ll
 *  if token == STREAM_END && tree_state != INITED
 *    something wrong fail.
 *  else tree_state = COMPLETED
 *  if token == YAML_KEY_TOKEN && state != TREE_STARTED
 *    something wrong, fail.
 *  if token == YAML_SCALAR_TOKEN && state != KEY || VALUE
 *    fail.
 *  else if tree_state == KEY
 *     create a new sibling under the current head of the ll (if ll is
 *     empty insert the new node there and it becomes the root.)
 *    add the scalar value in the "string"
 *    tree_state = KEY_FILLED
 *  else if tree_state == VALUE
 *    try and figure out whether this is a double, int or string and store
 *    it appropriately
 *    state = TREE_STARTED
 * else if token == YAML_BLOCK_MAPPING_START_TOKEN && tree_state != VALUE
 *   fail
 * else push the current node on the ll && state = TREE_STARTED
 * if token == YAML_BLOCK_END_TOKEN && state != TREE_STARTED
 *   fail.
 * else pop the current token off the ll and make it the cur
 * if token == YAML_VALUE_TOKEN && state != KEY_FILLED
 *   fail.
 * else state = VALUE
 *
 */

static enum cYAML_handler_error yaml_no_token(yaml_token_t *token,
					      struct cYAML_tree_node *tree)
{
	return CYAML_ERROR_NONE;
}

static enum cYAML_handler_error yaml_stream_start(yaml_token_t *token,
						  struct cYAML_tree_node *tree)
{
	enum cYAML_handler_error rc;

	/* with each new stream initialize a new tree */
	rc = cYAML_tree_init(tree);

	if (rc != CYAML_ERROR_NONE)
		return rc;

	tree->state = TREE_STATE_INITED;

	return CYAML_ERROR_NONE;
}

static enum cYAML_handler_error yaml_stream_end(yaml_token_t *token,
						struct cYAML_tree_node *tree)
{
	if (tree->state != TREE_STATE_TREE_STARTED &&
	    tree->state != TREE_STATE_COMPLETE &&
	    tree->state != TREE_STATE_INITED)
		return CYAML_ERROR_UNEXPECTED_STATE;

	tree->state = TREE_STATE_INITED;

	return CYAML_ERROR_NONE;
}

static enum cYAML_handler_error
yaml_document_start(yaml_token_t *token, struct cYAML_tree_node *tree)
{
	if (tree->state != TREE_STATE_INITED)
		return CYAML_ERROR_UNEXPECTED_STATE;

	/* go to started state since we're expecting more tokens to come */
	tree->state = TREE_STATE_TREE_STARTED;

	return CYAML_ERROR_NONE;
}

static enum cYAML_handler_error yaml_document_end(yaml_token_t *token,
						  struct cYAML_tree_node *tree)
{
	if (tree->state != TREE_STATE_COMPLETE)
		return CYAML_ERROR_UNEXPECTED_STATE;

	tree->state = TREE_STATE_TREE_STARTED;

	return CYAML_ERROR_NONE;
}

static enum cYAML_handler_error yaml_key(yaml_token_t *token,
					 struct cYAML_tree_node *tree)
{
	if (tree->state != TREE_STATE_BLK_STARTED &&
	    tree->state != TREE_STATE_VALUE)
		return CYAML_ERROR_UNEXPECTED_STATE;

	if (tree->from_blk_map_start == 0 ||
	    tree->state == TREE_STATE_VALUE)
		tree->cur = create_sibling(tree->cur);

	tree->from_blk_map_start = 0;

	tree->state = TREE_STATE_KEY;

	return CYAML_ERROR_NONE;
}

static enum cYAML_handler_error yaml_scalar(yaml_token_t *token,
					    struct cYAML_tree_node *tree)
{
	if (tree->state == TREE_STATE_KEY) {
		/* assign the scalar value to the key that was created */
		tree->cur->cy_string =
		  strdup((const char *)token->data.scalar.value);

		tree->state = TREE_STATE_KEY_FILLED;
	} else if (tree->state == TREE_STATE_VALUE ||
		   tree->state == TREE_STATE_SEQ_START) {
		if (assign_type_value(tree->cur,
				      (char *)token->data.scalar.value))
			/* failed to assign a value */
			return CYAML_ERROR_BAD_VALUE;
		tree->state = TREE_STATE_BLK_STARTED;
	} else {
		return CYAML_ERROR_UNEXPECTED_STATE;
	}

	return CYAML_ERROR_NONE;
}

static enum cYAML_handler_error yaml_value(yaml_token_t *token,
					   struct cYAML_tree_node *tree)
{
	if (tree->state != TREE_STATE_KEY_FILLED)
		return CYAML_ERROR_UNEXPECTED_STATE;

	tree->state = TREE_STATE_VALUE;

	return CYAML_ERROR_NONE;
}

static enum cYAML_handler_error yaml_blk_seq_start(yaml_token_t *token,
						   struct cYAML_tree_node *tree)
{
	if (tree->state != TREE_STATE_VALUE)
		return CYAML_ERROR_UNEXPECTED_STATE;

	/* Since a sequenc start event determines that this is the start
	 * of an array, then that means the current node we're at is an
	 * array and we need to flag it as such */
	tree->cur->cy_type = CYAML_TYPE_ARRAY;
	tree->state = TREE_STATE_SEQ_START;

	return CYAML_ERROR_NONE;
}

static enum cYAML_handler_error yaml_entry_token(yaml_token_t *token,
						 struct cYAML_tree_node *tree)
{
	struct cYAML *obj;

	if (tree->state != TREE_STATE_SEQ_START &&
	    tree->state != TREE_STATE_BLK_STARTED &&
	    tree->state != TREE_STATE_VALUE)
		return CYAML_ERROR_UNEXPECTED_STATE;

	if (tree->state == TREE_STATE_SEQ_START) {
		obj = create_child(tree->cur);

		if (cYAML_ll_push(tree->cur, NULL, &tree->ll))
			return CYAML_ERROR_OUT_OF_MEM;

		tree->cur = obj;
	} else {
		tree->cur = create_sibling(tree->cur);
		tree->state = TREE_STATE_SEQ_START;
	}

	return CYAML_ERROR_NONE;
}

static enum cYAML_handler_error
yaml_blk_mapping_start(yaml_token_t *token,
		       struct cYAML_tree_node *tree)
{
	struct cYAML *obj;

	if (tree->state != TREE_STATE_VALUE &&
	    tree->state != TREE_STATE_INITED &&
	    tree->state != TREE_STATE_SEQ_START &&
	    tree->state != TREE_STATE_TREE_STARTED)
		return CYAML_ERROR_UNEXPECTED_STATE;

	/* block_mapping_start means we're entering another block
	 * indentation, so we need to go one level deeper
	 * create a child of cur */
	obj = create_child(tree->cur);

	/* push cur on the stack */
	if (cYAML_ll_push(tree->cur, NULL, &tree->ll))
		return CYAML_ERROR_OUT_OF_MEM;

	/* adding the new child to cur */
	tree->cur = obj;

	tree->state = TREE_STATE_BLK_STARTED;

	tree->from_blk_map_start = 1;

	return CYAML_ERROR_NONE;
}

static enum cYAML_handler_error yaml_block_end(yaml_token_t *token,
					       struct cYAML_tree_node *tree)
{
	if (tree->state != TREE_STATE_BLK_STARTED &&
	    tree->state != TREE_STATE_VALUE)
		return CYAML_ERROR_UNEXPECTED_STATE;

	tree->cur = cYAML_ll_pop(&tree->ll, NULL);

	/* if you have popped all the way to the top level, then move to
	 * the complete state. */
	if (cYAML_ll_count(&tree->ll) == 0)
		tree->state = TREE_STATE_COMPLETE;
	else if (tree->state == TREE_STATE_VALUE)
		tree->state = TREE_STATE_BLK_STARTED;

	return CYAML_ERROR_NONE;
}

static enum cYAML_handler_error yaml_not_supported(yaml_token_t *token,
						   struct cYAML_tree_node *tree)
{
	return CYAML_ERROR_NOT_SUPPORTED;
}

static bool clean_usr_data(struct cYAML *node, void *usr_data, void **out)
{
	cYAML_user_data_free_cb free_cb = usr_data;

	if (free_cb && node && node->cy_user_data) {
		free_cb(node->cy_user_data);
		node->cy_user_data = NULL;
	}

	return true;
}

static bool free_node(struct cYAML *node, void *user_data, void **out)
{
	if (!node)
		return true;

	if (node->cy_type == CYAML_TYPE_STRING)
		free(node->cy_valuestring);
	if (node->cy_string)
		free(node->cy_string);

	free(node);
	return true;
}

static bool find_obj_iter(struct cYAML *node, void *usr_data, void **out)
{
	char *name = usr_data;

	if (node != NULL && node->cy_string != NULL &&
	    strcmp(node->cy_string, name) == 0) {
		*out = node;
		return false;
	}

	return true;
}

struct cYAML *cYAML_get_object_item(struct cYAML *parent, const char *name)
{
	struct cYAML *node = parent, *found = NULL;

	if (!node || !name)
		return NULL;

	if (node->cy_string) {
		if (strcmp(node->cy_string, name) == 0)
			return node;
	}

	if (node->cy_child)
		found = cYAML_get_object_item(node->cy_child, name);

	if (!found && node->cy_next)
		found = cYAML_get_object_item(node->cy_next, name);

	return found;
}

struct cYAML *cYAML_get_next_seq_item(struct cYAML *seq, struct cYAML **itm)
{
	if (*itm != NULL && (*itm)->cy_next != NULL) {
		*itm = (*itm)->cy_next;
		return *itm;
	}

	if (*itm == NULL && seq->cy_type == CYAML_TYPE_ARRAY) {
		*itm = seq->cy_child;
		return *itm;
	}

	return NULL;
}

bool cYAML_is_sequence(struct cYAML *node)
{
	return (node != NULL ? node->cy_type == CYAML_TYPE_ARRAY : 0);
}

void cYAML_tree_recursive_walk(struct cYAML *node, cYAML_walk_cb cb,
				      bool cb_first,
				      void *usr_data,
				      void **out)
{
	if (node == NULL)
		return;

	if (cb_first) {
		if (!cb(node, usr_data, out))
			return;
	}

	if (node->cy_child)
		cYAML_tree_recursive_walk(node->cy_child, cb,
					  cb_first, usr_data, out);

	if (node->cy_next)
		cYAML_tree_recursive_walk(node->cy_next, cb,
					  cb_first, usr_data, out);

	if (!cb_first) {
		if (!cb(node, usr_data, out))
			return;
	}
}

struct cYAML *cYAML_find_object(struct cYAML *root, const char *name)
{
	struct cYAML *found = NULL;

	cYAML_tree_recursive_walk(root, find_obj_iter, true,
				  (void *)name, (void **)&found);

	return found;
}

void cYAML_clean_usr_data(struct cYAML *node, cYAML_user_data_free_cb free_cb)
{
	cYAML_tree_recursive_walk(node, clean_usr_data, false, free_cb, NULL);
}

void cYAML_free_tree(struct cYAML *node)
{
	cYAML_tree_recursive_walk(node, free_node, false, NULL, NULL);
}

static char *ensure(char *in, int len)
{
	int curlen;
	char *new = in;

	if (!in)
		return (char*)calloc(len, 1);

	curlen = strlen(in) + 1;

	if (curlen <= curlen + len) {
		new = calloc(curlen + len, 1);
		if (!new) {
			free(in);
			return NULL;
		}
		strcpy(new, in);
		free(in);
	}

	return new;
}

static inline void print_simple(char **out, struct cYAML *node,
				struct cYAML_print_info *cpi)
{
	int level = cpi->level;
	int ind = cpi->extra_ind;
	char *tmp = NULL;
	int len = (INDENT * level + ind) * 2 +
	  ((node->cy_string) ? strlen(node->cy_string) : 0) + LEAD_ROOM;

	*out = ensure(*out, len);
	if (!*out)
		return;

	tmp = ensure(tmp, len);
	if (!tmp)
		return;

	if (cpi->array_first_elem) {
		sprintf(tmp, "%*s- ", INDENT * level, "");
		strcat(*out, tmp);
	}

	sprintf(tmp, "%*s""%s: %" PRId64 "\n", (cpi->array_first_elem) ? 0 :
		INDENT * level + ind, "", node->cy_string,
		node->cy_valueint);
	strcat(*out, tmp);
	free(tmp);
}

static void print_string(char **out, struct cYAML *node,
			 struct cYAML_print_info *cpi)
{
	char *new_line;
	int level = cpi->level;
	int ind = cpi->extra_ind;
	char *tmp = NULL;
	int len = INDENT * level + ind +
	  ((node->cy_valuestring) ? strlen(node->cy_valuestring) : 0) +
	  ((node->cy_string) ? strlen(node->cy_string) : 0) + LEAD_ROOM;

	*out = ensure(*out, len);
	if (!*out)
		return;

	tmp = ensure(tmp, len);
	if (!tmp)
		return;

	if (cpi->array_first_elem) {
		sprintf(tmp, "%*s- ", INDENT * level, "");
		strcat(*out, tmp);
	}

	new_line = strchr(node->cy_valuestring, '\n');
	if (new_line == NULL) {
		sprintf(tmp, "%*s""%s: %s\n", (cpi->array_first_elem) ?
			0 : INDENT * level + ind, "",
			node->cy_string, node->cy_valuestring);
		strcat(*out, tmp);
	} else {
		int indent = 0;
		sprintf(tmp, "%*s""%s: ", (cpi->array_first_elem) ?
			0 : INDENT * level + ind, "",
			node->cy_string);
		strcat(*out, tmp);
		char *l = node->cy_valuestring;
		while (new_line) {
			*new_line = '\0';
			sprintf(tmp, "%*s""%s\n", indent, "", l);
			strcat(*out, tmp);
			indent = INDENT * level + ind +
				  strlen(node->cy_string) + 2;
			*new_line = '\n';
			l = new_line+1;
			new_line = strchr(l, '\n');
		}
		sprintf(tmp, "%*s""%s\n", indent, "", l);
		strcat(*out, tmp);
	}

	free(tmp);
}

static void print_number(char **out, struct cYAML *node,
			 struct cYAML_print_info *cpi)
{
	double d = node->cy_valuedouble;
	int level = cpi->level;
	int ind = cpi->extra_ind;
	char *tmp = NULL;
	int len = INDENT * level + ind + LEAD_ROOM;

	*out = ensure(*out, len);
	if (!*out)
		return;

	tmp = ensure(tmp, len);
	if (!tmp)
		return;

	if (cpi->array_first_elem) {
		sprintf(tmp, "%*s- ", INDENT * level, "");
		strcat(*out, tmp);
	}

	if ((fabs(((double)node->cy_valueint) - d) <= DBL_EPSILON) &&
	    (d <= INT_MAX) && (d >= INT_MIN)) {
		sprintf(tmp, "%*s""%s: %" PRId64 "\n", (cpi->array_first_elem) ? 0 :
			INDENT * level + ind, "",
			node->cy_string, node->cy_valueint);
		strcat(*out, tmp);
	} else {
		if ((fabs(floor(d) - d) <= DBL_EPSILON) &&
		    (fabs(d) < 1.0e60)) {
			sprintf(tmp, "%*s""%s: %.0f\n",
				(cpi->array_first_elem) ? 0 :
				INDENT * level + ind, "",
				node->cy_string, d);
			strcat(*out, tmp);
		} else if ((fabs(d) < 1.0e-6) || (fabs(d) > 1.0e9)) {
			sprintf(tmp, "%*s""%s: %e\n",
				(cpi->array_first_elem) ? 0 :
				INDENT * level + ind, "",
				node->cy_string, d);
			strcat(*out, tmp);
		} else {
			sprintf(tmp, "%*s""%s: %f\n",
				(cpi->array_first_elem) ? 0 :
				INDENT * level + ind, "",
				node->cy_string, d);
			strcat(*out, tmp);
		}
	}

	free(tmp);
}

static void print_object(char **out, struct cYAML *node,
			 struct list_head *stack,
			 struct cYAML_print_info *cpi)
{
	struct cYAML_print_info print_info;
	struct cYAML *child = node->cy_child;
	char *tmp = NULL;
	int len = ((cpi->array_first_elem) ? INDENT * cpi->level :
	  INDENT * cpi->level + cpi->extra_ind) +
	  ((node->cy_string) ? strlen(node->cy_string) : 0) +
	  LEAD_ROOM;

	*out = ensure(*out, len);
	if (!*out)
		return;

	tmp = ensure(tmp, len);
	if (!tmp)
		return;

	if (node->cy_string != NULL) {
		sprintf(tmp, "%*s""%s%s:\n", (cpi->array_first_elem) ?
			INDENT * cpi->level :
			INDENT * cpi->level + cpi->extra_ind,
			"", (cpi->array_first_elem) ? "- " : "",
			node->cy_string);
		strcat(*out, tmp);
	}

	print_info.level = (node->cy_string != NULL) ? cpi->level + 1 :
	  cpi->level;
	print_info.array_first_elem = (node->cy_string == NULL) ?
	  cpi->array_first_elem : 0;
	print_info.extra_ind = (cpi->array_first_elem) ? EXTRA_IND :
	  cpi->extra_ind;

	while (child) {
		if (cYAML_ll_push(child, &print_info, stack) != 0) {
			free(tmp);
			return;
		}
		print_value(out, stack);
		print_info.array_first_elem = 0;
		child = child->cy_next;
	}

	free(tmp);
}

static void print_array(char **out, struct cYAML *node,
			struct list_head *stack,
			struct cYAML_print_info *cpi)
{
	struct cYAML_print_info print_info;
	struct cYAML *child = node->cy_child;
	char *tmp = NULL;
	int len = ((node->cy_string) ? strlen(node->cy_string) : 0) +
	  INDENT * cpi->level + cpi->extra_ind + LEAD_ROOM;

	*out = ensure(*out, len);
	if (!*out)
		return;

	tmp = ensure(tmp, len);
	if (!tmp)
		return;

	if (node->cy_string != NULL) {
		sprintf(tmp, "%*s""%s:\n", INDENT * cpi->level + cpi->extra_ind,
			"", node->cy_string);
		strcat(*out, tmp);
	}

	print_info.level = (node->cy_string != NULL) ? cpi->level + 1 :
	  cpi->level;
	print_info.array_first_elem =  1;
	print_info.extra_ind = EXTRA_IND;

	while (child) {
		if (cYAML_ll_push(child, &print_info, stack) != 0) {
			free(tmp);
			return;
		}
		print_value(out, stack);
		child = child->cy_next;
	}

	free(tmp);
}

static void print_value(char **out, struct list_head *stack)
{
	struct cYAML_print_info *cpi = NULL;
	struct cYAML *node = cYAML_ll_pop(stack, &cpi);

	if (node == NULL)
		return;

	switch (node->cy_type) {
	case CYAML_TYPE_FALSE:
	case CYAML_TYPE_TRUE:
	case CYAML_TYPE_NULL:
		print_simple(out, node, cpi);
		break;
	case CYAML_TYPE_STRING:
		print_string(out, node, cpi);
		break;
	case CYAML_TYPE_NUMBER:
		print_number(out, node, cpi);
		break;
	case CYAML_TYPE_ARRAY:
		print_array(out, node, stack, cpi);
		break;
	case CYAML_TYPE_OBJECT:
		print_object(out, node, stack, cpi);
		break;
	default:
	break;
	}

	if (cpi != NULL)
		free(cpi);
}

void cYAML_dump(struct cYAML *node, char **buf)
{
	struct cYAML_print_info print_info;
	struct list_head list;

	*buf = ensure(NULL, PRINT_BUF_LEN);

	if (!*buf)
		return;

	INIT_LIST_HEAD(&list);

	if (node == NULL) {
		*buf = NULL;
		return;
	}

	memset(&print_info, 0, sizeof(struct cYAML_print_info));

	if (cYAML_ll_push(node, &print_info, &list) == 0)
		print_value(buf, &list);
}

void cYAML_print_tree(struct cYAML *node)
{
	struct cYAML_print_info print_info;
	struct list_head list;
	char *buf = ensure(NULL, PRINT_BUF_LEN);

	if (!buf)
		return;

	INIT_LIST_HEAD(&list);

	if (node == NULL)
		return;

	memset(&print_info, 0, sizeof(struct cYAML_print_info));

	if (cYAML_ll_push(node, &print_info, &list) == 0)
		print_value(&buf, &list);

	/* buf could've been freed if we ran out of memory */
	if (buf) {
		printf("%s", buf);
		free(buf);
	}
}

void cYAML_print_tree2file(FILE *f, struct cYAML *node)
{
	struct cYAML_print_info print_info;
	struct list_head list;
	char *buf = ensure(NULL, PRINT_BUF_LEN);

	if (!buf)
		return;

	INIT_LIST_HEAD(&list);

	if (node == NULL)
		return;

	memset(&print_info, 0, sizeof(struct cYAML_print_info));

	if (cYAML_ll_push(node, &print_info, &list) == 0)
		print_value(&buf, &list);

	/* buf could've been freed if we ran out of memory */
	if (buf) {
		fprintf(f, "%s", buf);
		free(buf);
	}
}

static struct cYAML *insert_item(struct cYAML *parent, char *key,
				 enum cYAML_object_type type)
{
	struct cYAML *node = calloc(1, sizeof(*node));

	if (node == NULL)
		return NULL;

	if (key != NULL)
		node->cy_string = strdup(key);

	node->cy_type = type;

	cYAML_insert_child(parent, node);

	return node;
}

struct cYAML *cYAML_create_seq(struct cYAML *parent, char *key)
{
	return insert_item(parent, key, CYAML_TYPE_ARRAY);
}

struct cYAML *cYAML_create_seq_item(struct cYAML *seq)
{
	return insert_item(seq, NULL, CYAML_TYPE_OBJECT);
}

struct cYAML *cYAML_create_object(struct cYAML *parent, char *key)
{
	return insert_item(parent, key, CYAML_TYPE_OBJECT);
}

struct cYAML *cYAML_create_string(struct cYAML *parent, char *key, char *value)
{
	struct cYAML *node = calloc(1, sizeof(*node));
	if (node == NULL)
		return NULL;

	node->cy_string = strdup(key);
	node->cy_valuestring = strdup(value);
	node->cy_type = CYAML_TYPE_STRING;

	cYAML_insert_child(parent, node);

	return node;
}

struct cYAML *cYAML_create_number(struct cYAML *parent, char *key, double value)
{
	struct cYAML *node = calloc(1, sizeof(*node));
	if (node == NULL)
		return NULL;

	node->cy_string = strdup(key);
	node->cy_valuedouble = value;
	node->cy_valueint = (int)value;
	node->cy_type = CYAML_TYPE_NUMBER;

	cYAML_insert_child(parent, node);

	return node;
}

void cYAML_insert_child(struct cYAML *parent, struct cYAML *node)
{
	struct cYAML *cur;

	if (parent && node) {
		if (parent->cy_child == NULL) {
			parent->cy_child = node;
			return;
		}

		cur = parent->cy_child;

		while (cur->cy_next)
			cur = cur->cy_next;

		cur->cy_next = node;
		node->cy_prev = cur;
	}
}

void cYAML_insert_sibling(struct cYAML *root, struct cYAML *sibling)
{
	struct cYAML *last = NULL;
	if (root == NULL || sibling == NULL)
		return;

	last = root;
	while (last->cy_next != NULL)
		last = last->cy_next;

	last->cy_next = sibling;
}

void cYAML_build_error(int rc, int seq_no, char *cmd,
		       char *entity, char *err_str,
		       struct cYAML **root)
{
	struct cYAML *r = NULL, *err, *s, *itm, *cmd_obj;
	if (root == NULL)
		return;

	/* add to the tail of the root that's passed in */
	if ((*root) == NULL) {
		*root = cYAML_create_object(NULL, NULL);
		if ((*root) == NULL)
			goto failed;
	}

	r = *root;

	/* look for the command */
	cmd_obj = cYAML_get_object_item(r, (const char *)cmd);
	if (cmd_obj != NULL && cmd_obj->cy_type == CYAML_TYPE_ARRAY)
		itm = cYAML_create_seq_item(cmd_obj);
	else if (cmd_obj == NULL) {
		s = cYAML_create_seq(r, cmd);
		itm = cYAML_create_seq_item(s);
	} else if (cmd_obj != NULL && cmd_obj->cy_type != CYAML_TYPE_ARRAY)
		goto failed;

	err = cYAML_create_object(itm, entity);
	if (err == NULL)
		goto failed;

	if (seq_no >= 0 &&
	    cYAML_create_number(err, "seq_no", seq_no) == NULL)
		goto failed;

	if (cYAML_create_number(err, "errno", rc) == NULL)
		goto failed;

	if (cYAML_create_string(err, "descr", err_str) == NULL)
		goto failed;

	return;

failed:
	/* Only reason we get here is if we run out of memory */
	cYAML_free_tree(r);
	r = NULL;
	fprintf(stderr, "error:\n\tfatal: out of memory\n");
}

static struct cYAML *
cYAML_parser_to_tree(yaml_parser_t *parser, struct cYAML **err_rc, bool debug)
{
	yaml_token_t token;
	struct cYAML_tree_node tree;
	enum cYAML_handler_error rc;
	yaml_token_type_t token_type;
	char err_str[256];
	int done = 0;

	memset(&tree, 0, sizeof(struct cYAML_tree_node));

	INIT_LIST_HEAD(&tree.ll);

	/* Read the event sequence. */
	while (!done) {
		/*
		 * Go through the parser and build a cYAML representation
		 * of the passed in YAML text
		 */
		yaml_parser_scan(parser, &token);

		if (debug)
			fprintf(stderr, "tree.state(%p:%d) = %s, token.type ="
					" %s: %s\n",
				&tree, tree.state, state_string[tree.state],
				token_type_string[token.type],
				(token.type == YAML_SCALAR_TOKEN) ?
				(char*)token.data.scalar.value : "");
		rc = dispatch_tbl[token.type](&token, &tree);
		if (rc != CYAML_ERROR_NONE) {
			snprintf(err_str, sizeof(err_str),
				"Failed to handle token:%d %s [state=%d, rc=%d]",
				 token.type, token_type_string[token.type],
				 tree.state, rc);
			cYAML_build_error(-1, -1, "yaml", "builder",
					  err_str,
					  err_rc);
		}
		/* Are we finished? */
		done = (rc != CYAML_ERROR_NONE ||
			token.type == YAML_STREAM_END_TOKEN);

		token_type = token.type;

		yaml_token_delete(&token);
	}

	if (token_type == YAML_STREAM_END_TOKEN &&
	    rc == CYAML_ERROR_NONE)
		return tree.root;

	cYAML_free_tree(tree.root);

	return NULL;
}

struct cYAML *cYAML_load(FILE *file, struct cYAML **err_rc, bool debug)
{
	yaml_parser_t parser;
	struct cYAML *yaml;

	yaml_parser_initialize(&parser);
	yaml_parser_set_input_file(&parser, file);

	yaml = cYAML_parser_to_tree(&parser, err_rc, debug);

	yaml_parser_delete(&parser);

	return yaml;
}

struct cYAML *cYAML_build_tree(char *path,
			       const char *yaml_blk,
			       size_t yaml_blk_size,
			       struct cYAML **err_rc,
			       bool debug)
{
	yaml_parser_t parser;
	struct cYAML *yaml;
	char err_str[256];
	FILE *input = NULL;

	/* Create the Parser object. */
	yaml_parser_initialize(&parser);

	/* file always takes precedence */
	if (path != NULL) {
		/* Set a file input. */
		input = fopen(path, "rb");
		if (input == NULL) {
			snprintf(err_str, sizeof(err_str),
				"cannot open '%s': %s", path, strerror(errno));
			cYAML_build_error(-1, -1, "yaml", "builder",
					  err_str,
					  err_rc);
			return NULL;
		}

		yaml_parser_set_input_file(&parser, input);
	} else if (yaml_blk != NULL) {
		yaml_parser_set_input_string(&parser,
					     (const unsigned char *) yaml_blk,
					     yaml_blk_size);
	} else {
		/* assume that we're getting our input froms stdin */
		yaml_parser_set_input_file(&parser, stdin);
	}

	yaml = cYAML_parser_to_tree(&parser, err_rc, debug);

	/* Destroy the Parser object. */
	yaml_parser_delete(&parser);

	if (input != NULL)
		fclose(input);

	return yaml;
}
