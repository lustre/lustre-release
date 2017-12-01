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

#ifndef CYAML_H
#define CYAML_H

#include <stdbool.h>

enum cYAML_object_type {
	CYAML_TYPE_FALSE = 0,
	CYAML_TYPE_TRUE,
	CYAML_TYPE_NULL,
	CYAML_TYPE_NUMBER,
	CYAML_TYPE_STRING,
	CYAML_TYPE_ARRAY,
	CYAML_TYPE_OBJECT
};

struct cYAML {
	/* next/prev allow you to walk array/object chains. */
	struct cYAML *cy_next, *cy_prev;
	/* An array or object item will have a child pointer pointing
	   to a chain of the items in the array/object. */
	struct cYAML *cy_child;
	/* The type of the item, as above. */
	enum cYAML_object_type cy_type;

	/* The item's string, if type==CYAML_TYPE_STRING */
	char *cy_valuestring;
	/* The item's number, if type==CYAML_TYPE_NUMBER */
	int cy_valueint;
	/* The item's number, if type==CYAML_TYPE_NUMBER */
	double cy_valuedouble;
	/* The item's name string, if this item is the child of,
	   or is in the list of subitems of an object. */
	char *cy_string;
	/* user data which might need to be tracked per object */
	void *cy_user_data;
};

typedef void (*cYAML_user_data_free_cb)(void *);

/*
 * cYAML_walk_cb
 *   Callback called when recursing through the tree
 *
 *   cYAML* - pointer to the node currently being visitied
 *   void* - user data passed to the callback.
 *   void** - output value from the callback
 *
 * Returns true to continue recursing.  false to stop recursing
 */
typedef bool (*cYAML_walk_cb)(struct cYAML *, void *, void**);

/*
 * cYAML_build_tree
 *   Build a tree representation of the YAML formatted text passed in.
 *
 *   yaml_file - YAML file to parse and build tree representation
 *   yaml_blk - blk of YAML.  yaml_file takes precedence if both
 *   are defined.
 *   yaml_blk_size - length of the yaml block (obtained via strlen)
 */
struct cYAML *cYAML_build_tree(char *yaml_file, const char *yaml_blk,
				size_t yaml_blk_size,
				struct cYAML **err_str, bool debug);

/*
 * cYAML_print_tree
 *   Print the textual representation of a YAML tree to stderr
 *
 *   node - Node where you want to start printing
 */
void cYAML_print_tree(struct cYAML *node);

/*
 * cYAML_print_tree2file
 *   Print the textual representation of a YAML tree to file
 *
 *   f - file to print to
 *   node - Node where you want to start printing
 */
void cYAML_print_tree2file(FILE *f, struct cYAML *node);

/*
 * cYAML_free_tree
 *   Free the cYAML tree returned as part of the cYAML_build_tree
 *
 *   node - root of the tree to be freed
 */
void cYAML_free_tree(struct cYAML *node);

/*
 * cYAML_get_object_item
 *   Returns the cYAML object which key correspods to the name passed in
 *   This function searches only through the current level.
 *
 *   parent - is the parent object on which you want to conduct the search
 *   name - key name of the object you want to find.
 */
struct cYAML *cYAML_get_object_item(struct cYAML *parent,
				    const char *name);

/*
 * cYAML_get_next_seq_item
 *   Returns the next item in the YAML sequence.  This function uses the
 *   itm parameter to keep track of its position in the sequence.  If the
 *   itm parameter is reset to NULL between calls that resets and returns
 *   the first item in the sequence.
 *   This function returns NULL when there are no more items in the
 *   sequence.
 *
 *   seq - is the head node of the YAML sequence
 *   itm - [OUT] next sequence item to continue looking from next time.
 *
 */
struct cYAML *cYAML_get_next_seq_item(struct cYAML *seq,
				      struct cYAML **itm);

/*
 * cYAML_is_seq
 *   Returns 1 if the node provided is an ARRAY 0 otherwise
 *
 *   node - the node to examine
 *
 */
bool cYAML_is_sequence(struct cYAML *node);

/*
 * cYAML_find_object
 *   Returns the cYAML object which key correspods to the name passed in
 *   this function searches the entire tree.
 *
 *   root - is the root of the tree on which you want to conduct the search
 *   name - key name of the object you want to find.
 */
struct cYAML *cYAML_find_object(struct cYAML *root, const char *key);

/*
 * cYAML_clean_usr_data
 *   walks the tree and for each node with some user data it calls the
 *   free_cb with the user data as a parameter.
 *
 *   node: node to start the walk from
 *   free_cb: cb to call to cleanup the user data
 */
void cYAML_clean_usr_data(struct cYAML *node,
			  cYAML_user_data_free_cb free_cb);

/*
 * cYAML_create_object
 *  Creates a CYAML of type OBJECT
 *
 *  parent - parent node
 *  key - node key
 */
struct cYAML *cYAML_create_object(struct cYAML *parent, char *key);

/*
 * cYAML_create_seq
 *  Creates a CYAML of type ARRAY
 *  Once this is created, more sequence items can be added.
 *
 *  parent - parent node
 *  key - node key
 */
struct cYAML *cYAML_create_seq(struct cYAML *parent, char *key);

/*
 * cYAML_create_object
 *  Create a sequence item, which can have more entites added underneath
 *  it
 *
 *  parent - parent node
 */
struct cYAML *cYAML_create_seq_item(struct cYAML *seq);

/*
 * cYAML_create_string
 *   Creates a cYAML node of type STRING
 *
 *   parent - parent node
 *   key - node key
 *   value - value of node
 */
struct cYAML *cYAML_create_string(struct cYAML *parent, char *key,
				  char *value);

/*
 * cYAML_create_string
 *   Creates a cYAML node of type STRING
 *
 *   parent - parent node
 *   key - node key
 *   value - value of node
 */
struct cYAML *cYAML_create_number(struct cYAML *parent, char *key,
				  double value);

/*
 * cYAML_insert_sibling
 *   inserts one cYAML object as a sibling to another
 *
 *   root - root node to have a sibling added to
 *   sibling - sibling to be added
 */
void cYAML_insert_sibling(struct cYAML *root, struct cYAML *sibling);

/*
 * cYAML_insert_child
 *   inserts one cYAML object as a child to another
 *
 *   parent - parent node to have a child added to
 *   child - child to be added
 */
void cYAML_insert_child(struct cYAML *parent, struct cYAML *node);

/*
 * cYAML_build_error
 *   Build a YAML error message given:
 *
 *   rc - return code to add in the error
 *   seq_no - a sequence number to add in the error
 *   cmd - the command that failed.
 *   entity - command entity that failed.
 *   err_str - error string to add in the error
 *   root - the root to which to add the YAML error
 */
void cYAML_build_error(int rc, int seq_no, char *cmd,
			char *entity, char *err_str,
			struct cYAML **root);


#endif /* CYAML_H */
