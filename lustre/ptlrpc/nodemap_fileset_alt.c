// SPDX-License-Identifier: GPL-2.0

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Marc Vef <mvef@whamcloud.com>
 */

#include <linux/rbtree.h>
#include <lustre_net.h>
#include "nodemap_internal.h"

/**
 * Allocate a lu_fileset_alt structure with a given fileset size.
 *
 * \param	fileset_size	size of the fileset path
 *
 * \retval	allocated lu_fileset_alt structure on success, NULL otherwise
 */
struct lu_fileset_alt *fileset_alt_init(unsigned int fileset_size)
{
	struct lu_fileset_alt *fileset;

	OBD_ALLOC_PTR(fileset);
	if (fileset == NULL)
		RETURN(NULL);

	fileset->nfa_path_size = fileset_size;
	fileset->nfa_id = 0; /* is set later on tree insertion */

	OBD_ALLOC(fileset->nfa_path, fileset->nfa_path_size);
	if (fileset->nfa_path == NULL) {
		OBD_FREE_PTR(fileset);
		RETURN(NULL);
	}

	return fileset;
}
EXPORT_SYMBOL(fileset_alt_init);

/**
 * Create a lu_fileset_alt structure with a given fileset path.
 *
 * \param	fileset_path	fileset path
 *
 * \retval	allocated lu_fileset_alt structure on success, NULL otherwise
 */
struct lu_fileset_alt *fileset_alt_create(const char *fileset_path)
{
	struct lu_fileset_alt *fileset;

	fileset = fileset_alt_init(strlen(fileset_path) + 1);
	if (fileset == NULL)
		RETURN(NULL);

	memcpy(fileset->nfa_path, fileset_path, fileset->nfa_path_size);

	return fileset;
}
EXPORT_SYMBOL(fileset_alt_create);

void fileset_alt_destroy(struct lu_fileset_alt *fileset)
{
	OBD_FREE(fileset->nfa_path, fileset->nfa_path_size);
	OBD_FREE_PTR(fileset);
}
EXPORT_SYMBOL(fileset_alt_destroy);

void fileset_alt_destroy_tree(struct rb_root *root)
{
	struct lu_fileset_alt *fileset;
	struct lu_fileset_alt *tmp;

	rbtree_postorder_for_each_entry_safe(fileset, tmp, root, nfa_rb)
		fileset_alt_destroy(fileset);

	*root = RB_ROOT;
}
EXPORT_SYMBOL(fileset_alt_destroy_tree);

/**
 * Helper function to find the first free id in the rb tree on insertion.
 *
 * \param	root	pointer to the root of the rb tree
 *
 * \retval	>0	first free id
 */
static unsigned int get_first_free_id(struct rb_root *root)
{
	struct rb_node *node;
	struct lu_fileset_alt *fileset;
	/* start at 1. 0 is reserved for the prim fileset in another context */
	unsigned int fset_id = 1;

	/* iterate over the tree and find gaps in the id sequence */
	for (node = rb_first(root); node; node = rb_next(node)) {
		fileset = rb_entry(node, struct lu_fileset_alt, nfa_rb);
		if (fileset->nfa_id != fset_id)
			RETURN(fset_id);
		fset_id++;
	}

	/* no gaps found, return the next id after the last one in the tree */
	return fset_id;
}

/**
 * Insert a fileset into the rb tree. If fileset->nfa_id is 0, the first free
 * id is assigned and used. The caller is free to set its own fileset->nfa_id
 * as long as it is not 0.
 *
 * \param	root		pointer to the root of the rb tree
 * \param	fileset		fileset to insert
 *
 * \retval	0		on success
 * \retval	-EEXIST		if the fileset id already exists
 * \retval	-ENOSPC		if the fileset id exceeds
 *				LUSTRE_NODEMAP_FILESET_NUM_MAX
 */
int fileset_alt_add(struct rb_root *root, struct lu_fileset_alt *fileset)
{
	struct rb_node **new = &(root->rb_node);
	struct rb_node *parent = NULL;
	struct lu_fileset_alt *this = NULL;

	if (fileset->nfa_id == 0)
		fileset->nfa_id = get_first_free_id(root);

	if (fileset->nfa_id > LUSTRE_NODEMAP_FILESET_NUM_MAX - 1)
		return -ENOSPC;

	/* determine the correct position in the tree */
	while (*new) {
		this = rb_entry(*new, struct lu_fileset_alt, nfa_rb);
		parent = *new;
		if (fileset->nfa_id < this->nfa_id)
			new = &((*new)->rb_left);
		else if (fileset->nfa_id > this->nfa_id)
			new = &((*new)->rb_right);
		else
			return -EEXIST;
	}

	/* insert the new node and rebalance tree */
	rb_link_node(&fileset->nfa_rb, parent, new);
	rb_insert_color(&fileset->nfa_rb, root);

	return 0;
}
EXPORT_SYMBOL(fileset_alt_add);

/**
 * Delete a fileset from the rb tree.
 *
 * \param	root		pointer to the root of the rb tree
 * \param	fileset		fileset to delete
 * \retval	>0		id of the deleted fileset
 * \retval	-EINVAL		fileset is NULL
 */
int fileset_alt_delete(struct rb_root *root, struct lu_fileset_alt *fileset)
{
	unsigned int fset_id;

	if (fileset == NULL)
		return -EINVAL;

	fset_id = fileset->nfa_id;
	rb_erase(&fileset->nfa_rb, root);
	fileset_alt_destroy(fileset);

	return fset_id;
}
EXPORT_SYMBOL(fileset_alt_delete);

static int compare_by_id(const void *key, const struct rb_node *node)
{
	const int *search_id;
	struct lu_fileset_alt *fileset;
	int rc;

	search_id = key;
	fileset = rb_entry(node, struct lu_fileset_alt, nfa_rb);

	if (*search_id < fileset->nfa_id)
		rc = -1;
	else if (*search_id > fileset->nfa_id)
		rc = 1;
	else
		rc = 0;

	return rc;
}

/**
 * Search for a fileset by its fileset id.
 *
 * \param	root		pointer to the root of the rb tree
 * \param	fileset_id	id of the fileset to search
 *
 * \retval	lu_fileset_alt structure on success, NULL otherwise
 */
struct lu_fileset_alt *fileset_alt_search_id(struct rb_root *root,
					 unsigned int fileset_id)
{
	struct lu_fileset_alt *fileset = NULL;
	struct rb_node *node;

	node = rb_find(&fileset_id, root, compare_by_id);
	if (node)
		fileset = rb_entry(node, struct lu_fileset_alt, nfa_rb);

	return fileset;
}
EXPORT_SYMBOL(fileset_alt_search_id);

/**
 * Search for a fileset by its fileset path.
 *
 * \param	root		pointer to the root of the rb tree
 * \param	fileset_path	path of the fileset to search
 *
 * \retval	lu_fileset_alt structure on success, NULL otherwise
 */
struct lu_fileset_alt *fileset_alt_search_path(struct rb_root *root,
					   const char *fileset_path)
{
	struct rb_node *node;
	struct lu_fileset_alt *fileset;
	bool found = false;
	int rc;

	/* search the full tree for a fileset with the given path */
	for (node = rb_first(root); node; node = rb_next(node)) {
		fileset = rb_entry(node, struct lu_fileset_alt, nfa_rb);
		rc = strcmp(fileset_path, fileset->nfa_path);
		if (!rc) {
			found = true;
			break;
		}
	}
	return found ? fileset : NULL;
}
EXPORT_SYMBOL(fileset_alt_search_path);

bool fileset_alt_path_exists(struct rb_root *root, const char *path)
{
	return fileset_alt_search_path(root, path) != NULL;
}
EXPORT_SYMBOL(fileset_alt_path_exists);

/**
 * Iterate over all rb tree entries and shrink the memory requirements
 * for the fileset to the actual needed size. This is required when the
 * fileset fragments are read from the nodemap IAM, and so the preallocated
 * size may be larger than needed.
 *
 * \param root	pointer to the root of the rb tree
 */
void fileset_alt_resize(struct rb_root *root)
{
	struct rb_node *node;
	struct lu_fileset_alt *fileset;
	unsigned int fset_size_actual, fset_size_prealloc;
	char *fset_tmp;

	for (node = rb_first(root); node; node = rb_next(node)) {
		fileset = rb_entry(node, struct lu_fileset_alt, nfa_rb);
		fset_size_prealloc = fileset->nfa_path_size;
		fset_size_actual = strlen(fileset->nfa_path) + 1;
		if (fset_size_actual == fset_size_prealloc)
			continue;
		/* Shrink fileset size to actual */
		OBD_ALLOC(fset_tmp, fset_size_actual);
		if (!fset_tmp) {
			CERROR("%s: Nodemaps's fileset cannot be resized: rc = %d\n",
			       fileset->nfa_path, -ENOMEM);
			continue;
		}

		memcpy(fset_tmp, fileset->nfa_path, fset_size_actual);

		OBD_FREE(fileset->nfa_path, fset_size_prealloc);

		fileset->nfa_path = fset_tmp;
		fileset->nfa_path_size = fset_size_actual;
	}
}
EXPORT_SYMBOL(fileset_alt_resize);
