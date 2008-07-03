#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/fs.h>
#include <linux/jbd.h>
#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/slab.h>
#include <libcfs/libcfs.h>
#include <lustre_fsfilt.h>

CFS_LIST_HEAD(fsfilt_types);

static struct fsfilt_operations *fsfilt_search_type(const char *type)
{
        struct fsfilt_operations *found;
        struct list_head *p;

        list_for_each(p, &fsfilt_types) {
                found = list_entry(p, struct fsfilt_operations, fs_list);
                if (!strcmp(found->fs_type, type)) {
                        return found;
                }
        }
        return NULL;
}

int fsfilt_register_ops(struct fsfilt_operations *fs_ops)
{
        struct fsfilt_operations *found;

        /* lock fsfilt_types list */
        if ((found = fsfilt_search_type(fs_ops->fs_type))) {
                if (found != fs_ops) {
                        CERROR("different operations for type %s\n",
                               fs_ops->fs_type);
                        /* unlock fsfilt_types list */
                        RETURN(-EEXIST);
                }
        } else {
                PORTAL_MODULE_USE;
                list_add(&fs_ops->fs_list, &fsfilt_types);
        }

        /* unlock fsfilt_types list */
        return 0;
}

void fsfilt_unregister_ops(struct fsfilt_operations *fs_ops)
{
        struct list_head *p;

        /* lock fsfilt_types list */
        list_for_each(p, &fsfilt_types) {
                struct fsfilt_operations *found;

                found = list_entry(p, typeof(*found), fs_list);
                if (found == fs_ops) {
                        list_del(p);
                        PORTAL_MODULE_UNUSE;
                        break;
                }
        }
        /* unlock fsfilt_types list */
}

struct fsfilt_operations *fsfilt_get_ops(const char *type)
{
        struct fsfilt_operations *fs_ops;

        /* lock fsfilt_types list */
        if (!(fs_ops = fsfilt_search_type(type))) {
                char name[32];
                int rc;

                snprintf(name, sizeof(name) - 1, "fsfilt_%s", type);
                name[sizeof(name) - 1] = '\0';

                if (!(rc = request_module(name))) {
                        fs_ops = fsfilt_search_type(type);
                        CDEBUG(D_INFO, "Loaded module '%s'\n", name);
                        if (!fs_ops)
                                rc = -ENOENT;
                }

                if (rc) {
                        CERROR("Can't find %s interface\n", name);
                        RETURN(ERR_PTR(rc < 0 ? rc : -rc));
                        /* unlock fsfilt_types list */
                }
        }
        try_module_get(fs_ops->fs_owner);
        /* unlock fsfilt_types list */

        return fs_ops;
}

void fsfilt_put_ops(struct fsfilt_operations *fs_ops)
{
        module_put(fs_ops->fs_owner);
}


EXPORT_SYMBOL(fsfilt_register_ops);
EXPORT_SYMBOL(fsfilt_unregister_ops);
EXPORT_SYMBOL(fsfilt_get_ops);
EXPORT_SYMBOL(fsfilt_put_ops);
