#include <linux/lustre_fsfilt.h>

LIST_HEAD(fsfilt_types);

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

int fsfilt_register_type(struct fsfilt_operations *ops)
{
        struct fsfilt_operations *found;

        /* lock fsfilt_types list */
        if ((found = fsfilt_search_type(ops->fs_type))) {
                if (found != ops) {
                        CERROR("different operations for type %s\n",
			       ops->fs_type);
                        /* unlock fsfilt_types list */
                        RETURN(-EEXIST);
                }
        } else {
		MOD_INC_USE_COUNT;
		list_add(&ops->fs_list, &fsfilt_types);
	}

	/* unlock fsfilt_types list */
        return 0;
}

void fsfilt_unregister_type(const char *type)
{
        struct list_head *p;

        /* lock fsfilt_types list */
        list_for_each(p, &fsfilt_types) {
		struct fsfilt_operations *found;

                found = list_entry(p, struct fsfilt_operations, fs_list);
                if (!strcmp(found->fs_type, type)) {
                        list_del(p);
                        MOD_DEC_USE_COUNT;
                        break;
                }
        }
        /* unlock fsfilt_types list */
}

struct fsfilt_operations *fsfilt_get_ops(char *type)
{
        struct fsfilt_operations *fs_ops;

        /* lock fsfilt_types list */
        if (!(fs_ops = fsfilt_search_type(type))) {
                char name[32];
                int rc;

                snprintf(name, sizeof(name) - 1, "fsfilt_%s", type);
                name[sizeof(name) - 1] = '\0';

                if ((rc = request_module(name))) {
                        fs_ops = fsfilt_search_type(type);
                        CDEBUG(D_INFO, "Loaded module '%s'\n", name);
                        if (!fs_ops)
                                rc = -ENOENT;
                }

                if (rc) {
                        CERROR("Can't find fsfilt_%s interface\n", name);
                        RETURN(ERR_PTR(rc));
			/* unlock fsfilt_types list */
                }
        }
        __MOD_INC_USE_COUNT(fs_ops->fs_owner);
        /* unlock fsfilt_types list */

        return fs_ops;
}

void fsfilt_put_ops(struct fsfilt_operations *fs_ops)
{
        __MOD_DEC_USE_COUNT(fs_ops->fs_owner);
}


EXPORT_SYMBOL(fsfilt_register_fs_type);
EXPORT_SYMBOL(fsfilt_unregister_fs_type);
