/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * by Cluster File Systems, Inc.
 * authors, Peter Braam <braam@clusterfs.com> &
 * Phil Schwan <phil@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LDLM

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_mds.h>

extern kmem_cache_t *ldlm_lock_slab;
int (*mds_reint_p)(int offset, struct ptlrpc_request *req) = NULL;
int (*mds_getattr_name_p)(int offset, struct ptlrpc_request *req) = NULL;

static int ldlm_plain_compat(struct ldlm_lock *a, struct ldlm_lock *b);
static int ldlm_intent_policy(struct ldlm_lock *lock, void *req_cookie,
                              ldlm_mode_t mode, void *data);

ldlm_res_compat ldlm_res_compat_table [] = {
        [LDLM_PLAIN] ldlm_plain_compat,
        [LDLM_EXTENT] ldlm_extent_compat,
        [LDLM_MDSINTENT] ldlm_plain_compat
};

ldlm_res_policy ldlm_res_policy_table [] = {
        [LDLM_PLAIN] NULL,
        [LDLM_EXTENT] ldlm_extent_policy,
        [LDLM_MDSINTENT] ldlm_intent_policy
};

static int ldlm_intent_policy(struct ldlm_lock *lock, void *req_cookie,
                              ldlm_mode_t mode, void *data)
{
        struct ptlrpc_request *req = req_cookie;
        int rc = 0;
        ENTRY;

        if (!req_cookie)
                RETURN(0);

        if (req->rq_reqmsg->bufcount > 1) {
                /* an intent needs to be considered */
                struct ldlm_intent *it = lustre_msg_buf(req->rq_reqmsg, 1);
                struct mds_body *mds_rep;
                struct ldlm_reply *rep;
                struct ldlm_namespace *ns = lock->l_resource->lr_namespace;
                __u32 type = lock->l_resource->lr_type;
                __u64 new_resid[3] = {0, 0, 0};
                int bufcount, rc, size[3] = {sizeof(struct ldlm_reply),
                                             sizeof(struct mds_body),
                                             sizeof(struct obdo)};

                it->opc = NTOH__u64(it->opc);

                switch(it->opc) {
                case IT_GETATTR:
                        /* Note that in the negative case you may be returning
                         * a file and its obdo */
                case IT_CREAT:
                case IT_CREAT|IT_OPEN:
                case IT_MKDIR:
                case IT_SYMLINK:
                case IT_MKNOD:
                case IT_LINK:
                case IT_OPEN:
                case IT_RENAME:
                        bufcount = 3;
                        break;
                default:
                        bufcount = 2;
                }

                rc = lustre_pack_msg(bufcount, size, NULL, &req->rq_replen,
                                     &req->rq_repmsg);
                if (rc) {
                        rc = req->rq_status = -ENOMEM;
                        RETURN(rc);
                }

                rep = lustre_msg_buf(req->rq_repmsg, 0);
                rep->lock_policy_res1 = 1;
                switch ( it->opc ) {
                case IT_CREAT:
                case IT_CREAT|IT_OPEN:
                case IT_MKDIR:
                case IT_SETATTR:
                case IT_SYMLINK:
                case IT_MKNOD:
                case IT_LINK:
                case IT_RENAME2:
                        if (mds_reint_p == NULL)
                                mds_reint_p =
                                        inter_module_get_request
                                        ("mds_reint", "mds");
                        if (IS_ERR(mds_reint_p)) {
                                CERROR("MDSINTENT locks require the MDS "
                                       "module.\n");
                                LBUG();
                                RETURN(-EINVAL);
                        }
                        rc = mds_reint_p(2, req);
                        if (rc)
                                LBUG();
                        break;
                case IT_GETATTR:
                case IT_READDIR:
                case IT_RENAME:
                case IT_OPEN:
                        if (mds_getattr_name_p == NULL)
                                mds_getattr_name_p =
                                        inter_module_get_request
                                        ("mds_getattr_name", "mds");
                        if (IS_ERR(mds_getattr_name_p)) {
                                CERROR("MDSINTENT locks require the MDS "
                                       "module.\n");
                                LBUG();
                                RETURN(-EINVAL);
                        }
                        rc = mds_getattr_name_p(2, req);
                        if (rc) {
                                req->rq_status = rc;
                                RETURN(rc);
                        }
                        break;
                case IT_READDIR|IT_OPEN:
                        LBUG();
                        break;
                default:
                        CERROR("Unhandled intent\n");
                        LBUG();
                }

                mds_rep = lustre_msg_buf(req->rq_repmsg, 1);
                rep->lock_policy_res2 = req->rq_status;
                new_resid[0] = mds_rep->ino;

                CDEBUG(D_INFO, "remote intent: locking %d instead of"
                       "%ld\n", mds_rep->ino,
                       (long)lock->l_resource->lr_name[0]);
                ldlm_resource_put(lock->l_resource);

                lock->l_resource =
                        ldlm_resource_get(ns, NULL, new_resid, type, 1);
                if (lock->l_resource == NULL) {
                        LBUG();
                        RETURN(-ENOMEM);
                }
                RETURN(ELDLM_LOCK_CHANGED);
        } else {
                int size = sizeof(struct ldlm_reply);
                rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen,
                                     &req->rq_repmsg);
                if (rc) {
                        CERROR("out of memory\n");
                        LBUG();
                        RETURN(-ENOMEM);
                }
        }
        RETURN(rc);
}

static int ldlm_plain_compat(struct ldlm_lock *a, struct ldlm_lock *b)
{
        return lockmode_compat(a->l_req_mode, b->l_req_mode);
}

/* Args: referenced, unlocked parent (or NULL)
 *       referenced, unlocked resource
 * Locks: parent->l_lock */
static struct ldlm_lock *ldlm_lock_new(struct ldlm_lock *parent,
                                       struct ldlm_resource *resource)
{
        struct ldlm_lock *lock;

        if (resource == NULL)
                LBUG();

        lock = kmem_cache_alloc(ldlm_lock_slab, SLAB_KERNEL);
        if (lock == NULL)
                return NULL;

        memset(lock, 0, sizeof(*lock));
        lock->l_resource = resource;
        INIT_LIST_HEAD(&lock->l_children);
        INIT_LIST_HEAD(&lock->l_res_link);
        init_waitqueue_head(&lock->l_waitq);
        lock->l_lock = SPIN_LOCK_UNLOCKED;

        if (parent != NULL) {
                spin_lock(&parent->l_lock);
                lock->l_parent = parent;
                list_add(&lock->l_childof, &parent->l_children);
                spin_unlock(&parent->l_lock);
        }

        return lock;
}

/* Args: unreferenced, locked lock
 *
 * Caller must do its own ldlm_resource_put() on lock->l_resource */
void ldlm_lock_free(struct ldlm_lock *lock)
{
        if (!list_empty(&lock->l_children)) {
                CERROR("lock %p still has children (%p)!\n", lock,
                       lock->l_children.next);
                ldlm_lock_dump(lock);
                LBUG();
        }

        if (lock->l_readers || lock->l_writers)
                CDEBUG(D_INFO, "lock still has references (%d readers, %d "
                       "writers)\n", lock->l_readers, lock->l_writers);

        if (lock->l_connection)
                ptlrpc_put_connection(lock->l_connection);
        kmem_cache_free(ldlm_lock_slab, lock);
}

void ldlm_lock2desc(struct ldlm_lock *lock, struct ldlm_lock_desc *desc)
{
        ldlm_res2desc(lock->l_resource, &desc->l_resource);
        desc->l_req_mode = lock->l_req_mode;
        desc->l_granted_mode = lock->l_granted_mode;
        memcpy(&desc->l_extent, &lock->l_extent, sizeof(desc->l_extent));
        memcpy(desc->l_version, lock->l_version, sizeof(desc->l_version));
}

/* Args: unlocked lock */
void ldlm_lock_addref(struct ldlm_lock *lock, __u32 mode)
{
        spin_lock(&lock->l_lock);
        if (mode == LCK_NL || mode == LCK_CR || mode == LCK_PR)
                lock->l_readers++;
        else
                lock->l_writers++;
        spin_unlock(&lock->l_lock);
}

void ldlm_send_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock *new)
{
        ENTRY;

        spin_lock(&lock->l_lock);
        if (lock->l_flags & LDLM_FL_AST_SENT) {
                EXIT;
                return;
        }

        lock->l_flags |= LDLM_FL_AST_SENT;
        spin_unlock(&lock->l_lock);

        lock->l_blocking_ast(lock, new, lock->l_data, lock->l_data_len);
        EXIT;
}

/* Args: unlocked lock */
void ldlm_lock_decref(struct ldlm_lock *lock, __u32 mode)
{
        ENTRY;

        if (lock == NULL)
                LBUG();

        spin_lock(&lock->l_lock);
        if (mode == LCK_NL || mode == LCK_CR || mode == LCK_PR)
                lock->l_readers--;
        else
                lock->l_writers--;
        if (!lock->l_readers && !lock->l_writers &&
            lock->l_flags & LDLM_FL_DYING) {
                /* Read this lock its rights. */
                if (!lock->l_resource->lr_namespace->ns_local) {
                        CERROR("LDLM_FL_DYING set on non-local lock!\n");
                        LBUG();
                }

                CDEBUG(D_INFO, "final decref done on dying lock, "
                       "calling callback.\n");
                spin_unlock(&lock->l_lock);
                lock->l_blocking_ast(lock, NULL, lock->l_data,
                                     lock->l_data_len);
        } else
                spin_unlock(&lock->l_lock);
        EXIT;
}

/* Args: locked lock */
static int _ldlm_lock_compat(struct ldlm_lock *lock, int send_cbs,
                             struct list_head *queue)
{
        struct list_head *tmp, *pos;
        int rc = 0;

        list_for_each_safe(tmp, pos, queue) {
                struct ldlm_lock *child;
                ldlm_res_compat compat;

                child = list_entry(tmp, struct ldlm_lock, l_res_link);
                if (lock == child)
                        continue;

                compat = ldlm_res_compat_table[child->l_resource->lr_type];
                if (compat(child, lock)) {
                        CDEBUG(D_OTHER, "compat function succeded, next.\n");
                        continue;
                }
                if (lockmode_compat(child->l_granted_mode, lock->l_req_mode)) {
                        CDEBUG(D_OTHER, "lock modes are compatible, next.\n");
                        continue;
                }

                rc = 1;

                CDEBUG(D_OTHER, "compat function failed and lock modes incompat\n");
                if (send_cbs && child->l_blocking_ast != NULL) {
                        CDEBUG(D_OTHER, "incompatible; sending blocking AST.\n");
                        ldlm_send_blocking_ast(child, lock);
                }
        }

        return rc;
}

/* Args: unlocked lock */
static int ldlm_lock_compat(struct ldlm_lock *lock, int send_cbs)
{
        int rc;
        ENTRY;

        rc = _ldlm_lock_compat(lock, send_cbs, &lock->l_resource->lr_granted);
        /* FIXME: should we be sending ASTs to converting? */
        rc |= _ldlm_lock_compat(lock, send_cbs,
                                &lock->l_resource->lr_converting);

        RETURN(rc);
}

/* Args: locked lock, locked resource */
void ldlm_grant_lock(struct ldlm_resource *res, struct ldlm_lock *lock)
{
        ENTRY;

        ldlm_resource_add_lock(res, &res->lr_granted, lock);
        lock->l_granted_mode = lock->l_req_mode;

        if (lock->l_granted_mode < res->lr_most_restr)
                res->lr_most_restr = lock->l_granted_mode;

        if (lock->l_completion_ast)
                lock->l_completion_ast(lock, NULL,
                                       lock->l_data, lock->l_data_len);
        EXIT;
}

static int search_queue(struct list_head *queue, ldlm_mode_t mode,
                        struct ldlm_extent *extent, struct lustre_handle *lockh)
{
        struct list_head *tmp;

        list_for_each(tmp, queue) {
                struct ldlm_lock *lock;
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                if (lock->l_flags & LDLM_FL_DYING)
                        continue;

                /* lock_convert() takes the resource lock, so we're sure that
                 * req_mode, lr_type, and l_cookie won't change beneath us */
                if (lock->l_req_mode != mode)
                        continue;

                if (lock->l_resource->lr_type == LDLM_EXTENT &&
                    (lock->l_extent.start > extent->start ||
                     lock->l_extent.end < extent->end))
                        continue;

                ldlm_lock_addref(lock, mode);
                ldlm_object2handle(lock, lockh);
                return 1;
        }

        return 0;
}

/* Must be called with no resource or lock locks held.
 *
 * Returns 1 if it finds an already-existing lock that is compatible; in this
 * case, lockh is filled in with a addref()ed lock */
int ldlm_local_lock_match(struct ldlm_namespace *ns, __u64 *res_id, __u32 type,
                          void *cookie, int cookielen, ldlm_mode_t mode,
                          struct lustre_handle *lockh)
{
        struct ldlm_resource *res;
        int rc = 0;
        ENTRY;

        res = ldlm_resource_get(ns, NULL, res_id, type, 0);
        if (res == NULL)
                RETURN(0);

        spin_lock(&res->lr_lock);
        if (search_queue(&res->lr_granted, mode, cookie, lockh))
                GOTO(out, rc = 1);
        if (search_queue(&res->lr_converting, mode, cookie, lockh))
                GOTO(out, rc = 1);
        if (search_queue(&res->lr_waiting, mode, cookie, lockh))
                GOTO(out, rc = 1);

        EXIT;
 out:
        ldlm_resource_put(res);
        spin_unlock(&res->lr_lock);
        return rc;
}

/* Must be called without the resource lock held.  Returns a referenced,
 * unlocked ldlm_lock. */
ldlm_error_t ldlm_local_lock_create(struct ldlm_namespace *ns,
                                    struct lustre_handle *parent_lock_handle,
                                    __u64 *res_id, __u32 type,
                                     ldlm_mode_t mode,
                                    void *data,
                                    __u32 data_len,
                                    struct lustre_handle *lockh)
{
        struct ldlm_resource *res, *parent_res = NULL;
        struct ldlm_lock *lock, *parent_lock;

        parent_lock = lustre_handle2object(parent_lock_handle);
        if (parent_lock)
                parent_res = parent_lock->l_resource;

        res = ldlm_resource_get(ns, parent_res, res_id, type, 1);
        if (res == NULL)
                RETURN(-ENOMEM);

        lock = ldlm_lock_new(parent_lock, res);
        if (lock == NULL) {
                spin_lock(&res->lr_lock);
                ldlm_resource_put(res);
                spin_unlock(&res->lr_lock);
                RETURN(-ENOMEM);
        }

        lock->l_req_mode = mode;
        lock->l_data = data;
        lock->l_data_len = data_len;
        ldlm_lock_addref(lock, mode);

        ldlm_object2handle(lock, lockh);
        return ELDLM_OK;
}

/* Must be called with lock->l_lock and lock->l_resource->lr_lock not held */
ldlm_error_t ldlm_local_lock_enqueue(struct lustre_handle *lockh,
                                     void *cookie, int cookie_len,
                                     int *flags,
                                     ldlm_lock_callback completion,
                                     ldlm_lock_callback blocking)
{
        struct ldlm_resource *res;
        struct ldlm_lock *lock;
        int incompat = 0, local;
        ldlm_res_policy policy;
        ENTRY;

        lock = lustre_handle2object(lockh);
        res = lock->l_resource;
        local = res->lr_namespace->ns_local;
        spin_lock(&res->lr_lock);

        lock->l_blocking_ast = blocking;

        if (res->lr_type == LDLM_EXTENT)
                memcpy(&lock->l_extent, cookie, sizeof(lock->l_extent));

        /* policies are not executed on the client */
        if (!local && (policy = ldlm_res_policy_table[res->lr_type])) {
                int rc = policy(lock, cookie, lock->l_req_mode, NULL);
                if (rc == ELDLM_LOCK_CHANGED) {
                        res = lock->l_resource;
                        *flags |= LDLM_FL_LOCK_CHANGED;
                }
                if (rc < 0) {
                        /* Abort. */
                        ldlm_resource_put(lock->l_resource);
                        ldlm_lock_free(lock);
                        RETURN(rc);
                }
        }

        lock->l_cookie = cookie;
        lock->l_cookie_len = cookie_len;

        if (local && lock->l_req_mode == lock->l_granted_mode) {
                /* The server returned a blocked lock, but it was granted before
                 * we got a chance to actually enqueue it.  We don't need to do
                 * anything else. */
                GOTO(out, ELDLM_OK);
        }

        /* If this is a local resource, put it on the appropriate list. */
        list_del_init(&lock->l_res_link);
        if (local) {
                if (*flags & LDLM_FL_BLOCK_CONV)
                        ldlm_resource_add_lock(res, res->lr_converting.prev,
                                               lock);
                else if (*flags & (LDLM_FL_BLOCK_WAIT | LDLM_FL_BLOCK_GRANTED))
                        ldlm_resource_add_lock(res, res->lr_waiting.prev, lock);
                else
                        ldlm_grant_lock(res, lock);
                GOTO(out, ELDLM_OK);
        }

        /* FIXME: We may want to optimize by checking lr_most_restr */
        if (!list_empty(&res->lr_converting)) {
                ldlm_resource_add_lock(res, res->lr_waiting.prev, lock);
                *flags |= LDLM_FL_BLOCK_CONV;
                GOTO(out, ELDLM_OK);
        }
        if (!list_empty(&res->lr_waiting)) {
                ldlm_resource_add_lock(res, res->lr_waiting.prev, lock);
                *flags |= LDLM_FL_BLOCK_WAIT;
                GOTO(out, ELDLM_OK);
        }
        incompat = ldlm_lock_compat(lock, 0);
        if (incompat) {
                ldlm_resource_add_lock(res, res->lr_waiting.prev, lock);
                *flags |= LDLM_FL_BLOCK_GRANTED;
                GOTO(out, ELDLM_OK);
        }

        ldlm_grant_lock(res, lock);
        EXIT;
 out:
        /* Don't set 'completion_ast' until here so that if the lock is granted
         * immediately we don't do an unnecessary completion call. */
        lock->l_completion_ast = completion;
        spin_unlock(&res->lr_lock);
        return ELDLM_OK;
}

/* Must be called with resource->lr_lock taken. */
static int ldlm_reprocess_queue(struct ldlm_resource *res,
                                struct list_head *converting)
{
        struct list_head *tmp, *pos;
        ENTRY;

        list_for_each_safe(tmp, pos, converting) {
                struct ldlm_lock *pending;
                pending = list_entry(tmp, struct ldlm_lock, l_res_link);

                /* the resource lock protects ldlm_lock_compat */
                if (ldlm_lock_compat(pending, 1))
                        RETURN(1);

                list_del_init(&pending->l_res_link);
                ldlm_grant_lock(res, pending);

                ldlm_lock_addref(pending, pending->l_req_mode);
                ldlm_lock_decref(pending, pending->l_granted_mode);
        }

        RETURN(0);
}

/* Must be called with resource->lr_lock not taken. */
void ldlm_reprocess_all(struct ldlm_resource *res)
{
        /* Local lock trees don't get reprocessed. */
        if (res->lr_namespace->ns_local)
                return;

        spin_lock(&res->lr_lock);
        ldlm_reprocess_queue(res, &res->lr_converting);
        if (list_empty(&res->lr_converting))
                ldlm_reprocess_queue(res, &res->lr_waiting);
        spin_unlock(&res->lr_lock);
}

/* Must be called with lock and lock->l_resource unlocked */
struct ldlm_resource *ldlm_local_lock_cancel(struct ldlm_lock *lock)
{
        struct ldlm_resource *res;
        ENTRY;

        res = lock->l_resource;

        spin_lock(&res->lr_lock);
        spin_lock(&lock->l_lock);

        if (lock->l_readers || lock->l_writers)
                CDEBUG(D_INFO, "lock still has references (%d readers, %d "
                       "writers)\n", lock->l_readers, lock->l_writers);

        ldlm_resource_del_lock(lock);
        if (ldlm_resource_put(res))
                res = NULL; /* res was freed, nothing else to do. */
        else
                spin_unlock(&res->lr_lock);
        ldlm_lock_free(lock);

        RETURN(res);
}

/* Must be called with lock and lock->l_resource unlocked */
struct ldlm_resource *ldlm_local_lock_convert(struct lustre_handle *lockh,
                                              int new_mode, int *flags)
{
        struct ldlm_lock *lock;
        struct ldlm_resource *res;
        ENTRY;

        lock = lustre_handle2object(lockh);
        res = lock->l_resource;

        spin_lock(&res->lr_lock);

        lock->l_req_mode = new_mode;
        list_del_init(&lock->l_res_link);

        /* If this is a local resource, put it on the appropriate list. */
        if (res->lr_namespace->ns_local) {
                if (*flags & LDLM_FL_BLOCK_CONV)
                        ldlm_resource_add_lock(res, res->lr_converting.prev,
                                               lock);
                else if (*flags & (LDLM_FL_BLOCK_WAIT | LDLM_FL_BLOCK_GRANTED))
                        ldlm_resource_add_lock(res, res->lr_waiting.prev, lock);
                else
                        ldlm_grant_lock(res, lock);
        } else {
                list_add(&lock->l_res_link, res->lr_converting.prev);
        }

        spin_unlock(&res->lr_lock);

        RETURN(res);
}

void ldlm_lock_dump(struct ldlm_lock *lock)
{
        char ver[128];

        if (!(portal_debug & D_OTHER))
                return;

        if (RES_VERSION_SIZE != 4)
                LBUG();

        if (!lock) {
                CDEBUG(D_OTHER, "  NULL LDLM lock\n");
                return;
        }

        snprintf(ver, sizeof(ver), "%x %x %x %x",
                 lock->l_version[0], lock->l_version[1],
                 lock->l_version[2], lock->l_version[3]);

        CDEBUG(D_OTHER, "  -- Lock dump: %p (%s)\n", lock, ver);
        CDEBUG(D_OTHER, "  Parent: %p\n", lock->l_parent);
        CDEBUG(D_OTHER, "  Resource: %p\n", lock->l_resource);
        CDEBUG(D_OTHER, "  Requested mode: %d, granted mode: %d\n",
               (int)lock->l_req_mode, (int)lock->l_granted_mode);
        CDEBUG(D_OTHER, "  Readers: %u ; Writers; %u\n",
               lock->l_readers, lock->l_writers);
        if (lock->l_resource->lr_type == LDLM_EXTENT)
                CDEBUG(D_OTHER, "  Extent: %Lu -> %Lu\n",
                       (unsigned long long)lock->l_extent.start,
                       (unsigned long long)lock->l_extent.end);
}
