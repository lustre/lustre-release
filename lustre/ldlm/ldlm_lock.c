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
#include <linux/random.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_mds.h>

/* lock types */
char *ldlm_lockname[] = {
        [0]      "--",
        [LCK_EX] "EX",
        [LCK_PW] "PW",
        [LCK_PR] "PR",
        [LCK_CW] "CW",
        [LCK_CR] "CR",
        [LCK_NL] "NL"
};
char *ldlm_typename[] = {
        [LDLM_PLAIN]     "PLN",
        [LDLM_EXTENT]    "EXT",
        [LDLM_MDSINTENT] "INT"
};

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


/*
 * REFCOUNTED LOCK OBJECTS
 */


/*
 * Lock refcounts, during creation:
 *   - one special one for allocation, dec'd only once in destroy
 *   - one for being a lock that's in-use
 *   - one for the addref associated with a new lock
 */
struct ldlm_lock *ldlm_lock_get(struct ldlm_lock *lock)
{
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        lock->l_refc++;
        ldlm_resource_getref(lock->l_resource);
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        return lock;
}

void ldlm_lock_put(struct ldlm_lock *lock)
{
        struct lustre_lock *nslock = &lock->l_resource->lr_namespace->ns_lock;
        ENTRY;

        l_lock(nslock);
        lock->l_refc--;
        LDLM_DEBUG(lock, "after refc--");
        if (lock->l_refc < 0)
                LBUG();

        ldlm_resource_put(lock->l_resource);
        if (lock->l_parent)
                ldlm_lock_put(lock->l_parent);

        if (lock->l_refc == 0 && (lock->l_flags & LDLM_FL_DESTROYED)) {
                if (lock->l_connection)
                        ptlrpc_put_connection(lock->l_connection);
                CDEBUG(D_MALLOC, "kfreed 'lock': %d at %p (tot 1).\n",
                       sizeof(*lock), lock);
                kmem_cache_free(ldlm_lock_slab, lock);
        }
        l_unlock(nslock);
        EXIT;
}

void ldlm_lock_destroy(struct ldlm_lock *lock)
{
        ENTRY;
        l_lock(&lock->l_resource->lr_namespace->ns_lock);

        if (!list_empty(&lock->l_children)) {
                LDLM_DEBUG(lock, "still has children (%p)!",
                           lock->l_children.next);
                ldlm_lock_dump(lock);
                LBUG();
        }
        if (lock->l_readers || lock->l_writers) {
                LDLM_DEBUG(lock, "lock still has references");
                ldlm_lock_dump(lock);
                LBUG();
        }

        if (!list_empty(&lock->l_res_link)) {
                ldlm_lock_dump(lock);
                LBUG();
        }

        if (lock->l_flags & LDLM_FL_DESTROYED) {
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                EXIT;
                return;
        }

        lock->l_flags = LDLM_FL_DESTROYED;
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        ldlm_lock_put(lock);
        EXIT;
}

/*
   usage: pass in a resource on which you have done get
          pass in a parent lock on which you have done a get
          do not put the resource or the parent
   returns: lock with refcount 1
*/
static struct ldlm_lock *ldlm_lock_new(struct ldlm_lock *parent,
                                       struct ldlm_resource *resource)
{
        struct ldlm_lock *lock;
        ENTRY;

        if (resource == NULL)
                LBUG();

        lock = kmem_cache_alloc(ldlm_lock_slab, SLAB_KERNEL);
        if (lock == NULL)
                RETURN(NULL);
        CDEBUG(D_MALLOC, "kmalloced 'lock': %d at "
               "%p (tot %d).\n", sizeof(*lock), lock, 1);

        memset(lock, 0, sizeof(*lock));
        get_random_bytes(&lock->l_random, sizeof(__u64));

        lock->l_resource = resource;
        /* this refcount matches the one of the resource passed
           in which is not being put away */
        lock->l_refc = 1;
        INIT_LIST_HEAD(&lock->l_children);
        INIT_LIST_HEAD(&lock->l_res_link);
        init_waitqueue_head(&lock->l_waitq);

        if (parent != NULL) {
                l_lock(&parent->l_resource->lr_namespace->ns_lock);
                lock->l_parent = parent;
                list_add(&lock->l_childof, &parent->l_children);
                l_unlock(&parent->l_resource->lr_namespace->ns_lock);
        }
        /* this is the extra refcount, to prevent the lock
           evaporating */
        ldlm_lock_get(lock);
        RETURN(lock);
}

int ldlm_lock_change_resource(struct ldlm_lock *lock, __u64 new_resid[3])
{
        struct ldlm_namespace *ns = lock->l_resource->lr_namespace;
        struct ldlm_resource *oldres = lock->l_resource;
        int type, i;
        ENTRY;

        l_lock(&ns->ns_lock);
        type = lock->l_resource->lr_type;

        lock->l_resource = ldlm_resource_get(ns, NULL, new_resid, type, 1);
        if (lock->l_resource == NULL) {
                LBUG();
                RETURN(-ENOMEM);
        }

        /* move references over */
        for (i = 0; i < lock->l_refc; i++) {
                int rc;
                ldlm_resource_getref(lock->l_resource);
                rc = ldlm_resource_put(oldres);
                if (rc == 1 && i != lock->l_refc - 1)
                        LBUG();
        }
        /* compensate for the initial get above.. */
        ldlm_resource_put(lock->l_resource);

        l_unlock(&ns->ns_lock);
        RETURN(0);
}

/*
 *  HANDLES
 */

void ldlm_lock2handle(struct ldlm_lock *lock, struct lustre_handle *lockh)
{
        lockh->addr = (__u64)(unsigned long)lock;
        lockh->cookie = lock->l_random;
}

struct ldlm_lock *ldlm_handle2lock(struct lustre_handle *handle)
{
        struct ldlm_lock *lock = NULL;
        ENTRY;

        if (!handle || !handle->addr)
                RETURN(NULL);

        lock = (struct ldlm_lock *)(unsigned long)(handle->addr);
        if (!kmem_cache_validate(ldlm_lock_slab, (void *)lock))
                RETURN(NULL);

        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        if (lock->l_random != handle->cookie)
                GOTO(out, handle = NULL);

        if (lock->l_flags & LDLM_FL_DESTROYED)
                GOTO(out, handle = NULL);

        ldlm_lock_get(lock);
        EXIT;
 out:
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        return lock;
}



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
                __u64 new_resid[3] = {0, 0, 0}, old_res;
                int bufcount = -1, rc, size[3] = {sizeof(struct ldlm_reply),
                                                  sizeof(struct mds_body),
                                                  sizeof(struct obdo)};

                it->opc = NTOH__u64(it->opc);

                LDLM_DEBUG(lock, "intent policy, opc: %Ld", it->opc);

                /* prepare reply */
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
                case IT_UNLINK:
                        bufcount = 2;
                        size[1] = sizeof(struct obdo);
                        break;
                case IT_RMDIR:
                case IT_RENAME2:
                        bufcount = 1;
                        break;
                default:
                        LBUG();
                }

                rc = lustre_pack_msg(bufcount, size, NULL, &req->rq_replen,
                                     &req->rq_repmsg);
                if (rc) {
                        rc = req->rq_status = -ENOMEM;
                        RETURN(rc);
                }

                rep = lustre_msg_buf(req->rq_repmsg, 0);
                rep->lock_policy_res1 = 1;

                /* execute policy */
                switch (it->opc) {
                case IT_CREAT:
                case IT_CREAT|IT_OPEN:
                case IT_MKDIR:
                case IT_SETATTR:
                case IT_SYMLINK:
                case IT_MKNOD:
                case IT_LINK:
                case IT_UNLINK:
                case IT_RMDIR:
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
                        if (rc || req->rq_status != 0) {
                                rep->lock_policy_res2 = req->rq_status;
                                RETURN(ELDLM_LOCK_ABORTED);
                        }
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
                        /* FIXME: we need to sit down and decide on who should
                         * set req->rq_status, who should return negative and
                         * positive return values, and what they all mean. */
                        if (rc || req->rq_status != 0) {
                                rep->lock_policy_res2 = req->rq_status;
                                RETURN(ELDLM_LOCK_ABORTED);
                        }
                        break;
                case IT_READDIR|IT_OPEN:
                        LBUG();
                        break;
                default:
                        CERROR("Unhandled intent\n");
                        LBUG();
                }

                if (it->opc == IT_UNLINK || it->opc == IT_RMDIR || 
                    it->opc == IT_RENAME || it->opc == IT_RENAME2)
                        RETURN(ELDLM_LOCK_ABORTED);

                rep->lock_policy_res2 = req->rq_status;
                mds_rep = lustre_msg_buf(req->rq_repmsg, 1);
                new_resid[0] = NTOH__u32(mds_rep->ino);
                if (new_resid[0] == 0)
                        LBUG();
                old_res = lock->l_resource->lr_name[0];

                CDEBUG(D_INFO, "remote intent: locking %d instead of"
                       "%ld\n", mds_rep->ino, (long)old_res);

                ldlm_lock_change_resource(lock, new_resid);
                if (lock->l_resource == NULL) {
                        LBUG();
                        RETURN(-ENOMEM);
                }
                LDLM_DEBUG(lock, "intent policy, old res %ld",
                           (long)old_res);
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

void ldlm_lock2desc(struct ldlm_lock *lock, struct ldlm_lock_desc *desc)
{
        ldlm_res2desc(lock->l_resource, &desc->l_resource);
        desc->l_req_mode = lock->l_req_mode;
        desc->l_granted_mode = lock->l_granted_mode;
        memcpy(&desc->l_extent, &lock->l_extent, sizeof(desc->l_extent));
        memcpy(desc->l_version, lock->l_version, sizeof(desc->l_version));
}

static void ldlm_add_ast_work_item(struct ldlm_lock *lock,
                                   struct ldlm_lock *new)
{
        struct ldlm_ast_work *w;
        ENTRY;

        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        if (new && (lock->l_flags & LDLM_FL_AST_SENT))
                GOTO(out, 0);

        OBD_ALLOC(w, sizeof(*w));
        if (!w) {
                LBUG();
                return;
        }

        if (new) {
                lock->l_flags |= LDLM_FL_AST_SENT;
                w->w_blocking = 1;
                ldlm_lock2desc(new, &w->w_desc);
        }

        w->w_lock = ldlm_lock_get(lock);
        list_add(&w->w_list, lock->l_resource->lr_tmp);
 out:
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        return;
}

void ldlm_lock_addref(struct lustre_handle *lockh, __u32 mode)
{
        struct ldlm_lock *lock;

        lock = ldlm_handle2lock(lockh);
        ldlm_lock_addref_internal(lock, mode);
        ldlm_lock_put(lock);
}

/* only called for local locks */
void ldlm_lock_addref_internal(struct ldlm_lock *lock, __u32 mode)
{
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        if (mode == LCK_NL || mode == LCK_CR || mode == LCK_PR)
                lock->l_readers++;
        else
                lock->l_writers++;
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        ldlm_lock_get(lock);
        LDLM_DEBUG(lock, "ldlm_lock_addref(%s)", ldlm_lockname[mode]);
}

/* Args: unlocked lock */
void ldlm_lock_decref(struct lustre_handle *lockh, __u32 mode)
{
        struct ldlm_lock *lock = ldlm_handle2lock(lockh);
        ENTRY;

        if (lock == NULL)
                LBUG();

        LDLM_DEBUG(lock, "ldlm_lock_decref(%s)", ldlm_lockname[mode]);
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        if (mode == LCK_NL || mode == LCK_CR || mode == LCK_PR)
                lock->l_readers--;
        else
                lock->l_writers--;

        /* If we received a blocked AST and this was the last reference,
         * run the callback. */
        if (!lock->l_readers && !lock->l_writers &&
            (lock->l_flags & LDLM_FL_CBPENDING)) {
                struct lustre_handle lockh;

                if (!lock->l_resource->lr_namespace->ns_client) {
                        CERROR("LDLM_FL_CBPENDING set on non-local lock!\n");
                        LBUG();
                }

                LDLM_DEBUG(lock, "final decref done on cbpending lock");
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);

                ldlm_lock2handle(lock, &lockh);
                /* FIXME: -1 is a really, really bad 'desc' */
                lock->l_blocking_ast(&lockh, (void *)-1, lock->l_data,
                                     lock->l_data_len);
        } else
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);

        ldlm_lock_put(lock); /* matches the ldlm_lock_get in addref */
        ldlm_lock_put(lock); /* matches the handle2lock above */

        EXIT;
}

static int ldlm_lock_compat_list(struct ldlm_lock *lock, int send_cbs,
                             struct list_head *queue)
{
        struct list_head *tmp, *pos;
        int rc = 1;

        list_for_each_safe(tmp, pos, queue) {
                struct ldlm_lock *child;
                ldlm_res_compat compat;

                child = list_entry(tmp, struct ldlm_lock, l_res_link);
                if (lock == child)
                        continue;

                compat = ldlm_res_compat_table[child->l_resource->lr_type];
                if (compat && compat(child, lock)) {
                        CDEBUG(D_OTHER, "compat function succeded, next.\n");
                        continue;
                }
                if (lockmode_compat(child->l_granted_mode, lock->l_req_mode)) {
                        CDEBUG(D_OTHER, "lock modes are compatible, next.\n");
                        continue;
                }

                rc = 0;

                if (send_cbs && child->l_blocking_ast != NULL) {
                        CDEBUG(D_OTHER, "incompatible; sending blocking "
                               "AST.\n");
                        ldlm_add_ast_work_item(child, lock);
                }
        }

        return rc;
}

static int ldlm_lock_compat(struct ldlm_lock *lock, int send_cbs)
{
        int rc;
        ENTRY;

        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        rc = ldlm_lock_compat_list(lock, send_cbs,
                                   &lock->l_resource->lr_granted);
        /* FIXME: should we be sending ASTs to converting? */
        if (rc)
                rc = ldlm_lock_compat_list
                        (lock, send_cbs, &lock->l_resource->lr_converting);

        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        RETURN(rc);
}

/* NOTE: called by
   - ldlm_handle_enqueuque - resource
*/
void ldlm_grant_lock(struct ldlm_lock *lock)
{
        struct ldlm_resource *res = lock->l_resource;
        ENTRY;

        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        ldlm_resource_add_lock(res, &res->lr_granted, lock);
        lock->l_granted_mode = lock->l_req_mode;

        if (lock->l_granted_mode < res->lr_most_restr)
                res->lr_most_restr = lock->l_granted_mode;

        if (lock->l_completion_ast) {
                ldlm_add_ast_work_item(lock, NULL);
        }
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        EXIT;
}

static struct ldlm_lock *search_queue(struct list_head *queue, ldlm_mode_t mode,
                                      struct ldlm_extent *extent)
{
        struct ldlm_lock *lock;
        struct list_head *tmp;

        list_for_each(tmp, queue) {
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                if (lock->l_flags & LDLM_FL_CBPENDING)
                        continue;

                /* lock_convert() takes the resource lock, so we're sure that
                 * req_mode, lr_type, and l_cookie won't change beneath us */
                if (lock->l_req_mode != mode)
                        continue;

                if (lock->l_resource->lr_type == LDLM_EXTENT &&
                    (lock->l_extent.start > extent->start ||
                     lock->l_extent.end < extent->end))
                        continue;

                ldlm_lock_addref_internal(lock, mode);
                return lock;
        }

        return NULL;
}

/* Must be called with no resource or lock locks held.
 *
 * Returns 1 if it finds an already-existing lock that is compatible; in this
 * case, lockh is filled in with a addref()ed lock */
int ldlm_lock_match(struct ldlm_namespace *ns, __u64 *res_id, __u32 type,
                    void *cookie, int cookielen, ldlm_mode_t mode,
                    struct lustre_handle *lockh)
{
        struct ldlm_resource *res;
        struct ldlm_lock *lock;
        int rc = 0;
        ENTRY;

        res = ldlm_resource_get(ns, NULL, res_id, type, 0);
        if (res == NULL)
                RETURN(0);

        ns = res->lr_namespace;
        l_lock(&ns->ns_lock);

        if ((lock = search_queue(&res->lr_granted, mode, cookie)))
                GOTO(out, rc = 1);
        if ((lock = search_queue(&res->lr_converting, mode, cookie)))
                GOTO(out, rc = 1);
        if ((lock = search_queue(&res->lr_waiting, mode, cookie)))
                GOTO(out, rc = 1);

        EXIT;
 out:
        ldlm_resource_put(res);
        l_unlock(&ns->ns_lock);

        if (lock) {
                ldlm_lock2handle(lock, lockh);
                wait_event(lock->l_waitq,
                           lock->l_req_mode == lock->l_granted_mode);
        }
        if (rc)
                LDLM_DEBUG(lock, "matched");
        else
                LDLM_DEBUG_NOLOCK("not matched");
        return rc;
}

/*   Returns a referenced, lock */
struct ldlm_lock *ldlm_lock_create(struct ldlm_namespace *ns,
                                   struct lustre_handle *parent_lock_handle,
                                   __u64 *res_id, __u32 type,
                                   ldlm_mode_t mode,
                                   void *data,
                                   __u32 data_len)
{
        struct ldlm_resource *res, *parent_res = NULL;
        struct ldlm_lock *lock, *parent_lock;

        parent_lock = ldlm_handle2lock(parent_lock_handle);
        if (parent_lock)
                parent_res = parent_lock->l_resource;

        res = ldlm_resource_get(ns, parent_res, res_id, type, 1);
        if (res == NULL)
                RETURN(NULL);

        lock = ldlm_lock_new(parent_lock, res);
        if (lock == NULL) {
                ldlm_resource_put(res);
                RETURN(NULL);
        }

        lock->l_req_mode = mode;
        lock->l_data = data;
        lock->l_data_len = data_len;

        return lock;
}

/* Must be called with lock->l_lock and lock->l_resource->lr_lock not held */
ldlm_error_t ldlm_lock_enqueue(struct ldlm_lock *lock,
                               void *cookie, int cookie_len,
                               int *flags,
                               ldlm_lock_callback completion,
                               ldlm_lock_callback blocking)
{
        struct ldlm_resource *res;
        int local;
        ldlm_res_policy policy;
        ENTRY;

        res = lock->l_resource;
        lock->l_blocking_ast = blocking;

        if (res->lr_type == LDLM_EXTENT)
                memcpy(&lock->l_extent, cookie, sizeof(lock->l_extent));

        /* policies are not executed on the client */
        local = res->lr_namespace->ns_client;
        if (!local && (policy = ldlm_res_policy_table[res->lr_type])) {
                int rc;
                rc = policy(lock, cookie, lock->l_req_mode, NULL);

                if (rc == ELDLM_LOCK_CHANGED) {
                        res = lock->l_resource;
                        *flags |= LDLM_FL_LOCK_CHANGED;
                } else if (rc == ELDLM_LOCK_ABORTED) {
                        ldlm_lock_destroy(lock);
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
        /* FIXME: don't like this: can we call ldlm_resource_unlink_lock? */
        list_del_init(&lock->l_res_link);
        if (local) {
                if (*flags & LDLM_FL_BLOCK_CONV)
                        ldlm_resource_add_lock(res, res->lr_converting.prev,
                                               lock);
                else if (*flags & (LDLM_FL_BLOCK_WAIT | LDLM_FL_BLOCK_GRANTED))
                        ldlm_resource_add_lock(res, res->lr_waiting.prev, lock);
                else
                        ldlm_grant_lock(lock);
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
        if (!ldlm_lock_compat(lock,0)) {
                ldlm_resource_add_lock(res, res->lr_waiting.prev, lock);
                *flags |= LDLM_FL_BLOCK_GRANTED;
                GOTO(out, ELDLM_OK);
        }

        ldlm_grant_lock(lock);
        EXIT;
 out:
        /* Don't set 'completion_ast' until here so that if the lock is granted
         * immediately we don't do an unnecessary completion call. */
        lock->l_completion_ast = completion;
        return ELDLM_OK;
}

/* Must be called with namespace taken: queue is waiting or converting. */
static int ldlm_reprocess_queue(struct ldlm_resource *res,
                                struct list_head *queue)
{
        struct list_head *tmp, *pos;
        ENTRY;

        list_for_each_safe(tmp, pos, queue) {
                struct ldlm_lock *pending;
                pending = list_entry(tmp, struct ldlm_lock, l_res_link);

                CDEBUG(D_INFO, "Reprocessing lock %p\n", pending);

                if (!ldlm_lock_compat(pending, 1))
                        RETURN(1);

                list_del_init(&pending->l_res_link);
                ldlm_grant_lock(pending);
        }

        RETURN(0);
}

void ldlm_run_ast_work(struct list_head *rpc_list)
{
        struct list_head *tmp, *pos;
        int rc;
        ENTRY;

        list_for_each_safe(tmp, pos, rpc_list) {
                struct ldlm_ast_work *w =
                        list_entry(tmp, struct ldlm_ast_work, w_list);
                struct lustre_handle lockh;

                ldlm_lock2handle(w->w_lock, &lockh);
                if (w->w_blocking)
                        rc = w->w_lock->l_blocking_ast
                                (&lockh, &w->w_desc, w->w_data, w->w_datalen);
                else
                        rc = w->w_lock->l_completion_ast
                                (&lockh, NULL, w->w_data, w->w_datalen);
                if (rc)
                        CERROR("Failed AST - should clean & disconnect "
                               "client\n");
                ldlm_lock_put(w->w_lock);
                list_del(&w->w_list);
                OBD_FREE(w, sizeof(*w));
        }
        EXIT;
}

/* Must be called with resource->lr_lock not taken. */
void ldlm_reprocess_all(struct ldlm_resource *res)
{
        struct list_head rpc_list = LIST_HEAD_INIT(rpc_list);
        ENTRY;

        /* Local lock trees don't get reprocessed. */
        if (res->lr_namespace->ns_client) {
                EXIT;
                return;
        }

        l_lock(&res->lr_namespace->ns_lock);
        res->lr_tmp = &rpc_list;

        ldlm_reprocess_queue(res, &res->lr_converting);
        if (list_empty(&res->lr_converting))
                ldlm_reprocess_queue(res, &res->lr_waiting);

        res->lr_tmp = NULL;
        l_unlock(&res->lr_namespace->ns_lock);

        ldlm_run_ast_work(&rpc_list);
        EXIT;
}

/* Must be called with lock and lock->l_resource unlocked */
void ldlm_lock_cancel(struct ldlm_lock *lock)
{
        struct ldlm_resource *res;
        struct ldlm_namespace *ns;
        ENTRY;

        res = lock->l_resource;
        ns = res->lr_namespace;

        l_lock(&ns->ns_lock);
        if (lock->l_readers || lock->l_writers)
                CDEBUG(D_INFO, "lock still has references (%d readers, %d "
                       "writers)\n", lock->l_readers, lock->l_writers);

        ldlm_resource_unlink_lock(lock);
        ldlm_lock_destroy(lock);
        l_unlock(&ns->ns_lock);
}

/* Must be called with lock and lock->l_resource unlocked */
struct ldlm_resource *ldlm_lock_convert(struct ldlm_lock *lock, int new_mode,
                                        int *flags)
{
        struct list_head rpc_list = LIST_HEAD_INIT(rpc_list);
        struct ldlm_resource *res;
        struct ldlm_namespace *ns;
        int granted = 0;
        ENTRY;

        res = lock->l_resource;
        ns = res->lr_namespace;

        l_lock(&ns->ns_lock);

        lock->l_req_mode = new_mode;
        ldlm_resource_unlink_lock(lock);

        /* If this is a local resource, put it on the appropriate list. */
        if (res->lr_namespace->ns_client) {
                if (*flags & (LDLM_FL_BLOCK_CONV | LDLM_FL_BLOCK_GRANTED))
                        ldlm_resource_add_lock(res, res->lr_converting.prev,
                                               lock);
                else {
                        res->lr_tmp = &rpc_list;
                        ldlm_grant_lock(lock);
                        res->lr_tmp = NULL;
                        granted = 1;
                        /* FIXME: completion handling not with ns_lock held ! */
                        wake_up(&lock->l_waitq);
                }
        } else
                list_add(&lock->l_res_link, res->lr_converting.prev);

        l_unlock(&ns->ns_lock);

        if (granted)
                ldlm_run_ast_work(&rpc_list);
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
        CDEBUG(D_OTHER, "  Resource: %p (%Ld)\n", lock->l_resource,
               lock->l_resource->lr_name[0]);
        CDEBUG(D_OTHER, "  Requested mode: %d, granted mode: %d\n",
               (int)lock->l_req_mode, (int)lock->l_granted_mode);
        CDEBUG(D_OTHER, "  Readers: %u ; Writers; %u\n",
               lock->l_readers, lock->l_writers);
        if (lock->l_resource->lr_type == LDLM_EXTENT)
                CDEBUG(D_OTHER, "  Extent: %Lu -> %Lu\n",
                       (unsigned long long)lock->l_extent.start,
                       (unsigned long long)lock->l_extent.end);
}
