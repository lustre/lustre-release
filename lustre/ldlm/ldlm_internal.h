/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

/* ldlm_request.c */
typedef enum {
        LDLM_ASYNC,
        LDLM_SYNC,
} ldlm_sync_t;

int ldlm_cancel_lru(struct ldlm_namespace *ns, ldlm_sync_t sync);

/* ldlm_resource.c */
void ldlm_resource_insert_lock_after(struct ldlm_lock *original,
                                     struct ldlm_lock *new);

/* ldlm_lock.c */
void ldlm_grant_lock(struct ldlm_lock *lock, void *data, int datalen,
                     int run_ast);
struct ldlm_lock *
ldlm_lock_create(struct ldlm_namespace *ns,
                 struct lustre_handle *parent_lock_handle, struct ldlm_res_id,
                 ldlm_type_t type, ldlm_mode_t, ldlm_blocking_callback,
                 ldlm_completion_callback, ldlm_glimpse_callback, void *data,
                 __u32 lvb_len);
ldlm_error_t ldlm_lock_enqueue(struct ldlm_namespace *, struct ldlm_lock **,
                               void *cookie, int *flags);
void ldlm_lock_addref_internal(struct ldlm_lock *, __u32 mode);
void ldlm_lock_decref_internal(struct ldlm_lock *, __u32 mode);
void ldlm_add_ast_work_item(struct ldlm_lock *lock, struct ldlm_lock *new,
                            void *data, int datalen);
int ldlm_reprocess_queue(struct ldlm_resource *res, struct list_head *queue);
int ldlm_run_ast_work(struct ldlm_namespace *, struct list_head *rpc_list);

/* ldlm_lockd.c */
int ldlm_bl_to_thread(struct ldlm_namespace *ns, struct ldlm_lock_desc *ld,
                      struct ldlm_lock *lock);
void ldlm_handle_bl_callback(struct ldlm_namespace *ns,
                             struct ldlm_lock_desc *ld, struct ldlm_lock *lock);

/* ldlm_plain.c */
int ldlm_process_plain_lock(struct ldlm_lock *lock, int *flags, int first_enq,
                            ldlm_error_t *err);

/* ldlm_extent.c */
int ldlm_process_extent_lock(struct ldlm_lock *lock, int *flags, int first_enq,
                             ldlm_error_t *err);

/* ldlm_flock.c */
int ldlm_process_flock_lock(struct ldlm_lock *lock, int *flags, int first_enq,
                            ldlm_error_t *err);

/* ldlm_inodebits.c */
int ldlm_process_inodebits_lock(struct ldlm_lock *lock, int *flags,
                                int first_enq, ldlm_error_t *err);

/* l_lock.c */
void l_check_ns_lock(struct ldlm_namespace *ns);
void l_check_no_ns_lock(struct ldlm_namespace *ns);

extern cfs_proc_dir_entry_t *ldlm_svc_proc_dir;

struct ldlm_state {
        struct ptlrpc_service *ldlm_cb_service;
        struct ptlrpc_service *ldlm_cancel_service;
        struct ptlrpc_client *ldlm_client;
        struct ptlrpc_connection *ldlm_server_conn;
        struct ldlm_bl_pool *ldlm_bl_pool;
};

int ldlm_init(void);
void ldlm_exit(void);

