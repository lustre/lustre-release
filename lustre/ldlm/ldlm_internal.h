/* ldlm_request.c */
int ldlm_cancel_lru(struct ldlm_namespace *ns);

/* ldlm_lock.c */
void ldlm_grant_lock(struct ldlm_lock *lock, void *data, int datalen,
		     int run_ast);
struct ldlm_lock *
ldlm_lock_create(struct ldlm_namespace *ns,
                 struct lustre_handle *parent_lock_handle, struct ldlm_res_id,
                 __u32 type, ldlm_mode_t, ldlm_blocking_callback,
                 ldlm_completion_callback, void *data);
ldlm_error_t ldlm_lock_enqueue(struct ldlm_namespace *, struct ldlm_lock **,
                               void *cookie, int cookie_len, int *flags);
