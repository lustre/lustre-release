/* ldlm_request.c */
int ldlm_cancel_lru(struct ldlm_namespace *ns);

/* ldlm_lock.c */
void ldlm_grant_lock(struct ldlm_lock *lock, void *data, int datalen,
		     int run_ast);
struct ldlm_lock *
ldlm_lock_create(struct ldlm_namespace *ns,
                 struct lustre_handle *parent_lock_handle, struct ldlm_res_id,
                 __u32 type, ldlm_mode_t, ldlm_blocking_callback, void *data);
