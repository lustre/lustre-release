int osc_create(struct obd_export *exp, struct obdo *oa,
	       struct lov_stripe_md **ea, struct obd_trans_info *oti);
int osc_real_create(struct obd_export *exp, struct obdo *oa,
	       struct lov_stripe_md **ea, struct obd_trans_info *oti);
int osccd_setup(void);
int osccd_cleanup(void);
void oscc_init(struct lustre_handle *exph);

int lproc_osc_attach_seqstat(struct obd_device *dev);
extern atomic_t osc_max_rpcs_in_flight;
extern atomic_t osc_max_pages_per_rpc;
int osc_rpcd_addref(void);
int osc_rpcd_decref(void);
void lproc_osc_hist(struct osc_histogram *oh, unsigned int value);
void lproc_osc_hist_pow2(struct osc_histogram *oh, unsigned int value);
int lproc_osc_attach_seqstat(struct obd_device *dev);
void osc_rpcd_add_req(struct ptlrpc_request *req);
