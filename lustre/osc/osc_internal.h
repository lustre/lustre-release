int osc_create(struct lustre_handle *exph, struct obdo *oa,
	       struct lov_stripe_md **ea, struct obd_trans_info *oti);
int osc_real_create(struct lustre_handle *exph, struct obdo *oa,
	       struct lov_stripe_md **ea, struct obd_trans_info *oti);
int osccd_setup(void);
int osccd_cleanup(void);
void oscc_init(struct lustre_handle *exph);
