#ifndef KRB5_UTIL_H
#define KRB5_UTIL_H

#include <krb5.h>

/*
 * List of principals from our keytab that we
 * may try to get credentials for
 */
struct gssd_k5_kt_princ {
	struct gssd_k5_kt_princ *next;
	krb5_principal princ;
	unsigned int	fl_root:1,
			fl_mds:1;
	char *ccname;
	char *realm;
	krb5_timestamp endtime;
};


void gssd_setup_krb5_user_gss_ccache(uid_t uid, char *servername);
int  gssd_get_krb5_machine_cred_list(char ***list);
int  gssd_refresh_krb5_machine_creds(void);
void gssd_free_krb5_machine_cred_list(char **list);
void gssd_setup_krb5_machine_gss_ccache(char *servername);
void gssd_destroy_krb5_machine_creds(void);
void gssd_obtain_kernel_krb5_info(void);


#endif /* KRB5_UTIL_H */
