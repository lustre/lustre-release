#include <ldap.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int main(int argc, char **argv)
{
        LDAP *ld;
        int err;

        ld = ldap_init("localhost", 389); 
        if (!ld) {
                fprintf(stderr, "ldap_init: %s\n", strerror(errno));
                exit(1);
        }
        
        err = ldap_bind_s(ld, "cn=Manager,dc=lustre,dc=cfs", "secret", 
                        LDAP_AUTH_SIMPLE);
        if (err) { 
                fprintf(stderr, "ldap_bind: %s\n", ldap_err2string(err));
                exit(1);
        }


        

}
