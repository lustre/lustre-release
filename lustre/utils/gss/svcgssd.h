/*
  Copyright (c) 2004 The Regents of the University of Michigan.
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.
  3. Neither the name of the University nor the names of its
     contributors may be used to endorse or promote products derived
     from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _RPC_SVCGSSD_H_
#define _RPC_SVCGSSD_H_

#include <sys/types.h>
#include <sys/queue.h>
#include <gssapi/gssapi.h>

int krb_enabled;

int handle_channel_request(FILE *f);
void svcgssd_run(void);
int gssd_prepare_creds(int must_srv_mgs, int must_srv_mds, int must_srv_oss);
gss_cred_id_t gssd_select_svc_cred(int lustre_svc);
const char *gss_OID_mech_name(gss_OID mech);

extern char *mds_local_realm;
extern char *oss_local_realm;
extern int null_enabled;
extern int krb_enabled;
extern int sk_enabled;

#define GSSD_SERVICE_NAME	"lustre"

/* XXX */
#define GSSD_SERVICE_MGS			"lustre_mgs"
#define GSSD_SERVICE_MDS			"lustre_mds"
#define GSSD_SERVICE_OSS			"lustre_oss"
#define LUSTRE_ROOT_NAME			"lustre_root"
#define LUSTRE_ROOT_NAMELEN			11

#endif /* _RPC_SVCGSSD_H_ */
