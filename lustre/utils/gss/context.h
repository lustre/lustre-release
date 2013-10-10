/*
  Copyright (c) 2004-2006 The Regents of the University of Michigan.
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

#ifndef _CONTEXT_H_
#define _CONTEXT_H_

#include <krb5.h>

/* Hopefully big enough to hold any serialized context */
#define MAX_CTX_LEN 4096

/* New context format flag values */
#define KRB5_CTX_FLAG_INITIATOR         0x00000001
#define KRB5_CTX_FLAG_CFX               0x00000002
#define KRB5_CTX_FLAG_ACCEPTOR_SUBKEY   0x00000004

#if HAVE_KRB5INT_DERIVE_KEY
/* Taken from crypto_int.h */
enum deriv_alg {
	DERIVE_RFC3961,		/* RFC 3961 section 5.1 */
#ifdef CAMELLIA
	DERIVE_SP800_108_CMAC,	/* NIST SP 800-108 with CMAC as PRF */
#endif
};

extern krb5_error_code krb5int_derive_key(const void *enc,
					  krb5_key inkey, krb5_key *outkey,
					  const krb5_data *in_constant,
					  enum deriv_alg alg);
extern krb5_error_code krb5_k_create_key(krb5_context context,
					 const krb5_keyblock *key_data,
					 krb5_key *out);
#else /* !HAVE_KRB5INT_DERIVE_KEY */

extern krb5_error_code krb5_derive_key(const void *enc,
				       const krb5_keyblock *inkey,
				       krb5_keyblock *outkey,
				       const krb5_data *in_constant);
#endif

int serialize_context_for_kernel(gss_ctx_id_t ctx, gss_buffer_desc *buf,
				 gss_OID mech);
int serialize_spkm3_ctx(gss_ctx_id_t ctx, gss_buffer_desc *buf);
int serialize_krb5_ctx(gss_ctx_id_t ctx, gss_buffer_desc *buf);

#endif /* _CONTEXT_H_ */
