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

#ifndef _WRITE_BYTES_H_
#define _WRITE_BYTES_H_

#include <stdlib.h>
#include <sys/types.h>

static inline int
write_bytes(char **ptr, const char *end, const void *arg, int arg_len)
{
	char *p = *ptr, *arg_end;

	arg_end = p + arg_len;
	if (arg_end > end || arg_end < p)
		return -1;
	memcpy(p, arg, arg_len);
	*ptr = arg_end;
	return 0;
}

#define WRITE_BYTES(p, end, arg) write_bytes(p, end, &arg, sizeof(arg))

static inline int
write_buffer(char **p, char *end, gss_buffer_desc *arg)
{
	int len = (int)arg->length;		/* make an int out of size_t */
	if (WRITE_BYTES(p, end, len))
		return -1;
	if (*p + len > end)
		return -1;
	memcpy(*p, arg->value, len);
	*p += len;
	return 0;
}

static inline int
write_oid(char **p, char *end, gss_OID_desc *arg)
{
	int len = (int)arg->length;		/* make an int out of size_t */
	if (WRITE_BYTES(p, end, len))
		return -1;
	if (*p + arg->length > end)
		return -1;
	memcpy(*p, arg->elements, len);
	*p += len;
	return 0;
}

#endif /* _WRITE_BYTES_H_ */
