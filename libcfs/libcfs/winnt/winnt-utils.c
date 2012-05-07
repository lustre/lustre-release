/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */


/*
 * miscellaneous libcfs stuff
 */
#define DEBUG_SUBSYSTEM S_LNET
#include <libcfs/libcfs.h>
#include <errno.h>

/*
 *  IDR support routines
 *
 *  local global id <-> handle context
 */

/* idr definitions */

#define IDR_BITS 7
#define IDR_FULL 0xffffffff
#define IDR_SIZE (1 << IDR_BITS)
#define IDR_MASK ((1 << IDR_BITS)-1)
#define MAX_ID_SHIFT (sizeof(int)*8 - 1)
#define MAX_ID_BIT (1U << MAX_ID_SHIFT)
#define MAX_ID_MASK (MAX_ID_BIT - 1)
#define MAX_LEVEL (MAX_ID_SHIFT + IDR_BITS - 1) / IDR_BITS
#define IDR_FREE_MAX MAX_LEVEL + MAX_LEVEL

#define idr_set_bit(bit, v) (v) |= (1<<(bit))
#define idr_clear_bit(bit, v) (v) &= ~(1<<(bit))
#define idr_test_bit(bit, v) ((v) & (1<<(bit)))

struct idr_layer {
	uint32_t            bitmap;
	struct idr_layer   *ary[IDR_SIZE];
	int			        count;
};

struct idr_context {
	struct idr_layer *top;
	struct idr_layer *id_free;
	int		  layers;
	int		  id_free_cnt;
};


/*
 * id (fd) <-> pointer (HANDLE)
 */

/**********************************************************
  private structures and routines for id implementation
***********************************************************/
				   
static struct idr_layer *alloc_layer(struct idr_context *idp)
{
	struct idr_layer *p;

	if (!(p = idp->id_free))
		return NULL;
	idp->id_free = p->ary[0];
	idp->id_free_cnt--;
	p->ary[0] = NULL;
	return p;
}

static int find_next_idrbit(uint32_t bm, int maxid, int n)
{
	while (n<maxid && !idr_test_bit(n, bm)) n++;
	return n;
}

static void free_layer(struct idr_context *idp, struct idr_layer *p)
{
	p->ary[0] = idp->id_free;
	idp->id_free = p;
	idp->id_free_cnt++;
}

static int idr_pre_get(struct idr_context *idp)
{
	while (idp->id_free_cnt < IDR_FREE_MAX) {
		struct idr_layer *new;

        new = cfs_alloc(sizeof(struct idr_layer), CFS_ALLOC_ZERO);
		if(new == NULL)
			return (0);
		free_layer(idp, new);
	}
	return 1;
}

static int sub_alloc(struct idr_context *idp, void *ptr, int *starting_id)
{
	int n, m, sh;
	struct idr_layer *p, *new;
	struct idr_layer *pa[MAX_LEVEL];
	int l, id;
	uint32_t bm;

	memset(pa, 0, sizeof(pa));

	id = *starting_id;
	p = idp->top;
	l = idp->layers;
	pa[l--] = NULL;
	while (1) {
		/*
		 * We run around this while until we reach the leaf node...
		 */
		n = (id >> (IDR_BITS*l)) & IDR_MASK;
		bm = ~p->bitmap;
		m = find_next_idrbit(bm, IDR_SIZE, n);
		if (m == IDR_SIZE) {
			/* no space available go back to previous layer. */
			l++;
			id = (id | ((1 << (IDR_BITS*l))-1)) + 1;
			if (!(p = pa[l])) {
				*starting_id = id;
				return -2;
			}
			continue;
		}
		if (m != n) {
			sh = IDR_BITS*l;
			id = ((id >> sh) ^ n ^ m) << sh;
		}
		if ((id >= MAX_ID_BIT) || (id < 0))
			return -1;
		if (l == 0)
			break;
		/*
		 * Create the layer below if it is missing.
		 */
		if (!p->ary[m]) {
			if (!(new = alloc_layer(idp)))
				return -1;
			p->ary[m] = new;
			p->count++;
		}
		pa[l--] = p;
		p = p->ary[m];
	}
	/*
	 * We have reached the leaf node, plant the
	 * users pointer and return the raw id.
	 */
	p->ary[m] = (struct idr_layer *)ptr;
	idr_set_bit(m, p->bitmap);
	p->count++;
	/*
	 * If this layer is full mark the bit in the layer above
	 * to show that this part of the radix tree is full.
	 * This may complete the layer above and require walking
	 * up the radix tree.
	 */
	n = id;
	while (p->bitmap == IDR_FULL) {
		if (!(p = pa[++l]))
			break;
		n = n >> IDR_BITS;
		idr_set_bit((n & IDR_MASK), p->bitmap);
	}
	return(id);
}

static int idr_get_new_above_int(struct idr_context *idp, void *ptr, int starting_id)
{
	struct idr_layer *p, *new;
	int layers, v, id;

	idr_pre_get(idp);
	
	id = starting_id;
build_up:
	p = idp->top;
	layers = idp->layers;
	if (!p) {
		if (!(p = alloc_layer(idp)))
			return -1;
		layers = 1;
	}
	/*
	 * Add a new layer to the top of the tree if the requested
	 * id is larger than the currently allocated space.
	 */
	while ((layers < MAX_LEVEL) && (id >= (1 << (layers*IDR_BITS)))) {
		layers++;
		if (!p->count)
			continue;
		if (!(new = alloc_layer(idp))) {
			/*
			 * The allocation failed.  If we built part of
			 * the structure tear it down.
			 */
			for (new = p; p && p != idp->top; new = p) {
				p = p->ary[0];
				new->ary[0] = NULL;
				new->bitmap = new->count = 0;
				free_layer(idp, new);
			}
			return -1;
		}
		new->ary[0] = p;
		new->count = 1;
		if (p->bitmap == IDR_FULL)
			idr_set_bit(0, new->bitmap);
		p = new;
	}
	idp->top = p;
	idp->layers = layers;
	v = sub_alloc(idp, ptr, &id);
	if (v == -2)
		goto build_up;
	return(v);
}

static int sub_remove(struct idr_context *idp, int shift, int id)
{
	struct idr_layer *p = idp->top;
	struct idr_layer **pa[MAX_LEVEL];
	struct idr_layer ***paa = &pa[0];
	int n;

	*paa = NULL;
	*++paa = &idp->top;

	while ((shift > 0) && p) {
		n = (id >> shift) & IDR_MASK;
		idr_clear_bit(n, p->bitmap);
		*++paa = &p->ary[n];
		p = p->ary[n];
		shift -= IDR_BITS;
	}
	n = id & IDR_MASK;
	if (p != NULL && idr_test_bit(n, p->bitmap)) {
		idr_clear_bit(n, p->bitmap);
		p->ary[n] = NULL;
		while(*paa && ! --((**paa)->count)){
			free_layer(idp, **paa);
			**paa-- = NULL;
		}
		if ( ! *paa )
			idp->layers = 0;
		return 0;
	}
	return -1;
}

static void *_idr_find(struct idr_context *idp, int id)
{
	int n;
	struct idr_layer *p;

	n = idp->layers * IDR_BITS;
	p = idp->top;
	/*
	 * This tests to see if bits outside the current tree are
	 * present.  If so, tain't one of ours!
	 */
	if ((id & ~(~0 << MAX_ID_SHIFT)) >> (n + IDR_BITS))
	     return NULL;

	/* Mask off upper bits we don't use for the search. */
	id &= MAX_ID_MASK;

	while (n >= IDR_BITS && p) {
		n -= IDR_BITS;
		p = p->ary[(id >> n) & IDR_MASK];
	}
	return((void *)p);
}

static int _idr_remove(struct idr_context *idp, int id)
{
	struct idr_layer *p;

	/* Mask off upper bits we don't use for the search. */
	id &= MAX_ID_MASK;

	if (sub_remove(idp, (idp->layers - 1) * IDR_BITS, id) == -1) {
		return -1;
	}

	if ( idp->top && idp->top->count == 1 && 
	     (idp->layers > 1) &&
	     idp->top->ary[0]) {
		/* We can drop a layer */
		p = idp->top->ary[0];
		idp->top->bitmap = idp->top->count = 0;
		free_layer(idp, idp->top);
		idp->top = p;
		--idp->layers;
	}
	while (idp->id_free_cnt >= IDR_FREE_MAX) {
		p = alloc_layer(idp);
		cfs_free(p);
	}
	return 0;
}

/**********************************************************
  publick interfaces of id vs handle conversion
***********************************************************/

/**
  initialise a idr tree.
 */
struct idr_context *cfs_idr_init()
{
    struct idr_context * idp = NULL;
    idp = cfs_alloc(sizeof(struct idr_context), 0);
    if (idp) {
        memset(idp, 0, sizeof(struct idr_context));
    }

    return idp;
}

/**
  remove an id from the idr tree
*/
int cfs_idr_remove(struct idr_context *idp, int id)
{
	int ret;
	ret = _idr_remove((struct idr_context *)idp, id);
	if (ret != 0) {
		CWARN("WARNING: attempt to remove unset id %d in idtree\n", id);
	}
	return ret;
}

/**
  allocate the next available id, and assign 'ptr' into its slot.
  you can retrieve later this pointer using idr_find()
*/
int cfs_idr_get_new(struct idr_context *idp, void *ptr)
{
	int ret = idr_get_new_above_int(idp, ptr, 0);
	if (ret > MAX_ID_MASK) {
		cfs_idr_remove(idp, ret);
		return -1;
	}
	return ret;
}

/**
   allocate a new id, giving the first available value greater than or
   equal to the given starting id
*/
int cfs_idr_get_new_above(struct idr_context *idp, void *ptr, int starting_id)
{
	int ret = idr_get_new_above_int(idp, ptr, starting_id);
	if (ret > MAX_ID_MASK) {
		cfs_idr_remove(idp, ret);
		return -1;
	}
	return ret;
}

/**
  find a pointer value previously set with idr_get_new given an id
*/
void *cfs_idr_find(struct idr_context *idp, int id)
{
	return _idr_find(idp, id);
}

/**
  destroy a idr tree. 
 */
void cfs_idr_exit(struct idr_context *idp)
{
    if (idp) {
	    cfs_free(idp);
    }
}

/*
 * convert <fcntl.h> flag from client to server.
 * 
 * nt kernel uses several members to describe the open flags
 * such as DesiredAccess/ShareAccess/CreateDisposition/CreateOptions
 * so it's better to convert when using, not here.
 */

int convert_client_oflag(int cflag, int *result)
{
    *result = 0;
	return 0;
}

int cfs_error_code(NTSTATUS Status)
{
    switch (Status) {

        case STATUS_ACCESS_DENIED:
            return (-EACCES);

        case STATUS_ACCESS_VIOLATION:
            return (-EFAULT);
    
        case STATUS_BUFFER_TOO_SMALL:
            return (-ETOOSMALL);

        case STATUS_INVALID_PARAMETER:
            return (-EINVAL);

        case STATUS_NOT_IMPLEMENTED:
        case STATUS_NOT_SUPPORTED:
            return (-EOPNOTSUPP);

        case STATUS_INVALID_ADDRESS:
        case STATUS_INVALID_ADDRESS_COMPONENT:
            return (-EADDRNOTAVAIL);

        case STATUS_NO_SUCH_DEVICE:
        case STATUS_NO_SUCH_FILE:
        case STATUS_OBJECT_NAME_NOT_FOUND:
        case STATUS_OBJECT_PATH_NOT_FOUND:  
        case STATUS_NETWORK_BUSY:
        case STATUS_INVALID_NETWORK_RESPONSE:
        case STATUS_UNEXPECTED_NETWORK_ERROR:
            return (-ENETDOWN);

        case STATUS_BAD_NETWORK_PATH:
        case STATUS_NETWORK_UNREACHABLE:
        case STATUS_PROTOCOL_UNREACHABLE:     
            return (-ENETUNREACH);

        case STATUS_LOCAL_DISCONNECT:
        case STATUS_TRANSACTION_ABORTED:
        case STATUS_CONNECTION_ABORTED:
            return (-ECONNABORTED);

        case STATUS_REMOTE_DISCONNECT:
        case STATUS_LINK_FAILED:
        case STATUS_CONNECTION_DISCONNECTED:
        case STATUS_CONNECTION_RESET:
        case STATUS_PORT_UNREACHABLE:
            return (-ECONNRESET);

        case STATUS_INSUFFICIENT_RESOURCES:
            return (-ENOMEM);

        case STATUS_PAGEFILE_QUOTA:
        case STATUS_NO_MEMORY:
        case STATUS_CONFLICTING_ADDRESSES:
        case STATUS_QUOTA_EXCEEDED:
        case STATUS_TOO_MANY_PAGING_FILES:
        case STATUS_WORKING_SET_QUOTA:
        case STATUS_COMMITMENT_LIMIT:
        case STATUS_TOO_MANY_ADDRESSES:
        case STATUS_REMOTE_RESOURCES:
            return (-ENOBUFS);

        case STATUS_INVALID_CONNECTION:
            return (-ENOTCONN);

        case STATUS_PIPE_DISCONNECTED:
            return (-ESHUTDOWN);

        case STATUS_TIMEOUT:
        case STATUS_IO_TIMEOUT:
        case STATUS_LINK_TIMEOUT:
            return (-ETIMEDOUT);

        case STATUS_REMOTE_NOT_LISTENING:
        case STATUS_CONNECTION_REFUSED:
            return (-ECONNREFUSED);

        case STATUS_HOST_UNREACHABLE:
            return (-EHOSTUNREACH);

        case STATUS_PENDING:
        case STATUS_DEVICE_NOT_READY:
            return (-EAGAIN);

        case STATUS_CANCELLED:
        case STATUS_REQUEST_ABORTED:
            return (-EINTR);

        case STATUS_BUFFER_OVERFLOW:
        case STATUS_INVALID_BUFFER_SIZE:
            return (-EMSGSIZE);

        case STATUS_ADDRESS_ALREADY_EXISTS:
            return (-EADDRINUSE);
    }

    if (NT_SUCCESS(Status)) 
        return 0;

    return (-EINVAL);
}

/*
 * Convert server error code to client format. Error codes are from
 * Linux errno.h, so for Linux client---identity.
 */
int convert_server_error(__u64 ecode)
{
	return cfs_error_code((NTSTATUS)ecode);
}

char * strsep(char **strp, const char *delim)
{
    char *begin, *end;

    begin = *strp;
    if (begin == NULL) {
        return NULL;
    }

    if (delim[0] == '\0' || delim[1] == '\0') {
        char ch = delim[0];
        if (ch == '\0') {
	        end = NULL;
        } else {
	        if (*begin == ch) {
	            end = begin;
	        } else if (*begin == '\0') {
	            end = NULL;
	        } else {
	            end = strchr (begin + 1, ch);
	        }
        }
    } else {
        end = strpbrk (begin, delim);
    }

    if (end) {
        *end++ = '\0';
        *strp = end;
    } else {
        *strp = NULL;
    }

    return begin;
}

/*
 * strnchr - Find a character in a length limited string
 * @s: The string to be searched
 * @count: The number of characters to be searched
 * @c: The character to search for
 */

char *strnchr(const char *s, size_t count, int c)
{
    for (; count-- && *s != '\0'; ++s)
        if (*s == (char) c)
            return (char *) s;
    return NULL;
}

__u64 strtoull(char *nptr, char **endptr,int base)
{
	char *s = nptr;
	__u64 acc, cutoff;
	int c, neg = 0, any, cutlim;

	/*
	 * See strtol for comments as to the logic used.
	 */
	do {
		c = *s++;
	} while (cfs_isspace(c));
	if (c == '-') {
		neg = 1;
		c = *s++;
	} else if (c == '+')
		c = *s++;
	if ((base == 0 || base == 16) &&
	    c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		base = 16;
	}
	if (base == 0)
		base = c == '0' ? 8 : 10;
	cutoff = (__u64)ULONG_LONG_MAX / (__u64)base;
	cutlim = (int)((__u64)ULONG_LONG_MAX % (__u64)base);
	for (acc = 0, any = 0;; c = *s++) {
		if (cfs_isdigit(c))
			c -= '0';
		else if (cfs_isalpha(c))
			c -= cfs_isupper(c) ? 'A' - 10 : 'a' - 10;
		else
			break;
		if (c >= base)
			break;
               if (any < 0 || acc > cutoff || (acc == cutoff && c > cutlim))
			any = -1;
		else {
			any = 1;
			acc *= base;
			acc += c;
		}
	}
	if (any < 0) {
		acc = ULONG_LONG_MAX;
	} else if (neg)
		acc = 0 - acc;
	if (endptr != 0)
		*endptr = (char *) (any ? s - 1 : nptr);
	return (acc);
}

#if __KERNEL__

#define BASE 65521L /* largest prime smaller than 65536 */
#define NMAX 5552
/* NMAX is the largest n such that 255n(n+1)/2 + (n+1)(BASE-1) <= 2^32-1 */

#define DO1(buf,i)  {s1 += buf[i]; s2 += s1;}
#define DO2(buf,i)  DO1(buf,i); DO1(buf,i+1);
#define DO4(buf,i)  DO2(buf,i); DO2(buf,i+2);
#define DO8(buf,i)  DO4(buf,i); DO4(buf,i+4);
#define DO16(buf)   DO8(buf,0); DO8(buf,8);

/* ========================================================================= */
/* 
    Update a running Adler-32 checksum with the bytes buf[0..len-1] and
  return the updated checksum. If buf is NULL, this function returns
  the required initial value for the checksum.
  An Adler-32 checksum is almost as reliable as a CRC32 but can be computed
  much faster. Usage example:

    uLong adler = adler32(0L, NULL, 0);

    while (read_buffer(buffer, length) != EOF) {
      adler = adler32(adler, buffer, length);
    }
    if (adler != original_adler) error();
*/

ULONG zlib_adler32(ULONG adler,
                   const BYTE *buf,
                   UINT len)
{
    unsigned long s1 = adler & 0xffff;
    unsigned long s2 = (adler >> 16) & 0xffff;
    int k;

    if (buf == NULL) return 1L;

    while (len > 0) {
        k = len < NMAX ? len : NMAX;
        len -= k;
        while (k >= 16) {
            DO16(buf);
            buf += 16;
            k -= 16;
        }
        if (k != 0) do {
            s1 += *buf++;
            s2 += s1;
        } while (--k);
        s1 %= BASE;
        s2 %= BASE;
    }
    return (s2 << 16) | s1;
}

#if  !defined(NTDDI_VERSION) || NTDDI_VERSION < 0x06000000
_CRTIMP size_t  __cdecl strnlen(const char * _Str, size_t _MaxCount)
{
        size_t len = 0;
        while(len < _MaxCount && _Str[len++]);
        return len;
}
#endif

int (__cdecl *_cfs_isalpha)(int);
int (__cdecl *_cfs_isspace)(int);
int (__cdecl *_cfs_isupper)(int);
int (__cdecl *_cfs_isdigit)(int);
int (__cdecl *_cfs_isxdigit)(int);

int cfs_isalpha(int c)
{
    if (_cfs_isalpha) {
        return _cfs_isalpha(c);
    } else {
        return ((c >= 'a' && c <= 'z') ||
                (c >= 'A' && c <= 'Z'));
    }
}

int cfs_isspace(int c)
{
    if (_cfs_isspace) {
        return _cfs_isspace(c);
    } else {
        return ((c >= 0x09 && c <= 0x0d) ||
                (c == 0x20));
    }
}

int cfs_isupper(int c)
{
    if (_cfs_isupper) {
        return _cfs_isupper(c);
    } else {
        return (c >= 'A' && c <= 'Z');
    }
}

int cfs_isdigit(int c)
{
    if (_cfs_isdigit) {
        return _cfs_isdigit(c);
    } else {
        return (c >= '0' && c <= '9');
    }
}

int cfs_isxdigit(int c)
{
    if (_cfs_isxdigit) {
        return _cfs_isxdigit(c);
    } else {
        return ((c >= '0' && c <= '9') ||
                (c >= 'A' && c <= 'F') ||
                (c >= 'a' && c <= 'F'));
    }
}

void cfs_libc_init()
{
    UNICODE_STRING  fn;
    int             i;

    struct {WCHAR * name; PVOID * addr;} funcs[] = {
            { L"isspace", (PVOID *)&_cfs_isspace},
            { L"isalpha", (PVOID *)&_cfs_isalpha},
            { L"isupper", (PVOID *)&_cfs_isupper},
            { L"isdigit", (PVOID *)&_cfs_isdigit},
            { L"isxdigit",(PVOID *)&_cfs_isxdigit},
            { NULL, NULL },
            };

    for (i=0; funcs[i].name != NULL; i++) {
        RtlInitUnicodeString(&fn, funcs[i].name);
        *(funcs[i].addr) = MmGetSystemRoutineAddress(&fn);
    }

#if DBG
    ASSERT(cfs_isspace(0x20) && cfs_isspace(0x09) &&
           cfs_isspace(0x0a) && cfs_isspace(0x0d) &&
           !cfs_isspace('a') && !cfs_isspace('0'));
    ASSERT(cfs_isalpha('a')  && cfs_isalpha('Z') && 
           !cfs_isalpha('0') && !cfs_isalpha('='));
    ASSERT(cfs_isupper('A')  && cfs_isupper('Z') && 
           !cfs_isupper('a') && !cfs_isupper('='));
    ASSERT(cfs_isdigit('0')   && cfs_isdigit('9') && 
           !cfs_isdigit('a')  && !cfs_isdigit('#'));
    ASSERT(cfs_isxdigit('0')  && cfs_isxdigit('9') && 
           cfs_isxdigit('a')  && cfs_isxdigit('A') &&
           cfs_isxdigit('F')  && cfs_isxdigit('f') &&
           !cfs_isxdigit('G') && !cfs_isxdigit('z'));
#endif    
}

#else

unsigned int libcfs_subsystem_debug = ~0;

int cfs_isalpha(int c)
{
    return isalpha(c);
}

int cfs_isspace(int c)
{
    return isspace(c);
}

int cfs_isupper(int c)
{
    return isupper(c);
}

int cfs_isdigit(int c)
{
    return isdigit(c);
}

int cfs_isxdigit(int c)
{
    return isxdigit(c);
}

void cfs_libc_init()
{
}


#endif
