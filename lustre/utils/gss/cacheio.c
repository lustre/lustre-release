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

/*
 * support/nfs/cacheio.c
 * support IO on the cache channel files in 2.5 and beyond.
 * These use 'qwords' which are like words, but with a little quoting.
 *
 */


/*
 * Support routines for text-based upcalls.
 * Fields are separated by spaces.
 * Fields are either mangled to quote space tab newline slosh with slosh
 * or a hexified with a leading \x
 * Record is terminated with newline.
 *
 */

#include "cacheio.h"
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "err_util.h"

void qword_add(char **bpp, int *lp, const char *str)
{
	char *bp = *bpp;
	int len = *lp;
	char c;

	if (len < 0) return;

	while ((c=*str++) && len)
		switch(c) {
		case ' ':
		case '\t':
		case '\n':
		case '\\':
			if (len >= 4) {
				*bp++ = '\\';
				*bp++ = '0' + ((c & 0300)>>6);
				*bp++ = '0' + ((c & 0070)>>3);
				*bp++ = '0' + ((c & 0007)>>0);
			}
			len -= 4;
			break;
		default:
			*bp++ = c;
			len--;
		}
	if (c || len <1) len = -1;
	else {
		*bp++ = ' ';
		len--;
	}
	*bpp = bp;
	*lp = len;
}

void qword_addhex(char **bpp, int *lp, char *buf, int blen)
{
	char *bp = *bpp;
	int len = *lp;

	if (len < 0) return;

	if (len > 2) {
		*bp++ = '\\';
		*bp++ = 'x';
		len -= 2;
		while (blen && len >= 2) {
			unsigned char c = *buf++;
			*bp++ = '0' + ((c&0xf0)>>4) + (c>=0xa0)*('a'-'9'-1);
			*bp++ = '0' + (c&0x0f) + ((c&0x0f)>=0x0a)*('a'-'9'-1);
			len -= 2;
			blen--;
		}
	}
	if (blen || len<1) len = -1;
	else {
		*bp++ = ' ';
		len--;
	}
	*bpp = bp;
	*lp = len;
}

void qword_addint(char **bpp, int *lp, int n)
{
	int len;

	len = snprintf(*bpp, *lp, "%d ", n);
	if (len > *lp)
		len = *lp;
	*bpp += len;
	*lp -= len;
}

void qword_adduint(char **bpp, int *lp, unsigned int n)
{
	int len;

	len = snprintf(*bpp, *lp, "%u ", n);
	if (len > *lp)
		len = *lp;
	*bpp += len;
	*lp -= len;
}

void qword_addeol(char **bpp, int *lp)
{
	if (*lp <= 0)
		return;
	**bpp = '\n';
	(*bpp)++;
	(*lp)--;
}

static char qword_buf[8192];
static char tmp_buf[8192];
int qword_print(FILE *f, const char *str)
{
	char *bp = qword_buf;
	int len = sizeof(qword_buf);
	size_t sret;

	qword_add(&bp, &len, str);
	sret = fwrite(qword_buf, bp-qword_buf, 1, f);
	/* XXX: */
	memcpy(tmp_buf, qword_buf, bp-qword_buf);
	tmp_buf[bp-qword_buf] = '\0';
	printerr(2, "%s", tmp_buf);

	return sret != 1;
}

int qword_printhex(FILE *f, char *str, int slen)
{
	char *bp = qword_buf;
	int len = sizeof(qword_buf);
	size_t sret;

	qword_addhex(&bp, &len, str, slen);
	sret = fwrite(qword_buf, bp-qword_buf, 1, f);
	/* XXX: */
	memcpy(tmp_buf, qword_buf, bp-qword_buf);
	tmp_buf[bp-qword_buf] = '\0';
	printerr(2, "%s", tmp_buf);

	return sret != 1;
}

void qword_printint(FILE *f, int num)
{
	fprintf(f, "%d ", num);
	printerr(2, "%d ", num);
}

int qword_eol(FILE *f)
{
	int err;
	fprintf(f,"\n");
	err = fflush(f);
	printerr(2, "\n");
	return err;
}



#define isodigit(c) (isdigit(c) && c <= '7')
int qword_get(char **bpp, char *dest, int bufsize)
{
	/* return bytes copied, or -1 on error */
	char *bp = *bpp;
	int len = 0;

	while (*bp == ' ') bp++;

	if (bp[0] == '\\' && bp[1] == 'x') {
		/* HEX STRING */
		bp += 2;
		while (isxdigit(bp[0]) && isxdigit(bp[1]) && len < bufsize) {
			int byte = isdigit(*bp) ? *bp-'0' : toupper(*bp)-'A'+10;
			bp++;
			byte <<= 4;
			byte |= isdigit(*bp) ? *bp-'0' : toupper(*bp)-'A'+10;
			*dest++ = byte;
			bp++;
			len++;
		}
	} else {
		/* text with \nnn octal quoting */
		while (*bp != ' ' && *bp != '\n' && *bp && len < bufsize-1) {
			if (*bp == '\\' &&
			    isodigit(bp[1]) && (bp[1] <= '3') &&
			    isodigit(bp[2]) &&
			    isodigit(bp[3])) {
				int byte = (*++bp -'0');
				bp++;
				byte = (byte << 3) | (*bp++ - '0');
				byte = (byte << 3) | (*bp++ - '0');
				*dest++ = byte;
				len++;
			} else {
				*dest++ = *bp++;
				len++;
			}
		}
	}

	if (*bp != ' ' && *bp != '\n' && *bp != '\0')
		return -1;
	while (*bp == ' ') bp++;
	*bpp = bp;
// why should we clear *dest???
//	*dest = '\0';
	return len;
}

int qword_get_int(char **bpp, int *anint)
{
	char buf[50];
	char *ep;
	int rv;
	int len = qword_get(bpp, buf, 50);
	if (len < 0) return -1;
	if (len ==0) return -1;
	rv = strtol(buf, &ep, 0);
	if (*ep) return -1;
	*anint = rv;
	return 0;
}

#define READLINE_BUFFER_INCREMENT 2048

int readline(int fd, char **buf, int *lenp)
{
	/* read a line into *buf, which is malloced *len long
	 * realloc if needed until we find a \n
	 * nul out the \n and return
	 * 0 of eof, 1 of success
	 */
	int len;

	if (*lenp == 0) {
		char *b = malloc(READLINE_BUFFER_INCREMENT);
		if (b == NULL)
			return 0;
		*buf = b;
		*lenp = READLINE_BUFFER_INCREMENT;
	}
	len = read(fd, *buf, *lenp);
	if (len <= 0) {
		printerr(0, "readline: read error: len %d errno %d (%s)\n",
			 len, errno, strerror(errno));
		return 0;
	}
	while ((*buf)[len-1] != '\n') {
	/* now the less common case.  There was no newline,
	 * so we have to keep reading after re-alloc
	 */
		char *new;
		int nl;
		*lenp += READLINE_BUFFER_INCREMENT;
		new = realloc(*buf, *lenp);
		if (new == NULL)
			return 0;
		*buf = new;
		nl = read(fd, *buf +len, *lenp - len);
		if (nl <= 0 ) {
			printerr(0, "readline: read error: len %d "
				 "errno %d (%s)\n", nl, errno, strerror(errno));
			return 0;
		}
		len += nl;
	}
	(*buf)[len-1] = 0;
	printerr(3, "readline: read %d chars into buffer of size %d:\n%s\n",
		 len, *lenp, *buf);
	return 1;
}
