[= AutoGen5 Template h -*- Mode: C -*- =]
[= (dne " * " "/* ") =]
 *
[= (gpl "lustre" " * ") =]
 */
/**
 * \file [= (out-name) =]
 * The flags and collections of flags (masks) for \see struct ldlm_lock.
 * This file is derived from flag definitions in [=(def-file)=].
 * The format is defined in the [=(tpl-file)=] template file.
 *
 * \addtogroup LDLM Lustre Distributed Lock Manager
 * @{
 *
 * \name flags
 * The flags and collections of flags (masks) for \see struct ldlm_lock.
 * @{
 */
#ifndef LDLM_ALL_FLAGS_MASK
[=

;; Guile is unable to handle 64 bit unsigned ints very easily.
;; BASH does just fine.  Construct a shell script to compute the
;; bit masks and echo out the appropriate #defines.
;;
(out-push-new "script.sh")

=]
mask_list=
allbits=0
fmt='#define LDLM_FL_%-16s        0x%016XULL // bit  %2u
#define ldlm_is_%-20s    LDLM_TEST_FLAG(( _l), 1ULL << %2u)
#define ldlm_set_%-20s   LDLM_SET_FLAG((  _l), 1ULL << %2u)
#define ldlm_clear_%-20s LDLM_CLEAR_FLAG((_l), 1ULL << %2u)\n'
acc_fmt=''
tmpfile=[=(base-name)=]-$$.tmp
exec 8>&1 1> $tmpfile
[=

FOR flag

=]
bitno=[=(define temp-txt (get "f-desc"))
        (for-index)=]
bitval=$(( 1 << $bitno ))
echo[=

  IF (< (string-length temp-txt) 72)=]
echo '/**' [= (raw-shell-str temp-txt) =] '*/'[=
  ELSE=]
echo '/**'
{ fmt -w 74 | sed 's/^/ * /;s/ *$//;$s@$@ */@'
} <<_EOF_
[=(. temp-txt)=]
_EOF_[=
  ENDIF

=]
dn_name=[= (string-downcase! (string->c-name! (get "f-name"))) =]'(_l)'
up_name=[= (string-upcase!   (string->c-name! (get "f-name"))) =]
printf "$fmt" $up_name $bitval $bitno \
	$dn_name $bitno \
	$dn_name $bitno \
	$dn_name $bitno

(( allbits += bitval ))[=

  FOR f-mask            =]
mask_list=${mask_list}[= f-mask =]$'\n'
mask_[= f-mask =]=$(( ${mask_[= f-mask =]:-0} + bitval ))[=
  ENDFOR f-mask         =][=

ENDFOR flag

=]
exec 1>&8 8>&-
fmt='\n/** l_flags bits marked as "%s" bits */
#define LDLM_FL_%-22s  0x%016XULL\n'
printf "$fmt" all_flags ALL_FLAGS_MASK $allbits

for f in $(echo "$mask_list" | sort -u)
do
    ucf=$(echo $f | tr a-z A-Z)_MASK
    eval v=\$mask_$f
    printf "$fmt" $f $ucf $v
done

cat $tmpfile
rm -f $tmpfile script.sh[=

;; The script is done.  Pop off the temporary output, handing
;; it to the shell for evaluation.  stdout becomes the output text
;;
(out-pop)
(shell ". script.sh")

=]

/** test for ldlm_lock flag bit set */
#define LDLM_TEST_FLAG(_l, _b)        (((_l)->l_flags & (_b)) != 0)

/** set a ldlm_lock flag bit */
#define LDLM_SET_FLAG(_l, _b)         (((_l)->l_flags |= (_b))

/** clear a ldlm_lock flag bit */
#define LDLM_CLEAR_FLAG(_l, _b)       (((_l)->l_flags &= ~(_b))

/** Mask of flags inherited from parent lock when doing intents. */
#define LDLM_INHERIT_FLAGS            LDLM_FL_INHERIT_MASK

/** Mask of Flags sent in AST lock_flags to map into the receiving lock. */
#define LDLM_AST_FLAGS                LDLM_FL_AST_MASK

/** @} subgroup */
/** @} group */
#ifdef WIRESHARK_COMPILE[=
FOR flag                       =][=
  (sprintf "\nstatic int hf_lustre_ldlm_fl_%-20s= -1;"
           (string-downcase! (get "f-name")) ) =][=
ENDFOR flag                    =]

const value_string lustre_ldlm_flags_vals[] = {[=

FOR flag                       =][=
   (define up-name (string-upcase! (string->c-name! (get "f-name"))))
   (sprintf "\n  {LDLM_FL_%-20s \"LDLM_FL_%s\"}," (string-append up-name ",")
            up-name)           =][=
ENDFOR flag                    =]
  { 0, NULL }
};
#endif /*  WIRESHARK_COMPILE */
[= #

// TEST CODE                    =][=
IF  (getenv "TESTING")          =][=

FOR flag (define len-list "")
         (define str-list "")
         (define temp-str "")
         (define header-name (out-name))
         (out-push-new (string-append (base-name) ".c"))

         (for-from 0) (for-by 1) =][=

  (if (exist? "f-name")
      (begin
         (set! temp-str (string-upcase! (get "f-name")))
         (set! len-list (string-append len-list (c-string
               (sprintf "%%%us" (- 20 (string-length temp-str))) ) "\n" ))
         (set! str-list (string-append str-list
               (c-string temp-str) "\n" ))
      )
      (begin
         (set! len-list (string-append len-list "NULL\n"))
         (set! str-list (string-append str-list "NULL\n"))
  )   )

  =][=

ENDFOR flag

\=]
#include "[=(. header-name)=]"
extern char ** args;

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

static char const * const fill_fmts[] = {
[=(out-push-new)=]
columns --spread=1 -I4 -S, --end=' };' <<_EOF_
[=(. len-list)=]
_EOF_

printf '\nstatic char const * const flag_names[] = {\n'
columns --spread=1 -I4 -S, --end=' };' <<_EOF_
[=(. str-list)=]
_EOF_
[= (shell (out-pop #t)) =]

static void
print_bits(unsigned long long v)
{
	static char const new_line[] = "\n";
	char const * space_fmt = new_line + 1;
	int ix = 0;
	int ct = 0;

	if ((v & ~LDLM_FL_ALL_FLAGS_MASK) != 0) {
		unsigned long long wrong = v & ~LDLM_FL_ALL_FLAGS_MASK;
		printf("undefined bits: 0x%016llX\n", wrong);
		v &= LDLM_FL_ALL_FLAGS_MASK;
	}

	for (ix = 0; v != 0ULL; ix++, v >>= 1) {
		if ((v & 0x1ULL) == 0)
			continue;

		printf(space_fmt, "");
		if ((++ct & 0x03) == 0)
			space_fmt = new_line;
		else
			space_fmt = fill_fmts[ix];
		fputs(flag_names[ix], stdout);
	}
	putc('\n', stdout);
}

void
cmd_ldlm_lock_flags(void)
{
	char * p = args[1];
	char * e;
	unsigned long long v;
	bool flip_val = false;

	if (p == NULL) {
		printf("no argument\n");
		return;
	}
	if (*p == '~') {
		flip_val = true;
		p++;
	}

	v = strtoull(p, &e, 0);
	if (*e != '\0') {
		errno = 0;
		v = strtoull(p, &e, 16);
		if ((errno != 0) || (*e != '\0')) {
			printf("invalid number: %s\n", p);
			return;
		}
	}
	if (flip_val) {
		v ^= ~0ULL;
		v &= LDLM_FL_ALL_FLAGS_MASK;
	}

	print_bits(v);
}

char * help_ldlm_lock_flags[] = {
	"ldlm_lock_flags",
	"flag bit names for ldlm_lock",
	"<numeric-value>",
	"The names of the bits that are set in the numeric value are printed.",
	NULL
};

#ifdef LDLM_FLAGS_PROGRAM
#include <ctype.h>

char ** args = NULL;

void
usage(int ex_code, char const * msg)
{
	int    ix = 3;
	FILE * fp = (ex_code == EXIT_SUCCESS) ? stdout : stderr;
	args = help_ldlm_lock_flags;
	if (msg != NULL)
		fprintf(fp, "%s usage error:  %s\n", args[0], msg);
	fprintf(fp, "%s - %s\n", args[0], args[1]);
	fprintf(fp, "Usage: %s %s\n", args[0], args[2]);
	for (;;) {
		char * txt = args[ix++];
		if (txt == NULL)
			break;
		fprintf(fp, "%s\n", txt);
	}
	exit(ex_code);
}

int
main(int argc, char ** argv)
{
	int ix = 1;
	char * av[3] = { argv[0], NULL, NULL };

	args = av;
	switch (argc) {
	case 0: case 1:
		usage(EXIT_FAILURE, "argument missing");

	case 2:
	{
		char * arg = argv[1];
		if (*arg != '-')
			break;
		switch (arg[1]) {
		case '-': if (arg[2] == 'h') break;
			/* FALLTHROUGH */
		case 'h': usage(EXIT_SUCCESS, NULL);
		default: break;
		}
		break;
	}
	}

	while (ix < argc) {
		av[1] = argv[ix++];
		cmd_ldlm_lock_flags();
	}
	return EXIT_SUCCESS;
}
#endif /* LDLM_FLAGS_PROGRAM */
[= (out-pop) =][=

ENDIF TESTING

 * Local Variables:
 * mode: C
 * c-file-style: "linux"
 * indent-tabs-mode: t
 * End:

\=]
#endif /* LDLM_ALL_FLAGS_MASK */
