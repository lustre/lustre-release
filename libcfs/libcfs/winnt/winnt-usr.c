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

#ifndef __KERNEL__

#define _NTDDK_
#include <windows.h>
#include <libcfs/libcfs.h>

void sleep(int time)
{
    DWORD Time = 1000 * time;
    Sleep(Time);
}

void print_last_error(char* Prefix)
{
    LPVOID lpMsgBuf;

    FormatMessage( 
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        GetLastError(),
        0,
        (LPTSTR) &lpMsgBuf,
        0,
        NULL
        );

    printf("%s %s", Prefix, (LPTSTR) lpMsgBuf);

    LocalFree(lpMsgBuf);
}


int gethostname(char * name, int namelen)
{
    return 0;
}

int ioctl (
    int handle,
    int cmd,
    void *buffer
    )
{
    printf("hello, world\n");
    return 0;
}


/*
 * getopt structures & routines
 */


/* Data type for reentrant functions.  */
struct _getopt_data
{
  /* These have exactly the same meaning as the corresponding global
     variables, except that they are used for the reentrant
     versions of getopt.  */
  int optind;
  int opterr;
  int optopt;
  char *optarg;

  /* Internal members.  */

  /* True if the internal members have been initialized.  */
  int __initialized;

  /* The next char to be scanned in the option-element
     in which the last option character we returned was found.
     This allows us to pick up the scan where we left off.

     If this is zero, or a null string, it means resume the scan
     by advancing to the next ARGV-element.  */
  char *__nextchar;

  /* Describe how to deal with options that follow non-option ARGV-elements.

     If the caller did not specify anything,
     the default is REQUIRE_ORDER if the environment variable
     POSIXLY_CORRECT is defined, PERMUTE otherwise.

     REQUIRE_ORDER means don't recognize them as options;
     stop option processing when the first non-option is seen.
     This is what Unix does.
     This mode of operation is selected by either setting the environment
     variable POSIXLY_CORRECT, or using `+' as the first character
     of the list of option characters.

     PERMUTE is the default.  We permute the contents of ARGV as we
     scan, so that eventually all the non-options are at the end.
     This allows options to be given in any order, even with programs
     that were not written to expect this.

     RETURN_IN_ORDER is an option available to programs that were
     written to expect options and other ARGV-elements in any order
     and that care about the ordering of the two.  We describe each
     non-option ARGV-element as if it were the argument of an option
     with character code 1.  Using `-' as the first character of the
     list of option characters selects this mode of operation.

     The special argument `--' forces an end of option-scanning regardless
     of the value of `ordering'.  In the case of RETURN_IN_ORDER, only
     `--' can cause `getopt' to return -1 with `optind' != ARGC.  */

  enum
    {
      REQUIRE_ORDER, PERMUTE, RETURN_IN_ORDER
    } __ordering;

  /* If the POSIXLY_CORRECT environment variable is set.  */
  int __posixly_correct;


  /* Handle permutation of arguments.  */

  /* Describe the part of ARGV that contains non-options that have
     been skipped.  `first_nonopt' is the index in ARGV of the first
     of them; `last_nonopt' is the index after the last of them.  */

  int __first_nonopt;
  int __last_nonopt;
};

/* For communication from `getopt' to the caller.
   When `getopt' finds an option that takes an argument,
   the argument value is returned here.
   Also, when `ordering' is RETURN_IN_ORDER,
   each non-option ARGV-element is returned here.  */

char *optarg;

/* Index in ARGV of the next element to be scanned.
   This is used for communication to and from the caller
   and for communication between successive calls to `getopt'.

   On entry to `getopt', zero means this is the first call; initialize.

   When `getopt' returns -1, this is the index of the first of the
   non-option elements that the caller should itself scan.

   Otherwise, `optind' communicates from one call to the next
   how much of ARGV has been scanned so far.  */

/* 1003.2 says this must be 1 before any call.  */
int optind = 1;

/* Callers store zero here to inhibit the error message
   for unrecognized options.  */

int opterr = 1;

/* Set to an option character which was unrecognized.
   This must be initialized on some systems to avoid linking in the
   system's own getopt implementation.  */

int optopt = '?';

/* Keep a global copy of all internal members of getopt_data.  */

static struct _getopt_data getopt_data;


/* Initialize the internal data when the first call is made.  */

static const char *
_getopt_initialize (int argc, char *const *argv, const char *optstring,
		    struct _getopt_data *d)
{
  /* Start processing options with ARGV-element 1 (since ARGV-element 0
     is the program name); the sequence of previously skipped
     non-option ARGV-elements is empty.  */

  d->__first_nonopt = d->__last_nonopt = d->optind;

  d->__nextchar = NULL;

  d->__posixly_correct = 0;

  /* Determine how to handle the ordering of options and nonoptions.  */

  if (optstring[0] == '-')
    {
      d->__ordering = RETURN_IN_ORDER;
      ++optstring;
    }
  else if (optstring[0] == '+')
    {
      d->__ordering = REQUIRE_ORDER;
      ++optstring;
    }
  else if (d->__posixly_correct)
    d->__ordering = REQUIRE_ORDER;
  else
    d->__ordering = PERMUTE;

  return optstring;
}

/* Scan elements of ARGV (whose length is ARGC) for option characters
   given in OPTSTRING.

   If an element of ARGV starts with '-', and is not exactly "-" or "--",
   then it is an option element.  The characters of this element
   (aside from the initial '-') are option characters.  If `getopt'
   is called repeatedly, it returns successively each of the option characters
   from each of the option elements.

   If `getopt' finds another option character, it returns that character,
   updating `optind' and `nextchar' so that the next call to `getopt' can
   resume the scan with the following option character or ARGV-element.

   If there are no more option characters, `getopt' returns -1.
   Then `optind' is the index in ARGV of the first ARGV-element
   that is not an option.  (The ARGV-elements have been permuted
   so that those that are not options now come last.)

   OPTSTRING is a string containing the legitimate option characters.
   If an option character is seen that is not listed in OPTSTRING,
   return '?' after printing an error message.  If you set `opterr' to
   zero, the error message is suppressed but we still return '?'.

   If a char in OPTSTRING is followed by a colon, that means it wants an arg,
   so the following text in the same ARGV-element, or the text of the following
   ARGV-element, is returned in `optarg'.  Two colons mean an option that
   wants an optional arg; if there is text in the current ARGV-element,
   it is returned in `optarg', otherwise `optarg' is set to zero.

   If OPTSTRING starts with `-' or `+', it requests different methods of
   handling the non-option ARGV-elements.
   See the comments about RETURN_IN_ORDER and REQUIRE_ORDER, above.

   Long-named options begin with `--' instead of `-'.
   Their names may be abbreviated as long as the abbreviation is unique
   or is an exact match for some defined option.  If they have an
   argument, it follows the option name in the same ARGV-element, separated
   from the option name by a `=', or else the in next ARGV-element.
   When `getopt' finds a long-named option, it returns 0 if that option's
   `flag' field is nonzero, the value of the option's `val' field
   if the `flag' field is zero.

   The elements of ARGV aren't really const, because we permute them.
   But we pretend they're const in the prototype to be compatible
   with other systems.

   LONGOPTS is a vector of `struct option' terminated by an
   element containing a name which is zero.

   LONGIND returns the index in LONGOPT of the long-named option found.
   It is only valid when a long-named option has been found by the most
   recent call.

   If LONG_ONLY is nonzero, '-' as well as '--' can introduce
   long-named options.  */

/* Exchange two adjacent subsequences of ARGV.
   One subsequence is elements [first_nonopt,last_nonopt)
   which contains all the non-options that have been skipped so far.
   The other is elements [last_nonopt,optind), which contains all
   the options processed since those non-options were skipped.

   `first_nonopt' and `last_nonopt' are relocated so that they describe
   the new indices of the non-options in ARGV after they are moved.  */

#define SWAP_FLAGS(ch1, ch2)

static void
exchange (char **argv, struct _getopt_data *d)
{
  int bottom = d->__first_nonopt;
  int middle = d->__last_nonopt;
  int top = d->optind;
  char *tem;

  /* Exchange the shorter segment with the far end of the longer segment.
     That puts the shorter segment into the right place.
     It leaves the longer segment in the right place overall,
     but it consists of two parts that need to be swapped next.  */

  while (top > middle && middle > bottom)
    {
      if (top - middle > middle - bottom)
	{
	  /* Bottom segment is the short one.  */
	  int len = middle - bottom;
	  register int i;

	  /* Swap it with the top part of the top segment.  */
	  for (i = 0; i < len; i++)
	    {
	      tem = argv[bottom + i];
	      argv[bottom + i] = argv[top - (middle - bottom) + i];
	      argv[top - (middle - bottom) + i] = tem;
	      SWAP_FLAGS (bottom + i, top - (middle - bottom) + i);
	    }
	  /* Exclude the moved bottom segment from further swapping.  */
	  top -= len;
	}
      else
	{
	  /* Top segment is the short one.  */
	  int len = top - middle;
	  register int i;

	  /* Swap it with the bottom part of the bottom segment.  */
	  for (i = 0; i < len; i++)
	    {
	      tem = argv[bottom + i];
	      argv[bottom + i] = argv[middle + i];
	      argv[middle + i] = tem;
	      SWAP_FLAGS (bottom + i, middle + i);
	    }
	  /* Exclude the moved top segment from further swapping.  */
	  bottom += len;
	}
    }

  /* Update records for the slots the non-options now occupy.  */

  d->__first_nonopt += (d->optind - d->__last_nonopt);
  d->__last_nonopt = d->optind;
}

int
_getopt_internal_r (int argc, char *const *argv, const char *optstring,
		    const struct option *longopts, int *longind,
		    int long_only, struct _getopt_data *d)
{
  int print_errors = d->opterr;
  if (optstring[0] == ':')
    print_errors = 0;

  if (argc < 1)
    return -1;

  d->optarg = NULL;

  if (d->optind == 0 || !d->__initialized)
    {
      if (d->optind == 0)
	d->optind = 1;	/* Don't scan ARGV[0], the program name.  */
      optstring = _getopt_initialize (argc, argv, optstring, d);
      d->__initialized = 1;
    }

  /* Test whether ARGV[optind] points to a non-option argument.
     Either it does not have option syntax, or there is an environment flag
     from the shell indicating it is not an option.  The later information
     is only used when the used in the GNU libc.  */

# define NONOPTION_P (argv[d->optind][0] != '-' || argv[d->optind][1] == '\0')

  if (d->__nextchar == NULL || *d->__nextchar == '\0')
    {
      /* Advance to the next ARGV-element.  */

      /* Give FIRST_NONOPT & LAST_NONOPT rational values if OPTIND has been
	 moved back by the user (who may also have changed the arguments).  */
      if (d->__last_nonopt > d->optind)
	d->__last_nonopt = d->optind;
      if (d->__first_nonopt > d->optind)
	d->__first_nonopt = d->optind;

      if (d->__ordering == PERMUTE)
	{
	  /* If we have just processed some options following some non-options,
	     exchange them so that the options come first.  */

	  if (d->__first_nonopt != d->__last_nonopt
	      && d->__last_nonopt != d->optind)
	    exchange ((char **) argv, d);
	  else if (d->__last_nonopt != d->optind)
	    d->__first_nonopt = d->optind;

	  /* Skip any additional non-options
	     and extend the range of non-options previously skipped.  */

	  while (d->optind < argc && NONOPTION_P)
	    d->optind++;
	  d->__last_nonopt = d->optind;
	}

      /* The special ARGV-element `--' means premature end of options.
	 Skip it like a null option,
	 then exchange with previous non-options as if it were an option,
	 then skip everything else like a non-option.  */

      if (d->optind != argc && !strcmp (argv[d->optind], "--"))
	{
	  d->optind++;

	  if (d->__first_nonopt != d->__last_nonopt
	      && d->__last_nonopt != d->optind)
	    exchange ((char **) argv, d);
	  else if (d->__first_nonopt == d->__last_nonopt)
	    d->__first_nonopt = d->optind;
	  d->__last_nonopt = argc;

	  d->optind = argc;
	}

      /* If we have done all the ARGV-elements, stop the scan
	 and back over any non-options that we skipped and permuted.  */

      if (d->optind == argc)
	{
	  /* Set the next-arg-index to point at the non-options
	     that we previously skipped, so the caller will digest them.  */
	  if (d->__first_nonopt != d->__last_nonopt)
	    d->optind = d->__first_nonopt;
	  return -1;
	}

      /* If we have come to a non-option and did not permute it,
	 either stop the scan or describe it to the caller and pass it by.  */

      if (NONOPTION_P)
	{
	  if (d->__ordering == REQUIRE_ORDER)
	    return -1;
	  d->optarg = argv[d->optind++];
	  return 1;
	}

      /* We have found another option-ARGV-element.
	 Skip the initial punctuation.  */

      d->__nextchar = (argv[d->optind] + 1
		  + (longopts != NULL && argv[d->optind][1] == '-'));
    }

  /* Decode the current option-ARGV-element.  */

  /* Check whether the ARGV-element is a long option.

     If long_only and the ARGV-element has the form "-f", where f is
     a valid short option, don't consider it an abbreviated form of
     a long option that starts with f.  Otherwise there would be no
     way to give the -f short option.

     On the other hand, if there's a long option "fubar" and
     the ARGV-element is "-fu", do consider that an abbreviation of
     the long option, just like "--fu", and not "-f" with arg "u".

     This distinction seems to be the most useful approach.  */

  if (longopts != NULL
      && (argv[d->optind][1] == '-'
	  || (long_only && (argv[d->optind][2]
			    || !strchr (optstring, argv[d->optind][1])))))
    {
      char *nameend;
      const struct option *p;
      const struct option *pfound = NULL;
      int exact = 0;
      int ambig = 0;
      int indfound = -1;
      int option_index;

      for (nameend = d->__nextchar; *nameend && *nameend != '='; nameend++)
	/* Do nothing.  */ ;

      /* Test all long options for either exact match
	 or abbreviated matches.  */
      for (p = longopts, option_index = 0; p->name; p++, option_index++)
	if (!strncmp (p->name, d->__nextchar, nameend - d->__nextchar))
	  {
	    if ((unsigned int) (nameend - d->__nextchar)
		== (unsigned int) strlen (p->name))
	      {
		/* Exact match found.  */
		pfound = p;
		indfound = option_index;
		exact = 1;
		break;
	      }
	    else if (pfound == NULL)
	      {
		/* First nonexact match found.  */
		pfound = p;
		indfound = option_index;
	      }
	    else if (long_only
		     || pfound->has_arg != p->has_arg
		     || pfound->flag != p->flag
		     || pfound->val != p->val)
	      /* Second or later nonexact match found.  */
	      ambig = 1;
	  }

      if (ambig && !exact)
	{
	  if (print_errors)
	    {
	      fprintf (stderr, "%s: option '%s' is ambiguous\n",
		       argv[0], argv[d->optind]);
	    }
	  d->__nextchar += strlen (d->__nextchar);
	  d->optind++;
	  d->optopt = 0;
	  return '?';
	}

      if (pfound != NULL)
	{
	  option_index = indfound;
	  d->optind++;
	  if (*nameend)
	    {
	      /* Don't test has_arg with >, because some C compilers don't
		 allow it to be used on enums.  */
	      if (pfound->has_arg)
		d->optarg = nameend + 1;
	      else
		{
		  if (print_errors)
		    {

		      if (argv[d->optind - 1][1] == '-')
			{
			  /* --option */
			  fprintf (stderr, "%s: option '--%s' doesn't allow an argument\n",
				   argv[0], pfound->name);
			}
		      else
			{
			  /* +option or -option */
			  fprintf (stderr, "%s: option '%c%s' doesn't allow an argument\n",
				   argv[0], argv[d->optind - 1][0],
				   pfound->name);
			}

		    }

		  d->__nextchar += strlen (d->__nextchar);

		  d->optopt = pfound->val;
		  return '?';
		}
	    }
	  else if (pfound->has_arg == 1)
	    {
	      if (d->optind < argc)
		d->optarg = argv[d->optind++];
	      else
		{
		  if (print_errors)
		    {
		      fprintf (stderr,
			       "%s: option '%s' requires an argument\n",
			       argv[0], argv[d->optind - 1]);
		    }
		  d->__nextchar += strlen (d->__nextchar);
		  d->optopt = pfound->val;
		  return optstring[0] == ':' ? ':' : '?';
		}
	    }
	  d->__nextchar += strlen (d->__nextchar);
	  if (longind != NULL)
	    *longind = option_index;
	  if (pfound->flag)
	    {
	      *(pfound->flag) = pfound->val;
	      return 0;
	    }
	  return pfound->val;
	}

      /* Can't find it as a long option.  If this is not getopt_long_only,
	 or the option starts with '--' or is not a valid short
	 option, then it's an error.
	 Otherwise interpret it as a short option.  */
      if (!long_only || argv[d->optind][1] == '-'
	  || strchr (optstring, *d->__nextchar) == NULL)
	{
	  if (print_errors)
	    {
	      if (argv[d->optind][1] == '-')
		{
		  /* --option */

		  fprintf (stderr, "%s: unrecognized option '--%s'\n",
			   argv[0], d->__nextchar);
		}
	      else
		{
		  /* +option or -option */
		  fprintf (stderr, "%s: unrecognized option '%c%s'\n",
			   argv[0], argv[d->optind][0], d->__nextchar);
		}


	    }
	  d->__nextchar = (char *) "";
	  d->optind++;
	  d->optopt = 0;
	  return '?';
	}
    }

  /* Look at and handle the next short option-character.  */

  {
    char c = *d->__nextchar++;
    char *temp = strchr (optstring, c);

    /* Increment `optind' when we start to process its last character.  */
    if (*d->__nextchar == '\0')
      ++d->optind;

    if (temp == NULL || c == ':')
      {
	if (print_errors)
	  {
	    fprintf (stderr, "%s: invalid option -- '%c'\n", argv[0], c);
	  }
	d->optopt = c;
	return '?';
      }
    /* Convenience. Treat POSIX -W foo same as long option --foo */
    if (temp[0] == 'W' && temp[1] == ';')
      {
	char *nameend;
	const struct option *p;
	const struct option *pfound = NULL;
	int exact = 0;
	int ambig = 0;
	int indfound = 0;
	int option_index;

	/* This is an option that requires an argument.  */
	if (*d->__nextchar != '\0')
	  {
	    d->optarg = d->__nextchar;
	    /* If we end this ARGV-element by taking the rest as an arg,
	       we must advance to the next element now.  */
	    d->optind++;
	  }
	else if (d->optind == argc)
	  {
	    if (print_errors)
	      {
		fprintf (stderr,
			 "%s: option requires an argument -- '%c'\n",
			 argv[0], c);
	      }
	    d->optopt = c;
	    if (optstring[0] == ':')
	      c = ':';
	    else
	      c = '?';
	    return c;
	  }
	else
	  /* We already incremented `d->optind' once;
	     increment it again when taking next ARGV-elt as argument.  */
	  d->optarg = argv[d->optind++];

	/* optarg is now the argument, see if it's in the
	   table of longopts.  */

	for (d->__nextchar = nameend = d->optarg; *nameend && *nameend != '=';
	     nameend++)
	  /* Do nothing.  */ ;

	/* Test all long options for either exact match
	   or abbreviated matches.  */
	for (p = longopts, option_index = 0; p->name; p++, option_index++)
	  if (!strncmp (p->name, d->__nextchar, nameend - d->__nextchar))
	    {
	      if ((unsigned int) (nameend - d->__nextchar) == strlen (p->name))
		{
		  /* Exact match found.  */
		  pfound = p;
		  indfound = option_index;
		  exact = 1;
		  break;
		}
	      else if (pfound == NULL)
		{
		  /* First nonexact match found.  */
		  pfound = p;
		  indfound = option_index;
		}
	      else
		/* Second or later nonexact match found.  */
		ambig = 1;
	    }
	if (ambig && !exact)
	  {
	    if (print_errors)
	      {
		fprintf (stderr, "%s: option '-W %s' is ambiguous\n",
			 argv[0], argv[d->optind]);
	      }
	    d->__nextchar += strlen (d->__nextchar);
	    d->optind++;
	    return '?';
	  }
	if (pfound != NULL)
	  {
	    option_index = indfound;
	    if (*nameend)
	      {
		/* Don't test has_arg with >, because some C compilers don't
		   allow it to be used on enums.  */
		if (pfound->has_arg)
		  d->optarg = nameend + 1;
		else
		  {
		    if (print_errors)
		      {
			fprintf (stderr, "\
%s: option '-W %s' doesn't allow an argument\n",
				 argv[0], pfound->name);
		      }

		    d->__nextchar += strlen (d->__nextchar);
		    return '?';
		  }
	      }
	    else if (pfound->has_arg == 1)
	      {
		if (d->optind < argc)
		  d->optarg = argv[d->optind++];
		else
		  {
		    if (print_errors)
		      {

			fprintf (stderr,
				 "%s: option '%s' requires an argument\n",
				 argv[0], argv[d->optind - 1]);
		      }
		    d->__nextchar += strlen (d->__nextchar);
		    return optstring[0] == ':' ? ':' : '?';
		  }
	      }
	    d->__nextchar += strlen (d->__nextchar);
	    if (longind != NULL)
	      *longind = option_index;
	    if (pfound->flag)
	      {
		*(pfound->flag) = pfound->val;
		return 0;
	      }
	    return pfound->val;
	  }
	  d->__nextchar = NULL;
	  return 'W';	/* Let the application handle it.   */
      }
    if (temp[1] == ':')
      {
	if (temp[2] == ':')
	  {
	    /* This is an option that accepts an argument optionally.  */
	    if (*d->__nextchar != '\0')
	      {
		d->optarg = d->__nextchar;
		d->optind++;
	      }
	    else
	      d->optarg = NULL;
	    d->__nextchar = NULL;
	  }
	else
	  {
	    /* This is an option that requires an argument.  */
	    if (*d->__nextchar != '\0')
	      {
		d->optarg = d->__nextchar;
		/* If we end this ARGV-element by taking the rest as an arg,
		   we must advance to the next element now.  */
		d->optind++;
	      }
	    else if (d->optind == argc)
	      {
		if (print_errors)
		  {
		    fprintf (stderr,
			     "%s: option requires an argument -- '%c'\n",
			     argv[0], c);
		  }
		d->optopt = c;
		if (optstring[0] == ':')
		  c = ':';
		else
		  c = '?';
	      }
	    else
	      /* We already incremented `optind' once;
		 increment it again when taking next ARGV-elt as argument.  */
	      d->optarg = argv[d->optind++];
	    d->__nextchar = NULL;
	  }
      }
    return c;
  }
}

int
_getopt_internal (int argc, char *const *argv, const char *optstring,
		  const struct option *longopts, int *longind, int long_only)
{
  int result;

  getopt_data.optind = optind;
  getopt_data.opterr = opterr;

  result = _getopt_internal_r (argc, argv, optstring, longopts,
			       longind, long_only, &getopt_data);

  optind = getopt_data.optind;
  optarg = getopt_data.optarg;
  optopt = getopt_data.optopt;

  return result;
}

int
getopt_long (int argc, char *const *argv, const char *options,
	     const struct option *long_options, int *opt_index)
{
  return _getopt_internal (argc, argv, options, long_options, opt_index, 0);
}

#define TOLOWER(c) tolower(c)
typedef unsigned chartype;

char *
strcasestr (phaystack, pneedle)
     const char *phaystack;
     const char *pneedle;
{
  register const unsigned char *haystack, *needle;
  register chartype b, c;


  haystack = (const unsigned char *) phaystack;
  needle = (const unsigned char *) pneedle;

  b = TOLOWER (*needle);
  if (b != '\0')
    {
      haystack--;				/* possible ANSI violation */
      do
	{
	  c = *++haystack;
	  if (c == '\0')
	    goto ret0;
	}
      while (TOLOWER (c) != (int) b);

      c = TOLOWER (*++needle);
      if (c == '\0')
	goto foundneedle;
      ++needle;
      goto jin;

      for (;;)
        {
          register chartype a;
	  register const unsigned char *rhaystack, *rneedle;

	  do
	    {
	      a = *++haystack;
	      if (a == '\0')
		goto ret0;
	      if (TOLOWER (a) == (int) b)
		break;
	      a = *++haystack;
	      if (a == '\0')
		goto ret0;
shloop:
	      ;
	    }
          while (TOLOWER (a) != (int) b);

jin:	  a = *++haystack;
	  if (a == '\0')
	    goto ret0;

	  if (TOLOWER (a) != (int) c)
	    goto shloop;

	  rhaystack = haystack-- + 1;
	  rneedle = needle;
	  a = TOLOWER (*rneedle);

	  if (TOLOWER (*rhaystack) == (int) a)
	    do
	      {
		if (a == '\0')
		  goto foundneedle;
		++rhaystack;
		a = TOLOWER (*++needle);
		if (TOLOWER (*rhaystack) != (int) a)
		  break;
		if (a == '\0')
		  goto foundneedle;
		++rhaystack;
		a = TOLOWER (*++needle);
	      }
	    while (TOLOWER (*rhaystack) == (int) a);

	  needle = rneedle;		/* took the register-poor approach */

	  if (a == '\0')
	    break;
        }
    }
foundneedle:
  return (char*) haystack;
ret0:
  return 0;
}

int glob (const char * __pattern, int __flags,
		 int (*__errfunc) (const char *, int),
		 glob_t * __pglob) {

    cfs_enter_debugger();
    return 0;
}

void globfree(glob_t *__pglog)
{
}

int setenv(const char *envname, const char *envval, int overwrite)
{
    int rc = 0;

    if (GetEnvironmentVariable(envname, NULL, 0) == 0) {
        overwrite = TRUE;
    }

    if (overwrite) {
        rc = SetEnvironmentVariable(envname, envval);
        rc = rc > 0 ? 0 : -1;
    } else {
        rc = -1;
    }
    return rc;
}

int uname(struct utsname *uts)
{
    OSVERSIONINFO   OsVerInfo;

    /* query computer name */
    memset(uts, 0, sizeof(struct utsname));
    strcpy(uts->sysname, "winnt");
    strcpy(uts->release, "winnt");

    /* query system version */
    OsVerInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&OsVerInfo);

    if (OsVerInfo.dwPlatformId == VER_PLATFORM_WIN32_NT) {
        if (OsVerInfo.dwMajorVersion == 6 &&
            OsVerInfo.dwBuildNumber > 3790) {
            strcpy(uts->release, "Vista");
        }
    } else {
        /* we got errors */
        return -1;
    }

    sprintf(uts->version, "%d.%d", OsVerInfo.dwMajorVersion,
            OsVerInfo.dwMinorVersion);
    return 0;
}

struct passwd * getpwuid(uid_t uid)
{
    static struct passwd generic_passwd = {0, "root"};
    return &generic_passwd;
}

void* pgalloc(size_t factor)
{
    LPVOID page;

    page = VirtualAlloc(NULL, CFS_PAGE_SIZE << factor,
                        MEM_COMMIT, PAGE_READWRITE);
    return page;
}

void  pgfree(void * page)
{
    _ASSERT(page != NULL);
    VirtualFree(page, 0, MEM_RELEASE);
}

#endif /* !__KERNEL__ */
