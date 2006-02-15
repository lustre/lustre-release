#ifndef __LUSTRE_UTILS_PLATFORM_H
#define __LUSTRE_UTILS_PLATFORM_H

#ifdef HAVE_LIBREADLINE
# define READLINE_LIBRARY
# include <readline/readline.h>

/* completion_matches() is #if 0-ed out in modern glibc */
# ifdef __linux__
# ifndef completion_matches
#   define completion_matches rl_completion_matches
# endif
  extern void using_history(void);
  extern void stifle_history(int);
  extern void add_history(char *);
# elif __APPLE__
  typedef VFunction       rl_vintfunc_t;
  typedef VFunction       rl_voidfunc_t;
# else
# endif /* __linux__ */

#endif /* HAVE_LIBREADLINE */

#endif
