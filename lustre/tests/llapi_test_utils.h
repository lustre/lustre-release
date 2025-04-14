/* SPDX License Identifier: GPL-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/signal.h>
#include <sys/wait.h>

#define ERROR(fmt, ...)							\
	fprintf(stderr, "%s: %s:%d: %s: " fmt "\n",			\
		program_invocation_short_name, __FILE__, __LINE__,	\
		__func__, ## __VA_ARGS__)

#define DIE(fmt, ...)							\
do {									\
	ERROR(fmt, ## __VA_ARGS__);					\
	exit(EXIT_FAILURE);						\
} while (0)

#define ASSERTF(cond, fmt, ...)						\
do {									\
	if (!(cond))							\
		DIE("assertion '%s' failed: "fmt, #cond, ## __VA_ARGS__);\
} while (0)

#define TEST_DESC_LEN	80
struct test_tbl_entry {
	void		(*tte_fn)(void);
	char		tte_desc[TEST_DESC_LEN];
	unsigned int	tte_num;
	bool		tte_skip;
};

#define TEST_REGISTER(num) \
	{ .tte_fn = &test ## num, .tte_desc = T ## num ## _DESC, .tte_num = num}
#define TEST_REGISTER_END { .tte_fn = NULL }

extern char fsmountdir[PATH_MAX];	/* Lustre mountpoint */

/* Run all tests declared in @tst_tbl until a NULL entry is found.
 * The tests are run by forking the process.  That way, if test segfaults,
 * the test program won't crash.
 * Tests may be skipped by setting .tte_skip = true.
 */
int run_tests(const char *lustre_dir, struct test_tbl_entry *tst_tbl);

/* 'str_tests' are the tests to be skipped/run, such as "1,3,4,.." */
void set_tests_to_skip(const char *str_tests, struct test_tbl_entry *tst_tbl);
void set_tests_to_run(const char *str_tests, struct test_tbl_entry *tst_tbl);
