#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include "callvpe.h"

enum {
	NSEC_PER_SEC = 1000000000L,
};

static int iabf_debug = false;
static const char iabf_delim[] = "---";
static __thread pid_t iabf_tid;

#define DEBUG(fmt, args...)						\
	do {								\
		if (iabf_debug)						\
			fprintf(stderr, "DEBUG [%d] %s:%d: "fmt, iabf_tid, __func__, __LINE__, ##args); \
	} while (0)

#define DEBUG_B(x) DEBUG("%s = %s\n", #x, (x) ? "true" : "false")
#define DEBUG_D(x) DEBUG("%s = %"PRIdMAX"\n", #x, (intmax_t)(x))
#define DEBUG_P(x) DEBUG("%s = %p\n", #x, (x))
#define DEBUG_S(x) DEBUG("%s = '%s'\n", #x, (x))
#define DEBUG_U(x) DEBUG("%s = %"PRIuMAX"\n", #x, (uintmax_t)(x))
#define DEBUG_X(x) DEBUG("%s = %"PRIxMAX"\n", #x, (uintmax_t)(x))

#define ERROR(fmt, args...)						\
	fprintf(stderr, "%s: "fmt, program_invocation_short_name, ##args)

#define FATAL(fmt, args...)			    \
	do {					\
		ERROR("fatal: "fmt, ##args);	    \
		exit(EXIT_FAILURE);		    \
	} while (0)

#define xstrerror(e) strerror(abs(e))

static struct timespec
timespec_sub(struct timespec a, struct timespec b)
{
	struct timespec r = {
		.tv_sec = a.tv_sec - b.tv_sec,
		.tv_nsec = a.tv_nsec - b.tv_nsec,
	};

	while (r.tv_nsec >= NSEC_PER_SEC) {
		r.tv_sec++;
		r.tv_nsec -= NSEC_PER_SEC;
	}

	while (r.tv_nsec < 0) {
		r.tv_sec--;
		r.tv_nsec += NSEC_PER_SEC;
	}

	return r;
}

static struct timespec
timespec_from_ns(long ns)
{
	return (struct timespec) {
		.tv_sec = ns / NSEC_PER_SEC,
		.tv_nsec = ns % NSEC_PER_SEC,
	};
}

static long timespec_to_ns(struct timespec tv)
{
	return tv.tv_sec * NSEC_PER_SEC + tv.tv_nsec;
}

struct iabf_control {
	char **ic_init;
	char **ic_fini;
	cpu_set_t *ic_affinity;
	long ic_delay_begin_ns;
	long ic_delay_end_ns;
	long ic_delay_step_ns;
	long ic_step_count;
	long ic_autotune_count;

	pthread_barrier_t ic_barrier[2];
	int ic_should_stop;
};

struct iabf_task {
	struct iabf_control *it_control;
	const char *it_name;
	pthread_t it_thread;
	struct timespec it_delay;
	struct timespec it_elapsed;
	char **it_argv;
};

static long iabf_getenvl(const char *name, long def)
{
	const char *s = getenv(name);
	return s != NULL ? atol(s) : def;
}

static void iabf_barrier_wait(struct iabf_control *ic, int which)
{
	int rc;

	assert(PTHREAD_BARRIER_SERIAL_THREAD == -1);

	rc = pthread_barrier_wait(&ic->ic_barrier[which]);
	if (rc > 0)
		FATAL("cannot wait on barrier: %s\n", xstrerror(rc));
}

static void *iabf_task_thread(void *data)
{
	struct iabf_task *it = data;
	struct iabf_control *ic = it->it_control;
	int rc;

	iabf_tid = syscall(SYS_gettid);

	assert(PTHREAD_BARRIER_SERIAL_THREAD == -1);

	while (1) {
		struct timespec ts[2];
		pid_t pid, pid2;
		int status;

		iabf_barrier_wait(ic, 0);

		DEBUG_D(ic->ic_should_stop);
		if (ic->ic_should_stop)
			break;

		rc = clock_nanosleep(CLOCK_MONOTONIC, 0, &it->it_delay, NULL);
		if (rc != 0)
			FATAL("%s: cannot sleep: %s\n", it->it_name, xstrerror(rc));

		rc = clock_gettime(CLOCK_MONOTONIC, &ts[0]);
		if (rc != 0)
			FATAL("%s: cannot get time: %s\n", it->it_name, xstrerror(errno));

		pid = fork();
		if (pid < 0)
			FATAL("%s: cannot fork: %s\n", it->it_name, strerror(errno));

		if (pid == 0) {
			execvpe(it->it_argv[0], it->it_argv, environ);
			_exit(127);
		}

		pid2 = waitpid(pid, &status, 0);
		if (pid2 < 0)
			FATAL("%s: cannot wait for pid %d: %s\n", it->it_name, (int)pid, strerror(errno));

		rc = clock_gettime(CLOCK_MONOTONIC, &ts[1]);
		if (rc != 0)
			FATAL("%s: cannot get time: %s\n", it->it_name, xstrerror(errno));

		it->it_elapsed = timespec_sub(ts[1], ts[0]);

		assert(pid == pid2);

		DEBUG("%s: cmd = '%s', pid = %d, status = %d, elapsed_ns = %ld\n",
		      it->it_name, it->it_argv[0], pid, status, timespec_to_ns(it->it_elapsed));

		if (WIFEXITED(status) && WEXITSTATUS(status) == 127)
			FATAL("%s: command '%s' (pid %d) exited with status 127\n", it->it_name, it->it_argv[0], pid);

		iabf_barrier_wait(ic, 1);
	}

	return NULL;
}

/* Run I, A+B, F once. Task threads must already be started.
 *
 * If delay_ns < 0 then
 *     delay exec of A by labs(delay_ns) nsec
 * else
 *     delay exec of B by labs(delay_ns) nsec.
 */
static int iabf_step(struct iabf_control *ic,
		     struct iabf_task it[2],
		     long delay_ns)
{
	int rc;

	if (ic->ic_init != NULL && ic->ic_init[0] != NULL) {
		rc = callvpe(ic->ic_init[0], ic->ic_init, environ);
		DEBUG_D(rc); /* waitpid status */
		if (rc != 0)
			FATAL("initializer '%s' terminated with status %d\n", ic->ic_init[0], rc);
	}

	DEBUG_D(delay_ns);

	if (delay_ns < 0) {
		it[0].it_delay = timespec_from_ns(labs(delay_ns));
		it[1].it_delay = timespec_from_ns(0);
	} else {
		it[0].it_delay = timespec_from_ns(0);
		it[1].it_delay = timespec_from_ns(labs(delay_ns));
	}

	iabf_barrier_wait(ic, 0);

	/* A+B run here. */

	iabf_barrier_wait(ic, 1);

	if (ic->ic_fini != NULL && ic->ic_fini[0] != NULL) {
		rc = callvpe(ic->ic_fini[0], ic->ic_fini, environ);
		DEBUG_D(rc); /* waitpid status */
		if (rc != 0)
			FATAL("finalizer '%s' terminated with status %d\n", ic->ic_fini[0], rc);
	}

	return 0;
}

/* Run (I, A+B, F) step $IABF_AUTOTUNE_COUNT times. Task threads must
 * already be started. Get the average elapsed times for A and B.  We
 * want to choose delay_begin and delay_end to try to arrange all
 * possible overlaps given the expected elapsed times of A and B.
 *
 *     AAAAAAAAAA	delay(A) is approx elapsed(B)
 * BBBBB		delay(B) == 0
 *
 * AAAAAAAAAA		delay(A) == 0
 * BBBBB		delay(B) == 0
 *
 * AAAAAAAAAA		delay(A) == 0
 *          BBBBB	delay(B) is approx elapsed(A)
 *
 * Note that to delay task A we use a negative delay_ns.
 */
static int iabf_autotune(struct iabf_control *ic,
			 struct iabf_task it[2])
{
	long elapsed_ns[2] = { 0, 0 };
	long i, j;

	DEBUG("begin autotune\n");

	assert(ic->ic_autotune_count >= 0);

	if (ic->ic_autotune_count == 0)
		return 0;

	for (i = 0; i < ic->ic_autotune_count; i++) {
		iabf_step(ic, it, 0);

		for (j = 0; j < 2; j++)
			elapsed_ns[j] += timespec_to_ns(it[j].it_elapsed);
	}

	elapsed_ns[0] /= ic->ic_autotune_count;
	elapsed_ns[1] /= ic->ic_autotune_count;

	DEBUG_D(elapsed_ns[0]);
	DEBUG_D(elapsed_ns[1]);

	assert(0 <= elapsed_ns[0]);
	assert(0 <= elapsed_ns[1]);

	/* TODO Apply a multiplier to endpoints. */

	if (ic->ic_delay_begin_ns == LONG_MIN)
		ic->ic_delay_begin_ns = -elapsed_ns[1];

	if (ic->ic_delay_end_ns == LONG_MAX)
		ic->ic_delay_end_ns = +elapsed_ns[0];

	assert(ic->ic_delay_begin_ns <= ic->ic_delay_end_ns);
	assert(0 <= ic->ic_step_count);

	if (ic->ic_step_count != 0)
		ic->ic_delay_step_ns = (ic->ic_delay_end_ns - ic->ic_delay_begin_ns) / ic->ic_step_count;

	if (ic->ic_delay_step_ns == 0)
		ic->ic_delay_step_ns = 1; /* Or just leave it 0? */

	DEBUG("end autotune\n");

	return 0;
}

/* Start A and B threads, autotune delay parameters if needed, run
 * iabf_step() however many times. */
static int iabf(struct iabf_control *ic, char **a, char **b)
{
	struct iabf_task it[2] = {
		[0] = {
			.it_control = ic,
			.it_name = "A",
			.it_argv = a,
		},
		[1] = {
			.it_control = ic,
			.it_name = "B",
			.it_argv = b,
		},
	};
	pthread_attr_t attr_, *attr = NULL;
	long i;
	int rc;

	rc = pthread_attr_init(&attr_);
	if (rc != 0)
		FATAL("cannot initialize thread attributes: %s\n", xstrerror(rc));

	attr = &attr_;

	for (i = 0; i < 2; i++) {
		rc = pthread_barrier_init(&ic->ic_barrier[i], NULL, 3);
		if (rc != 0)
			FATAL("cannot initialize barrier: %s\n", xstrerror(rc));
	}

	if (ic->ic_affinity != NULL) {
		rc = pthread_setaffinity_np(pthread_self(), sizeof(ic->ic_affinity[2]), &ic->ic_affinity[2]);
		if (rc != 0)
			FATAL("cannot set CPU affinity : %s\n", xstrerror(rc));
	}

	for (i = 0; i < 2; i++) {
		if (ic->ic_affinity != NULL) {
			rc = pthread_attr_setaffinity_np(attr, sizeof(ic->ic_affinity[i]), &ic->ic_affinity[i]);
			if (rc != 0)
				FATAL("cannot set thread attr CPU affinity : %s\n", xstrerror(rc));
		}

		rc = pthread_create(&it[i].it_thread,
				    attr,
				    iabf_task_thread,
				    &it[i]);
		if (rc != 0)
			FATAL("cannot create thread: %s\n", xstrerror(rc));
	}

	if (ic->ic_delay_begin_ns == LONG_MIN ||
	    ic->ic_delay_end_ns == LONG_MAX ||
	    ic->ic_delay_step_ns == 0)
		iabf_autotune(ic, it);

	DEBUG_D(ic->ic_delay_begin_ns);
	DEBUG_D(ic->ic_delay_end_ns);
	DEBUG_D(ic->ic_delay_step_ns);

	long delay_ns;
	for (delay_ns = ic->ic_delay_begin_ns;
	     delay_ns < ic->ic_delay_end_ns;
	     delay_ns += ic->ic_delay_step_ns)
		iabf_step(ic, it, delay_ns);

	ic->ic_should_stop = 1;
	DEBUG_D(ic->ic_should_stop);

	iabf_barrier_wait(ic, 0);

	for (i = 0; i < 2; i++) {
		rc = pthread_join(it[i].it_thread, NULL);
		if (rc != 0)
			FATAL("cannot join thread %s: %s\n", it[i].it_name, xstrerror(rc));
	}

	for (i = 0; i < 2; i++) {
		rc = pthread_barrier_destroy(&ic->ic_barrier[i]);
		if (rc != 0)
			FATAL("cannot destroy barrier: %s\n", xstrerror(rc));
	}

	if (attr != NULL)
		pthread_attr_destroy(attr);

	return 0;
}

/* strsep() for argvs */
static char **arg_sep(char ***pargs, const char *delim)
{
	char **begin, **end;

	begin = *pargs;
	if (begin == NULL)
		return NULL;

	/* Find the end of the token.  */
	/* end = begin + strcspn (begin, delim); */

	for (end = begin; *end != NULL && strcmp(*end, delim) != 0; end++)
		;

	if (*end != NULL) {
		/* Terminate the token and set *STRINGP past NUL character. */
		*end++ = NULL;
		*pargs = end;
	} else {
		/* No more delimiters; this is the last token. */
		*pargs = NULL;
	}

	return begin;
}

static cpu_set_t *iabf_affinity(const char *str)
{
	cpu_set_t *cpu_sets = NULL;
	char *str1 = NULL;
	char *p;
	char *q;
	char *r;
	int i;

	if (str == NULL)
		return NULL;

	cpu_sets = calloc(3, sizeof(cpu_sets[0]));
	p = str1 = strdup(str);

	for (i = 0; i < 3; i++) {
		CPU_ZERO(&cpu_sets[i]);

		q = strsep(&p, " ");
		if (q == NULL)
			FATAL("invalid affinity '%s'\n", str);

		while ((r = strsep(&q, ",")) != NULL)
			CPU_SET(atoi(r), &cpu_sets[i]);
	}

	if (p != NULL)
		FATAL("invalid affinity '%s'\n", str);

	free(str1);

	return cpu_sets;
}

int main(int argc, char **argv)
{
	struct iabf_control ic = {
		.ic_should_stop = 0,
	};
	char **args = argv + 1;
	char **a;
	char **b;

	iabf_tid = syscall(SYS_gettid);

	iabf_debug = atoi(getenv("IABF_DEBUG") ?: "0");

	ic.ic_init = arg_sep(&args, iabf_delim);
	a = arg_sep(&args, iabf_delim);
	b = arg_sep(&args, iabf_delim);
	ic.ic_fini = arg_sep(&args, iabf_delim);

	if (ic.ic_init == NULL ||
	    a == NULL ||
	    b == NULL ||
	    ic.ic_fini == NULL)
		FATAL("missing '%s' in argv\n", iabf_delim);

	int i;
	for (i = 0; ic.ic_init[i] != NULL; i++)
		DEBUG_S(ic.ic_init[i]);

	for (i = 0; a[i] != NULL; i++)
		DEBUG_S(a[i]);

	for (i = 0; b[i] != NULL; i++)
		DEBUG_S(b[i]);

	for (i = 0; ic.ic_fini[i] != NULL; i++)
		DEBUG_S(ic.ic_fini[i]);

	ic.ic_affinity = iabf_affinity(getenv("IABF_AFFINITY"));
	ic.ic_delay_begin_ns = iabf_getenvl("IABF_DELAY_BEGIN_NS", LONG_MIN);
	ic.ic_delay_end_ns = iabf_getenvl("IABF_DELAY_END_NS", LONG_MAX);
	ic.ic_delay_step_ns = iabf_getenvl("IABF_DELAY_STEP_NS", 0);
	ic.ic_step_count = iabf_getenvl("IABF_STEP_COUNT", 0);
	ic.ic_autotune_count = iabf_getenvl("IABF_AUTOTUNE_COUNT", 16);

	DEBUG_D(ic.ic_delay_begin_ns);
	DEBUG_D(ic.ic_delay_end_ns);
	DEBUG_D(ic.ic_delay_step_ns);
	DEBUG_D(ic.ic_step_count);
	DEBUG_D(ic.ic_autotune_count);

	assert(ic.ic_delay_begin_ns <= ic.ic_delay_end_ns);
	assert(0 <= ic.ic_delay_step_ns);
	assert(0 <= ic.ic_step_count);

	iabf(&ic, a, b);

	return 0;
}
