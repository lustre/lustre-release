---
name: lustre-test-scripts
description: Use when writing, changing, running or verifying Lustre tests in lustre/tests - "add a sanity test for this", "write a regression test", "make sanity/271c more robust", "run sanity 56", "does the test fail without the fix", "use fail_loc to inject an error", "which subtest number should I use", "add a version check". Covers running suites with auster, subtest structure, bash style, version checks for interop, fault injection with fail_loc, subtest numbering, cleanup, and proving that a test catches the bug.
---

# Lustre test scripts

Test suites are bash scripts in `lustre/tests/` built on
`test-framework.sh`.  The human-oriented guide is
https://wiki.lustre.org/Lustre_Script_Coding_Style.

## Running tests

Run tests only on test nodes, never on the development host: they format
devices, load modules and can crash the node.  The ltvm skill
(https://github.com/lustre-tools/lustre-test-vms) sets up VMs and runs
suites on them.

```bash
lustre/tests/auster -r -v sanity --only "56a 56b"  # format, mount, run
lustre/tests/auster -v -s sanity --only 400-420    # SLOW=yes, a range
ONLY_REPEAT=100 lustre/tests/auster -v sanity --only 56a
ONLY_MINUTES=30 lustre/tests/auster -v sanity --only 56a
```

- If no filesystem is mounted, auster mounts one described by the test
  configuration (below), using modules and utilities from the build tree.  It
  formats the devices only with `-r` (needed the first time).  If it did
  the mount, it unmounts at the end, even after failures, so mount with
  `llmount.sh` first to inspect a failed run.  Logs go to
  `/tmp/test_logs/<date>/<time>/`.
- `ONLY=`, `EXCEPT=` and per-suite `SANITY_EXCEPT=` select subtests.
  `ONLY_REPEAT=N` repeats a subtest and `ONLY_MINUTES=M` repeats it for
  M minutes.
- `llmount.sh` formats and mounts; `llmountcleanup.sh` unmounts and
  unloads.
- Check that the code under test is really there: `lctl get_param -n
  version` on the test node should match `git describe --match "[0-9]*"
  --abbrev=7` of the build (with `-` shown as `_`), or version checks
  will skip new tests and they "pass" without running.  Look for the
  test's own output in the log, not just PASS.

## Test configuration

`test-framework.sh` loads `cfg/$NAME.sh` (`NAME=local` by default).
`cfg/local.sh` holds the common defaults (filesystem `lustre` mounted on
`/mnt/lustre`, one MDT, two OSTs, ldiskfs on loop files in `$TMP`), and
should almost never be modified or committed.  For another
configuration, create `cfg/<name>.sh` that sources `cfg/local.sh` and
overrides what differs, then run with `NAME=<name>` (or `auster -f
<name>`).  `cfg/ncli.sh`, for multiple clients with `RCLIENTS`, works
this way.  Set `FSNAME` before sourcing `cfg/local.sh`, since the mount
point and device names are derived from it.  Don't commit personal
configurations.

```bash
# lustre/tests/cfg/dne4.sh
FSNAME=testfs
. $LUSTRE/tests/cfg/local.sh
MDSCOUNT=4
OSTCOUNT=4
```

```bash
NAME=dne4 lustre/tests/auster -r -v sanity --only 56a
```

## Subtest structure

```bash
test_123b() {
	(( MDS1_VERSION >= $(version_code 2.17.59.12) )) ||
		skip "need MDS >= 2.17.59.12 for foo bar support"

	local old=$($LCTL get_param -n mdc.*.foo | head -n1)

	# set up the layout that triggers the bug
	test_mkdir $DIR/$tdir || error "mkdir $tdir failed"
	stack_trap "$LCTL set_param -n mdc.*.foo=$old"
	$LCTL set_param -n mdc.*.foo=1 || error "set foo=1 failed"

	# the second open used to return -EINVAL
	$MULTIOP $DIR/$tdir/$tfile oO_CREAT:O_RDWR:c ||
		error "multiop $tfile failed"
}
run_test 123b "open after foo is set does not fail"
```

- `test_NNNx()` followed by `run_test NNNx "short lower-case description"`.
- Use `$DIR/$tdir` and `$tfile` (derived from the subtest number), never
  hard-coded names or numbers; `$testnum` and `$TESTNAME` if needed.
- Never hard-code the filesystem name, mount points or devices: they
  change with the configuration.  Use `$FSNAME`, `$MOUNT`/`$DIR`,
  `$MOUNT2`/`$DIR2`, and `mdsdevname`, `ostdevname` or `facet_device`.
- `test_mkdir` unless placement matters; then `mkdir_on_mdt0`, or
  `$LFS mkdir -i`.  Run server commands with `do_facet mds1|ost1 ...` or
  `do_nodes`.  Wait for state with `wait_update`; drop client locks with
  `cancel_lru_locks`.
- Restore every tunable you change, and remove large (over ~1 MB) or
  many (over ~50) files, with `stack_trap`.  Small files named with
  `$tfile` and `$tdir` can be left behind: `test-framework.sh` removes
  them, including between repetitions of a looped subtest, and until then
  they are useful "chaff" that varies the conditions later subtests run
  under.
- `skip` for a configuration that can never run the test; `skip_env` for
  something missing from the test environment (a tool, a feature).
- Known failures are excluded at the top of the suite with
  `always_except LU-NNNNN 42a 42c`, not by editing the test.
- A new suite or helper binary is added to `lustre/tests/Makefile.am`.
- Suite-specific helpers stay in the suite; only genuinely shared code
  goes in `test-framework.sh`.

## Style

- `#!/usr/bin/bash`.  Tabs, 80 columns; checkpatch checks `.sh` files and
  `prepare-commit-msg` runs shellcheck on them.
- `[[ ]]`, `(( ))` and `$(...)`.  Never `[ ]`, `-lt`/`-eq` comparisons,
  backticks, `expr` or `let`.
- Declare `local` variables near their first use, not all at the top
  (loop counters too).  Lowercase locals, UPPERCASE globals and exports.
  Name positional arguments with locals.
- Every command that can fail gets `|| error "..."`, on the same line if
  it fits.  Error messages are short, unique tokens that locate the
  failure, plus the values needed to diagnose it, not prose.
- Prefer bash builtins to forking: parameter expansion instead of
  sed/tr, `<<<` instead of `echo |`, one `awk '/pat/ {...}'` instead of
  `grep | awk`, `for ((i = 0; ...))` instead of `seq`, no useless `cat`.
- `sleep 0.1`, not `usleep`.  `$SECONDS` for elapsed time.  `$TMP`, not
  `/tmp`, for files outside Lustre.
- A short comment before each phase of the test.  Helpers get a header
  comment with purpose, usage, arguments and return value.
- Booleans as `local x=false; if $x; then`.  End a function with `[[
  check ]] || action`, not `&& action`, so it doesn't return failure.
- Make the test robust even if the root cause is later fixed elsewhere.
  Give exact thresholds and the reasoning behind them.
- Use `fallocate` for large files only where `check_set_fallocate`
  allows and the contents don't matter.

## Version checks for interop

Test scripts run from the client's own lustre-tests package.
`test-framework.sh` sets `CLIENT_VERSION` from the local node and queries
`MDS1_VERSION` and `OST1_VERSION` from the servers.  A new or changed
test needs a check only for a *peer* that might lack the change it tests:

- **Server-side change:** the first line is a permissive check against
  the version of the patched build itself:
  `(( MDS1_VERSION >= $(version_code 2.17.58.63) )) || skip "need MDS >=
  2.17.58.63 for ..."` (`OST1_VERSION` for an OST-side change).  Take the
  number from `git describe --match "[0-9]*" HEAD` on the patch commit
  (`2.17.58-63-g1234abc` -> `2.17.58.63`).  Never use the next release,
  which would skip the test on the patched build.  For a series, use the
  first patch's version for all of them.
- **Client-only change tested on the local client:** no check.  An older
  client doesn't have the test, and a `CLIENT_VERSION` check can never
  skip it.
- **Change exercised on another client node** (e.g. the remote client in
  sanityn): check that node's version.
- `MDS1_VERSION` stands for every MDT: MDS versions in one filesystem are
  never more than a few builds apart, so don't check each MDT.
- When a server change breaks an *existing* subtest for older clients,
  which run their own unmodified scripts, list it in
  `lustre/tests/except/<suite>.<tag>.ex` (format in
  `lustre/tests/except/README`).  Clients read these files from the
  servers and skip the listed subtests.

## Fault injection

- The kernel code checks a fault point with `CFS_FAIL_CHECK(OBD_FAIL_xxx)`
  (or `CFS_FAIL_TIMEOUT`, `CFS_RACE`, ...); IDs are in
  `lustre/include/obd_support.h`.
- The test copies the ID as a comment and sets it on the right node:

  ```bash
  #define OBD_FAIL_MDS_REINT_NET 0x107
  do_facet mds1 $LCTL set_param fail_loc=0x80000107 fail_val=0
  ```

  `0x80000000` (`CFS_FAIL_ONCE`) fires once; other flag bits are in
  `include/linux/libcfs/libcfs_fail.h`.  Reset with `fail_loc=0` (or
  `reset_fail_loc`), and add a `stack_trap` so it is reset on failure.
- Existing helpers cover common cases: `drop_request`, `drop_reply`,
  `pause_bulk`, `drop_bl_callback`, `replay_barrier`, `fail mds1`.

## Subtest numbers

- Keep numbers below 1000 and next to related tests, leaving occasional
  gaps when adding at the end of a file.
- Never have both `56` and `56a`: rename `56` to `56a` when adding
  `56b`.  When `a`-`z` are taken, or for a variant of `56e`, use `56ea`,
  `56eb` (placed after `56e`).  Continue `a`-`z` with `A`-`Z`, but never
  add two-letter suffixes after `z` or `Z`.
- Before choosing, list open Gerrit changes to the same script
  (`project:fs/lustre-release branch:master status:open
  file:^lustre/tests/sanity.sh`) and look at the subtests they add or
  change.  Stay clear of those numbers, and leave a gap rather than
  taking the next free number when another open patch works just after
  it, so neither patch conflicts on rebase.

## Proving the test

A test that passes without the fix does not test the fix.  For a new or
changed regression test:

1. Build and deploy the tree with only the fix reverted, keeping the new
   test (so its version check still passes):
   `git checkout HEAD~1 -- <non-test files>`.
2. Run the subtest and confirm it FAILS for the expected reason, not on
   a setup error or a skip.
3. Restore the fix (`git checkout HEAD -- .`), rebuild and redeploy, and
   confirm the subtest passes.
4. Report both results with the patch.

For intermittent bugs (races, timing), one passing run without the fix
proves nothing.  Repeat with `ONLY_REPEAT=N`, up to about 100 iterations
as the run time allows, and report the failure counts both ways (e.g.
7/100 without the fix, 0/100 with it).  If it never fails without the
fix, say so and ask whether to keep the test: it may still catch the bug
in CI, where it runs far more often.
