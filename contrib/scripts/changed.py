#!/usr/bin/env python3

#
# Analyzes a lustre-release commit and reports, as JSON:
#
#   updated_tests   suite -> [ test_N, ... ] for every subtest that changed or was added. A
#                   subtest is only reported when the post-image still has its run_test line,
#                   so renamed/removed tests and test_* helpers are excluded.
#   affected_files  { m: [...], a: [...], d: [...] } modified/added/deleted paths
#   SkipTesting     true when every affected path is non-functional (docs, licenses, ...)
#
# A subtest spans from its column 0 test_N() definition to its column 0 "run_test N" line,
# everything in that range belongs to test_N. Lines outside any range, such as suite setup
# code and helper functions defined between tests, are not attributed to any subtest. Blank
# lines, comments, test_N() definition lines and run_test lines (test descriptions) do not
# count as changes; renames are reported through the new run_test line.
#
# The analysis reads the pre- and post-image blobs from the repository, it does not need a
# checkout and does not run anything from the tree being analyzed.
#
# usage: changed.py [-C repo_dir] [rev]
#
#   -C repo_dir  path to the lustre-release repository (default: cwd)
#   rev          commit to analyze (default: FETCH_HEAD)
#

import argparse
import json
import os
import re
import subprocess
import sys

TEST_DEF_RE = re.compile(r"^(?:function\s+)?test_([A-Za-z0-9_]+)\s*\(\)")
HUNK_RE     = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", re.M)
RUN_TEST_RE = re.compile(r"^run_test\s+([A-Za-z0-9_]+)\b", re.M)
SUITE_DIR   = "lustre/tests/"

# These tests are wrappers for complete suites rather than individual subtests.
IGNORED_TESTS = [ "test_sanity", "test_sanityn" ]

# parallel-scale-nfs is run as these two suites
NFS_SUITE   = "parallel-scale-nfs"
NFS_TARGETS = [ "parallel-scale-nfsv3", "parallel-scale-nfsv4" ]

ALWAYS_TEST_PREFIXES  = [ "contrib/lbuild/" ]
NON_TESTABLE_PREFIXES = [ "Documentation/", "LICENSES/", "contrib/" ]
NON_TESTABLE_EXACT    = [ "lustre/ChangeLog" ]


def run(argv):
    return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          encoding="utf-8", errors="replace")


def git(repo, *argv):
    proc = run([ "git", "-C", repo ] + list(argv))
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        sys.exit("git %s failed" % " ".join(argv))
    return proc.stdout


def blob_lines(repo, rev, path):
    # empty when the path does not exist at rev (added or deleted by the commit)
    proc = run([ "git", "-C", repo, "show", "%s:%s" % (rev, path) ])
    return proc.stdout.splitlines() if proc.returncode == 0 else []


def affected_files(repo, rev):
    changes = { "m": [ ], "a": [ ], "d": [ ] }
    out = git(repo, "diff-tree", "--no-commit-id", "--no-renames", "--name-status", "-r", rev)
    for line in out.splitlines():
        status, path = line.split("\t", 1)
        changes[{ "A": "a", "D": "d" }.get(status[0], "m")].append(path)
    return changes


def run_test_names(lines):
    return { "test_" + m.group(1) for m in RUN_TEST_RE.finditer("\n".join(lines)) }


def test_ranges(lines):
    # [ (test_N, first_line, last_line) ] with last_line the run_test N line and first_line
    # the most recent test_N() definition, or the line after the previous run_test when the
    # test has no definition of its own
    ranges, defs, prev = [], { }, 0
    for i, line in enumerate(lines, 1):
        m = TEST_DEF_RE.match(line)
        if m:
            defs["test_" + m.group(1)] = i
            continue
        m = RUN_TEST_RE.match(line)
        if m:
            name = "test_" + m.group(1)
            ranges.append(( name, defs.pop(name, prev + 1), i ))
            prev = i
    return ranges


def enclosing(ranges, n):
    return [ name for name, s, e in ranges if s <= n <= e ]


def natural_key(name):
    # test_1a, test_2f, test_12a, test_27b rather than test_12a, test_1a, test_27b, test_2f
    return [ int(s) if s.isdigit() else s for s in re.split(r"(\d+)", name) ]


def significant(lines, n):
    # blank lines, comments, test_N() definition lines and run_test lines (test descriptions)
    # do not count as changes
    line = lines[n - 1] if n <= len(lines) else ""
    text = line.strip()
    return text and not text.startswith("#") and not RUN_TEST_RE.match(line) \
        and not TEST_DEF_RE.match(line)


def removed_test(r, new, hunks):
    # true when a hunk removes the run_test line of pre-image test r without adding a run_test
    # line for the same name, so the test was removed or renamed rather than its description
    # changed. hunks: [ [ a, b, c, d ] ] from the "@@ -a,b +c,d @@" headers
    name, _, run_test_line = r
    for a, b, c, d in hunks:
        removes_run_test = a <= run_test_line < a + b
        added_lines      = new[c - 1:c - 1 + d]
        if removes_run_test and name not in run_test_names(added_lines):
            return True
    return False


def suite_tests(repo, rev, path):
    # returns [ test_N, ... ] changed in the suite file at path, or None if not a suite
    old = blob_lines(repo, rev + "^", path)
    new = blob_lines(repo, rev, path)
    run_tests = run_test_names(new)
    if not run_tests:
        return None

    # Added lines are attributed by their post-image segment and removed lines by their
    # pre-image segment, so removing the start of a test or a whole test lands on the right
    # name. A pre-image name that no longer has a run_test line (the test was removed or
    # renamed) is dropped by the final intersection with run_tests.
    diff  = git(repo, "diff-tree", "-p", "-U0", rev + "^", rev, "--", path)
    hunks = [ [ int(g) if g else 1 for g in h.groups() ] for h in HUNK_RE.finditer(diff) ]

    # Removed lines of a removed or renamed test are not attributed, otherwise they would land
    # on the old name when another test still uses it.
    old_ranges = [ r for r in test_ranges(old) if not removed_test(r, new, hunks) ]
    new_ranges = test_ranges(new)
    hit = set()
    for a, b, c, d in hunks:
        for n in range(a, a + b):
            if significant(old, n):
                hit.update(enclosing(old_ranges, n))
        for n in range(c, c + d):
            if significant(new, n):
                hit.update(enclosing(new_ranges, n))
    # tests whose run_test line is new to this commit
    hit.update(run_tests - run_test_names(old))
    return sorted((t for t in hit & run_tests if t not in IGNORED_TESTS), key=natural_key)


def suite_path(path):
    # only lustre/tests/*.sh and lustre/tests/runtests are suites
    if not path.startswith(SUITE_DIR) or "/" in path[len(SUITE_DIR):]:
        return False
    name = os.path.basename(path)
    return name.endswith(".sh") or name == "runtests"


def updated_tests(repo, rev, affected):
    tests = {}
    for path in affected["m"] + affected["a"]:
        if not suite_path(path):
            continue
        names = suite_tests(repo, rev, path)
        if names:
            tests[re.sub(r"\.sh$", "", os.path.basename(path))] = names
    if NFS_SUITE in tests:
        for target in NFS_TARGETS:
            tests[target] = list(tests[NFS_SUITE])
        del tests[NFS_SUITE]
    return tests


def only_non_testable_paths(affected):
    paths = affected["m"] + affected["a"] + affected["d"]
    if not paths:
        return False
    for path in paths:
        if any(path.startswith(p) for p in ALWAYS_TEST_PREFIXES):
            return False
        if path not in NON_TESTABLE_EXACT and \
                not any(path.startswith(p) for p in NON_TESTABLE_PREFIXES):
            return False
    return True


def main():
    parser = argparse.ArgumentParser(usage="%(prog)s [-C repo_dir] [rev]")
    parser.add_argument("-C", dest="repo", default=".", help="lustre-release repository")
    parser.add_argument("rev", nargs="?", default="FETCH_HEAD", help="commit to analyze")
    args = parser.parse_args()

    if not os.path.isdir(args.repo):
        sys.exit("'%s' does not exist" % args.repo)
    if run([ "git", "-C", args.repo, "rev-parse", "-q", "--verify",
             args.rev + "^{commit}" ]).returncode != 0:
        sys.exit("'%s' is not a commit in %s" % (args.rev, args.repo))

    change   = {}
    affected = affected_files(args.repo, args.rev)
    tests    = updated_tests(args.repo, args.rev, affected)
    if tests:
        change["updated_tests"] = tests
    change["affected_files"] = affected
    if only_non_testable_paths(affected):
        change["SkipTesting"] = True
        change.pop("updated_tests", None)

    print(json.dumps(change))


if __name__ == "__main__":
    main()
