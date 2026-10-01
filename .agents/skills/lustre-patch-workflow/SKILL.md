---
name: lustre-patch-workflow
description: Use for any work that takes a Lustre change from ticket to landed patch - "write a patch for LU-NNNNN", "fix this bug in Lustre", "prepare this patch for review", "push this to Gerrit", "the patch failed CI", "should I refresh this patch", "rebase the series", "who should review this". Covers looking for existing work, design questions, build and test, checkpatch, review, human approval, pushing, patch series, following CI, refresh and retest decisions, and landing.
---

# Lustre patch workflow

The steps below apply to every patch.  The lustre-commit,
lustre-coding-style and lustre-test-scripts skills hold the detail for
their parts.  Tool usage (gc, jira, maloo, lreview, ltvm) is in the
skills of https://github.com/lustre/llm_code_and_review_tools and
https://github.com/lustre-tools/lustre-test-vms.

## 1. Start

- Get the LU ticket.  Read it, including comments and linked tickets:
  they often give a reproducer, an existing patch, or the reason an
  earlier approach was dropped.
- Branch from the current `master` of the Gerrit remote, one branch per
  independent change.  A checkout holds one build at a time, so use a
  separate `git worktree` per concurrent patch, outside the main checkout
  (build cleanup can delete files under the whole tree).
- **Look for existing work** before writing a new patch that isn't a
  follow-on to one in hand:
  - open Gerrit changes by keyword and by the files you expect to touch
    (`project:fs/lustre-release branch:master status:open
    message:"<keyword>"`, `... file:^lustre/ptlrpc/sec.c`);
  - Jira tickets on the same problem (`project = LU AND text ~
    "<keyword>"`);
  - open changes to any test script you will modify, noting the subtest
    numbers they add or change.

  Report anything similar to your human before writing code.

## 2. Design

- Read the code involved and verify behaviour against the current tree,
  and on a test VM where it matters, before claiming how it works.
  `Documentation/internals.md` maps the subsystems.
- List the real design alternatives (which interface to extend, where a
  tunable or statistic lives, what is in scope) and ask about any that
  aren't obvious *before* implementing.  Review rounds are for catching
  mistakes, not for making the first design decision.
- Reuse or generalize existing code rather than adding a near-copy.
- New wire or on-disk formats, `OBD_CONNECT_*` flags and large features
  need agreement on lustre-devel and in Jira first.  Ask your human.

## 3. Implement

- One purpose per patch.  Fold small related cleanups, dead-code removal
  and style fixes on adjacent lines into the patch they follow from, as
  long as it stays under roughly 500 changed lines and the extras don't
  overshadow its purpose.  Put unrelated or large refactoring in a
  separate patch.
- Tests and documentation (man pages for new tunables and options) go in
  the same patch as the change.
- A series is ordered with the uncontroversial patches first.  Every
  patch must build and pass tests by itself.  Fold a fix into the patch
  that introduced the code (`git commit --fixup=<commit>`, then
  `GIT_SEQUENCE_EDITOR=: git rebase -i --autosquash <base>`), never as a
  new patch on top.

## 4. Build and test

- Build and run tests in a VM, never on the development host (see the
  ltvm skill).  After HEAD moves, remove `configure` and
  `autom4te.cache` before rebuilding so the version string is current,
  and confirm it with `lctl get_param -n version` on the VM.
- Run the tests that cover the change, not only the new subtest.
- A new or changed regression test must fail without the fix and pass
  with it; see the lustre-test-scripts skill for how to show that.
- Clean up after yourself on shared test nodes: unmount, remove test
  files, logs and crash dumps you no longer need, and release VMs you
  are done with.

## 5. Check and review

- Run checkpatch on every commit:
  `git format-patch -1 --stdout | ./contrib/scripts/checkpatch.pl -`
  (`make checkpatch` checks only `git diff HEAD~1` and skips the commit
  message).  Fix everything except the advisory warnings on each new
  `CERROR` (review the message) and `LASSERT` (consider error handling),
  and make sure those lines are justified.
- Validate new kernel-doc with `contrib/scripts/kernel-doc -none -v
  <file>`.
- Do a local AI review pass (`lreview`, see the lreview-spin-cycle skill)
  once the patch is complete.  Fix real findings; ask your human if one
  would expand the scope significantly.  Minor style fixes in code the
  patch already touches are fine without mention in the commit message.
- Amend; never stack fixups.

## 6. Human review, then push

- Present to your human: the commit message, the diff, and the test
  results (for a new or changed test, both the failing run without the
  fix and the passing run with it).  Wait for their explicit instruction
  to push that patch.  A dry run is fine before then.
- Push to `refs/for/<branch>`:
  `git push ssh://<user>@review.whamcloud.com:29418/fs/lustre-release
  HEAD:refs/for/master`, or `gc upload` (see the gerrit-patch-workflow
  skill for its options for a series or a new change).  A series is
  pushed in one go from its top commit.
- A new patchset keeps the same `Change-Id:` and contains the whole
  change, not a delta.
- Don't rebase or re-push another developer's unlanded change that yours
  depends on; base yours on it as it is.
- Suggested reviewers: `contrib/scripts/get_maintainer.pl -f <file>` and
  the `R:` entries in `MAINTAINERS`, usually two or three.  Add them only
  when your human asks.

## 7. CI and refreshing

Jenkins builds each patchset and Autotest runs the test sessions, with
results in Maloo; the Gerrit Janitor separately runs new or modified
tests.  Autotest posts links to all of a build's running test sessions
on the change, and links to any failed sessions before it votes Verified
+1 or -1, so there is no need to look up or post them by hand.  The
lustre-ci-triage skill covers reading the results.

- A new patchset aborts the running sessions once Jenkins finishes its
  build (30-45 minutes) and puts the new build at the back of the test
  queue.  Retests go to the front.
- **The build under test is wrong:** refresh it, almost always.
- **Only nits, or a better `Test-Parameters:`:** refresh only if testing
  has not started or has only just started (check the build's Maloo Test
  Queue link).  Otherwise fix them only if the patch needs another
  patchset anyway.
- **A session failed:** find out why before anything else.  Link the
  failure to an existing LU ticket, or raise a new one, then retest an
  unrelated or intermittent failure.  Never retest a failure that points
  at the patch; fix the patch.  Failures in tests the patch modifies are
  the patch's to fix.
- When refreshing a change that is still in development or has been
  modified, rebase it onto the tip of master.  Don't rebase when it
  depends on unlanded patches that shouldn't be refreshed (patches that
  are reviewed, tested and ready to land), or when it must keep a
  specific parent (bisection or test patches, branch fixes).
- Retest or refresh within about a week, before the build expires.

## 8. Landing

A change lands when it has two Code-Review +1 (or +2) votes from people
other than the owner, Verified +1 from Jenkins and Maloo (all enforced
sessions passed), and no Janitor -1 on modified tests.  The gatekeeper
then lands it.  Answer every review comment, by fixing it or explaining
why not, and refresh promptly.

## Jira

Gerrit adds a comment with the change's link to the Jira ticket named in
the summary line whenever a patch is pushed, so don't post patch links to
a ticket by hand.  When a patch needs mentioning elsewhere, e.g. in a
different ticket, write `patch https://review.whamcloud.com/NNNNN
("LU-MMMMM summary")`.  Put extra results (performance, interop) in the
ticket.  Comment on, create or change tickets only when your human asks,
each time.
