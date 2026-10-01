---
name: lustre-commit
description: Use when writing, amending or checking a Lustre commit message - "commit this", "write the commit message", "amend the commit", "what component should this use", "add Test-Parameters", "add a Fixes line", "port this patch to b2_17". Covers the summary line and component, body content, performance evidence, the trailers the commit-msg hook accepts, Signed-off-by and Assisted-by, Change-Id, ports, and choosing Test-Parameters.
---

# Lustre commit messages

`contrib/git-hooks/commit-msg` enforces most of the format and adds the
`Change-Id:`.  `prepare-commit-msg` adds checkpatch and shellcheck output
as comments only when git opens an editor, so with `git commit -F` run
checkpatch yourself (see the lustre-patch-workflow skill).  Install both
once in the main checkout (worktrees use the main checkout's hooks):

```bash
ln -sf ../../contrib/git-hooks/{prepare-,}commit-msg .git/hooks/
```

## Steps

1. Check what is staged (`git diff --cached`).  If nothing is, look at
   `git diff` and ask what belongs in the commit.
2. Get the LU ticket from the context, or ask for it.  `LU-0000` is only
   a placeholder until the real ticket is known.
3. Choose the component (below), write the message, and commit with a
   heredoc or `git commit -F file` so the formatting survives.
4. Amend the existing commit for later changes; never add fixup commits.

## Summary line

`LU-NNNNN component: imperative summary`

- At most 62 characters (the hook rejects more); aim for 60 or less.
  No trailing period.  Imperative mood: "fix", "add", "allow".
- Master patches use an LU ticket.  The hook accepts other projects'
  tickets, but they belong only on vendor branches.
- The component is 2-11 characters of `[-a-z0-9]`, normally the
  subsystem directory the patch changes: `llite`, `lmv`, `lov`, `mdc`,
  `osc`, `ptlrpc`, `ldlm`, `obdclass`, `mdt`, `mdd`, `lod`, `osp`, `ofd`,
  `osd-ldiskfs`, `osd-zfs`, `mgc`, `mgs`, `quota`, `lfsck`, `target`,
  `fid`, `fld`, `ec`, `lnet`, `libcfs`, an LND name (`socklnd`,
  `o2iblnd`, `kfilnd`, `efalnd`), `utils`, `lfs`, `llapi`, `tests`,
  `doc`, `build`, `ldiskfs`, `rustreapi`, and for features that span
  directories `nodemap`, `sec`, `gss`, `pcc`, `hsm`, `llog`, `osd`.  Use
  `kernel` for support of new kernel versions, `build` for other build
  and packaging changes, and the most important component when a patch
  spans several.  Ask if it is unclear.
- For test changes, name the script and subtest:
  `LU-NNNNN tests: make sanity/271c more robust`.
- A patch imported from upstream Linux keeps its original summary with an
  LU ticket and component added, plus `Linux-commit:` and the original
  author and Signed-off-by.

## Body

- Blank line after the summary.  Wrap at 70 columns (the hook enforces
  it; lines containing a URL are exempt).  ASCII only: no curly quotes
  or long dashes.  Two spaces after a period.
- First paragraph: the problem, concretely: what fails, under what
  conditions, and the error message or stack if there is one.
- Then the fix, in the imperative ("Add ...", "Fix ...", "Allow ...").
  Name the key functions or tunables, not every function touched.  Use
  "Also fix ..." for small adjacent fixes.
- As short as possible while still clear.  Reviewers know Lustre; don't
  narrate the diff or list every nit fixed.
- Don't cite other Gerrit changes to explain duplicated hunks in a
  series; restack the series instead.
- **Performance claims need evidence**: a brief description of the test
  (workload, layout, process and client count), then the numbers.
  Relative improvement, or fewer RPCs, lock enqueues or reads per
  operation, is enough for results from a VM.  A compact ASCII table
  works well.  Don't name hosts.

## Trailers

One contiguous block after a blank line, no blank lines inside it, in
this order when present:

```
Test-Parameters: ...
Fixes: 0123456789ab ("LU-MMMMM component: original summary")
Signed-off-by: Real Name <email@example.com>
Assisted-by: AGENT:MODEL_ID [TOOL ...]
Change-Id: I<40 hex digits>
```

- The hook accepts only `Test-Parameters`, `Build-Parameters`, `Fixes`,
  `Signed-off-by`, `Assisted-by`, `Change-Id`, `Acked-by`, `Tested-by`,
  `Reported-by`, `Reviewed-by`, `Suggested-by`, `CC`, `CoverityID`,
  `Linux-commit`, `Lustre-change`, `Lustre-commit`, `Was-Change-Id` and
  `<Org>-bug-id`.  It rejects everything else, including
  `Co-Authored-By`, `Link` and `Reviewed-on`.
- `Fixes:` uses a 12-character hash that resolves in the tree, and the
  quoted original summary.
- `Signed-off-by:` certifies the Developer Certificate of Origin, which
  only a person can do.  It is your human's, from their `git config
  user.name` and `user.email` (`git commit -s`).  Never sign off as the
  agent or invent an identity, and make sure your human has reviewed
  the patch before it is pushed under their name.
- `Assisted-by:` credits the agent: the agent name and the exact model ID
  as the API reports it, then any specialised tools used, space
  separated, e.g. `Assisted-by: ClaudeCode:claude-opus-5-5 ltvm
  llm_code_and_review_tools`.  Don't list ordinary tools (git, gcc,
  make, editors).
- `Change-Id:` is added by the hook.  Keep it unchanged across amends,
  rebases and refreshes, and when porting to another branch.  Exactly
  one per commit.  When a reverted patch is resubmitted as a new change,
  add `Was-Change-Id:` with the original Change-Id.
- Keep each trailer on one line.  The hook silently joins lines ending in
  `\`.

## Ports to another branch

Keep the summary, body, author, original Signed-off-by and Change-Id.
Turn the original `Reviewed-on:` URL into `Lustre-change:
https://review.whamcloud.com/NNNNN`, and "cherry picked from commit X"
into `Lustre-commit: X`.  Always use the short
`https://review.whamcloud.com/NNNNN` form for a Gerrit change, never the
`/c/fs/lustre-release/+/NNNNN` form; the hook rejects it.  Drop
`Tested-by: Maloo` and Jenkins lines.  Describe non-trivial port changes
in the body, and add your human's Signed-off-by after the original ones.

## Test-Parameters

Every patch gets the default CI test sessions.  `Test-Parameters:` lines
change or add to them; the syntax is described at
https://wiki.whamcloud.com/display/PUB/Changing+Test+Parameters+with+Gerrit+Commit+Messages.
Each session spends 20-30 minutes setting up its nodes before any test
runs, a full run costs hundreds of node-hours, and every extra session is
another chance for an unrelated intermittent failure, so add only what the
change needs.

What runs without any line (measured on master, September 2026):

- A full run is about 70 sessions in 25 groups: about 350 node-hours and
  9-11 hours of wall time, bounded by conf-sanity.
- With `Test-Parameters: trivial`, only three `review-ldiskfs-dne`
  sessions run (two x86_64, one aarch64) with sanity, sanity-lnet and
  lnet-selftest: about 18 node-hours and 7 hours of wall time.
- A patch that changes a test script also gets two
  `review-dne-subtest-change` sessions that loop each new or modified
  `test_NNN` with `ONLY=NNN,ONLY_MINUTES=30`, even with `trivial`.

Choosing:

- Use `trivial` for test-only, documentation and build changes, and for
  low-risk code changes whose effect is fully covered by sanity,
  sanity-lnet or the patch's own new or changed test, which the
  subtest-change sessions exercise heavily (for example, changing when
  an error message is printed).
- Don't add `testlist=sanity env=ONLY=NNN` for subtests the patch adds or
  changes: the subtest-change sessions already loop them.
- Add explicit lines only for coverage the defaults lack: another suite
  that exercises changed code the patch doesn't test itself,
  `fstype=zfs`, `clientarch=aarch64`, interop with `clientversion=` or
  `serverversion=`, DNE with `mdscount=`/`mdtcount=`, or repeating a test
  the patch doesn't modify.
- Use one `Test-Parameters:` line per test script so the sessions run in
  parallel.  Given the setup time, make each run at least 30 minutes:
  `ONLY_MINUTES=30` for fast subtests, or `ONLY_REPEAT=N` for slow ones,
  where N >= ln(0.01) / ln(1 - p) for a historical failure rate p.
- Use the keyword parameters (`ostcount=`, `mdtcount=`, `fstype=`,
  `ostsizegb=`), not `env=OSTCOUNT=...`.
- `fortestonly` runs only the listed sessions and stops the patch from
  landing; use it only for experiments.
