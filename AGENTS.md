# Lustre development guide for AI agents

Guidance for AI coding agents working on Lustre (fs/lustre-release).
These rules apply to every session.  Task-specific detail lives in skills
under `.agents/skills/` (`.claude/skills` is a symlink to it), and a map
of the code is in `Documentation/internals.md`.  Load the matching skill
before starting that kind of work.

Claude Code reads this file itself only when no `CLAUDE.md` exists in
the tree.  If you keep your own `CLAUDE.md` or `CLAUDE.local.md`, or run
an older Claude Code, put `@AGENTS.md` in that file.

## Project

Lustre is a distributed parallel filesystem.  The tree holds Linux
kernel modules (client and servers), userspace utilities and the
liblustreapi library in C, test scripts in bash, and Rust bindings in
`rustreapi/`, which has its own agent rules in that directory.

- Changes are reviewed in Gerrit, project `fs/lustre-release` at
  https://review.whamcloud.com/, branch `master` (see `.gitreview`).
  Bugs and features are tracked in Jira project LU at
  https://jira.whamcloud.com/.  The process and style pages are under
  https://wiki.lustre.org/Development, and user-visible behaviour is
  documented in the Lustre Operations Manual,
  https://doc.lustre.org/lustre_manual.xhtml.
- Supported client and server kernels are listed at the top of
  `lustre/ChangeLog`.  The oldest is RHEL 8 (4.18 with backports);
  differences between kernels are handled by configure checks and the
  compat headers (see the lustre-coding-style skill).
- `Documentation/versioning.txt` explains version numbers and the
  compatibility promised between them.

## Source map

| Path | Contents |
|------|----------|
| `lustre/llite/` | client VFS interface (`lustre.ko`) |
| `lustre/lmv/`, `lustre/lov/` | client metadata / data striping over MDTs / OSTs |
| `lustre/mdc/`, `lustre/osc/` | client RPC interfaces to MDTs / OSTs |
| `lustre/obdclass/` | device model, `lu_object`, CLIO (`cl_*`), llog, config |
| `lustre/ptlrpc/` | RPC layer, recovery, NRS, sptlrpc; `ldlm/` and `target/` link into ptlrpc.ko |
| `lustre/ldlm/` | distributed lock manager |
| `lustre/target/` | common server code: request dispatch, last_rcvd, grants, server mount |
| `lustre/mdt/`, `mdd/`, `lod/`, `osp/` | metadata server stack: MDT -> MDD -> LOD -> OSD or OSP |
| `lustre/ofd/` | OST data server (OBD Filter Device) |
| `lustre/osd-ldiskfs/`, `osd-zfs/`, `osd-wbcfs/` | backend storage (wbcfs is experimental, in memory) |
| `lustre/mgc/`, `lustre/mgs/` | configuration client / server |
| `lustre/fid/`, `lustre/fld/` | FID sequence allocation, FID location database |
| `lustre/quota/`, `lfsck/`, `ec/` | quota, online checker, erasure-code math |
| `lustre/utils/` | `lfs`, `lctl`, `mkfs.lustre`, `mount.lustre`, liblustreapi |
| `lustre/tests/` | test suites and `test-framework.sh` |
| `lnet/` | networking: `lnet/lnet/`, LNDs in `lnet/klnds/`, `lnet/libcfs/`, `lnet/utils/` |
| `lustre_compat/`, `include/lustre_compat/` | kernel compatibility code and headers |
| `include/uapi/linux/{lustre,lnet}/` | headers shared with userspace (ABI) |
| `include/linux/{libcfs,lnet}/`, `lustre/include/` | kernel-internal headers |
| `ldiskfs/` | ext4 patch series that builds ldiskfs |
| `config/*.m4` | configure checks (`HAVE_*`) |
| `contrib/scripts/` | `checkpatch.pl`, `get_maintainer.pl`, `kernel-doc` |

`Documentation/internals.md` describes each subsystem, its key structures
and entry points, and how requests flow between them.  Read it before
working in an unfamiliar part of the tree.

## Tools and test environment

Two companion projects provide the tooling.  Install them and use their
skills; their instructions are not repeated here.

- **ltvm** (https://github.com/lustre-tools/lustre-test-vms): builds
  Lustre and kernels in a container and runs it in QEMU VMs, single node
  or clusters.  Its `ltvm` skill covers creating VMs, building and
  deploying a tree, mounting, running tests and collecting crashes.
- **llm_code_and_review_tools**
  (https://github.com/lustre/llm_code_and_review_tools): command-line
  tools for agents: `gc` (Gerrit), `jira`, `maloo` (test results),
  `jenkins`, `janitor`, `lreview` (AI patch review) and `lustre-crash`
  (vmcore analysis).  Its skills include gerrit-patch-workflow,
  jira-bug-research, lustre-ci-triage, lreview-spin-cycle,
  lustre-crash-triage and lustre-debug-logs.  It is the reference for
  Lustre's CI, review and bug-tracking systems and how to use them.

Never run Lustre tests, load Lustre modules or format devices on the
development host.  Tests reformat devices, load kernel modules and can
crash the node.  Use a test VM.

## Build

```bash
sh autogen.sh
./configure        # --disable-server, --with-linux=, --with-zfs=, ...
make               # or: make modules, make utils (configured tree only)
make rpms          # also debs, dkms-rpm; see `make help`
```

After HEAD moves, remove `configure` and `autom4te.cache` before
rebuilding, or the build keeps a stale version string and test version
checks will skip.  Check `lctl get_param -n version` on the test node.

## Testing

```bash
lustre/tests/auster -r -v sanity --only "1 2"  # format, mount, run
lustre/tests/auster -v -s sanity               # reuse mount, SLOW tests
lustre/tests/llmount.sh                        # format + mount only
lustre/tests/llmountcleanup.sh                 # unmount + unload
```

If no filesystem is mounted, auster mounts one described by
`lustre/tests/cfg/$NAME.sh` (`local.sh` by default; put other
configurations in their own file rather than changing it), using
modules from the build tree.  It formats the devices only with `-r`.
If it did the mount, it unmounts at the end.  Logs go to
`/tmp/test_logs/`.  Common suites:
sanity, sanityn, sanity-pfl, sanity-flr, sanity-dom, sanity-ec,
sanity-quota, sanity-sec, sanity-lnet, conf-sanity, recovery-small,
replay-single, replay-dual, insanity.  The lustre-test-scripts skill
covers writing and verifying tests.

## How to work

1. **Every patch has an LU ticket.**  Ask for it if it isn't clear from
   context; `LU-0000` is only a placeholder until then.
2. **Look for existing work first**: open Gerrit changes on the same
   topic or touching the same files, and Jira tickets on the same
   problem.  Report anything similar before writing code.
3. **Read the code before making claims about it**, and verify behaviour
   against the current tree.  Raise design choices that aren't obvious
   (where a tunable or stat belongs, which interface to extend, what is in
   scope) with your human *before* implementing.
4. **Keep each patch to one purpose**, but fold small related cleanups,
   dead-code removal and style fixes into the patch they follow from,
   up to roughly 500 changed lines.  In a series, every patch must build
   and pass tests by itself.  Squash fixes into the patch that introduced
   the code; never stack fixup patches.
5. **Build and test in a VM.**  A new or changed test must fail without
   the fix and pass with it.  Report both runs.
6. **Run checkpatch** on each commit and fix what it reports:
   `git format-patch -1 --stdout | ./contrib/scripts/checkpatch.pl -`.
   It also warns on every new `CERROR` (review the message) and
   `LASSERT` (consider error handling); those two are fine once the line
   is justified, but fix any message format it reports.
7. **Do a review pass** (lreview) once the patch is complete, and fix what
   it finds.  Ask before expanding the patch's scope.
8. **Your human decides what leaves the machine.**  Never push to Gerrit,
   post or reply to review comments, vote, add reviewers, retest, or
   create or comment on Jira tickets unless your human explicitly asks
   for that action.  Present the commit message, diff and test results,
   then wait.

The lustre-patch-workflow skill has the full sequence, including pushing,
following CI, and when to refresh or retest a patch.

## Commit messages

```
LU-NNNNN component: imperative summary of the change

The problem, concretely: what fails, when, and the error or symptom.
Then how this patch fixes it, in the imperative ("Add ...", "Fix ...").
"Also fix ..." for small adjacent changes.  Wrap at 70 columns.

Test-Parameters: trivial
Fixes: 0123456789ab ("LU-MMMMM component: original summary")
Signed-off-by: Real Name <email@example.com>
Assisted-by: AGENT:MODEL_ID [TOOL ...]
Change-Id: I0123456789abcdef0123456789abcdef01234567
```

- Summary at most 62 characters (the hook enforces it), no period.
  The component is the subsystem directory (`llite`, `ptlrpc`, `tests`,
  ...).  ASCII only.
- Keep the body terse.  Reviewers know Lustre: explain the problem and
  the approach, and name the key functions, but don't narrate the diff or
  list every small change; those belong under one summary sentence.
- Trailers are one contiguous block, and the hook rejects tags it does
  not know, including `Co-Authored-By:`.  `Signed-off-by:` is your
  human's certification of the Developer Certificate of Origin: use the
  name and email from their `git config`, never your own.  Credit the
  agent with `Assisted-by:`, giving the exact model ID as the API reports
  it and any specialised tools used.
- `Change-Id:` is added by `contrib/git-hooks/commit-msg`.  Install the
  hooks once in the main checkout (worktrees share them):
  `ln -sf ../../contrib/git-hooks/{prepare-,}commit-msg .git/hooks/`.
  Keep the Change-Id when amending, rebasing or porting the patch.

The lustre-commit skill has the full rules, the component list and how
to choose `Test-Parameters:`.

## Coding style

Linux kernel style, checked by `contrib/scripts/checkpatch.pl`, plus:

- Tabs, 80 columns.  Never split a user-visible string to fit.  Only
  `/* */` comments, apart from the `// SPDX-License-Identifier:` line.
- `#define DEBUG_SUBSYSTEM S_xxx` comes before the includes in a kernel
  `.c` file.
- In `lustre/`, allocate with `OBD_ALLOC_PTR()`/`OBD_FREE_PTR()`,
  `OBD_ALLOC()`/`OBD_FREE()` (the free needs the size) and
  `OBD_ALLOC_LARGE()` for buffers that may be large.  In `lnet/` use
  `LIBCFS_ALLOC()`/`CFS_ALLOC_PTR()`.  Not raw `kmalloc()`/`kfree()`.
- Console errors: `CERROR("%s: what failed: rc = %d\n", name, ...,
  rc)`, with the device or filesystem name first.  Use `CDEBUG(D_xxx,
  ...)` for debug messages.  Use the `ENTRY`/`RETURN()`/`GOTO(out, rc =
  -EFOO)` tracing wherever the file already does.
- Never `LASSERT()` on data from disk, the network or userspace; return
  an error.  Prefer an error return over an assertion in general.
- Kernel differences go into helpers in
  `include/lustre_compat/<kernel header path>`, guarded by `HAVE_*`
  configure checks (mostly in `config/lustre-core.m4`), not `#ifdef` in
  function bodies.  Kernel code tests `CONFIG_LUSTRE_FS_SERVER`, not
  `HAVE_SERVER_SUPPORT`.
- ABI and wire structures (`include/uapi/`): fixed-width types (`__u32`,
  `__u64`), explicit padding, explicit values for every enum member.
- Comment functions in kernel-doc form, not Doxygen.  Comments explain
  why, sparingly, and cite bugs as `(LU-NNNNN)`.
- Reuse or generalize existing helpers instead of adding near-copies, and
  remove code the patch leaves unused.

The lustre-coding-style skill has the full C, header, configure-check and
man page rules.

## Reviewing a patch

Besides correctness, check that:

- kernel APIs that differ across supported kernels have a `HAVE_*` check
  defined in `config/*.m4` and a compat helper;
- the Lustre wrappers are used (allocation, `CERROR`/`CDEBUG`, tracing);
- pointers stored in anything that outlives the caller (xarray, global
  list, netlink dump state) are owned or pinned.  A reference on the
  containing object does not pin what it points to; a pointer to a module's
  string literal dangles after rmmod;
- new tunables and command options have man pages, and new or changed
  behaviour has a test.

In a patch series, comment on the patch where the code is first added,
not on later patches that carry it.

## Skills in this tree

| Skill | Use it to |
|-------|-----------|
| lustre-patch-workflow | take a change from ticket to landed patch |
| lustre-coding-style | write or review C code, headers, configure checks, man pages |
| lustre-test-scripts | write, change, run and verify tests in `lustre/tests/` |
| lustre-commit | write or amend a commit message, choose Test-Parameters |
