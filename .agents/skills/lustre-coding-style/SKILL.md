---
name: lustre-coding-style
description: Use when writing, changing or reviewing Lustre C code, headers, kernel compatibility code, configure checks or man pages - "add a function to llite", "fix this kernel API change", "add a configure check for", "add a tunable", "add an lfs option", "is this the Lustre style", "review this code". Covers formatting, declarations, errors and console messages, tracing macros, memory allocation, assertions, kernel-doc comments, includes, kernel compatibility and HAVE_* checks, ABI and wire structures, userspace utilities and man pages.
---

# Lustre coding style

Lustre follows the Linux kernel coding style with the additions below.
`contrib/scripts/checkpatch.pl` checks much of it, including a table of
deprecated APIs and their replacements in `contrib/scripts/spelling.txt`
(`spelling-userspace.txt` for userspace).  The longer human-oriented
guide is https://wiki.lustre.org/Lustre_Coding_Style_Guidelines.

## Formatting

- Tabs (8 columns) for indentation; spaces only for alignment after the
  tabs.  80 columns.  Never split a user-visible format string; a long
  string on its own line is allowed.
- When changing space-indented lines, convert them to tabs, along with a
  few lines between them or the whole small function.
- No trailing whitespace (`git diff --check`).
- Opening brace on the same line, except for functions.  If one branch
  of an `if` has braces, all do.  Never put the body on the `if` line.
- Continuation lines align after the open parenthesis they continue.
  Binary operators go at the end of the line.
- Pack function arguments onto as few lines as fit, not one per line.
- Only `/* */` comments.  Multi-line comments put `/*` and `*/` on their
  own lines.  `//` is used only for the SPDX line of a `.c` file.

## Declarations and control flow

- One variable per line.  Longest declaration line first, `int rc;`
  last.  A blank line after the declarations.  No needless `= 0`, and no
  function calls in initializers.
- Declare variables in the innermost scope that makes sense.
- Handle the error or simple case first.  No `else` after `return`,
  `break`, `continue` or `goto`.
- Test booleans, pointers and `rc` implicitly (`if (!rc)`, `if (ptr)`);
  compare other function results explicitly (`strcmp(a, b) == 0`).
- No assignments inside conditions.
- Keep the first error: `if (!rc) rc = rc2;`.
- Errors are negative errnos in kernel code (`rc = -EINVAL`,
  `ERR_PTR(-ENOMEM)`).  Use `-EOPNOTSUPP`, not `-ENOTSUPP`, and `-EAGAIN`,
  not `-EWOULDBLOCK`.  For detected on-disk corruption `-EUCLEAN` is
  available and mapped on the wire; `EFSCORRUPTED` is not defined.
- A function returns either NULL or `ERR_PTR()` on failure, never both.
- `inline` only where it is shown to matter for performance.
- No new typedefs, except for function-pointer types.  Never typedef a
  struct or a pointer.  Callback parameters use concrete struct pointer
  types, not `void *`.
- Use designated initializers.  Give struct fields a prefix derived from
  the struct name.  Use a named enum, starting at 1, instead of a list of
  `#define`s.
- Macros parenthesize every argument.  Multi-statement macros use `do {
  } while (0)` without a trailing `;`.
- `sizeof(*ptr)` or `sizeof(var)`, not `sizeof(type)`.
- Use current APIs: `strscpy()` (not `strncpy`/`strcpy`),
  `snprintf()`/`scnprintf()`, `cfs_time_seconds()` instead of `HZ`
  arithmetic, `timeout_t`, `min_t()`/`max_t()`, `wait_event_idle*()`,
  `list_for_each_entry[_safe]()`.  checkpatch names the others.
- Code that should disappear in a later release is wrapped in `#if
  LUSTRE_VERSION_CODE < OBD_OCD_VERSION(X, Y, 53, 0)`.  It is compiled
  out silently once that version is reached, so it is found by grepping
  for these blocks when preparing a release.

## Debug, errors and tracing

- Every kernel `.c` file defines `#define DEBUG_SUBSYSTEM S_xxx` after
  the SPDX and copyright header and before any include.
- `CDEBUG(D_xxx, ...)` for debug messages.  Debug masks and subsystems
  are in `include/uapi/linux/lnet/libcfs_debug.h`.
- Console messages (`CERROR`, `CWARN`, `CNETERR`, `CEMERG`, `LCONSOLE_*`)
  only for events an administrator must act on.  Start with the device
  or filesystem name, end errors with the return code, and include the
  FID, NID or values needed to diagnose:
  `CERROR("%s: cannot open "DFID": rc = %d\n", obd->obd_name,
  PFID(fid), rc);`.
  Use `CDEBUG_LIMIT()` rather than `CDEBUG(D_ERROR|D_WARNING, ...)`.
- `ENTRY`, `EXIT`, `RETURN(rc)` and `GOTO(label, rc = -EFOO)` trace
  function flow.  Use them where the surrounding file does (most of
  `lustre/`, rarely `lnet/`).  A function with `ENTRY` leaves through
  `RETURN` or `EXIT`.  `GOTO()` does not assign its second argument; the
  assignment must be written inside it.
- Complex cleanup uses a single exit path with labels.
- `LASSERT()` only for internal invariants that indicate a code bug.
  Never assert on data from disk, the network or userspace; return an
  error instead.  No side effects inside an assertion.  On paths that
  only produce debug output, prefer `CERROR` to an assertion.
- Fault injection points: `if (CFS_FAIL_CHECK(OBD_FAIL_FOO_BAR))`, with
  the ID defined in `lustre/include/obd_support.h` in the block for its
  subsystem.  The other `CFS_FAIL_*` and `CFS_RACE*` macros are in
  `include/linux/libcfs/libcfs_fail.h`.

## Memory

- In `lustre/`: `OBD_ALLOC_PTR(ptr)`/`OBD_FREE_PTR(ptr)` for structs,
  `OBD_ALLOC_PTR_ARRAY(ptr, n)`, `OBD_ALLOC(ptr, size)`/`OBD_FREE(ptr,
  size)` with matching sizes, and `OBD_ALLOC_LARGE()`/`OBD_FREE_LARGE()`
  for buffers that may exceed a few pages.  The memory is zeroed and
  allocated with `GFP_NOFS`.  The array macros don't check for overflow.
- In `lnet/`: `LIBCFS_ALLOC()`/`LIBCFS_FREE()` and `CFS_ALLOC_PTR()`.
- Pointers stored in objects that outlive the caller (xarray, global
  list, netlink dump state) must be owned (copied) or explicitly pinned.
  A reference on the containing object does not pin what it points to,
  and a pointer to a module's string literal dangles after rmmod.

## Comments

- New and changed functions get kernel-doc comments, not Doxygen
  (`\param`, `\retval`, `\a`):

  ```c
  /**
   * lod_foo_bar() - one-line summary
   * @env: execution environment
   * @lo: LOD object to update
   *
   * Longer description, if one is needed.
   *
   * Context: when it matters, e.g. "Caller holds lo->ldo_layout_mutex."
   * Return:
   * * %0 - success
   * * %-ENOMEM - out of memory
   */
  ```

  Check with `contrib/scripts/kernel-doc -none -v <file>`.
- Comments explain why, not what, and sparingly.  Cite bugs as
  `(LU-NNNNN)`.  Reword a comment that only slightly overflows a line
  to fit on one line; otherwise write a filled multi-line block.  No
  hedging, and no comments added only to pre-empt a reviewer.

## Headers and includes

- New files start with the SPDX line (`// SPDX-License-Identifier:
  GPL-2.0` in `.c`, `/* ... */` in `.h`; see
  `Documentation/process/license-rules.rst`), then a copyright line with
  the current year.
- Include groups, in order: kernel `<linux/...>`; `<lustre_compat/...>`;
  libcfs and LNet `<linux/libcfs/...>`, `<linux/lnet/...>`;
  `<uapi/linux/lustre/...>`; `lustre/include` headers; then the local
  `"*_internal.h"`.  Add a new include in sorted position within its
  group, but don't reorder existing blocks just to sort them.  A real
  header dependency takes precedence over the order.
- LNet code never includes Lustre headers.
- No `extern` prototypes in `.c` files: put them in the most local header
  (`*_internal.h`).  Prototypes name their parameters.
- `EXPORT_SYMBOL()` goes right after the function.
- Kernel code tests `CONFIG_LUSTRE_FS_SERVER` for server-only code.
  `HAVE_SERVER_SUPPORT` is only for userspace.

## Kernel compatibility

- The oldest supported kernel is RHEL 8 (4.18 with backports); see the
  top of `lustre/ChangeLog`.
- Detect the *new* kernel API, not the removal of the old one, and put
  the difference in a helper named after the new API.  No `#ifdef` inside
  function bodies.
- Compat helpers go in `include/lustre_compat/<kernel header path>`
  (e.g. `<lustre_compat/linux/fs.h>` wraps `<linux/fs.h>`), with code in
  `lustre_compat/`.  `lustre/include/lustre_compat.h` is the legacy
  catch-all; don't add to it.
- Each `HAVE_*` check is a pair of macros, mostly in
  `config/lustre-core.m4`: `LC_SRC_xxx` builds a test with
  `LB2_LINUX_TEST_SRC`, and `LC_xxx` uses `LB2_MSG_LINUX_TEST_RESULT` and
  `AC_DEFINE`.  Add the two calls to `LC_PROG_LINUX_SRC` and
  `LC_PROG_LINUX_RESULTS`, under the kernel version that introduced the
  change.  The other files use their own prefixes (`LIBCFS_SRC_` in
  `lustre-libcfs.m4`, `LN_SRC_` in `lustre-lnet.m4`, `LB_SRC_` in
  `lustre-build-ldiskfs.m4`).  Annotate the check with the kernel version
  and commit in `git describe` form, as the neighbouring checks do.
- Use kernel APIs through the Lustre wrappers where they exist.

## ABI, wire and disk formats

- `include/uapi/` structures use fixed-width types (`__u32`, `__u64`),
  64-bit alignment and explicit padding.  Every enum member has an
  explicit value; never rely on auto-increment.
- A new wire structure is added to `lustre/utils/wirecheck.c`,
  `wiretest.c` is regenerated, and the structure is byte-swapped on
  unpack.
- New `OBD_CONNECT_*` flags and `obd_connect_data` fields are reserved on
  lustre-devel and landed as a flag-only patch before they are used (see
  the comments after them in `lustre_idl.h`).
- Keep getopt option tables and similar lists in alphabetical order
  unless ABI order matters.
- Formats: `%llu`/`%llx` for `__u64` (cast `loff_t` to `long long`),
  `DFID`/`PFID()` for FIDs, `DOSTID`/`POSTID()` for `ost_id`.  Printf-like
  functions get `__attribute__((format(printf, n, m)))`.

## Userspace utilities

- Errors name the command, quote user-supplied values and give the
  error string: `fprintf(stderr, "%s: cannot get layout of '%s': %s\n",
  progname, fname, strerror(-rc));` in `lfs`, with
  `jt_cmdname(argv[0])` in place of `progname` in `lctl` commands.  Keep
  the format string on one line, and tell the user what to do about it.
- A new or changed command or option updates the man page
  `Documentation/man{1,8}/<cmd>-<subcmd>.{1,8}`; a new or changed tunable
  gets or updates `Documentation/man4/<param>.4`.

## Man pages

- `.TH NAME SECTION YYYY-MM-DD ...` with the date of the change.  A new
  page is also added to its directory's `Makefile.am` where there is one.
- One sentence per source line.
- Examples in `.EX`/`.EE` with prompts showing where to run them:
  `.RB client# " lctl get_param ..."`, `mgs#`.
- The AVAILABILITY section ends with a line saying which release the
  feature appeared in, and a `.\" Added in commit ...` comment.
- `contrib/scripts/checkpatch-man.pl` runs automatically on `*.[1-8]`
  files through checkpatch.
