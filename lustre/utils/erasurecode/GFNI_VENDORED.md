# Vendored ISA-L GFNI kernels

The 17 `gf_*_gfni.c` GFNI EC kernels in this directory are vendored from the
canonical ISA-L tree (`isa-l-tlc`): the `scopedog-nishida` branch of
https://github.com/TheLustreCollective/isa-l, snapshot at commit
6b2b74fcdd7210a8b6ac8dec08863f17541bc366 (files under `erasure_code/`).
They are C intrinsics kernels; upstream Intel ISA-L implements its GFNI
kernels in NASM and has no C equivalent, so these have no upstream-Intel
original.  The BSD-3-Clause notice they carry is inherited from the ISA-L
`.asm` kernels the algorithms follow.

IMPORTANT: these copies **intentionally diverge from `isa-l-tlc`**.  The
divergence is deliberate and of two kinds:

1. **Reflow for the lustre checkpatch style** -- lines wrapped to <=80
   columns, a blank line inserted after declaration blocks, and long asm
   template strings split into adjacent string literals (which the C
   preprocessor concatenates, so the emitted asm is unchanged).  This is
   whitespace and line-wrapping only.

2. **SPDX license headers** -- lustre requires an `SPDX-License-Identifier`
   line, so the ISA-L block-comment banner is rewritten as an SPDX line plus
   a `/* ... */` comment.  The licence text and copyright holder are
   unchanged.  `isa-l-tlc` itself is only partly converted: of the 17 files
   vendored here, five (`gf_{,3,4,5,6}vect_mad_avx512_gfni.c`) still carry
   the original block-comment banner there.

Apart from the `gf_tbl_load()` fix described below, which is not yet in
`isa-l-tlc`, no token that reaches the compiler as code -- identifier,
intrinsic, asm constraint, or numeric literal -- differs between the two
trees.  That property is verified by stripping whitespace and comparing the
resulting token streams.

**Fixes must flow both ways.**  A correctness fix made here has to be
propagated back to `isa-l-tlc`, and vice versa; they are the same kernels.
Two such fixes live in the five `gf_*vect_dot_prod_avx512_gfni.c` files --
the `"m"` asm input that keeps the table read visible to the compiler, and
the comment describing how gcc allocates the `AFFINE_XOR_BCAST` scratch
register -- and both are present in both trees.

One fix made here after that snapshot still has to go back to `isa-l-tlc`:
the 8-byte table entries are read through `gf_tbl_load()` (a memcpy) and the
asm `"m"` input is a `const unsigned char [8]`, instead of casting the
table pointer to `const uint64_t *`.  This avoids a strict-aliasing
violation and an unaligned 8-byte access; the generated code is unchanged
apart from register allocation.

When re-syncing from `isa-l-tlc` (e.g. a future `sync-ec-to-consumers.sh`
run), the reflow and the SPDX headers MUST be re-applied on top of the
freshly synced sources -- do not blindly clobber these files with the
canonical (long-line, block-banner) versions, or checkpatch will regress and
the SPDX lines will be lost.
