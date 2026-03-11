# PVM Recompiler Sandboxing: Design Analysis

## Problem Statement

PolkaVM's compiler backend requires spawning sandbox worker processes even when
`sandboxing_enabled = false`. This uses Linux namespaces, `clone3()`, `userfaultfd`,
and `seccomp` — syscalls commonly blocked in containers, CI runners, and locked-down
production environments. The result: **polkavm's JIT simply doesn't work** in Docker,
Kubernetes pods, GitHub Actions, devcontainers, or any environment with seccomp
profiles or restricted capabilities.

Our grey recompiler already works in these environments. This document analyzes why,
compares the approaches, and proposes how to maintain security without OS-level
sandboxing.

## PolkaVM Compiler Architecture

### Worker Process Model

PolkaVM's compiler backend is **architecturally dependent** on a separate worker
process, regardless of security settings:

```
Host Process                     Worker Process
┌──────────────────┐            ┌──────────────────┐
│ Compile PVM→x86  │            │                  │
│ into shared mem  │──memfd────▶│ Guest memory     │
│                  │            │ Guest code (RX)  │
│ Set vmctx.PC     │            │ vmctx struct     │
│ Wake futex ──────│──futex────▶│ Execute JIT code │
│ Wait futex ◀─────│──futex────│ Set exit reason  │
│ Read result      │            │                  │
└──────────────────┘            └──────────────────┘
```

The worker exists because polkavm maps guest code at **fixed low addresses**
(0x0000–0xFFFFFFFF) that would collide with the host's address space. The worker
provides a clean address space for this mapping.

### What `sandboxing_enabled = false` Actually Does

Setting `sandboxing_enabled = false` only disables:
- Security checks on memory access patterns
- Some page-permission enforcement

It does **not** disable:
- Worker process creation (`clone3` / `clone`)
- Linux namespace creation (`CLONE_NEWPID`, `CLONE_NEWNS`, etc.)
- `userfaultfd` for demand paging
- `memfd_create` for shared memory
- `futex` for host↔worker synchronization

The worker is an **execution requirement**, not a security feature.

### Syscalls That Fail in Containers

| Syscall | Purpose | Blocked By |
|---------|---------|------------|
| `clone3` / `clone` with namespace flags | Worker creation | seccomp, no `CAP_SYS_ADMIN` |
| `userfaultfd` | Demand paging | seccomp, no `CAP_SYS_PTRACE` |
| `mount` (tmpfs) | Filesystem isolation | no `CAP_SYS_ADMIN` |
| `pivot_root` | Filesystem isolation | no `CAP_SYS_ADMIN` |
| `prctl(PR_SET_SECCOMP)` | Syscall filtering | already under seccomp |
| `unshare` | Namespace separation | no `CAP_SYS_ADMIN` |

PolkaVM's `generic-sandbox` alternative runs in-process using signal handlers
(`SIGSEGV`/`SIGILL`) but is marked experimental and provides no real isolation.

## Grey Recompiler Architecture

### In-Process JIT Model

Our recompiler runs JIT code **directly in the host process** without any OS-level
isolation:

```
Host Process
┌─────────────────────────────────────────────────┐
│ Compile PVM→x86 into mmap'd buffer (RW→RX)     │
│                                                 │
│ JitContext (repr(C), heap-allocated):            │
│   regs[13], gas, memory*, exit_reason, ...      │
│                                                 │
│ entry(ctx_ptr)  ──→  Native x86-64 code         │
│   ◀── returns when exit_reason set              │
│                                                 │
│ All memory access via helper fn calls:           │
│   mem_read_u8(ctx, addr) → bounds-checked       │
│   mem_write_u32(ctx, addr, val) → bounds-checked│
└─────────────────────────────────────────────────┘
```

### Why It Works Everywhere

- **No child processes**: Single-threaded, in-process execution
- **No namespaces**: No `clone`, `unshare`, or `clone3`
- **No special syscalls**: Only `mmap`/`mprotect`/`munmap` (universally available)
- **No signal handlers**: Faults detected by Rust code in helper functions, not signals
- **No shared memory**: JitContext is a regular heap allocation

### Current Safety Model

**Memory isolation** is enforced at the *software* level, not the OS level:

1. **All guest memory accesses go through helper functions** (`mem_read_u8`, etc.)
   that call into the `Memory` struct's bounds-checked methods
2. **Guest code cannot issue arbitrary memory loads/stores** — the compiler emits
   `call` instructions to helpers, not raw `mov [addr], val`
3. **Executable memory is read-only after compilation** — `mprotect(PROT_READ | PROT_EXEC)`
   prevents the JIT code from modifying itself
4. **R15 is reserved** for the JitContext pointer; guest code cannot clobber it
   (callee-saved, restored in epilogue)
5. **Gas metering** checks at every basic block boundary prevent infinite loops
6. **The native stack (RSP) is never exposed** to guest computation

## Threat Analysis: Do We Need OS-Level Sandboxing?

### What We're Protecting Against

In the JAM protocol, PVM code comes from **untrusted service authors**. A malicious
service could submit PVM bytecode designed to:

| Threat | Risk Level | Current Mitigation |
|--------|------------|-------------------|
| Read host memory | **Low** | All loads go through helper functions |
| Write host memory | **Low** | All stores go through helper functions |
| Execute arbitrary syscalls | **None** | JIT code has no `syscall` instruction |
| Infinite loops / DoS | **None** | Gas metering at every BB |
| Stack overflow | **None** | Guest doesn't control RSP |
| JIT spray / code injection | **None** | Code buffer is RX (not RWX) |
| Corrupt JitContext | **Low** | R15 is callee-saved; only helpers write exit fields |
| Side-channel / timing | **Medium** | Not mitigated (same as polkavm) |

### The Critical Invariant

Our safety rests on one invariant:

> **Every guest memory access is mediated by a helper function call.**

If this invariant holds, guest code cannot escape the `Memory` abstraction regardless
of what instructions it contains. The compiler never emits raw memory operations
against guest addresses — it always calls a helper that validates the address
through the `Memory` struct.

### Comparison with PolkaVM's Security

| Property | PolkaVM (Linux sandbox) | Grey (in-process) |
|----------|------------------------|-------------------|
| Memory isolation | OS-level (separate address space) | Software (helper functions) |
| Syscall prevention | seccomp filter | No `syscall` emitted |
| Resource limits | rlimits (stack, heap, nproc) | Gas metering |
| Filesystem access | Mount namespace | N/A (no file ops) |
| Network access | Network namespace | N/A (no network ops) |
| Portability | Linux x86-64 only | Any x86-64 OS |
| Container support | Broken | Works everywhere |
| Performance overhead | futex handoff per exit | Direct function call |
| Side channels | Same exposure | Same exposure |

PolkaVM's sandbox defends against a broader class of attacks (kernel exploits,
speculative execution) but at the cost of portability and with the same side-channel
exposure. For blockchain consensus — where determinism matters more than
defending against kernel exploits — the software approach is more practical.

## Design Recommendations

### 1. Keep the In-Process Model

The in-process JIT model is the right choice for a blockchain node PVM:

- **Determinism**: No inter-process communication means no race conditions or
  timing variations from futex scheduling
- **Portability**: Works in containers, VMs, CI, embedded — anywhere with `mmap`
- **Performance**: No context-switch overhead for host calls (critical for
  accumulate/refine which make many host calls)
- **Simplicity**: ~500 lines of execution scaffolding vs polkavm's ~3000

### 2. Harden the Software Boundary

To strengthen the current model without OS-level sandboxing:

**A. Compiler verification pass** (recommended, low effort):
After compilation, scan the emitted x86-64 for disallowed instructions:
- `syscall` / `sysenter` (0x0F 0x05 / 0x0F 0x34)
- `int` (0xCD)
- `in` / `out` (0xE4-E7, 0xEC-EF)

This is a defense-in-depth check — our compiler should never emit these, but
verifying the output catches compiler bugs.

**B. Guard pages around JitContext** (recommended, low effort):
Allocate the JitContext with guard pages before and after:
```rust
// mmap guard page (PROT_NONE) | JitContext | mmap guard page (PROT_NONE)
```
This turns any buffer overflow from the JIT code into a hard SIGSEGV instead
of silent corruption.

**C. W^X enforcement** (already implemented):
The code buffer transitions from RW→RX before execution. Never RWX.

**D. Register contract verification** (optional, for debug builds):
In debug builds, verify after JIT returns that R15 still points to the
JitContext (catches register clobber bugs in the compiler).

### 3. Do NOT Add OS-Level Sandboxing

Adding `seccomp`, namespaces, or worker processes would:
- Break container deployments (the exact problem polkavm has)
- Add complexity with minimal security benefit for our threat model
- Introduce non-determinism through OS scheduler interactions
- Require Linux-specific code paths

The PVM threat model is **deterministic computation with bounded resources**,
not **arbitrary code execution**. Software-level mediation is sufficient and
more appropriate.

### 4. Consider `prctl(PR_SET_MDWE)` on Supported Kernels (Optional)

Linux 6.3+ supports Memory-Deny-Write-Execute at the process level:
```rust
prctl(PR_SET_MDWE, MDWE_REFUSE_EXEC_GAIN, 0, 0, 0);
```
This prevents any memory region from being both writable and executable
simultaneously, hardening the W^X guarantee at the OS level. Unlike
namespaces/seccomp, this single prctl call works in containers. It should be
applied opportunistically (best-effort, not required).

## Summary

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Execution model | In-process JIT | Portability, performance, simplicity |
| Memory safety | Software-mediated helpers | Sufficient for PVM threat model |
| OS sandboxing | None required | Breaks containers, minimal benefit |
| W^X | Already enforced (RW→RX) | Defense in depth |
| Hardening | Instruction scan + guard pages | Catches compiler bugs |
| Side channels | Not mitigated | Same as polkavm; out of scope for consensus |

Our recompiler's in-process model is not a security compromise — it's a
**deliberate architectural choice** that trades OS-level isolation (which
polkavm proves is fragile in practice) for portability, determinism, and
simplicity. The software boundary (helper-mediated memory access) is the
right abstraction for a deterministic VM where the instruction set is fully
controlled by the compiler.
