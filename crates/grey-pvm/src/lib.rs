//! Polkadot Virtual Machine (PVM) implementation for JAM (Appendix A).
//!
//! The PVM is a register-based virtual machine with:
//! - 13 general-purpose 64-bit registers (φ₀..φ₁₂)
//! - 32-bit pageable memory address space
//! - Gas metering for bounded execution
//! - Host-call interface for system interactions
//!
//! When the `std` feature is disabled, only the interpreter (`Pvm`) is available.
//! The x86-64 JIT recompiler requires `std` (mmap, env vars, etc.).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod args;
pub mod instruction;
pub mod memory;
pub mod program;
#[cfg(feature = "std")]
pub mod recompiler;
pub mod vm;

pub use memory::Memory;
pub use vm::{ExitReason, Pvm};
#[cfg(feature = "std")]
pub use recompiler::RecompiledPvm;
