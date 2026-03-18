//! Single-pass gas pipeline simulator with fast-forward optimization.
//!
//! Simulates a CPU pipeline (32-entry ROB, 4 decode/5 dispatch slots per cycle)
//! to compute per-basic-block gas costs. Designed to be fed one instruction at a
//! time during codegen, producing a block cost at each block boundary.
//!
//! The key optimization over the batch `gas_sim_fast()` is **fast-forward**:
//! when the pipeline stalls waiting for a long-latency op (e.g. 25-cycle load),
//! we skip directly to the next completion event instead of ticking one cycle
//! at a time.
//!
//! Platform support:
//! - x86-64 AVX2: SIMD bulk subtract + compare for cycle advance
//! - All platforms: scalar bitmask iteration fallback

use crate::gas_cost::FastCost;

const EU_NONE: u8 = 0;
const EU_ALU: u8 = 1;
const EU_LOAD: u8 = 2;
const EU_STORE: u8 = 3;
const EU_MUL: u8 = 4;
const EU_DIV: u8 = 5;

/// Single-pass pipeline gas simulator. Stack-allocated, zero heap allocation.
pub struct GasSimulator {
    // 32-entry SoA ROB
    cycles_left: [u8; 32],
    exec_unit: [u8; 32],
    deps: [u32; 32],
    reg_writer: [u8; 16], // per-register: ROB slot index, 0xFF = none

    // Bitmask state tracking
    wait_mask: u32,
    exe_mask: u32,
    fin_mask: u32,

    next_slot: u8,
    cycles: u32,
    decode_slots: u8,
    dispatch_slots: u8,
    eu_avail: [u8; 5], // alu, load, store, mul, div
}

impl GasSimulator {
    pub fn new() -> Self {
        Self {
            cycles_left: [0; 32],
            exec_unit: [0; 32],
            deps: [0; 32],
            reg_writer: [0xFF; 16],
            wait_mask: 0,
            exe_mask: 0,
            fin_mask: 0,
            next_slot: 0,
            cycles: 0,
            decode_slots: 4,
            dispatch_slots: 5,
            eu_avail: [4, 4, 4, 1, 1],
        }
    }

    /// Feed one instruction into the pipeline. Advances cycles as needed.
    #[inline]
    pub fn feed(&mut self, cost: &FastCost) {
        if cost.is_move_reg {
            // move_reg: no ROB entry, just consume decode slots
            self.decode_slots = self.decode_slots.saturating_sub(cost.decode_slots);
            return;
        }

        // ROB full (32 entries used) — stop simulating (matches old behavior)
        if (self.next_slot as usize) >= 32 {
            return;
        }

        // Wait for decode slots if needed
        while self.decode_slots < cost.decode_slots {
            self.dispatch_all();
            if self.decode_slots >= cost.decode_slots { break; }
            if self.exe_mask != 0 {
                self.tick_fast_forward();
            } else {
                self.advance_one_cycle();
            }
        }

        // Build dependency mask
        let mut dep_mask: u32 = 0;
        let mut src = cost.src_mask;
        while src != 0 {
            let reg = src.trailing_zeros() as usize;
            src &= src - 1;
            let writer = self.reg_writer[reg];
            if writer != 0xFF && (self.fin_mask & (1u32 << writer)) == 0 {
                dep_mask |= 1u32 << writer;
            }
        }

        // Insert into ROB
        let slot = self.next_slot as usize;
        self.cycles_left[slot] = cost.cycles;
        self.exec_unit[slot] = cost.exec_unit;
        self.deps[slot] = dep_mask;
        self.wait_mask |= 1u32 << slot;

        // Update register writers
        let mut dst = cost.dst_mask;
        while dst != 0 {
            let reg = dst.trailing_zeros() as usize;
            dst &= dst - 1;
            self.reg_writer[reg] = self.next_slot;
        }

        self.next_slot += 1;
        self.decode_slots = self.decode_slots.saturating_sub(cost.decode_slots);
    }

    /// Drain all in-flight instructions and return max(cycles - 3, 1).
    pub fn flush_and_get_cost(&mut self) -> u32 {
        // Flush: keep ticking until pipeline is empty
        for _ in 0..100_000u32 {
            // Try dispatching any ready WAIT entries
            self.dispatch_all();
            // Check if done
            if self.exe_mask == 0 && self.wait_mask == 0 {
                break;
            }
            // If there are EXE entries, advance (with fast-forward)
            if self.exe_mask != 0 {
                self.tick_fast_forward();
            } else {
                // Only WAIT entries remain — need a cycle to dispatch them
                self.advance_one_cycle();
            }
        }
        let c = self.cycles;
        if c > 3 { c - 3 } else { 1 }
    }

    /// Reset for the next gas block.
    #[inline]
    pub fn reset(&mut self) {
        self.cycles_left = [0; 32];
        self.exec_unit = [0; 32];
        self.deps = [0; 32];
        self.reg_writer = [0xFF; 16];
        self.wait_mask = 0;
        self.exe_mask = 0;
        self.fin_mask = 0;
        self.next_slot = 0;
        self.cycles = 0;
        self.decode_slots = 4;
        self.dispatch_slots = 5;
        self.eu_avail = [4, 4, 4, 1, 1];
    }

    /// Dispatch as many ready WAIT entries as possible this cycle.
    #[inline]
    fn dispatch_all(&mut self) {
        while self.dispatch_slots > 0 {
            let mut candidates = self.wait_mask;
            let mut found = false;
            while candidates != 0 {
                let i = candidates.trailing_zeros() as usize;
                candidates &= candidates - 1;
                if (self.deps[i] & !self.fin_mask) == 0
                    && eu_available(&self.eu_avail, self.exec_unit[i])
                {
                    eu_consume(&mut self.eu_avail, self.exec_unit[i]);
                    self.wait_mask &= !(1u32 << i);
                    self.exe_mask |= 1u32 << i;
                    self.dispatch_slots -= 1;
                    found = true;
                    break;
                }
            }
            if !found { break; }
        }
    }

    /// Advance cycles with fast-forward: skip to the next completion event.
    ///
    /// Instead of ticking one cycle at a time, compute the minimum cycles_left
    /// among all EXE entries and subtract that in one step. This turns a
    /// 25-iteration loop (for a load) into a single operation.
    #[inline]
    fn tick_fast_forward(&mut self) {
        if self.exe_mask == 0 {
            // Nothing executing — just reset per-cycle state
            self.advance_one_cycle();
            return;
        }

        // Find minimum cycles remaining among executing entries
        let skip = self.min_exe_cycles();
        if skip <= 1 {
            // Normal single-cycle tick
            self.advance_one_cycle();
            return;
        }

        // Fast-forward: subtract (skip - 1) cycles from all EXE entries,
        // then do one normal tick to handle state transitions.
        // We subtract (skip - 1) so the final normal tick transitions
        // the entry to FIN correctly.
        let bulk = skip - 1;
        self.cycles += bulk as u32;
        bulk_decrement_exe(&mut self.cycles_left, self.exe_mask, bulk);
        // Now do one normal tick cycle
        self.advance_one_cycle();
    }

    /// Normal single-cycle advance.
    #[inline(always)]
    fn advance_one_cycle(&mut self) {
        advance_cycle_scalar(&mut self.cycles_left, &mut self.exe_mask, &mut self.fin_mask);
        self.cycles += 1;
        self.decode_slots = 4;
        self.dispatch_slots = 5;
        self.eu_avail = [4, 4, 4, 1, 1];
    }

    /// Find minimum cycles_left among EXE entries.
    #[inline]
    fn min_exe_cycles(&self) -> u8 {
        min_exe_cycles_impl(&self.cycles_left, self.exe_mask)
    }
}

// ---- Platform-specific implementations ----

/// Scalar: find minimum cycles_left among EXE entries.
#[inline]
fn min_exe_cycles_impl(cycles_left: &[u8; 32], exe_mask: u32) -> u8 {
    let mut min_c = u8::MAX;
    let mut exe = exe_mask;
    while exe != 0 {
        let i = exe.trailing_zeros() as usize;
        exe &= exe - 1;
        min_c = min_c.min(cycles_left[i]);
    }
    min_c
}

/// Scalar: subtract `amount` from all EXE entries.
#[inline]
fn bulk_decrement_exe(cycles_left: &mut [u8; 32], exe_mask: u32, amount: u8) {
    let mut exe = exe_mask;
    while exe != 0 {
        let i = exe.trailing_zeros() as usize;
        exe &= exe - 1;
        cycles_left[i] = cycles_left[i].saturating_sub(amount);
    }
}

/// Scalar: advance one cycle — decrement EXE entries, transition FIN.
#[inline(always)]
fn advance_cycle_scalar(cycles_left: &mut [u8; 32], exe_mask: &mut u32, fin_mask: &mut u32) {
    let mut exe = *exe_mask;
    while exe != 0 {
        let i = exe.trailing_zeros() as usize;
        exe &= exe - 1;
        if cycles_left[i] <= 1 {
            cycles_left[i] = 0;
            *exe_mask &= !(1u32 << i);
            *fin_mask |= 1u32 << i;
        } else {
            cycles_left[i] -= 1;
        }
    }
}

#[inline(always)]
fn eu_available(avail: &[u8; 5], eu: u8) -> bool {
    match eu {
        EU_NONE => true,
        EU_ALU => avail[0] >= 1,
        EU_LOAD => avail[0] >= 1 && avail[1] >= 1,
        EU_STORE => avail[0] >= 1 && avail[2] >= 1,
        EU_MUL => avail[0] >= 1 && avail[3] >= 1,
        EU_DIV => avail[0] >= 1 && avail[4] >= 1,
        _ => false,
    }
}

#[inline(always)]
fn eu_consume(avail: &mut [u8; 5], eu: u8) {
    match eu {
        EU_ALU => { avail[0] -= 1; }
        EU_LOAD => { avail[0] -= 1; avail[1] -= 1; }
        EU_STORE => { avail[0] -= 1; avail[2] -= 1; }
        EU_MUL => { avail[0] -= 1; avail[3] -= 1; }
        EU_DIV => { avail[0] -= 1; avail[4] -= 1; }
        _ => {}
    }
}
