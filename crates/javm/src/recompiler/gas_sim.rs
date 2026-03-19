//! Pipeline gas simulator (JAR v0.8.0).
//!
//! Simulates a CPU pipeline (32-entry ROB, 4 decode/5 dispatch slots per cycle)
//! to compute per-basic-block gas costs. Collects instructions via feed(),
//! then simulates the pipeline in flush_and_get_cost().
//!
//! This is a stack-allocated, zero-heap replacement for gas_cost::gas_sim_traced()
//! that produces identical results.

use crate::gas_cost::FastCost;

const MAX_INSTRS: usize = 32;

/// Collected instruction for simulation.
#[derive(Clone, Copy)]
struct Instr {
    cycles: u8,
    decode_slots: u8,
    exec_unit: u8,
    src_mask: u16,
    dst_mask: u16,
    is_move_reg: bool,
}

/// ROB entry state.
#[derive(Clone, Copy, PartialEq)]
enum State { Wait, Exe, Fin }

/// Single-pass pipeline gas simulator. Stack-allocated, zero heap allocation.
pub struct GasSimulator {
    instrs: [Instr; MAX_INSTRS],
    count: usize,
}

impl GasSimulator {
    pub fn new() -> Self {
        Self {
            instrs: [Instr { cycles: 0, decode_slots: 0, exec_unit: 0, src_mask: 0, dst_mask: 0, is_move_reg: false }; MAX_INSTRS],
            count: 0,
        }
    }

    /// Collect one instruction. Call flush_and_get_cost() at block boundary.
    #[inline]
    pub fn feed(&mut self, cost: &FastCost) {
        if self.count < MAX_INSTRS {
            self.instrs[self.count] = Instr {
                cycles: cost.cycles,
                decode_slots: cost.decode_slots,
                exec_unit: cost.exec_unit,
                src_mask: cost.src_mask,
                dst_mask: cost.dst_mask,
                is_move_reg: cost.is_move_reg,
            };
            self.count += 1;
        }
    }

    /// Simulate the pipeline and return max(cycles - 3, 1).
    /// Matches gas_sim_traced() behavior exactly.
    pub fn flush_and_get_cost(&mut self) -> u32 {
        let n = self.count;
        if n == 0 { return 1; }

        // ROB entries (stack-allocated)
        let mut state = [State::Fin; MAX_INSTRS];
        let mut cycles_left = [0u8; MAX_INSTRS];
        let mut deps = [0u32; MAX_INSTRS]; // bitmask of ROB indices this entry depends on
        let mut exec_unit = [0u8; MAX_INSTRS];
        let mut rob_len: usize = 0;

        // Per-register: bitmask of ROB entries that wrote it and haven't finished yet
        let mut reg_writers = [0u32; 16];

        // Simulation state
        let mut ip: usize = 0; // next instruction to decode (index into self.instrs)
        let mut decode_slots: u8 = 4;
        let mut dispatch_slots: u8 = 5;
        let mut eu_avail: [u8; 5] = [4, 4, 4, 1, 1]; // alu, load, store, mul, div
        let mut cycles: u32 = 0;
        let mut ip_done = false; // true when all instructions decoded (or terminator hit)

        for _ in 0..100_000u32 {
            // Priority 1: Decode
            if !ip_done && ip < n && decode_slots > 0 && rob_len < MAX_INSTRS {
                let inst = &self.instrs[ip];

                if inst.is_move_reg {
                    // move_reg: consume decode slots, no ROB entry
                    decode_slots = decode_slots.saturating_sub(inst.decode_slots);
                    ip += 1;
                    if ip >= n { ip_done = true; }
                    continue;
                }

                {
                    // Build dependency mask: depend on ALL non-Fin writers of source regs
                    let mut dep_mask: u32 = 0;
                    let mut src = inst.src_mask;
                    while src != 0 {
                        let reg = src.trailing_zeros() as usize;
                        src &= src - 1;
                        if reg < 16 {
                            // Add all non-Fin writers of this register
                            let mut writers = reg_writers[reg];
                            while writers != 0 {
                                let w = writers.trailing_zeros() as usize;
                                writers &= writers - 1;
                                if state[w] != State::Fin {
                                    dep_mask |= 1u32 << w;
                                }
                            }
                        }
                    }

                    // Insert into ROB
                    let slot = rob_len;
                    state[slot] = State::Wait;
                    cycles_left[slot] = inst.cycles;
                    deps[slot] = dep_mask;
                    exec_unit[slot] = inst.exec_unit;
                    rob_len += 1;

                    // Update register writers (add this slot to writer set)
                    let mut dst = inst.dst_mask;
                    while dst != 0 {
                        let reg = dst.trailing_zeros() as usize;
                        dst &= dst - 1;
                        if reg < 16 {
                            reg_writers[reg] |= 1u32 << slot;
                        }
                    }

                    decode_slots = decode_slots.saturating_sub(inst.decode_slots);
                    ip += 1;
                    if ip >= n { ip_done = true; }
                    continue;
                }
            }  // end priority 1

            // Priority 2: Dispatch one ready entry
            let mut dispatched = false;
            if dispatch_slots > 0 {
                for i in 0..rob_len {
                    if state[i] != State::Wait { continue; }
                    // Check all deps are Fin
                    let dep = deps[i];
                    let mut all_fin = true;
                    let mut d = dep;
                    while d != 0 {
                        let j = d.trailing_zeros() as usize;
                        d &= d - 1;
                        if state[j] != State::Fin { all_fin = false; break; }
                    }
                    if !all_fin { continue; }
                    // Check EU available
                    if !eu_available(&eu_avail, exec_unit[i]) { continue; }

                    // Dispatch
                    eu_consume(&mut eu_avail, exec_unit[i]);
                    state[i] = State::Exe;
                    dispatch_slots -= 1;
                    dispatched = true;
                    break;
                }
            }
            if dispatched { continue; }

            // Priority 3: Check done
            if ip_done {
                let mut all_done = true;
                for i in 0..rob_len {
                    if state[i] != State::Fin { all_done = false; break; }
                }
                if all_done { break; }
            }

            // Priority 4: Advance cycle
            for i in 0..rob_len {
                if state[i] == State::Exe {
                    if cycles_left[i] <= 1 {
                        state[i] = State::Fin;
                        cycles_left[i] = 0;
                    } else {
                        cycles_left[i] -= 1;
                    }
                }
            }
            cycles += 1;
            decode_slots = 4;
            dispatch_slots = 5;
            eu_avail = [4, 4, 4, 1, 1];
        }

        let c = cycles;
        if c > 3 { c - 3 } else { 1 }
    }

    /// Reset for the next gas block.
    #[inline]
    pub fn reset(&mut self) {
        self.count = 0;
    }
}

#[inline(always)]
fn eu_available(avail: &[u8; 5], eu: u8) -> bool {
    match eu {
        0 => true,       // EU_NONE
        1 => avail[0] >= 1, // EU_ALU
        2 => avail[0] >= 1 && avail[1] >= 1, // EU_LOAD (alu + load)
        3 => avail[0] >= 1 && avail[2] >= 1, // EU_STORE (alu + store)
        4 => avail[0] >= 1 && avail[3] >= 1, // EU_MUL (alu + mul)
        5 => avail[0] >= 1 && avail[4] >= 1, // EU_DIV (alu + div)
        _ => false,
    }
}

#[inline(always)]
fn eu_consume(avail: &mut [u8; 5], eu: u8) {
    match eu {
        1 => { avail[0] -= 1; }             // ALU
        2 => { avail[0] -= 1; avail[1] -= 1; } // LOAD
        3 => { avail[0] -= 1; avail[2] -= 1; } // STORE
        4 => { avail[0] -= 1; avail[3] -= 1; } // MUL
        5 => { avail[0] -= 1; avail[4] -= 1; } // DIV
        _ => {}
    }
}
