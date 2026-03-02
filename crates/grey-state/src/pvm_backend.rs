//! Pluggable PVM backend.
//!
//! Provides a unified `PvmInstance` wrapper around either:
//! - `grey-pvm` (default) — our own PVM implementation
//! - `polkavm` (feature `polkavm`) — the reference PVM implementation
//!
//! The accumulate code uses `PvmInstance` so switching backends is just
//! a feature flag: `cargo test --features polkavm`.

use grey_types::Gas;

/// Backend-independent PVM exit reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitReason {
    Halt,
    Panic,
    OutOfGas,
    PageFault(u32),
    HostCall(u32),
}

// =========================================================================
// grey-pvm backend (default)
// =========================================================================

#[cfg(not(feature = "polkavm"))]
pub struct PvmInstance {
    inner: grey_pvm::vm::Pvm,
}

#[cfg(not(feature = "polkavm"))]
impl PvmInstance {
    /// Create a PVM from a code blob, arguments, and gas budget.
    pub fn initialize(code_blob: &[u8], args: &[u8], gas: Gas) -> Option<Self> {
        grey_pvm::program::initialize_program(code_blob, args, gas)
            .map(|pvm| PvmInstance { inner: pvm })
    }

    /// Run until exit (halt, panic, OOG, page fault, or host call).
    pub fn run(&mut self) -> ExitReason {
        let (reason, _) = self.inner.run();
        match reason {
            grey_pvm::ExitReason::Halt => ExitReason::Halt,
            grey_pvm::ExitReason::Panic => ExitReason::Panic,
            grey_pvm::ExitReason::OutOfGas => ExitReason::OutOfGas,
            grey_pvm::ExitReason::PageFault(a) => ExitReason::PageFault(a),
            grey_pvm::ExitReason::HostCall(id) => ExitReason::HostCall(id),
        }
    }

    pub fn gas(&self) -> Gas {
        self.inner.gas
    }
    pub fn set_gas(&mut self, gas: Gas) {
        self.inner.gas = gas;
    }

    pub fn pc(&self) -> u32 {
        self.inner.pc
    }
    pub fn set_pc(&mut self, pc: u32) {
        self.inner.pc = pc;
    }

    pub fn reg(&self, index: usize) -> u64 {
        self.inner.registers[index]
    }
    pub fn set_reg(&mut self, index: usize, value: u64) {
        self.inner.registers[index] = value;
    }

    pub fn read_byte(&self, addr: u32) -> Option<u8> {
        self.inner.memory.read_u8(addr)
    }

    pub fn write_byte(&mut self, addr: u32, value: u8) {
        self.inner.memory.write_u8(addr, value);
    }

    pub fn read_bytes(&self, addr: u32, len: u32) -> Vec<u8> {
        (0..len)
            .map(|i| self.inner.memory.read_u8(addr + i).unwrap_or(0))
            .collect()
    }

    pub fn write_bytes(&mut self, addr: u32, data: &[u8]) {
        for (i, &byte) in data.iter().enumerate() {
            self.inner.memory.write_u8(addr + i as u32, byte);
        }
    }
}

// =========================================================================
// polkavm backend (feature = "polkavm")
// =========================================================================

#[cfg(feature = "polkavm")]
pub struct PvmInstance {
    instance: polkavm::RawInstance,
    /// GP-conformant heap pointer, starts at rw_data_address (not polkavm's heap_base).
    heap_ptr: u32,
    /// Decoded code bytes for sbrk instruction detection during step tracing.
    code: Vec<u8>,
}

#[cfg(feature = "polkavm")]
impl PvmInstance {
    /// Create a PVM from a code blob, arguments, and gas budget.
    ///
    /// Uses polkavm in standard mode with step_tracing to intercept sbrk.
    ///
    /// polkavm's memory layout matches the GP when VM_MAX_PAGE_SIZE == ZZ,
    /// EXCEPT heap_base: polkavm puts it at rw_addr + rw_size, while GP
    /// puts it at rw_addr. We intercept sbrk via step_tracing to return
    /// the GP-conformant value.
    pub fn initialize(code_blob: &[u8], args: &[u8], gas: Gas) -> Option<Self> {
        let (ro_size, rw_size, heap_pages, stack_size, ro_data, rw_data, code) =
            parse_gp_blob(code_blob)?;

        let mut config = polkavm::Config::new();
        config.set_backend(Some(polkavm::BackendKind::Interpreter));
        let engine = polkavm::Engine::new(&config).ok()?;

        let page_size = grey_types::constants::PVM_PAGE_SIZE;
        let zi = grey_types::constants::PVM_INIT_INPUT_SIZE;

        // rw region includes declared rw_data + heap pages (GP eq A.42)
        let rw_total = rw_size + heap_pages * page_size;

        // Keep a copy of the code bytes for sbrk detection
        let code_bytes = code.clone();

        let mut parts = polkavm_common::program::ProgramParts::empty(
            polkavm_common::program::InstructionSetKind::JamV1,
        );
        parts.ro_data_size = ro_size;
        parts.rw_data_size = rw_total;
        parts.stack_size = stack_size;
        parts.ro_data = polkavm_common::utils::ArcBytes::from(ro_data);
        parts.rw_data = polkavm_common::utils::ArcBytes::from(rw_data);
        parts.code_and_jump_table = polkavm_common::utils::ArcBytes::from(code);

        let blob = polkavm::ProgramBlob::from_parts(parts).ok()?;
        let mut module_config = polkavm::ModuleConfig::new();
        module_config.set_gas_metering(Some(polkavm::GasMeteringKind::Sync));
        module_config.set_aux_data_size(zi);
        module_config.set_step_tracing(true);

        let module = polkavm::Module::from_blob(&engine, &module_config, blob).ok()?;
        let mem_map = module.memory_map();
        let aux_addr = mem_map.aux_data_address();
        let rw_addr = mem_map.rw_data_address();

        let mut instance = module.instantiate().ok()?;

        // Write arguments into the aux_data region
        if !args.is_empty() {
            instance.write_memory(aux_addr, args).ok()?;
        }

        // Set registers per GP standard initialization Y(p,a) (eq A.43)
        instance.set_gas(gas as i64);
        instance.set_reg(polkavm::Reg::RA, 0xFFFF0000u64);
        instance.set_reg(polkavm::Reg::SP, u64::from(mem_map.stack_address_high()));
        instance.set_reg(polkavm::Reg::A0, u64::from(aux_addr));
        instance.set_reg(polkavm::Reg::A1, args.len() as u64);
        instance.set_next_program_counter(polkavm::ProgramCounter(0));

        // GP heap_ptr starts at rw_data_address (not polkavm's heap_base)
        let heap_ptr = rw_addr;

        Some(PvmInstance {
            instance,
            heap_ptr,
            code: code_bytes,
        })
    }

    /// Run until exit, intercepting sbrk instructions via step tracing.
    pub fn run(&mut self) -> ExitReason {
        loop {
            match self.instance.run().expect("polkavm run error") {
                polkavm::InterruptKind::Finished => return ExitReason::Halt,
                polkavm::InterruptKind::Trap => return ExitReason::Panic,
                polkavm::InterruptKind::NotEnoughGas => return ExitReason::OutOfGas,
                polkavm::InterruptKind::Ecalli(id) => return ExitReason::HostCall(id),
                polkavm::InterruptKind::Step => {
                    let pc = self
                        .instance
                        .program_counter()
                        .map(|p| p.0)
                        .unwrap_or(0) as usize;
                    if pc < self.code.len() && self.code[pc] == 101 {
                        eprintln!("[sbrk_intercept] at pc={pc}");
                        self.handle_sbrk(pc);
                    }
                    continue;
                }
                other => panic!("unexpected polkavm interrupt: {other:?}"),
            }
        }
    }

    /// Emulate GP-conformant sbrk (opcode 101).
    ///
    /// GP sbrk: reg[rd] = h_p (old heap pointer), h_p' = h_p + reg[ra]
    fn handle_sbrk(&mut self, pc: usize) {
        let arg_byte = if pc + 1 < self.code.len() {
            self.code[pc + 1]
        } else {
            0
        };
        let rd = (arg_byte % 16).min(12) as usize;
        let ra = (arg_byte / 16).min(12) as usize;

        let size = self.instance.reg(reg_from_index(ra));
        let old_hp = self.heap_ptr;
        let new_hp = old_hp as u64 + size;

        if new_hp <= u32::MAX as u64 {
            self.instance
                .set_reg(reg_from_index(rd), old_hp as u64);
            self.heap_ptr = new_hp as u32;
        } else {
            self.instance
                .set_reg(reg_from_index(rd), u64::MAX);
        }

        // Skip past the 2-byte sbrk instruction
        self.instance
            .set_next_program_counter(polkavm::ProgramCounter((pc + 2) as u32));
    }

    pub fn gas(&self) -> Gas {
        self.instance.gas().max(0) as u64
    }
    pub fn set_gas(&mut self, gas: Gas) {
        self.instance.set_gas(gas as i64);
    }

    pub fn pc(&self) -> u32 {
        self.instance
            .program_counter()
            .map(|p| p.0)
            .unwrap_or(0)
    }
    pub fn set_pc(&mut self, pc: u32) {
        self.instance
            .set_next_program_counter(polkavm::ProgramCounter(pc));
    }

    pub fn reg(&self, index: usize) -> u64 {
        self.instance.reg(reg_from_index(index))
    }
    pub fn set_reg(&mut self, index: usize, value: u64) {
        self.instance.set_reg(reg_from_index(index), value);
    }

    pub fn read_byte(&self, addr: u32) -> Option<u8> {
        let mut buf = [0u8; 1];
        self.instance
            .read_memory_into(addr, &mut buf)
            .ok()
            .map(|s| s[0])
    }

    pub fn write_byte(&mut self, addr: u32, value: u8) {
        let _ = self.instance.write_memory(addr, &[value]);
    }

    pub fn read_bytes(&self, addr: u32, len: u32) -> Vec<u8> {
        self.instance
            .read_memory(addr, len)
            .unwrap_or_else(|_| vec![0u8; len as usize])
    }

    pub fn write_bytes(&mut self, addr: u32, data: &[u8]) {
        if !data.is_empty() {
            let _ = self.instance.write_memory(addr, data);
        }
    }
}

#[cfg(feature = "polkavm")]
fn reg_from_index(i: usize) -> polkavm::Reg {
    match i {
        0 => polkavm::Reg::RA,
        1 => polkavm::Reg::SP,
        2 => polkavm::Reg::T0,
        3 => polkavm::Reg::T1,
        4 => polkavm::Reg::T2,
        5 => polkavm::Reg::S0,
        6 => polkavm::Reg::S1,
        7 => polkavm::Reg::A0,
        8 => polkavm::Reg::A1,
        9 => polkavm::Reg::A2,
        10 => polkavm::Reg::A3,
        11 => polkavm::Reg::A4,
        12 => polkavm::Reg::A5,
        _ => panic!("invalid register index: {i}"),
    }
}

// --- GP blob parsing (shared with grey-pvm, needed for polkavm init) ---

#[cfg(feature = "polkavm")]
fn parse_gp_blob(
    raw_blob: &[u8],
) -> Option<(u32, u32, u32, u32, Vec<u8>, Vec<u8>, Vec<u8>)> {
    let blob = skip_metadata(raw_blob);
    if blob.len() < 15 {
        return None;
    }
    let mut offset = 0;

    let ro_size = read_le_u24(blob, &mut offset)?;
    let rw_size = read_le_u24(blob, &mut offset)?;
    let heap_pages = read_le_u16(blob, &mut offset)? as u32;
    let stack_size = read_le_u24(blob, &mut offset)?;

    if offset + ro_size as usize > blob.len() {
        return None;
    }
    let ro_data = blob[offset..offset + ro_size as usize].to_vec();
    offset += ro_size as usize;

    if offset + rw_size as usize > blob.len() {
        return None;
    }
    let rw_data = blob[offset..offset + rw_size as usize].to_vec();
    offset += rw_size as usize;

    let code_len = read_le_u32(blob, &mut offset)? as usize;
    if offset + code_len > blob.len() {
        return None;
    }
    let code = blob[offset..offset + code_len].to_vec();

    Some((ro_size, rw_size, heap_pages, stack_size, ro_data, rw_data, code))
}

#[cfg(feature = "polkavm")]
fn skip_metadata(blob: &[u8]) -> &[u8] {
    if blob.len() < 14 {
        return blob;
    }
    let ro_size = blob[0] as u32 | ((blob[1] as u32) << 8) | ((blob[2] as u32) << 16);
    if (ro_size as usize) + 14 <= blob.len() {
        return blob;
    }
    let first = blob[0];
    let (meta_len, consumed) = if first < 128 {
        (first as usize, 1)
    } else if first < 192 {
        if blob.len() < 2 {
            return blob;
        }
        let val = ((first as usize & 0x3F) << 8) | blob[1] as usize;
        (val, 2)
    } else {
        return blob;
    };
    let skip = consumed + meta_len;
    if skip < blob.len() {
        &blob[skip..]
    } else {
        blob
    }
}

#[cfg(feature = "polkavm")]
fn read_le_u16(data: &[u8], offset: &mut usize) -> Option<u16> {
    if *offset + 2 > data.len() {
        return None;
    }
    let val = u16::from_le_bytes([data[*offset], data[*offset + 1]]);
    *offset += 2;
    Some(val)
}

#[cfg(feature = "polkavm")]
fn read_le_u24(data: &[u8], offset: &mut usize) -> Option<u32> {
    if *offset + 3 > data.len() {
        return None;
    }
    let val =
        data[*offset] as u32 | ((data[*offset + 1] as u32) << 8) | ((data[*offset + 2] as u32) << 16);
    *offset += 3;
    Some(val)
}

#[cfg(feature = "polkavm")]
fn read_le_u32(data: &[u8], offset: &mut usize) -> Option<u32> {
    if *offset + 4 > data.len() {
        return None;
    }
    let val = u32::from_le_bytes([
        data[*offset],
        data[*offset + 1],
        data[*offset + 2],
        data[*offset + 3],
    ]);
    *offset += 4;
    Some(val)
}
