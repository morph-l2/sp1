mod air;
mod columns;
mod trace;

pub use air::*;
pub use columns::*;
pub use trace::*;

use sp1_core::{
    utils::field::Field,
    runtime::Syscall,
};

// Core parameters for Poseidon hash
pub const WIDTH: usize = 3;
pub const FULL_ROUNDS: usize = 8;
pub const PARTIAL_ROUNDS: usize = 57;
pub const RATE: usize = 2;

// BN254-optimized MDS matrix (matching Scroll's implementation)
pub const POSEIDON_MDS: [[u64; WIDTH]; WIDTH] = [
    [0x2c6dad64b519f5f6, 0x88d797e2c3587014, 0xa07f783a0d634fb9],
    [0x2d80f016b6755e0c, 0x7433dfee8f82b561, 0x8c7131f3c6a437cb],
    [0x1c6046d8df5c8e93, 0xa7e6bdf9c9ebde0e, 0x980d68b4f6972ad4],
];

// Round constants for full rounds
pub const POSEIDON_ROUND_CONSTANTS: [u64; WIDTH * FULL_ROUNDS] = [
    0x0ee9a592707cd727, 0x31f96748d6800b8e, 0x43a7a26a2c46f8c4,
    0x9a9f5f67318bb461, 0x9a9f5f67318bb461, 0x9a9f5f67318bb461,
    0x9a9f5f67318bb461, 0x9a9f5f67318bb461, 0x9a9f5f67318bb461,
];

// Round constants for partial rounds
pub const POSEIDON_PARTIAL_CONSTANTS: [u64; WIDTH * PARTIAL_ROUNDS] = [
    0x18b075d6a5625b6e, 0x7e1d133dca7ac9d5, 0x9d80857ae9751e67,
    0x9a9f5f67318bb461, 0x9a9f5f67318bb461, 0x9a9f5f67318bb461,
];

#[derive(Default)]
pub struct PoseidonChip;

impl PoseidonChip {
    pub const fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
pub mod poseidon_tests {
    use sp1_core_executor::{syscalls::SyscallCode, Instruction, Opcode, Program};
    use sp1_stark::CpuProver;
    use test_artifacts::POSEIDON_ELF;
    use crate::utils::{run_test, setup_logger};

    pub fn poseidon_program() -> Program {
        let input_ptr = 100;
        let output_ptr = 1000;
        
        let mut instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true)
        ];

        // Setup input state
        for i in 0..WIDTH {
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 30, 0, input_ptr + i * 4, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
            ]);
        }

        // Call Poseidon
        instructions.extend(vec![
            Instruction::new(Opcode::ADD, 5, 0, SyscallCode::POSEIDON as u32, false, true),
            Instruction::new(Opcode::ADD, 10, 0, input_ptr, false, true),
            Instruction::new(Opcode::ADD, 11, 0, output_ptr, false, true),
            Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
        ]);

        Program::new(instructions, 0, 0)
    }

    #[test]
    fn prove_babybear() {
        setup_logger();
        let program = poseidon_program();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_poseidon_program() {
        setup_logger();
        let program = Program::from(POSEIDON_ELF).unwrap();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }
}