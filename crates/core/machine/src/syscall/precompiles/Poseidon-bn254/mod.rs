mod air;
mod columns;
mod trace;

pub use air::*;
pub use columns::*;
pub use trace::*;

use sp1_core_executor::{
    events::{ByteRecord, FieldOperation, PrecompileEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use sp1_stark::{
    air::{BaseAirBuilder, InteractionScope, MachineAir, Polynomial, SP1AirBuilder},
    MachineRecord,
};
use sp1_curves::{
    params::{Limbs, NumLimbs, NumWords},
    uint256::U256Field,
    weierstrass::bn254::Bn254ScalarField,
};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_air::{Air, AirBuilder, BaseAir};
use num::{BigUint, One, Zero};

pub const WIDTH: usize = 3;
pub const FULL_ROUNDS: usize = 8;
pub const PARTIAL_ROUNDS: usize = 57;
pub const RATE: usize = 2;
pub const NUM_COLS: usize = size_of::<PoseidonCols<u8>>();

pub const POSEIDON_MDS: [[u64; WIDTH]; WIDTH] = [
    [0x2c6dad64b519f5f6, 0x88d797e2c3587014, 0xa07f783a0d634fb9],
    [0x2d80f016b6755e0c, 0x7433dfee8f82b561, 0x8c7131f3c6a437cb],
    [0x1c6046d8df5c8e93, 0xa7e6bdf9c9ebde0e, 0x980d68b4f6972ad4],
];

pub const POSEIDON_ROUND_CONSTANTS: [[u64; WIDTH]; FULL_ROUNDS] = [
    [0x0ee9a592707cd727, 0x31f96748d6800b8e, 0x43a7a26a2c46f8c4],
    [0x273b2e90f3844677, 0x0b84c7f81b420ef3, 0x4b7814aa1c136336],
    [0x4f6b30dd1dda2c34, 0x34c082258a3a00d6, 0x0827694a053cf4b6],
    [0x36ae6793eb7d2052, 0x4e56b8d5f7defde4, 0x223e35558ed85f2b],
    [0x0c74c1e32def5e9f, 0x0b9e3f19c8e5d191, 0x4ff34451be63f050],
    [0x08b6e2d2c4467642, 0x366be28448dc562a, 0x4c43183de1739691],
    [0x37962c7e4222ff96, 0x1ba80d4be0c8090f, 0x4c43183de1739691],
    [0x2c6dad64b519f5f6, 0x88d797e2c3587014, 0xa07f783a0d634fb9],
];

pub const POSEIDON_PARTIAL_CONSTANTS: [u64; PARTIAL_ROUNDS] = [
    0x18b075d6a5625b6e, 0x7e1d133dca7ac9d5, 0x9d80857ae9751e67,
    0x0ee9a592707cd727, 0x31f96748d6800b8e, 0x43a7a26a2c46f8c4,
    0x273b2e90f3844677, 0x0b84c7f81b420ef3, 0x4b7814aa1c136336,
    0x4f6b30dd1dda2c34, 0x34c082258a3a00d6, 0x0827694a053cf4b6,
    0x36ae6793eb7d2052, 0x4e56b8d5f7defde4, 0x223e35558ed85f2b,
    0x0c74c1e32def5e9f, 0x0b9e3f19c8e5d191, 0x4ff34451be63f050,
    0x08b6e2d2c4467642, 0x366be28448dc562a, 0x4c43183de1739691,
    0x37962c7e4222ff96, 0x1ba80d4be0c8090f, 0x4c43183de1739691,
    0x2c6dad64b519f5f6, 0x88d797e2c3587014, 0xa07f783a0d634fb9,
    0x2d80f016b6755e0c, 0x7433dfee8f82b561, 0x8c7131f3c6a437cb,
    0x1c6046d8df5c8e93, 0xa7e6bdf9c9ebde0e, 0x980d68b4f6972ad4,
    0x18b075d6a5625b6e, 0x7e1d133dca7ac9d5, 0x9d80857ae9751e67,
    0x0ee9a592707cd727, 0x31f96748d6800b8e, 0x43a7a26a2c46f8c4,
    0x273b2e90f3844677, 0x0b84c7f81b420ef3, 0x4b7814aa1c136336,
    0x4f6b30dd1dda2c34, 0x34c082258a3a00d6, 0x0827694a053cf4b6,
    0x36ae6793eb7d2052, 0x4e56b8d5f7defde4, 0x223e35558ed85f2b,
    0x0c74c1e32def5e9f, 0x0b9e3f19c8e5d191, 0x4ff34451be63f050,
    0x08b6e2d2c4467642, 0x366be28448dc562a, 0x4c43183de1739691,
    0x37962c7e4222ff96, 0x1ba80d4be0c8090f, 0x4c43183de1739691,
    0x2c6dad64b519f5f6, 0x88d797e2c3587014, 0xa07f783a0d634fb9,
];

type WordsFieldElement = <U256Field as NumWords>::WordsFieldElement;
const WORDS_FIELD_ELEMENT: usize = WordsFieldElement::USIZE;

#[derive(Default)]
pub struct PoseidonChip;

impl PoseidonChip {
    pub const fn new() -> Self {
        Self {}
    }
}

impl<F: PrimeField32> MachineAir<F> for PoseidonChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Poseidon".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();
        
        // Process Poseidon events
        for (_, event) in input.get_precompile_events(SyscallCode::POSEIDON) {
            let event = if let PrecompileEvent::Poseidon(event) = event {
                event
            } else {
                unreachable!()
            };
            
            // Generate trace rows for this event
            let mut state = [F::zero(); WIDTH];
            
            // Initialize state with input
            for i in 0..RATE {
                state[i] = event.input[i];
            }
            
            // Add trace rows for each round
            for round in 0..FULL_ROUNDS + PARTIAL_ROUNDS {
                let is_full = round < FULL_ROUNDS/2 || round >= FULL_ROUNDS/2 + PARTIAL_ROUNDS;
                
                let mut row = vec![F::zero(); NUM_COLS];
                let cols: &mut PoseidonCols<F> = row.as_mut_slice().borrow_mut();
                
                cols.populate_trace_row(
                    event.shard,
                    event.clk,
                    round as u32,
                    &state,
                    is_full,
                );
                
                rows.push(row);
            }
        }

        // Pad rows to power of 2
        while !rows.len().is_power_of_two() {
            let mut row = vec![F::zero(); NUM_COLS];
            let cols: &mut PoseidonCols<F> = row.as_mut_slice().borrow_mut();
            cols.populate_empty_row();
            rows.push(row);
        }

        RowMajorMatrix::new(
            rows.into_iter().flatten().collect(),
            NUM_COLS
        )
    }

    fn included(&self, record: &Self::Record) -> bool {
        !record.get_precompile_events(SyscallCode::POSEIDON).is_empty()
    }
}

#[cfg(test)]
pub mod poseidon_tests {
    use super::*;
    use sp1_core_executor::{
        syscalls::SyscallCode,
        Instruction, 
        Opcode,
        Program,
    };
    
    pub fn poseidon_program() -> Program {
        let input_ptr = 100;
        let output_ptr = 1000;
        
        let mut instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true)
        ];

        for i in 0..WIDTH {
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 30, 0, input_ptr + i * 4, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
            ]);
        }

        instructions.extend(vec![
            Instruction::new(Opcode::ADD, 5, 0, SyscallCode::POSEIDON as u32, false, true),
            Instruction::new(Opcode::ADD, 10, 0, input_ptr, false, true),
            Instruction::new(Opcode::ADD, 11, 0, output_ptr, false, true),
            Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
        ]);

        Program::new(instructions, 0, 0)
    }

    #[test]
    fn test_poseidon() {
        let program = poseidon_program();
        let chip = PoseidonChip::new();
        
        let mut input_record = ExecutionRecord::default();
        let mut output_record = ExecutionRecord::default();
        
        // Add test event
        input_record.add_precompile_event(
            SyscallCode::POSEIDON,
            PrecompileEvent::Poseidon(PoseidonEvent {
                shard: 0,
                clk: 0,
                input: [
                    Bn254ScalarField::from_canonical_u64(1),
                    Bn254ScalarField::from_canonical_u64(2),
                    Bn254ScalarField::from_canonical_u64(3),
                ],
                output: [Bn254ScalarField::from_canonical_u64(0)],
            })
        );
        
        let trace = chip.generate_trace(&input_record, &mut output_record);
        
        assert_eq!(trace.height(), FULL_ROUNDS + PARTIAL_ROUNDS);
        assert_eq!(trace.width(), NUM_COLS);
    }
}