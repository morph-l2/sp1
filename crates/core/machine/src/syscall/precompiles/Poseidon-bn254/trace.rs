use super::*;

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

impl PoseidonChip {
    pub fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<Field> {
        let mut rows = Vec::new();
        let mut new_byte_lookup_events = Vec::new();

        // Process Poseidon events
        for (_, event) in input.get_precompile_events(SyscallCode::POSEIDON) {
            let event = if let PrecompileEvent::Poseidon(event) = event {
                event
            } else {
                unreachable!()
            };

            // Generate rows for each round
            let mut state = [Field::zero(); WIDTH];
            
            // Initialize state with input values
            for i in 0..WIDTH {
                state[i] = Field::from_canonical_u64(event.input[i]);
            }

            // Process each round
            for round in 0..FULL_ROUNDS + PARTIAL_ROUNDS {
                let is_full = round < FULL_ROUNDS/2 || 
                             round >= FULL_ROUNDS/2 + PARTIAL_ROUNDS;
                
                let mut row = vec![Field::zero(); NUM_COLS];
                let cols: &mut PoseidonCols<Field> = row.as_mut_slice().borrow_mut();

                // Set execution context
                cols.is_real = Field::one();
                cols.shard = Field::from_canonical_u32(event.shard);
                cols.clk = Field::from_canonical_u32(event.clk);
                cols.round_ctr = Field::from_canonical_u32(round as u32);
                cols.is_full_round = if is_full { Field::one() } else { Field::zero() };

                // Set current state
                cols.state.copy_from_slice(&state);

                // Set round constants
                if is_full {
                    let rc_idx = if round < FULL_ROUNDS/2 { 
                        round 
                    } else { 
                        round - PARTIAL_ROUNDS 
                    };
                    for i in 0..WIDTH {
                        cols.round_constants[i] = Field::from_canonical_u64(
                            POSEIDON_ROUND_CONSTANTS[rc_idx][i]
                        );
                    }
                } else {
                    cols.round_constants[0] = Field::from_canonical_u64(
                        POSEIDON_PARTIAL_CONSTANTS[round - FULL_ROUNDS/2]
                    );
                    for i in 1..WIDTH {
                        cols.round_constants[i] = Field::zero();
                    }
                }

                // 1. Add round constants (ARK)
                let mut ark_state = state;
                for i in 0..WIDTH {
                    ark_state[i] += cols.round_constants[i];
                }
                cols.ark_state.copy_from_slice(&ark_state);

                // 2. S-box layer
                let mut sbox_state = ark_state;
                if is_full {
                    for i in 0..WIDTH {
                        let square = sbox_state[i].square();
                        let quad = square.square();
                        sbox_state[i] = quad * sbox_state[i];
                    }
                } else {
                    let square = sbox_state[0].square();
                    let quad = square.square();
                    sbox_state[0] = quad * sbox_state[0];
                }
                cols.sbox_state.copy_from_slice(&sbox_state);

                // 3. Mix layer (MDS)
                let mut mix_state = [Field::zero(); WIDTH];
                for i in 0..WIDTH {
                    for j in 0..WIDTH {
                        mix_state[i] += sbox_state[j] * Field::from_canonical_u64(
                            POSEIDON_MDS[i][j]
                        );
                    }
                }
                cols.mix_state.copy_from_slice(&mix_state);

                // Update state for next round
                state = mix_state;
                cols.next_state.copy_from_slice(&state);

                // Set memory related values
                cols.input_ptr = Field::from_canonical_u32(event.input_ptr);
                cols.output_ptr = Field::from_canonical_u32(event.output_ptr);

                // Set computation flags
                cols.is_arithmetic = Field::one();
                cols.is_binary = Field::zero();
                cols.is_memory_op = if round == 0 || round == FULL_ROUNDS + PARTIAL_ROUNDS - 1 {
                    Field::one()
                } else {
                    Field::zero()
                };

                rows.push(row);
            }
        }

        // Pad rows to power of 2
        while !rows.len().is_power_of_two() {
            let mut row = vec![Field::zero(); NUM_COLS];
            let cols: &mut PoseidonCols<Field> = row.as_mut_slice().borrow_mut();
            
            // Initialize empty state
            let zero_state = [Field::zero(); WIDTH];
            
            // Set minimal required values for empty rows
            cols.state.copy_from_slice(&zero_state);
            cols.next_state.copy_from_slice(&zero_state);
            cols.ark_state.copy_from_slice(&zero_state);
            cols.sbox_state.copy_from_slice(&zero_state);
            cols.mix_state.copy_from_slice(&zero_state);
            
            rows.push(row);
        }

        // Add byte lookup events to output record
        output.add_byte_lookup_events(new_byte_lookup_events);

        // Convert to matrix
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect(),
            NUM_COLS
        );

        // Write nonces
        for i in 0..trace.height() {
            let cols: &mut PoseidonCols<Field> = trace.row_slice_mut(i).borrow_mut();
            cols.nonce = Field::from_canonical_usize(i);
        }

        trace
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_generation() {
        let chip = PoseidonChip::new();
        
        let mut input_record = ExecutionRecord::default();
        let mut output_record = ExecutionRecord::default();

        // Create test event
        let test_event = PrecompileEvent::Poseidon(PoseidonEvent {
            shard: 0,
            clk: 0,
            input_ptr: 100,
            output_ptr: 200,
            input: [1u64, 2u64, 3u64],
        });

        input_record.add_precompile_event(SyscallCode::POSEIDON, test_event);

        let trace = chip.generate_trace(&input_record, &mut output_record);

        // Verify trace dimensions
        assert!(trace.height().is_power_of_two());
        assert_eq!(trace.width(), NUM_COLS);

        // Check first row
        let first_row: &PoseidonCols<Field> = trace.row_slice(0).borrow();
        assert_eq!(first_row.is_real, Field::one());
        assert_eq!(first_row.round_ctr, Field::zero());
        assert_eq!(first_row.is_full_round, Field::one());

        // Check state initialization
        assert_eq!(first_row.state[0], Field::from_canonical_u64(1));
        assert_eq!(first_row.state[1], Field::from_canonical_u64(2));
        assert_eq!(first_row.state[2], Field::from_canonical_u64(3));

        // Check last real row
        let last_row: &PoseidonCols<Field> = trace.row_slice(FULL_ROUNDS + PARTIAL_ROUNDS - 1).borrow();
        assert_eq!(last_row.is_real, Field::one());
        assert_ne!(last_row.state[0], Field::zero()); // Hash output should be non-zero
    }
}