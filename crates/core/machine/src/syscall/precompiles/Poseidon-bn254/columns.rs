use super::*;
use sp1_derive::AlignedBorrow;


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
/// Number of state elements
pub const STATE_WIDTH: usize = WIDTH;

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct PoseidonCols<T> {
    /// Execution context
    pub is_real: T,
    pub shard: T,
    pub clk: T,
    pub nonce: T,

    /// Round information
    pub round_ctr: T,
    pub is_full_round: T,

    /// Current state
    pub state: [T; STATE_WIDTH],
    
    /// Round constants for current round
    pub round_constants: [T; STATE_WIDTH],

    /// State after adding round constants (ARK)
    pub ark_state: [T; STATE_WIDTH],

    /// State after S-box layer
    pub sbox_state: [T; STATE_WIDTH],

    /// State after mix layer (MDS)
    pub mix_state: [T; STATE_WIDTH],

    /// State for next round
    pub next_state: [T; STATE_WIDTH],

    /// Memory operation flags and data
    pub is_memory_op: T,
    pub is_arithmetic: T,
    pub is_binary: T,
    pub is_input_op: T,
    pub is_output_op: T,
    
    /// Memory pointers
    pub input_ptr: T,
    pub output_ptr: T,

    /// Output value
    pub output_value: T,
}

impl<T: Clone + Default> Default for PoseidonCols<T> {
    fn default() -> Self {
        Self {
            // Execution context
            is_real: T::default(),
            shard: T::default(),
            clk: T::default(),
            nonce: T::default(),

            // Round information
            round_ctr: T::default(),
            is_full_round: T::default(),

            // States
            state: [T::default(); STATE_WIDTH],
            round_constants: [T::default(); STATE_WIDTH],
            ark_state: [T::default(); STATE_WIDTH],
            sbox_state: [T::default(); STATE_WIDTH],
            mix_state: [T::default(); STATE_WIDTH],
            next_state: [T::default(); STATE_WIDTH],

            // Memory operation flags
            is_memory_op: T::default(),
            is_arithmetic: T::default(),
            is_binary: T::default(),
            is_input_op: T::default(),
            is_output_op: T::default(),

            // Memory pointers
            input_ptr: T::default(),
            output_ptr: T::default(),

            // Output value
            output_value: T::default(),
        }
    }
}

impl<F: Field> PoseidonCols<F> {
    /// Populate a trace row for a real computation
    pub fn populate_trace_row(
        &mut self,
        shard: u32,
        clk: u32,
        round: u32,
        state: &[F; STATE_WIDTH],
        is_full: bool,
    ) {
        // Set execution context
        self.is_real = F::one();
        self.shard = F::from_canonical_u32(shard);
        self.clk = F::from_canonical_u32(clk);
        self.round_ctr = F::from_canonical_u32(round);
        
        // Set round type
        self.is_full_round = if is_full { F::one() } else { F::zero() };

        // Copy current state
        self.state.copy_from_slice(state);

        // Set round constants based on round type
        if is_full {
            let rc_idx = if round < (FULL_ROUNDS/2) as u32 {
                round as usize
            } else {
                (round - PARTIAL_ROUNDS as u32) as usize
            };
            for i in 0..STATE_WIDTH {
                self.round_constants[i] = F::from_canonical_u64(
                    POSEIDON_ROUND_CONSTANTS[rc_idx][i]
                );
            }
        } else {
            let partial_idx = (round - (FULL_ROUNDS/2) as u32) as usize;
            self.round_constants[0] = F::from_canonical_u64(
                POSEIDON_PARTIAL_CONSTANTS[partial_idx]
            );
            for i in 1..STATE_WIDTH {
                self.round_constants[i] = F::zero();
            }
        }

        // Compute ARK state
        for i in 0..STATE_WIDTH {
            self.ark_state[i] = self.state[i] + self.round_constants[i];
        }

        // Compute S-box state
        if is_full {
            for i in 0..STATE_WIDTH {
                let x = self.ark_state[i];
                let x2 = x.square();
                let x4 = x2.square();
                self.sbox_state[i] = x4 * x;
            }
        } else {
            // Only apply S-box to first element in partial rounds
            let x = self.ark_state[0];
            let x2 = x.square();
            let x4 = x2.square();
            self.sbox_state[0] = x4 * x;
            for i in 1..STATE_WIDTH {
                self.sbox_state[i] = self.ark_state[i];
            }
        }

        // Compute mix state (MDS multiplication)
        for i in 0..STATE_WIDTH {
            let mut sum = F::zero();
            for j in 0..STATE_WIDTH {
                sum += self.sbox_state[j] * F::from_canonical_u64(POSEIDON_MDS[i][j]);
            }
            self.mix_state[i] = sum;
        }

        // Set next state
        self.next_state.copy_from_slice(&self.mix_state);

        // Set computation flags
        self.is_arithmetic = F::one();
        self.is_binary = F::zero();
        
        // Set memory operation flags
        self.is_memory_op = if round == 0 || round == (FULL_ROUNDS + PARTIAL_ROUNDS - 1) as u32 {
            F::one()
        } else {
            F::zero()
        };
        self.is_input_op = if round == 0 { F::one() } else { F::zero() };
        self.is_output_op = if round == (FULL_ROUNDS + PARTIAL_ROUNDS - 1) as u32 {
            F::one()
        } else {
            F::zero()
        };
    }

    /// Populate an empty (padding) row
    pub fn populate_empty_row(&mut self) {
        *self = Self::default();
        
        // Set required zero values for empty rows
        let zero_state = [F::zero(); STATE_WIDTH];
        self.state.copy_from_slice(&zero_state);
        self.next_state.copy_from_slice(&zero_state);
        self.ark_state.copy_from_slice(&zero_state);
        self.sbox_state.copy_from_slice(&zero_state);
        self.mix_state.copy_from_slice(&zero_state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_column_dimensions() {
        // Verify column structure size
        assert_eq!(size_of::<PoseidonCols<u8>>(), NUM_COLS);
    }

    #[test]
    fn test_trace_row_population() {
        let mut cols = PoseidonCols::<Bn254ScalarField>::default();
        let state = [
            Bn254ScalarField::from_canonical_u64(1),
            Bn254ScalarField::from_canonical_u64(2),
            Bn254ScalarField::from_canonical_u64(3),
        ];

        // Test full round
        cols.populate_trace_row(0, 0, 0, &state, true);
        assert_eq!(cols.is_real, Bn254ScalarField::one());
        assert_eq!(cols.is_full_round, Bn254ScalarField::one());
        assert_eq!(cols.is_input_op, Bn254ScalarField::one());
        
        // Verify ARK computation
        for i in 0..STATE_WIDTH {
            assert_eq!(
                cols.ark_state[i],
                state[i] + cols.round_constants[i]
            );
        }

        // Test partial round
        cols.populate_trace_row(0, 1, 4, &state, false);
        assert_eq!(cols.is_full_round, Bn254ScalarField::zero());
        assert_eq!(cols.is_input_op, Bn254ScalarField::zero());
        
        // Only first element should be modified in partial rounds
        let x = cols.ark_state[0];
        let expected_sbox = x.square().square() * x;
        assert_eq!(cols.sbox_state[0], expected_sbox);
        
        // Other elements should pass through unchanged
        for i in 1..STATE_WIDTH {
            assert_eq!(cols.sbox_state[i], cols.ark_state[i]);
        }
    }

    #[test]
    fn test_empty_row() {
        let mut cols = PoseidonCols::<Bn254ScalarField>::default();
        cols.populate_empty_row();

        assert_eq!(cols.is_real, Bn254ScalarField::zero());
        assert_eq!(cols.is_memory_op, Bn254ScalarField::zero());
        
        // All states should be zero
        for i in 0..STATE_WIDTH {
            assert_eq!(cols.state[i], Bn254ScalarField::zero());
            assert_eq!(cols.next_state[i], Bn254ScalarField::zero());
            assert_eq!(cols.ark_state[i], Bn254ScalarField::zero());
            assert_eq!(cols.sbox_state[i], Bn254ScalarField::zero());
            assert_eq!(cols.mix_state[i], Bn254ScalarField::zero());
        }
    }
}