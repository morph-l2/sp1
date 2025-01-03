use super::*;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_matrix::Matrix;
use sp1_core::{
    air::{MachineAir, SP1AirBuilder, InteractionKind},
    utils::{range, bytes32},
    stark::proof::ProofWithIO,
};

impl<F: Field> BaseAir<F> for PoseidonChip {
    fn width(&self) -> usize {
        std::mem::size_of::<PoseidonCols<F>>()
    }
}

impl<AB: SP1AirBuilder> Air<AB> for PoseidonChip {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &PoseidonCols<AB::Var> = main.row_slice(0).borrow();
        let next: &PoseidonCols<AB::Var> = main.row_slice(1).borrow();

        // 1. Execution Context Constraints
        self.eval_execution_context(builder, local, next);

        // 2. Round Counter and Type Constraints
        self.eval_round_constraints(builder, local, next);

        // 3. State Transition Constraints
        self.eval_state_transition(builder, local, next);

        // 4. Memory Access Constraints
        self.eval_memory_constraints(builder, local, next);

        // 5. Arithmetic Constraints
        self.eval_arithmetic_constraints(builder, local);
    }
}

impl PoseidonChip {
    fn eval_execution_context<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &PoseidonCols<AB::Var>,
        next: &PoseidonCols<AB::Var>,
    ) {
        // Basic boolean constraints
        builder.assert_bool(local.is_real);
        builder.assert_bool(local.is_arithmetic);
        builder.assert_bool(local.is_memory);
        
        // Execution flow constraints
        builder.when_first_row().assert_zero(local.nonce);
        builder.when_transition().assert_eq(
            local.nonce + AB::Expr::one(),
            next.nonce
        );

        // Program counter constraints
        builder.when_transition().assert_eq(
            local.pc + AB::Expr::one(),
            next.pc
        );
    }

    fn eval_round_constraints<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &PoseidonCols<AB::Var>,
        next: &PoseidonCols<AB::Var>,
    ) {
        // Round counter progression
        builder.when_first_row().assert_zero(local.round_ctr);
        builder.when_transition().assert_eq(
            local.round_ctr + AB::Expr::one(),
            next.round_ctr
        );

        // Round type determination
        let half_full = AB::Expr::from_canonical_u32((FULL_ROUNDS/2) as u32);
        let partial_start = half_full.clone();
        let partial_end = partial_start + AB::Expr::from_canonical_u32(PARTIAL_ROUNDS as u32);
        
        let round = local.round_ctr.clone();
        let is_full = (round.clone() < half_full) | 
                     (round.clone() >= partial_end);
        
        builder.assert_eq(local.is_full_round, is_full);
    }

    fn eval_state_transition<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &PoseidonCols<AB::Var>,
        next: &PoseidonCols<AB::Var>,
    ) {
        // 1. Add Round Key (ARK)
        for i in 0..WIDTH {
            builder.assert_eq(
                local.ark_state[i],
                local.state[i] + local.round_constants[i]
            );
        }

        // 2. S-box Layer
        for i in 0..WIDTH {
            let should_apply_sbox = local.is_full_round.clone() | (i == 0);
            let sbox_in = local.ark_state[i].clone();
            
            // Optimized S-box computation using temporary registers
            builder.when(should_apply_sbox).assert_eq(
                local.temp_1,
                sbox_in.clone() * sbox_in.clone()
            );
            
            builder.when(should_apply_sbox).assert_eq(
                local.temp_2,
                local.temp_1.clone() * local.temp_1.clone()
            );
            
            builder.when(should_apply_sbox).assert_eq(
                local.sbox_state[i],
                local.temp_2 * sbox_in
            );
            
            builder.when(!should_apply_sbox).assert_eq(
                local.sbox_state[i],
                sbox_in
            );
        }

        // 3. Mix Layer (MDS Matrix Multiplication)
        for i in 0..WIDTH {
            let mut sum = AB::Expr::zero();
            for j in 0..WIDTH {
                sum = sum + local.sbox_state[j].clone() * 
                    AB::Expr::from_canonical_u64(POSEIDON_MDS[i][j].to_canonical_u64());
            }
            builder.assert_eq(local.mix_state[i], sum);
        }

        // 4. State Update
        for i in 0..WIDTH {
            builder.assert_eq(local.next_state[i], local.mix_state[i]);
            builder.assert_eq(next.state[i], local.next_state[i]);
        }
    }

    fn eval_memory_constraints<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &PoseidonCols<AB::Var>,
        next: &PoseidonCols<AB::Var>,
    ) {
        builder.when(local.is_memory).assert_valid_ptr(local.input_ptr);
        builder.when(local.is_memory).assert_valid_ptr(local.output_ptr);
        
        // Memory alignment
        builder.when(local.is_memory).assert_word_aligned(local.input_ptr);
        builder.when(local.is_memory).assert_word_aligned(local.output_ptr);

        // Memory access validation
        builder.when(local.is_input_access).receive_syscall(
            local.shard,
            local.clk,
            local.nonce,
            AB::F::from_canonical_u32(SyscallCode::POSEIDON as u32),
            local.input_ptr,
            local.output_ptr,
            local.is_real,
            InteractionKind::Read,
        );

        builder.when(local.is_output_access).receive_syscall(
            local.shard,
            local.clk,
            local.nonce,
            AB::F::from_canonical_u32(SyscallCode::POSEIDON as u32),
            local.input_ptr,
            local.output_ptr,
            local.is_real,
            InteractionKind::Write,
        );
    }

    fn eval_arithmetic_constraints<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &PoseidonCols<AB::Var>,
    ) {
        builder.when(local.is_arithmetic).assert_valid_field_element(local.temp_1);
        builder.when(local.is_arithmetic).assert_valid_field_element(local.temp_2);
        
        // Range check for intermediate values
        for i in 0..WIDTH {
            builder.when(local.is_arithmetic).assert_valid_field_element(local.state[i]);
            builder.when(local.is_arithmetic).assert_valid_field_element(local.next_state[i]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp1_core::stark::{StarkConfig, StarkProof};
    use sp1_core_executor::Node;

    #[test]
    fn test_constraints() {
        let input = [Fr::one(), Fr::zero(), Fr::zero()];
        let chip = PoseidonChip::new();
        
        // Generate trace
        let trace = chip.generate_trace(&input);
        
        // Verify dimensions
        assert_eq!(trace.width(), chip.width());
        assert_eq!(trace.height(), FULL_ROUNDS + PARTIAL_ROUNDS);
        
        // Verify round types
        let cols: &PoseidonCols<Fr> = trace.row_slice(0).borrow();
        assert_eq!(cols.is_full_round, Fr::one());
        
        let mid_cols: &PoseidonCols<Fr> = trace.row_slice(FULL_ROUNDS/2).borrow();
        assert_eq!(mid_cols.is_full_round, Fr::zero());
    }

    #[test]
    fn test_state_transition() {
        let chip = PoseidonChip::new();
        let input = [Fr::one(), Fr::zero(), Fr::zero()];
        let trace = chip.generate_trace(&input);
        
        // Verify state transitions
        for row in 0..trace.height()-1 {
            let curr: &PoseidonCols<Fr> = trace.row_slice(row).borrow();
            let next: &PoseidonCols<Fr> = trace.row_slice(row+1).borrow();
            
            for i in 0..WIDTH {
                assert_eq!(curr.next_state[i], next.state[i]);
            }
        }
    }
}