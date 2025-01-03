use super::*;



use sp1_core_executor::{
    events::{ByteRecord, FieldOperation, PrecompileEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use sp1_stark::{
    air::{BaseAirBuilder, InteractionScope, MachineAir, Polynomial, SP1AirBuilder},
    MachineRecord, ProofWithIO, InteractionKind
};
use sp1_curves::{
    params::{Limbs, NumLimbs, NumWords},
    uint256::U256Field,
    weierstrass::bn254::Bn254ScalarField,
};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_air::{Air, AirBuilder, BaseAir};




impl<F: Field> BaseAir<F> for PoseidonChip {
    fn width(&self) -> usize {
        NUM_COLS
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
        self.eval_state_transition(builder, local);

        // 4. Memory Access Constraints
        self.eval_memory_constraints(builder, local);

        // 5. Cross-Row State Update Constraints
        self.eval_state_update(builder, local, next);
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
        builder.assert_bool(local.is_memory_op);
        builder.assert_bool(local.is_binary);

        // Nonce progression
        builder.when_first_row().assert_zero(local.nonce);
        builder.when_transition().assert_eq(
            local.nonce + AB::Expr::one(),
            next.nonce,
        );

        // Clock constraints for real rows
        builder.when(local.is_real).assert_eq(
            next.clk,
            local.clk + AB::Expr::one(),
        );

        // Shard consistency
        builder.when_transition().when(local.is_real).assert_eq(
            local.shard,
            next.shard,
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
            next.round_ctr,
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
    ) {
        // 1. Add Round Constants (ARK)
        for i in 0..WIDTH {
            builder.assert_eq(
                local.ark_state[i],
                local.state[i] + local.round_constants[i],
            );
        }

        // 2. S-box Layer
        let should_apply_full_sbox = local.is_full_round;
        
        // First element always goes through S-box
        let x = local.ark_state[0].clone();
        let x2 = x.clone() * x.clone();
        let x4 = x2.clone() * x2.clone();
        builder.assert_eq(
            local.sbox_state[0],
            x4 * x,
        );

        // Other elements only in full rounds
        for i in 1..WIDTH {
            let x = local.ark_state[i].clone();
            let sbox_result = {
                let x2 = x.clone() * x.clone();
                let x4 = x2.clone() * x2.clone();
                x4 * x
            };
            let pass_through = x.clone();
            
            builder.assert_eq(
                local.sbox_state[i],
                AB::Expr::select(
                    should_apply_full_sbox.clone(),
                    sbox_result,
                    pass_through,
                ),
            );
        }

        // 3. Mix Layer (MDS matrix multiplication)
        for i in 0..WIDTH {
            let mut sum = AB::Expr::zero();
            for j in 0..WIDTH {
                sum = sum + local.sbox_state[j].clone() * 
                    AB::Expr::from_canonical_u64(POSEIDON_MDS[i][j]);
            }
            builder.assert_eq(local.mix_state[i], sum);
        }

        // 4. State Update
        for i in 0..WIDTH {
            builder.assert_eq(local.next_state[i], local.mix_state[i]);
        }
    }

    fn eval_memory_constraints<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &PoseidonCols<AB::Var>,
    ) {
        // Memory operation flags
        builder.when(local.is_memory_op).assert_bool(local.is_input_op);
        builder.when(local.is_memory_op).assert_bool(local.is_output_op);

        // Memory pointer validation
        builder.when(local.is_memory_op).assert_word_aligned(local.input_ptr);
        builder.when(local.is_memory_op).assert_word_aligned(local.output_ptr);

        // Input memory access
        builder.when(local.is_input_op).receive(
            local.shard,
            local.clk,
            local.nonce,
            AB::Expr::from_canonical_u32(SyscallCode::POSEIDON as u32),
            local.input_ptr,
            local.output_ptr,
            local.is_real,
            InteractionKind::Read,
        );

        // Output memory access
        builder.when(local.is_output_op).receive(
            local.shard,
            local.clk,
            local.nonce,
            AB::Expr::from_canonical_u32(SyscallCode::POSEIDON as u32),
            local.input_ptr,
            local.output_ptr,
            local.is_real,
            InteractionKind::Write,
        );
    }

    fn eval_state_update<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &PoseidonCols<AB::Var>,
        next: &PoseidonCols<AB::Var>,
    ) {
        // Ensure state continuity between rows
        for i in 0..WIDTH {
            builder.when_transition().assert_eq(
                local.next_state[i],
                next.state[i],
            );
        }

        // Validate final state matches output
        builder.when(local.is_output_op).assert_eq(
            local.next_state[0],
            local.output_value,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp1_core::stark::{StarkConfig, StarkProof};

    #[test]
    fn test_constraints() {
        let chip = PoseidonChip::new();
        
        // Create test input
        let mut input_record = ExecutionRecord::default();
        let mut output_record = ExecutionRecord::default();

        // Add test event
        input_record.add_precompile_event(
            SyscallCode::POSEIDON,
            PrecompileEvent::Poseidon(PoseidonEvent {
                shard: 0,
                clk: 0,
                input_ptr: 100,
                output_ptr: 200,
                input: [1u64, 2u64, 3u64],
            })
        );

        // Generate trace
        let trace = chip.generate_trace(&input_record, &mut output_record);

        // Create and verify proof
        let config = StarkConfig::standard();
        let proof = StarkProof::prove::<PoseidonChip>(&config, &trace).unwrap();
        
        assert!(proof.verify(&config, chip.width()));
    }
}