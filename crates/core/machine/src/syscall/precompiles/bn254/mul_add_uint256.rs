use crate::{
    memory::{value_as_limbs, MemoryReadCols, MemoryWriteCols},
    operations::field::field_op::FieldOpCols,
};

use crate::{
    air::MemoryAirBuilder,
    operations::{field::range::FieldLtCols, IsZeroOperation},
    utils::{
        limbs_from_access, limbs_from_prev_access, pad_rows_fixed, words_to_bytes_le,
        words_to_bytes_le_vec,
    },
};

use generic_array::GenericArray;
use num::{BigUint, One, Zero};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::{
    events::{ByteRecord, FieldOperation, PrecompileEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use sp1_curves::{
    params::{Limbs, NumLimbs, NumWords},
    uint256::U256Field,
    weierstrass::bn254::Bn254ScalarField,
};
use sp1_derive::AlignedBorrow;
use sp1_stark::{
    air::{BaseAirBuilder, InteractionScope, MachineAir, Polynomial, SP1AirBuilder},
    MachineRecord,
};
use std::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use typenum::Unsigned;

/// The number of columns in the Bn254MulAddCols.
const NUM_COLS: usize = size_of::<Bn254MulAddCols<u8>>();

#[derive(Default)]
pub struct Bn254MulAddChip;

impl Bn254MulAddChip {
    pub const fn new() -> Self {
        Self
    }
}

type WordsFieldElement = <U256Field as NumWords>::WordsFieldElement;
const WORDS_FIELD_ELEMENT: usize = WordsFieldElement::USIZE;

/// A set of columns for the Bn254MulAdd operation.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Bn254MulAddCols<T> {
    /// The shard number of the syscall.
    pub shard: T,

    /// The clock cycle of the syscall.
    pub clk: T,

    /// The nonce of the operation.
    pub nonce: T,

    /// The pointer to the first input.
    pub x_ptr: T,

    /// The pointer to the second input, which contains the a value and the b value.
    pub y_ptr: T,

    // Memory columns.
    // x_memory is written to with the result, which is why it is of type MemoryWriteCols.
    pub x_memory: GenericArray<MemoryWriteCols<T>, WordsFieldElement>,
    pub a_memory: GenericArray<MemoryReadCols<T>, WordsFieldElement>,
    pub b_memory: GenericArray<MemoryReadCols<T>, WordsFieldElement>,

    a_mul_b: FieldOpCols<T, Bn254ScalarField>,

    add_eval: FieldOpCols<T, Bn254ScalarField>, // x += (a * b)

    pub is_real: T,
}

impl<F: PrimeField32> MachineAir<F> for Bn254MulAddChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Bn254MulAdd".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the trace rows & corresponding records for each chunk of events concurrently.
        let rows_and_records = input
            .get_precompile_events(SyscallCode::BN254_MULADD)
            .chunks(1)
            .map(|events| {
                let mut records = ExecutionRecord::default();
                let mut new_byte_lookup_events = Vec::new();

                let rows = events
                    .iter()
                    .map(|(_, event)| {
                        let event = if let PrecompileEvent::Bn254MulAdd(event) = event {
                            event
                        } else {
                            unreachable!()
                        };
                        let mut row: [F; NUM_COLS] = [F::zero(); NUM_COLS];
                        let cols: &mut Bn254MulAddCols<F> = row.as_mut_slice().borrow_mut();

                        // Decode uint256 points
                        let x = BigUint::from_bytes_le(&words_to_bytes_le::<32>(&event.x));
                        let a = BigUint::from_bytes_le(&words_to_bytes_le::<32>(&event.a));
                        let b = BigUint::from_bytes_le(&words_to_bytes_le::<32>(&event.b));

                        // Assign basic values to the columns.
                        cols.is_real = F::one();
                        cols.shard = F::from_canonical_u32(event.shard);
                        cols.clk = F::from_canonical_u32(event.clk);
                        cols.x_ptr = F::from_canonical_u32(event.x_ptr);
                        cols.y_ptr = F::from_canonical_u32(event.y_ptr);

                        // Populate memory columns.
                        for i in 0..WORDS_FIELD_ELEMENT {
                            cols.x_memory[i]
                                .populate(event.x_memory_records[i], &mut new_byte_lookup_events);
                            cols.a_memory[i]
                                .populate(event.a_memory_records[i], &mut new_byte_lookup_events);
                            cols.b_memory[i]
                                .populate(event.b_memory_records[i], &mut new_byte_lookup_events);
                        }

                        let mul_result = cols.a_mul_b.populate(
                            &mut new_byte_lookup_events,
                            event.shard,
                            &a,
                            &b,
                            FieldOperation::Mul,
                        );

                        cols.add_eval.populate(
                            &mut new_byte_lookup_events,
                            event.shard,
                            &x,
                            &mul_result,
                            FieldOperation::Add,
                        );

                        row
                    })
                    .collect::<Vec<_>>();
                records.add_byte_lookup_events(new_byte_lookup_events);
                (rows, records)
            })
            .collect::<Vec<_>>();

        //  Generate the trace rows for each event.
        let mut rows = Vec::new();
        for (row, mut record) in rows_and_records {
            rows.extend(row);
            output.append(&mut record);
        }

        pad_rows_fixed(
            &mut rows,
            || {
                let mut row: [F; NUM_COLS] = [F::zero(); NUM_COLS];
                let cols: &mut Bn254MulAddCols<F> = row.as_mut_slice().borrow_mut();

                let zero = BigUint::zero();
                cols.a_mul_b.populate(&mut vec![], 0, &zero, &zero, FieldOperation::Mul);
                cols.add_eval.populate(&mut vec![], 0, &zero, &zero, FieldOperation::Add);

                row
            },
            input.fixed_log2_rows::<F, _>(self),
        );

        // Convert the trace to a row major matrix.
        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_COLS);

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut Bn254MulAddCols<F> =
                trace.values[i * NUM_COLS..(i + 1) * NUM_COLS].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::BN254_MULADD).is_empty()
        }
    }
}

impl<F> BaseAir<F> for Bn254MulAddChip {
    fn width(&self) -> usize {
        NUM_COLS
    }
}

impl<AB> Air<AB> for Bn254MulAddChip
where
    AB: SP1AirBuilder,
    Limbs<AB::Var, <U256Field as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Bn254MulAddCols<AB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &Bn254MulAddCols<AB::Var> = (*next).borrow();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder.when_transition().assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        // We are computing (x * y) % modulus. The value of x is stored in the "prev_value" of
        // the x_memory, since we write to it later.
        let x_limbs = limbs_from_prev_access(&local.x_memory);
        let a_limbs = limbs_from_access(&local.a_memory);
        let b_limbs = limbs_from_access(&local.b_memory);

        local.a_mul_b.eval(builder, &a_limbs, &b_limbs, FieldOperation::Mul, local.is_real);

        local.add_eval.eval(
            builder,
            &x_limbs,
            &local.a_mul_b.result,
            FieldOperation::Add,
            local.is_real,
        );

        // Assert that the correct result is being written to x_memory.
        builder
            .when(local.is_real)
            .assert_all_eq(local.add_eval.result, value_as_limbs(&local.x_memory));

        // Read and write x.
        builder.eval_memory_access_slice(
            local.shard,
            local.clk.into() + AB::Expr::one(),
            local.x_ptr,
            &local.x_memory,
            local.is_real,
        );

        // Evaluate the y_ptr memory access. We concatenate y and modulus into a single array since
        // we read it contiguously from the y_ptr memory location.
        builder.eval_memory_access_slice(
            local.shard,
            local.clk.into(),
            local.y_ptr,
            &[local.a_memory, local.b_memory].concat(),
            local.is_real,
        );

        // Receive the arguments.
        builder.receive_syscall(
            local.shard,
            local.clk,
            local.nonce,
            AB::F::from_canonical_u32(SyscallCode::BN254_MULADD.syscall_id()),
            local.x_ptr,
            local.y_ptr,
            local.is_real,
            InteractionScope::Local,
        );

        // Assert that is_real is a boolean.
        builder.assert_bool(local.is_real);
    }
}
