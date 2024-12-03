use crate::air::MemoryAirBuilder;
use num::{BigUint, Zero};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, Field, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::{
    events::{Bn254FieldOperation, ByteRecord, FieldOperation, PrecompileEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use sp1_curves::params::FieldParameters;
use sp1_curves::params::Limbs;
use sp1_curves::params::NumLimbs;
use sp1_curves::weierstrass::bn254::Bn254ScalarField;
use sp1_derive::AlignedBorrow;
use sp1_stark::air::{InteractionScope, MachineAir, SP1AirBuilder};
use std::borrow::{Borrow, BorrowMut};
use typenum::U8;

use crate::{
    memory::{MemoryCols, MemoryReadCols, MemoryWriteCols},
    operations::field::field_op::FieldOpCols,
    utils::{limbs_from_access, limbs_from_prev_access, pad_rows_fixed},
};

const NUM_WORDS_PER_FE: usize = 8;
const NUM_COLS: usize = core::mem::size_of::<Bn254ScalarMulAddCols<u8>>();

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Bn254ScalarMulAddCols<T> {
    is_real: T,
    shard: T,
    channel: T,
    clk: T,
    nonce: T,

    x_ptr: T,
    y_ptr: T,

    //x_ptr
    x_memory: [MemoryWriteCols<T>; NUM_WORDS_PER_FE],

    //y_ptr
    a_ptr_memory: MemoryReadCols<T>,
    b_ptr_memory: MemoryReadCols<T>,

    a_memory: [MemoryReadCols<T>; NUM_WORDS_PER_FE],
    b_memory: [MemoryReadCols<T>; NUM_WORDS_PER_FE],

    a_mul_b: FieldOpCols<T, Bn254ScalarField>,
    add_eval: FieldOpCols<T, Bn254ScalarField>, // x + (a * b)
}

pub struct Bn254ScalarMulAddChip;

impl Bn254ScalarMulAddChip {
    pub const fn new() -> Self {
        Self
    }
}

impl<F: PrimeField32> MachineAir<F> for Bn254ScalarMulAddChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Bn254ScalarMulAdd".to_string()
    }

    fn generate_trace(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        let mut rows = vec![];
        let mut new_byte_lookup_events = vec![];

        for event in input.get_precompile_events(SyscallCode::BN254_SCALAR_MULADD) {
            let event = if let (_, PrecompileEvent::Bn254ScalarMulAdd(event)) = event {
                event
            } else {
                unreachable!();
            };

            let mut row = [F::zero(); NUM_COLS];
            let cols: &mut Bn254ScalarMulAddCols<F> = row.as_mut_slice().borrow_mut();

            let x = event.arg1.prev_value_as_biguint();
            let a = event.a.as_ref().unwrap().value_as_biguint();
            let b = event.b.as_ref().unwrap().value_as_biguint();

            cols.is_real = F::one();
            cols.shard = F::from_canonical_u32(event.shard);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.x_ptr = F::from_canonical_u32(event.arg1.ptr);
            cols.y_ptr = F::from_canonical_u32(event.arg2.ptr);

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

            cols.a_ptr_memory.populate(event.arg2.memory_records[0], &mut new_byte_lookup_events);

            cols.b_ptr_memory.populate(event.arg2.memory_records[1], &mut new_byte_lookup_events);

            for i in 0..NUM_WORDS_PER_FE {
                cols.x_memory[i]
                    .populate(event.arg1.memory_records[i], &mut new_byte_lookup_events);
                cols.a_memory[i].populate(
                    event.a.as_ref().unwrap().memory_records[i],
                    &mut new_byte_lookup_events,
                );
                cols.b_memory[i].populate(
                    event.b.as_ref().unwrap().memory_records[i],
                    &mut new_byte_lookup_events,
                );
            }

            rows.push(row);
        }

        output.add_byte_lookup_events(new_byte_lookup_events);

        pad_rows_fixed(
            &mut rows,
            || {
                let mut row = [F::zero(); NUM_COLS];
                let cols: &mut Bn254ScalarMulAddCols<F> = row.as_mut_slice().borrow_mut();

                let zero = BigUint::zero();
                cols.a_mul_b.populate(&mut vec![], 0, &zero, &zero, FieldOperation::Mul);
                cols.add_eval.populate(&mut vec![], 0, &zero, &zero, FieldOperation::Add);

                row
            },
            input.fixed_log2_rows::<F, _>(self),
        );

        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_COLS);

        for i in 0..trace.height() {
            let cols: &mut Bn254ScalarMulAddCols<F> =
                trace.values[i * NUM_COLS..(i + 1) * NUM_COLS].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.get_precompile_events(SyscallCode::BN254_SCALAR_MULADD).is_empty()
    }
}

impl<F: Field> BaseAir<F> for Bn254ScalarMulAddChip {
    fn width(&self) -> usize {
        NUM_COLS
    }
}

impl<AB> Air<AB> for Bn254ScalarMulAddChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Bn254ScalarMulAddCols<AB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &Bn254ScalarMulAddCols<AB::Var> = (*next).borrow();

        builder.when_first_row().assert_zero(local.nonce);
        builder.when_transition().assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        builder.assert_bool(local.is_real);

        builder.receive_syscall(
            local.shard,
            local.clk,
            local.nonce,
            AB::F::from_canonical_u32(SyscallCode::BN254_SCALAR_MULADD.syscall_id()),
            local.x_ptr,
            local.y_ptr,
            local.is_real,
            InteractionScope::Local,
        );

        let x: Limbs<<AB as AirBuilder>::Var, <Bn254ScalarField as NumLimbs>::Limbs> =
            limbs_from_prev_access(&local.x_memory);
        let a_ptr_limbs: Limbs<<AB as AirBuilder>::Var, U8> =
            limbs_from_prev_access(&[local.a_ptr_memory]);
        let b_ptr_limbs: Limbs<<AB as AirBuilder>::Var, U8> =
            limbs_from_prev_access(&[local.b_ptr_memory]);
        let a: Limbs<<AB as AirBuilder>::Var, <Bn254ScalarField as NumLimbs>::Limbs> =
            limbs_from_prev_access(&local.a_memory);
        let b: Limbs<<AB as AirBuilder>::Var, <Bn254ScalarField as NumLimbs>::Limbs> =
            limbs_from_prev_access(&local.b_memory);

        local.a_mul_b.eval(builder, &a, &b, FieldOperation::Mul, local.is_real);

        local.add_eval.eval(builder, &x, &local.a_mul_b.result, FieldOperation::Add, local.is_real);

        for i in 0..Bn254ScalarField::NB_LIMBS {
            builder
                .when(local.is_real)
                .assert_eq(local.add_eval.result[i], local.x_memory[i / 4].value()[i % 4]);
        }

        builder.eval_memory_access_slice(
            local.shard,
            local.clk.into() + AB::Expr::one(),
            local.x_ptr,
            &local.x_memory,
            local.is_real,
        );

        builder.eval_memory_access_slice(
            local.shard,
            local.clk.into(),
            local.y_ptr,
            &[local.a_ptr_memory, local.b_ptr_memory],
            local.is_real,
        );

        assert_eq!(a_ptr_limbs.0.len(), 4);
        let a_ptr = a_ptr_limbs
            .0
            .iter()
            .rev()
            .cloned()
            .map(|v| v.into())
            .fold(AB::Expr::zero(), |acc, b| acc * AB::Expr::from_canonical_u16(0x100) + b);

        assert_eq!(b_ptr_limbs.0.len(), 4);
        let b_ptr = b_ptr_limbs
            .0
            .iter()
            .rev()
            .cloned()
            .map(|v| v.into())
            .fold(AB::Expr::zero(), |acc, b| acc * AB::Expr::from_canonical_u16(0x100) + b);

        builder.eval_memory_access_slice(
            local.shard,
            local.clk.into(),
            a_ptr,
            &local.a_memory,
            local.is_real,
        );

        builder.eval_memory_access_slice(
            local.shard,
            local.clk.into(),
            b_ptr,
            &local.b_memory,
            local.is_real,
        );
    }
}
