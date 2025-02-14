use std::borrow::{Borrow, BorrowMut};

use num::BigUint;
use num::Zero;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, Field, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::{
    events::{Bn254FieldOperation, ByteRecord, FieldOperation, PrecompileEvent, NUM_WORDS_PER_FE},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use sp1_curves::{
    params::{FieldParameters, Limbs, NumLimbs},
    weierstrass::bn254::Bn254ScalarField,
};
use sp1_derive::AlignedBorrow;
use sp1_stark::air::{InteractionScope, MachineAir, SP1AirBuilder};
use typenum::U8;

use crate::{
    air::MemoryAirBuilder,
    memory::{MemoryCols, MemoryReadCols, MemoryWriteCols},
    operations::field::field_op::FieldOpCols,
    utils::{limbs_from_prev_access, pad_rows_fixed},
};

const NUM_COLS: usize = core::mem::size_of::<Bn254ScalarMacCols<u8>>();
const OP: Bn254FieldOperation = Bn254FieldOperation::MulAdd;

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Bn254ScalarMacCols<T> {
    is_real: T,
    shard: T,
    channel: T,
    clk: T,
    arg1_ptr: T,
    arg2_ptr: T,
    arg1_access: [MemoryWriteCols<T>; NUM_WORDS_PER_FE],
    arg2_access: [MemoryReadCols<T>; 2],
    a_access: [MemoryReadCols<T>; NUM_WORDS_PER_FE],
    b_access: [MemoryReadCols<T>; NUM_WORDS_PER_FE],
    mul_eval: FieldOpCols<T, Bn254ScalarField>,
    add_eval: FieldOpCols<T, Bn254ScalarField>,
}

pub struct Bn254ScalarMacChip;

impl Bn254ScalarMacChip {
    pub fn new() -> Self {
        Self
    }
}

impl<F: Field> BaseAir<F> for Bn254ScalarMacChip {
    fn width(&self) -> usize {
        NUM_COLS
    }

    fn preprocessed_trace(&self) -> Option<&RowMajorMatrix<F>> {
        None
    }

    fn execute(&self, inputs: &[F], outputs: &mut [F]) {
        outputs.copy_from_slice(inputs);
    }

    fn degree(&self) -> usize {
        4
    }

    fn minimal_cyclic_domain_size(&self) -> usize {
        64
    }
}

impl<F: PrimeField32> MachineAir<F> for Bn254ScalarMacChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Bn254ScalarMac".to_string()
    }

    fn generate_trace(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = input.get_precompile_events(SyscallCode::BN254_SCALAR_MAC);

        let mut rows = vec![];
        let mut new_byte_lookup_events = vec![];

        for event in events {
            let event = if let (_, PrecompileEvent::Bn254ScalarMac(event)) = event {
                event
            } else {
                unreachable!();
            };
            let mut row = [F::zero(); NUM_COLS];
            let cols: &mut Bn254ScalarMacCols<F> = row.as_mut_slice().borrow_mut();

            let arg1 = event.arg1.prev_value_as_biguint();
            let a = event.a.as_ref().unwrap().value_as_biguint();
            let b = event.b.as_ref().unwrap().value_as_biguint();

            cols.is_real = F::one();
            cols.shard = F::from_canonical_u32(event.shard);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.arg1_ptr = F::from_canonical_u32(event.arg1.ptr);
            cols.arg2_ptr = F::from_canonical_u32(event.arg2.ptr);

            let mul =
                cols.mul_eval.populate(&mut new_byte_lookup_events, &a, &b, FieldOperation::Mul);
            cols.add_eval.populate(&mut new_byte_lookup_events, &arg1, &mul, FieldOperation::Add);

            for i in 0..cols.arg1_access.len() {
                cols.arg1_access[i]
                    .populate(event.arg1.memory_records[i], &mut new_byte_lookup_events);
            }
            for i in 0..cols.arg2_access.len() {
                cols.arg2_access[i]
                    .populate(event.arg2.memory_records[i], &mut new_byte_lookup_events);
            }
            for i in 0..cols.a_access.len() {
                cols.a_access[i].populate(
                    event.a.as_ref().unwrap().memory_records[i],
                    &mut new_byte_lookup_events,
                );
            }
            for i in 0..cols.b_access.len() {
                cols.b_access[i].populate(
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
                let cols: &mut Bn254ScalarMacCols<F> = row.as_mut_slice().borrow_mut();

                let zero = BigUint::zero();
                cols.mul_eval.populate(&mut vec![], &zero, &zero, FieldOperation::Mul);
                cols.add_eval.populate(&mut vec![], &zero, &zero, FieldOperation::Add);

                row
            },
            input.fixed_log2_rows::<F, _>(self),
        );

        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.get_precompile_events(SyscallCode::BN254_SCALAR_MAC).is_empty()
    }
}

impl<AB> Air<AB> for Bn254ScalarMacChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Bn254ScalarMacCols<AB::Var> = (*local).borrow();

        builder.assert_bool(local.is_real);

        let syscall_id = AB::F::from_canonical_u32(SyscallCode::BN254_SCALAR_MAC.syscall_id());
        builder.receive_syscall(
            local.shard,
            local.clk,
            syscall_id,
            local.arg1_ptr,
            local.arg2_ptr,
            local.is_real,
            InteractionScope::Local,
        );
    }
}
