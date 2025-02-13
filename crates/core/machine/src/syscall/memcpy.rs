use generic_array::{ArrayLength, GenericArray};
use sp1_core_executor::{
    events::{ByteRecord, MemCopyEvent, PrecompileEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext},
    ExecutionRecord, Program,
};
use sp1_curves::params::Limbs;
use sp1_stark::air::{BaseAirBuilder, InteractionScope, MachineAir, SP1AirBuilder};
use std::borrow::{Borrow, BorrowMut};
use std::marker::PhantomData;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, Field, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_derive::AlignedBorrow;

use crate::{
    air::MemoryAirBuilder,
    memory::{value_as_limbs, MemoryReadCols, MemoryWriteCols},
    utils::{limbs_from_access, limbs_from_prev_access, pad_rows_fixed},
};

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct MemCopyCols<T, NumWords: ArrayLength> {
    is_real: T,
    shard: T,
    channel: T,
    clk: T,
    src_ptr: T,
    dst_ptr: T,
    src_access: GenericArray<MemoryReadCols<T>, NumWords>,
    dst_access: GenericArray<MemoryWriteCols<T>, NumWords>,
}

pub struct MemCopyChip<NumWords: ArrayLength, NumBytes: ArrayLength> {
    _marker: PhantomData<(NumWords, NumBytes)>,
}

use typenum::{U16, U32, U64, U8};
pub type MemCopy32Chip = MemCopyChip<U8, U32>;
pub type MemCopy64Chip = MemCopyChip<U16, U64>;

impl<NumWords: ArrayLength, NumBytes: ArrayLength> MemCopyChip<NumWords, NumBytes> {
    const NUM_COLS: usize = core::mem::size_of::<MemCopyCols<u8, NumWords>>();

    pub fn new() -> Self {
        println!("MemCopyChip<{}> NUM_COLS = {}", NumWords::USIZE, Self::NUM_COLS);
        assert_eq!(NumWords::USIZE * 4, NumBytes::USIZE);
        Self { _marker: PhantomData }
    }

    pub fn syscall_id() -> u32 {
        match NumBytes::USIZE {
            32 => SyscallCode::MEMCPY_32.syscall_id(),
            64 => SyscallCode::MEMCPY_64.syscall_id(),
            _ => unreachable!(),
        }
    }
}

impl<F: PrimeField32, NumWords: ArrayLength + Send + Sync, NumBytes: ArrayLength + Send + Sync>
    MachineAir<F> for MemCopyChip<NumWords, NumBytes>
{
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        format!("MemCopy{}Chip", NumWords::USIZE)
    }

    fn generate_trace(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        let mut rows = vec![];
        let mut new_byte_lookup_events = vec![];
        let events = match NumWords::USIZE {
            8 => input.get_precompile_events(SyscallCode::MEMCPY_32),
            16 => input.get_precompile_events(SyscallCode::MEMCPY_64),
            _ => unreachable!(),
        };

        for event in events {
            let event: &MemCopyEvent = match NumWords::USIZE {
                8 => {
                    if let (_, PrecompileEvent::MemCopy32(event)) = event {
                        event
                    } else {
                        unreachable!();
                    }
                }
                16 => {
                    if let (_, PrecompileEvent::MemCopy64(event)) = event {
                        event
                    } else {
                        unreachable!();
                    }
                }
                _ => unreachable!(),
            };
            let mut row = Vec::with_capacity(Self::NUM_COLS);
            row.resize(Self::NUM_COLS, F::zero());
            let cols: &mut MemCopyCols<F, NumWords> = row.as_mut_slice().borrow_mut();

            cols.is_real = F::one();
            cols.shard = F::from_canonical_u32(event.shard);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.src_ptr = F::from_canonical_u32(event.src_ptr);
            cols.dst_ptr = F::from_canonical_u32(event.dst_ptr);

            for i in 0..NumWords::USIZE {
                cols.src_access[i].populate(event.read_records[i], &mut new_byte_lookup_events);
            }
            for i in 0..NumWords::USIZE {
                cols.dst_access[i].populate(event.write_records[i], &mut new_byte_lookup_events);
            }

            rows.push(row);
        }
        output.add_byte_lookup_events(new_byte_lookup_events);

        pad_rows_fixed(
            &mut rows,
            || vec![F::zero(); Self::NUM_COLS],
            input.fixed_log2_rows::<F, _>(self),
        );

        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), Self::NUM_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        match NumWords::USIZE {
            8 => !shard.get_precompile_events(SyscallCode::MEMCPY_32).is_empty(),
            16 => !shard.get_precompile_events(SyscallCode::MEMCPY_64).is_empty(),
            _ => unreachable!(),
        }
    }
}

impl<F: Field, NumWords: ArrayLength + Sync, NumBytes: ArrayLength + Sync> BaseAir<F>
    for MemCopyChip<NumWords, NumBytes>
{
    fn width(&self) -> usize {
        Self::NUM_COLS
    }
}

impl<AB: SP1AirBuilder, NumWords: ArrayLength + Sync, NumBytes: ArrayLength + Sync> Air<AB>
    for MemCopyChip<NumWords, NumBytes>
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemCopyCols<AB::Var, NumWords> = (*local).borrow();

        let src: Limbs<<AB as AirBuilder>::Var, NumBytes> =
            limbs_from_prev_access(&local.src_access);
        let dst: Limbs<<AB as AirBuilder>::Var, NumBytes> = limbs_from_access(&local.dst_access);

        builder
            .when(local.is_real)
            .assert_all_eq(value_as_limbs(&local.src_access), value_as_limbs(&local.dst_access));

        builder.eval_memory_access_slice(
            local.shard,
            local.clk.into(),
            local.src_ptr,
            &local.src_access,
            local.is_real,
        );
        builder.eval_memory_access_slice(
            local.shard,
            local.clk.into() + AB::Expr::one(),
            local.dst_ptr,
            &local.dst_access,
            local.is_real,
        );

        builder.receive_syscall(
            local.shard,
            local.clk,
            AB::F::from_canonical_u32(Self::syscall_id()),
            local.src_ptr,
            local.dst_ptr,
            local.is_real,
            InteractionScope::Local,
        );
    }
}
