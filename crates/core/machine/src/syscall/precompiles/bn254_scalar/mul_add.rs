use num::{BigUint, Zero};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, Field, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::{
    events::{Bn254FieldOperation, ByteRecord, FieldOperation, PrecompileEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use sp1_curves::{
    bn254::{Bn254ScalarField, BN254_SCALAR_FIELD_MODULUS},
    params::{FieldParameters, Limbs, NumLimbs},
};
use sp1_derive::AlignedBorrow;
use sp1_stark::air::{InteractionScope, MachineAir, SP1AirBuilder};
use std::borrow::{Borrow, BorrowMut};

use crate::{
    memory::{MemoryReadCols, MemoryWriteCols},
    operations::field::field_op::FieldOpCols,
    utils::{limbs_from_access, pad_rows_fixed},
};

const NUM_WORDS_PER_FE: usize = 8;
const NUM_COLS: usize = core::mem::size_of::<Bn254ScalarMacCols<u8>>();

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Bn254ScalarMacCols<T> {
    is_real: T,
    shard: T,
    clk: T,
    nonce: T,
    x_ptr: T, // 存储结果和第一个加数
    y_ptr: T, // 存储两个乘数

    // 内存访问列
    x_memory: [MemoryWriteCols<T>; NUM_WORDS_PER_FE], // 结果
    a_memory: [MemoryReadCols<T>; NUM_WORDS_PER_FE],  // 第一个乘数
    b_memory: [MemoryReadCols<T>; NUM_WORDS_PER_FE],  // 第二个乘数
    c_memory: [MemoryReadCols<T>; NUM_WORDS_PER_FE],  // 加数

    // 运算列
    mul_eval: FieldOpCols<T, Bn254ScalarField>, // a * b
    add_eval: FieldOpCols<T, Bn254ScalarField>, // (a * b) + c
}

pub struct Bn254ScalarMacChip;

impl Bn254ScalarMacChip {
    pub const fn new() -> Self {
        Self
    }

    // 辅助函数：判断是否为纯乘法操作
    fn is_mul_only(c: &BigUint) -> bool {
        c.is_zero()
    }
}

impl<F: PrimeField32> MachineAir<F> for Bn254ScalarMacChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Bn254ScalarMac".to_string()
    }

    fn generate_trace(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        let mut rows = vec![];
        let mut new_byte_lookup_events = vec![];

        // 处理MAC和MUL事件
        for event in input
            .get_precompile_events(SyscallCode::BN254_SCALAR_MAC)
            .into_iter()
            .chain(input.get_precompile_events(SyscallCode::BN254_SCALAR_MUL))
        {
            let (a, b, c) = match event {
                (_, PrecompileEvent::Bn254ScalarMac(event)) => (
                    event.a.value_as_biguint(),
                    event.b.value_as_biguint(),
                    event.c.value_as_biguint(),
                ),
                (_, PrecompileEvent::Bn254ScalarMul(event)) => {
                    (event.a.value_as_biguint(), event.b.value_as_biguint(), BigUint::zero())
                    // 乘法视为加0的MAC
                }
                _ => unreachable!(),
            };

            let mut row = [F::zero(); NUM_COLS];
            let cols: &mut Bn254ScalarMacCols<F> = row.as_mut_slice().borrow_mut();

            // 基本信息设置
            cols.is_real = F::one();
            cols.shard = F::from_canonical_u32(event.shard);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.x_ptr = F::from_canonical_u32(event.x_ptr);
            cols.y_ptr = F::from_canonical_u32(event.y_ptr);

            // 计算 a * b
            let mul_result = cols.mul_eval.populate(
                &mut new_byte_lookup_events,
                event.shard,
                &a,
                &b,
                FieldOperation::Mul,
            );

            // 计算 (a * b) + c
            cols.add_eval.populate(
                &mut new_byte_lookup_events,
                event.shard,
                &mul_result,
                &c,
                FieldOperation::Add,
            );

            // 填充内存访问记录
            for i in 0..NUM_WORDS_PER_FE {
                cols.x_memory[i].populate(event.x_memory[i], &mut new_byte_lookup_events);
                cols.a_memory[i].populate(event.a_memory[i], &mut new_byte_lookup_events);
                cols.b_memory[i].populate(event.b_memory[i], &mut new_byte_lookup_events);
                cols.c_memory[i].populate(event.c_memory[i], &mut new_byte_lookup_events);
            }

            rows.push(row);
        }

        output.add_byte_lookup_events(new_byte_lookup_events);

        // 填充行
        pad_rows_fixed(
            &mut rows,
            || {
                let mut row = [F::zero(); NUM_COLS];
                let cols: &mut Bn254ScalarMacCols<F> = row.as_mut_slice().borrow_mut();

                let zero = BigUint::zero();
                cols.mul_eval.populate(&mut vec![], 0, &zero, &zero, FieldOperation::Mul);
                cols.add_eval.populate(&mut vec![], 0, &zero, &zero, FieldOperation::Add);

                row
            },
            input.fixed_log2_rows::<F, _>(self),
        );

        // 生成矩阵并设置nonce
        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_COLS);

        for i in 0..trace.height() {
            let cols: &mut Bn254ScalarMacCols<F> =
                trace.values[i * NUM_COLS..(i + 1) * NUM_COLS].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.get_precompile_events(SyscallCode::BN254_SCALAR_MAC).is_empty()
            || !shard.get_precompile_events(SyscallCode::BN254_SCALAR_MUL).is_empty()
    }
}

impl<F: Field> BaseAir<F> for Bn254ScalarMacChip {
    fn width(&self) -> usize {
        NUM_COLS
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
        let next = main.row_slice(1);
        let next: &Bn254ScalarMacCols<AB::Var> = (*next).borrow();

        // nonce约束
        builder.when_first_row().assert_zero(local.nonce);
        builder.when_transition().assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        builder.assert_bool(local.is_real);

        // 获取所有输入值
        let a = limbs_from_access(&local.a_memory);
        let b = limbs_from_access(&local.b_memory);
        let c = limbs_from_access(&local.c_memory);

        // 验证乘法运算
        local.mul_eval.eval(builder, &a, &b, FieldOperation::Mul, local.is_real);

        // 验证加法运算
        local.add_eval.eval(
            builder,
            &local.mul_eval.result,
            &c,
            FieldOperation::Add,
            local.is_real,
        );

        // 验证结果写入
        for i in 0..Bn254ScalarField::NB_LIMBS {
            builder
                .when(local.is_real)
                .assert_eq(local.add_eval.result[i], local.x_memory[i / 4].value()[i % 4]);
        }

        // 内存访问验证
        builder.eval_memory_access_slice(
            local.shard,
            local.clk.into(),
            local.x_ptr,
            &local.x_memory,
            local.is_real,
        );

        builder.eval_memory_access_slice(
            local.shard,
            local.clk.into(),
            local.y_ptr,
            &[&local.a_memory[..], &local.b_memory[..], &local.c_memory[..]].concat(),
            local.is_real,
        );

        // 系统调用验证
        builder.receive_syscall(
            local.shard,
            local.clk,
            local.nonce,
            AB::F::from_canonical_u32(SyscallCode::BN254_SCALAR_MAC.syscall_id()),
            local.x_ptr,
            local.y_ptr,
            local.is_real,
            InteractionScope::Local,
        );
    }
}
