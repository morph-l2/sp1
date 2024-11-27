mod air;
pub use air::*;
mod mac;
pub use mac::*;

#[cfg(test)]
mod tests {
    use num::{BigUint, FromPrimitive, One};
    use sp1_core_executor::{syscalls::SyscallCode, Executor, Instruction, Opcode, Program};
    use sp1_curves::{
        bn254::{Bn254ScalarField, BN254_SCALAR_FIELD_MODULUS},
        params::FieldParameters,
        utils::biguint_from_limbs,
    };
    use sp1_stark::CpuProver;
    use test_artifacts::{BN254_SCALAR_MAC_ELF, BN254_SCALAR_MUL_ELF};

    use crate::{
        io::SP1Stdin,
        utils::{self, bytes_to_words_le, run_test, run_test_io, words_to_bytes_le},
    };

    fn create_mac_program(x: &[u8; 32], a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> Program {
        let x_ptr = 100;
        let y_ptr = 200;
        
        let mut instructions = vec![];
        
        // Store x (result location)
        for i in 0..8 {
            let value = u32::from_le_bytes(x[i*4..(i+1)*4].try_into().unwrap());
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 29, 0, value, false, true),
                Instruction::new(Opcode::ADD, 30, 0, x_ptr + i * 4, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
            ]);
        }

        // Store a, b, c consecutively
        for (offset, data) in [(0, a), (32, b), (64, c)] {
            for i in 0..8 {
                let value = u32::from_le_bytes(data[i*4..(i+1)*4].try_into().unwrap());
                instructions.extend(vec![
                    Instruction::new(Opcode::ADD, 29, 0, value, false, true),
                    Instruction::new(Opcode::ADD, 30, 0, y_ptr + offset + i * 4, false, true),
                    Instruction::new(Opcode::SW, 29, 30, 0, false, true),
                ]);
            }
        }

        // Call BN254_SCALAR_MAC
        instructions.extend(vec![
            Instruction::new(Opcode::ADD, 5, 0, SyscallCode::BN254_SCALAR_MAC as u32, false, true),
            Instruction::new(Opcode::ADD, 10, 0, x_ptr, false, true),
            Instruction::new(Opcode::ADD, 11, 0, y_ptr, false, true),
            Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
        ]);

        Program::new(instructions, 0, 0)
    }

    #[test]
    fn test_bn254_scalar_mac() {
        utils::setup_logger();
        let program = Program::from(BN254_SCALAR_MAC_ELF).unwrap();
        run_test_io::<CpuProver<_, _>>(program, SP1Stdin::new()).unwrap();
    }

    #[test]
    fn test_bn254_scalar_mul() {
        utils::setup_logger();
        let program = Program::from(BN254_SCALAR_MUL_ELF).unwrap();
        run_test_io::<CpuProver<_, _>>(program, SP1Stdin::new()).unwrap();
    }

    #[test]
    fn test_bn254_mac_simple() {
        utils::setup_logger();
        
        // Test case: (2 * 3) + 4
        let x = [0u8; 32];  // Result location
        let a = [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let b = [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let c = [4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        
        let program = create_mac_program(&x, &a, &b, &c);
        let mut runtime = Executor::new(program.clone(), Default::default());
        runtime.run().unwrap();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_bn254_mac_as_mul() {
        utils::setup_logger();
        
        // Test MAC with c=0 (equivalent to multiplication)
        let x = [0u8; 32];
        let a = [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let b = [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let c = [0u8; 32];  // Zero for pure multiplication
        
        let program = create_mac_program(&x, &a, &b, &c);
        let mut runtime = Executor::new(program.clone(), Default::default());
        runtime.run().unwrap();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_bn254_mac_large() {
        utils::setup_logger();
        
        let modulus_minus_one = &BN254_SCALAR_FIELD_MODULUS - BigUint::one();
        let mut x = [0u8; 32];
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        let mut c = [0u8; 32];
        
        let a_bytes = modulus_minus_one.to_bytes_le();
        let b_bytes = vec![2u8];
        let c_bytes = vec![1u8];
        
        a[..a_bytes.len()].copy_from_slice(&a_bytes);
        b[..b_bytes.len()].copy_from_slice(&b_bytes);
        c[..c_bytes.len()].copy_from_slice(&c_bytes);
        
        let program = create_mac_program(&x, &a, &b, &c);
        let mut runtime = Executor::new(program.clone(), Default::default());
        runtime.run().unwrap();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_bn254_mac_zero() {
        utils::setup_logger();
        
        let x = [0u8; 32];
        let a = [0u8; 32];  // First multiplicand is zero
        let b = [5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let c = [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        
        let program = create_mac_program(&x, &a, &b, &c);
        let mut runtime = Executor::new(program.clone(), Default::default());
        runtime.run().unwrap();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_bn254_mac_random() {
        use rand::{Rng, thread_rng};
        utils::setup_logger();
        
        let mut rng = thread_rng();
        
        let mut x = [0u8; 32];
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        let mut c = [0u8; 32];
        
        rng.fill(&mut a);
        rng.fill(&mut b);
        rng.fill(&mut c);
        
        let program = create_mac_program(&x, &a, &b, &c);
        let mut runtime = Executor::new(program.clone(), Default::default());
        runtime.run().unwrap();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_bn254_field_properties() {
        // Test modulus properties
        let modulus = BN254_SCALAR_FIELD_MODULUS;
        assert_eq!(modulus.bits(), 254);
        
        // Verify modulus matches the field parameters
        assert_eq!(
            biguint_from_limbs(Bn254ScalarField::MODULUS), 
            BN254_SCALAR_FIELD_MODULUS
        );
    }
}