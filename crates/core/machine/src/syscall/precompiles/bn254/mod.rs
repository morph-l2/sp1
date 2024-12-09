pub mod mul_add_uint256;

#[cfg(test)]
mod tests {

    use sp1_core_executor::Program;
    use sp1_stark::CpuProver;
    use test_artifacts::UINT256_MULADD_ELF;

    use crate::{
        io::SP1Stdin,
        utils::{self, run_test_io},
    };

    #[test]
    fn test_uint256_muladd() {
        utils::setup_logger();
        let program = Program::from(UINT256_MULADD_ELF).unwrap();
        run_test_io::<CpuProver<_, _>>(program, SP1Stdin::new()).unwrap();
    }
}
