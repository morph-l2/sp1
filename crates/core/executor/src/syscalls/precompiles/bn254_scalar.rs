use crate::{
    events::{create_bn254_scalar_arith_event, Bn254FieldOperation, PrecompileEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext},
};

pub(crate) struct Bn254ScalarMulAddSyscall;

impl Syscall for Bn254ScalarMulAddSyscall {
    fn execute(
        &self,
        rt: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let start_clk = rt.clk;
        let event = create_bn254_scalar_arith_event(rt, arg1, arg2, Bn254FieldOperation::MulAdd);
        let syscall_event =
            rt.rt.syscall_event(start_clk, syscall_code.syscall_id(), arg1, arg2, event.lookup_id);

        rt.record_mut().add_precompile_event(
            syscall_code,
            syscall_event,
            PrecompileEvent::Bn254ScalarMulAdd(event),
        );

        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}
