use crate::{
    events::{create_bn254_scalar_arith_event, Bn254FieldOperation, PrecompileEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext},
};

pub(crate) struct Bn254ScalarMacSyscall;

impl Syscall for Bn254ScalarMacSyscall {
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
            rt.rt.syscall_event(start_clk, None, None, syscall_code, arg1, arg2, rt.next_pc);

        rt.record_mut().add_precompile_event(
            syscall_code,
            syscall_event,
            PrecompileEvent::Bn254ScalarMac(event),
        );

        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}
