#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// memcopy32 operation.
///
/// The result is written over the first input.
///
/// ### Safety
///
/// The caller must ensure that `src` and `dst` are valid pointers to data that is aligned along a four
/// byte boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_memcopy32(src: *const [u32; 8], dst: *mut [u32; 8]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::MEMCPY_32,
            in("a0") src,
            in("a1") dst,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// memcopy64 operation.
///
/// The result is written over the first input.
///
/// ### Safety
///
/// The caller must ensure that `src` and `dst` are valid pointers to data that is aligned along a four
/// byte boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_memcopy64(src: *const [u32; 8], dst: *mut [u32; 8]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::syscalls::MEMCPY_64,
            in("a0") src,
            in("a1") dst,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
