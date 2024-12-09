use super::syscall_uint256_muladd;
use super::syscall_uint256_mulmod;

/// The number of limbs in a "uint256".
const N: usize = 8;

/// Sets `result` to be `(x op y) % modulus`.
///
/// Currently only multiplication is supported and `op` is not used. If the modulus is zero, then
/// the modulus applied is 2^256.
///
/// ### Safety
///
/// The caller must ensure that `result`, `x`, `y`, and `modulus` are valid pointers to data that is
/// aligned along a four byte boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn sys_bigint(
    result: *mut [u32; N],
    op: u32,
    x: *const [u32; N],
    y: *const [u32; N],
    modulus: *const [u32; N],
) {
    // Instantiate a new uninitialized array of words to place the concatenated y and modulus.
    let mut concat_y_modulus = core::mem::MaybeUninit::<[u32; N * 2]>::uninit();
    unsafe {
        let result_ptr = result as *mut u32;
        let x_ptr = x as *const u32;
        let y_ptr = y as *const u32;
        let concat_ptr = concat_y_modulus.as_mut_ptr() as *mut u32;

        // First copy the y value into the concatenated array.
        core::ptr::copy(y_ptr, concat_ptr, N);

        // Then, copy the modulus value into the concatenated array. Add the width of the y value
        // to the pointer to place the modulus value after the y value.
        core::ptr::copy(modulus as *const u32, concat_ptr.add(N), N);

        // Copy x into the result array, as our syscall will write the result into the first input.
        core::ptr::copy(x as *const u32, result_ptr, N);

        // Call the uint256_mul syscall to multiply the x value with the concatenated y and modulus.
        // This syscall writes the result in-place, so it will mutate the result ptr appropriately.
        let result_ptr = result_ptr as *mut [u32; N];
        let concat_ptr = concat_ptr as *mut [u32; N];
        syscall_uint256_mulmod(result_ptr, concat_ptr);
    }
}

/// Sets `result` to be `(x op y) + z`.
///
/// Currently only multiplication is supported and `op` is not used. If the z is zero, then
/// the z applied is 2^256.
///
/// ### Safety
///
/// The caller must ensure that `result`, `x`, `y`, and `z` are valid pointers to data that is
/// aligned along a four byte boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn sys_bn254_muladd(
    result: *mut [u32; N],
    op: u32,
    x: *const [u32; N],
    y: *const [u32; N],
    z: *const [u32; N],
) {
    // Instantiate a new uninitialized array of words to place the concatenated y and z.
    let mut concat_y_z = core::mem::MaybeUninit::<[u32; N * 2]>::uninit();
    unsafe {
        let result_ptr = result as *mut u32;
        let x_ptr = x as *const u32;
        let y_ptr = y as *const u32;
        let concat_ptr = concat_y_z.as_mut_ptr() as *mut u32;

        // First copy the y value into the concatenated array.
        core::ptr::copy(x_ptr, concat_ptr, N);

        // Then, copy the z value into the concatenated array. Add the width of the y value
        // to the pointer to place the z value after the y value.
        core::ptr::copy(y as *const u32, concat_ptr.add(N), N);

        // Copy x into the result array, as our syscall will write the result into the first input.
        core::ptr::copy(z as *const u32, result_ptr, N);

        // Call the uint256_mul syscall to multiply the x value with the concatenated y and z.
        // This syscall writes the result in-place, so it will mutate the result ptr appropriately.
        let result_ptr = result_ptr as *mut [u32; N];
        let concat_ptr = concat_ptr as *mut [u32; N];
        syscall_uint256_muladd(result_ptr, concat_ptr);
    }
}
