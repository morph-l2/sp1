#![no_main]
sp1_zkvm::entrypoint!(main);

use num::{BigUint, One};
use rand::Rng;
use sp1_zkvm::syscalls::sys_bn254_muladd;

fn uint256_muladd(x: &[u8; 32], y: &[u8; 32], z: &[u8; 32]) -> [u8; 32] {
    println!("cycle-tracker-start: uint256_muladd");
    let mut result = [0u32; 8];
    sys_bn254_muladd(
        result.as_mut_ptr() as *mut [u32; 8],
        0,
        x.as_ptr() as *const [u32; 8],
        y.as_ptr() as *const [u32; 8],
        z.as_ptr() as *const [u32; 8],
    );
    println!("cycle-tracker-end: uint256_muladd");
    bytemuck::cast::<[u32; 8], [u8; 32]>(result)
}

fn biguint_to_bytes_le(x: BigUint) -> [u8; 32] {
    let mut bytes = x.to_bytes_le();
    bytes.resize(32, 0);
    bytes.try_into().unwrap()
}

#[sp1_derive::cycle_tracker]
pub fn main() {
    // Test with random numbers.
    // let mut rng = rand::thread_rng();
    // let mut x: [u8; 32] = rng.gen();
    // let mut y: [u8; 32] = rng.gen();
    // let z: [u8; 32] = rng.gen();

    // // Convert byte arrays to BigUint
    // let z_big = BigUint::from_bytes_le(&z);
    // let x_big = BigUint::from_bytes_le(&x);
    // // x = biguint_to_bytes_le(x_big.clone());
    // let y_big = BigUint::from_bytes_le(&y);
    // // y = biguint_to_bytes_le(y_big.clone());

    let mut x: [u8; 32] = [0; 32];
    x[0] = 2;
    let mut y: [u8; 32] = [0; 32];
    y[0] = 3;
    let mut z: [u8; 32] = [0; 32];
    z[0] = 4;
    // Convert byte arrays to BigUint
    let z_big = BigUint::from_bytes_le(&z);
    let x_big = BigUint::from_bytes_le(&x);
    let y_big = BigUint::from_bytes_le(&y);

    let result_bytes = uint256_muladd(&x, &y, &z);

    let result = (x_big * y_big) + z_big;
    let result_syscall = BigUint::from_bytes_le(&result_bytes);

    assert_eq!(result, result_syscall); //10
}
