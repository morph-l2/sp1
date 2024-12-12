#![no_main]
sp1_zkvm::entrypoint!(main);

use num::{BigUint, Num, One};
use rand::Rng;
use sp1_zkvm::syscalls::syscall_memcopy32;

fn memcopy32(x: &[u8; 32], mut y: [u8; 32]) {
    println!("cycle-tracker-start: memcopy32");
    syscall_memcopy32(x.as_ptr() as *const [u32; 8], y.as_mut_ptr() as *mut [u32; 8]);
    println!("cycle-tracker-end: memcopy32");
}

#[sp1_derive::cycle_tracker]
pub fn main() {
    // Test with random numbers.
    let mut rng = rand::thread_rng();
    let mut x: [u8; 32] = rng.gen();
    let mut y: [u8; 32] = rng.gen();

    memcopy32(&x, y);
}
