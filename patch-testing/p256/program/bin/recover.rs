#![no_main]
sp1_zkvm::entrypoint!(main);

use ecdsa_core::RecoveryId;
use p256::ecdsa::{Signature, VerifyingKey};

pub fn main() {
    let times = sp1_zkvm::io::read::<u16>();

    for _ in 0..times {
        let vk = inner();
        sp1_zkvm::io::commit(&vk.map(|vk| vk.to_sec1_bytes()));
    }
}

fn inner() -> Option<VerifyingKey> {
    let (message, signature, recid_byte): (Vec<u8>, Signature, u8) = sp1_zkvm::io::read();
    let recid = RecoveryId::from_byte(recid_byte).unwrap();

    VerifyingKey::recover_from_prehash(&message, &signature, recid).ok()
}