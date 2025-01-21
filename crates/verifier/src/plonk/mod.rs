pub(crate) const GAMMA: &str = "gamma";
pub(crate) const BETA: &str = "beta";
pub(crate) const ALPHA: &str = "alpha";
pub(crate) const ZETA: &str = "zeta";
pub(crate) const U: &str = "u";

mod converter;
mod hash_to_field;
mod kzg;
mod proof;
mod transcript;
mod verify;

pub(crate) mod error;

pub(crate) use converter::{load_plonk_proof_from_bytes, load_plonk_verifying_key_from_bytes};
pub(crate) use proof::PlonkProof;
pub(crate) use verify::verify_plonk_algebraic;

use alloc::vec::Vec;
use bn::Fr;
use error::PlonkError;
use sha2::{Digest, Sha256};

use crate::{decode_sp1_vkey_hash, error::Error, hash_public_inputs};
/// A verifier for Plonk zero-knowledge proofs.
#[derive(Debug)]
pub struct PlonkVerifier;

impl PlonkVerifier {
    /// Verifies an SP1 PLONK proof, as generated by the SP1 SDK.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof bytes.
    /// * `public_inputs` - The SP1 public inputs.
    /// * `sp1_vkey_hash` - The SP1 vkey hash.
    ///   This is generated in the following manner:
    ///
    /// ```ignore
    /// use sp1_sdk::ProverClient;
    /// let client = ProverClient::new();
    /// let (pk, vk) = client.setup(ELF);
    /// let sp1_vkey_hash = vk.bytes32();
    /// ```
    /// * `plonk_vk` - The Plonk verifying key bytes.
    ///   Usually this will be the [`static@crate::PLONK_VK_BYTES`] constant.
    ///
    /// # Returns
    ///
    /// A success [`Result`] if verification succeeds, or a [`PlonkError`] if verification fails.
    pub fn verify(
        proof: &[u8],
        sp1_public_inputs: &[u8],
        sp1_vkey_hash: &str,
        plonk_vk: &[u8],
    ) -> Result<(), PlonkError> {
        // Hash the vk and get the first 4 bytes.
        let plonk_vk_hash: [u8; 4] = Sha256::digest(plonk_vk)[..4]
            .try_into()
            .map_err(|_| PlonkError::GeneralError(Error::InvalidData))?;

        // Check to make sure that this proof was generated by the plonk proving key corresponding to
        // the given plonk vk.
        //
        // SP1 prepends the raw Plonk proof with the first 4 bytes of the plonk vkey to
        // facilitate this check.
        if plonk_vk_hash != proof[..4] {
            return Err(PlonkError::PlonkVkeyHashMismatch);
        }

        let sp1_vkey_hash = decode_sp1_vkey_hash(sp1_vkey_hash)?;

        Self::verify_gnark_proof(
            &proof[4..],
            &[sp1_vkey_hash, hash_public_inputs(sp1_public_inputs)],
            plonk_vk,
        )
    }

    /// Verifies a Gnark PLONK proof using raw byte inputs.
    ///
    /// WARNING: if you're verifying an SP1 proof, you should use [`verify`] instead.
    /// This is a lower-level verification method that works directly with raw bytes rather than
    /// the SP1 SDK's data structures.
    ///
    /// # Arguments
    ///
    /// * `proof` - The raw PLONK proof bytes (without the 4-byte vkey hash prefix)
    /// * `public_inputs` - The public inputs to the circuit
    /// * `plonk_vk` - The PLONK verifying key bytes
    ///
    /// # Returns
    ///
    /// A [`Result`] containing unit `()` if the proof is valid,
    /// or a [`PlonkError`] if verification fails.
    pub fn verify_gnark_proof(
        proof: &[u8],
        public_inputs: &[[u8; 32]],
        plonk_vk: &[u8],
    ) -> Result<(), PlonkError> {
        let plonk_vk = load_plonk_verifying_key_from_bytes(plonk_vk).unwrap();
        let proof = load_plonk_proof_from_bytes(proof, plonk_vk.qcp.len()).unwrap();

        let public_inputs =
            public_inputs.iter().map(|input| Fr::from_slice(input).unwrap()).collect::<Vec<_>>();
        verify_plonk_algebraic(&plonk_vk, &proof, &public_inputs)
    }
}