// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2017-2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! ed25519 public keys.

use core::fmt::Debug;

use crate::constants::*;
use crate::errors::*;
use crate::ffi::*;
use crate::secret::*;
use crate::signature::*;
use crate::signature_vrf::*;

/// An ed25519 public key.
#[derive(Copy, Clone, Default, Eq, PartialEq)]
pub struct PublicKey(pub(crate) [u8; PUBLIC_KEY_LENGTH]);

impl Debug for PublicKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "PublicKey: {:?}", &self.0[..])
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<'a> From<&'a SecretKey> for PublicKey {
    /// Derive this public key from its corresponding `SecretKey`.
    fn from(secret_key: &SecretKey) -> PublicKey {
        let mut pubkey = PublicKey([0u8; PUBLIC_KEY_LENGTH]);

        unsafe {
            curve25519_keygen(
                pubkey.0.as_mut_ptr(),
                secret_key.0.as_ptr(),
            );
        }

        pubkey
    }
}

impl PublicKey {
    /// Convert this public key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0
    }

    /// View this public key as a byte array.
    #[inline]
    pub fn as_bytes<'a>(&'a self) -> &'a [u8; PUBLIC_KEY_LENGTH] {
        &(self.0)
    }

    /// Construct a `PublicKey` from a slice of bytes.
    ///
    /// # Warning
    ///
    /// The caller is responsible for ensuring that the bytes passed into this
    /// method actually represent a `curve25519_signal::curve::CompressedEdwardsY`
    /// and that said compressed point is actually a point on the curve.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate ed25519_signal;
    /// #
    /// use ed25519_signal::PublicKey;
    /// use ed25519_signal::PUBLIC_KEY_LENGTH;
    /// use ed25519_signal::SignatureError;
    ///
    /// # fn doctest() -> Result<PublicKey, SignatureError> {
    /// let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = [
    ///    215,  90, 152,   1, 130, 177,  10, 183, 213,  75, 254, 211, 201, 100,   7,  58,
    ///     14, 225, 114, 243, 218, 166,  35,  37, 175,   2,  26, 104, 247,   7,   81, 26];
    ///
    /// let public_key = PublicKey::from_bytes(&public_key_bytes)?;
    /// #
    /// # Ok(public_key)
    /// # }
    /// #
    /// # fn main() {
    /// #     doctest();
    /// # }
    /// ```
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is an EdDSA `PublicKey` or whose error value
    /// is an `SignatureError` describing the error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, SignatureError> {
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(SignatureError(InternalError::BytesLengthError {
                name: "PublicKey",
                length: PUBLIC_KEY_LENGTH,
            }));
        }
        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);

        Ok(PublicKey(bits))
    }

    /// Verify a signature on a message with this keypair's public key.
    ///
    /// # Return
    ///
    /// Returns `Ok(())` if the signature is valid, and `Err` otherwise.
    #[allow(non_snake_case)]
    pub fn verify(
        &self,
        message: &[u8],
        signature: &Signature
    ) -> Result<(), SignatureError>
    {
        let valid: bool;
        unsafe {
            let res = xed25519_verify(
                signature.0.as_ptr(),
                self.0.as_ptr(),
                message.as_ptr(),
                message.len() as u64,
            );
            valid = res == 0;
        }
        if !valid {
            Err(SignatureError(InternalError::VerifyError))
        } else {
            Ok(())
        }
    }

    pub fn verify_vrf(
        &self,
        message: &[u8],
        label: &[u8],
        signature: &SignatureVRF,
    ) -> Result<[u8; VRF_OUT_LENGTH], SignatureError>
    {
        let mut vrf_out = [0u8; VRF_OUT_LENGTH];

        let valid: bool;
        unsafe {
            let res = generalized_xveddsa_25519_verify(
                vrf_out.as_mut_ptr(),
                signature.0.as_ptr(),
                self.0.as_ptr(),
                message.as_ptr(),
                message.len() as u64,
                label.as_ptr(),
                label.len() as u64,
            );
            valid = res == 0;
        }
        if !valid {
            Err(SignatureError(InternalError::VerifyError))
        } else {
            Ok(vrf_out)
        }
    }
}
