// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2017-2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! An ed25519 signature.

use crate::constants::*;
use crate::errors::*;

/// An ed25519 signature.
///
/// # Note
///
/// These signatures, unlike the ed25519 signature reference implementation, are
/// "detached"—that is, they do **not** include a copy of the message which has
/// been signed.
#[derive(Copy)]
pub struct Signature(pub(crate) [u8; SIGNATURE_LENGTH]);

impl PartialEq for Signature {
    fn eq(&self, other: &Signature) -> bool {
        self.0.iter().zip(other.0.iter()).all(|(a,b)| a == b)
    }
}

impl Clone for Signature {
    fn clone(&self) -> Self {
        *self
    }
}

impl Signature {
    /// Convert this `Signature` to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        self.0
    }

    #[inline]
    pub fn as_bytes<'a>(&'a self) -> &'a [u8; SIGNATURE_LENGTH] {
        &(self.0)
    }

    /// Construct a `Signature` from a slice of bytes.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Signature, SignatureError> {
        if bytes.len() != SIGNATURE_LENGTH {
            return Err(SignatureError(InternalError::BytesLengthError {
                name: "Signature",
                length: SIGNATURE_LENGTH,
            }));
        }
        let mut bits: [u8; 64] = [0u8; 64];
        bits.copy_from_slice(&bytes[..64]);

        Ok(Signature(bits))
    }
}
