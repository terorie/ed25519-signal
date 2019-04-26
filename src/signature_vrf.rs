// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2017-2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

use core::fmt::Debug;

use crate::constants::*;
use crate::errors::*;

#[derive(Copy)]
pub struct SignatureVRF(pub(crate) [u8; SIGNATURE_VRF_LENGTH]);

impl PartialEq for SignatureVRF {
    fn eq(&self, other: &SignatureVRF) -> bool {
        self.0.iter().zip(other.0.iter()).all(|(a,b)| a == b)
    }
}

impl Clone for SignatureVRF {
    fn clone(&self) -> Self {
        *self
    }
}

impl Debug for SignatureVRF {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "SignatureVRF: {:?}", &self.0[..])
    }
}

impl SignatureVRF {
    /// Convert this `SignatureVRF` to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_VRF_LENGTH] {
        self.0
    }

    #[inline]
    pub fn as_bytes<'a>(&'a self) -> &'a [u8; SIGNATURE_VRF_LENGTH] {
        &(self.0)
    }

    /// Construct a `SignatureVRF` from a slice of bytes.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<SignatureVRF, SignatureError> {
        if bytes.len() != SIGNATURE_VRF_LENGTH {
            return Err(SignatureError(InternalError::BytesLengthError {
                name: "Signature",
                length: SIGNATURE_VRF_LENGTH,
            }));
        }
        let mut bits: [u8; 96] = [0u8; 96];
        bits.copy_from_slice(&bytes[..96]);

        Ok(SignatureVRF(bits))
    }
}
