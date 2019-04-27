// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2017-2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Integration tests for ed25519-dalek.

extern crate ed25519_signal;
extern crate rand;

use ed25519_signal::*;

use rand::thread_rng;
use rand::rngs::ThreadRng;

#[cfg(test)]
mod integrations {
    use super::*;

    static LARGE_MSG: [u8; 1024] = [42u8; 1024];

    #[test]
    fn sign_verify() {  // TestSignVerify
        let mut csprng: ThreadRng;
        let keypair: Keypair;
        let good_sig: Signature;
        let bad_sig:  Signature;

        let good: &[u8] = "test message".as_bytes();
        let bad:  &[u8] = "wrong message".as_bytes();

        csprng  = thread_rng();
        keypair  = Keypair::generate(&mut csprng);
        good_sig = keypair.sign(&good);
        bad_sig  = keypair.sign(&bad);
        keypair.sign(&LARGE_MSG);

        assert!(keypair.verify(&good, &good_sig).is_ok(),
                "Verification of a valid signature failed!");
        assert!(keypair.verify(&good, &bad_sig).is_err(),
                "Verification of a signature on a different message passed!");
        assert!(keypair.verify(&bad,  &good_sig).is_err(),
                "Verification of a signature on a different message passed!");
    }

    #[test]
    fn vrf_sign_verify() {
        let mut csprng: ThreadRng;
        let keypair: Keypair;
        let good_sig: SignatureVRF;
        let bad_sig: SignatureVRF;

        let label: &[u8] = "label".as_bytes();
        let good: &[u8] = "test message".as_bytes();
        let bad:  &[u8] = "wrong message".as_bytes();

        csprng = thread_rng();
        keypair = Keypair::generate(&mut csprng);
        good_sig = keypair.sign_vrf(&good, &label);
        bad_sig = keypair.sign_vrf(&bad, &label);
        // Test signing large message
        keypair.sign_vrf(&LARGE_MSG, &label);

        assert!(keypair.verify_vrf(&good, &label, &good_sig).is_ok(),
                "Verification of a valid signature failed!");
        assert!(keypair.verify_vrf(&good, &label, &bad_sig).is_err(),
                "Verification of a signature on a different message passed!");
        assert!(keypair.verify_vrf(&bad, &label, &good_sig).is_err(),
                "Verification of a signature on a different message passed!");
    }

    #[test]
    fn internal() {
        let res;
        unsafe {
            res = all_fast_tests(1);
        }
        assert!(res == 0, "Internal tests failed!");
    }
}
