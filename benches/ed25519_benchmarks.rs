// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2018-2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#[macro_use]
extern crate criterion;
extern crate ed25519_signal;
extern crate rand;

use criterion::Criterion;

mod ed25519_benches {
    use super::*;
    use ed25519_signal::Keypair;
    use ed25519_signal::Signature;
    use ed25519_signal::SignatureVRF;
    use rand::thread_rng;
    use rand::rngs::ThreadRng;

    fn sign(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let msg: &[u8] = b"";

        c.bench_function("XEd25519 signing", move |b| {
            b.iter(| | keypair.sign(msg))
        });
    }

    fn verify(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let msg: &[u8] = b"";
        let sig: Signature = keypair.sign(msg);
        
        c.bench_function("XEd25519 signature verification", move |b| {
            b.iter(| | keypair.verify(msg, &sig))
        });
    }

    fn sign_vrf(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let msg: &[u8] = b"";
        let label: &[u8] = b"";

        c.bench_function("VXEd25519 signing", move |b| {
            b.iter(| | keypair.sign_vrf(msg, label))
        });
    }

    fn verify_vrf(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let msg: &[u8] = b"";
        let label: &[u8] = b"";
        let sig: SignatureVRF = keypair.sign_vrf(msg, label);

        c.bench_function("VXEd25519 signature verification", move |b| {
            b.iter(| | keypair.verify_vrf(msg, label, &sig))
        });
}

    fn key_generation(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();

        c.bench_function("Ed25519 keypair generation", move |b| {
                         b.iter(| | Keypair::generate(&mut csprng))
        });
    }

    criterion_group!{
        name = ed25519_benches;
        config = Criterion::default();
        targets =
            sign,
            verify,
            sign_vrf,
            verify_vrf,
            key_generation,
    }
}

criterion_main!(
    ed25519_benches::ed25519_benches,
);
