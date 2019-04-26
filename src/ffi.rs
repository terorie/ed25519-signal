extern crate libc;

use crate::ffi::libc::*;

#[link(name = "curve25519-signal")]
extern "C" {
    pub fn sc_clamp(a: *mut c_uchar);

    pub fn curve25519_keygen(
        curve25519_pubkey_out: *mut c_uchar,
        curve25519_privkey: *const c_uchar,
    );

    pub fn xed25519_sign(
        signature_out: *mut c_uchar,
        curve25519_privkey: *const c_uchar,
        msg: *const c_uchar,
        msg_len: c_ulong,
        random: *const c_uchar,
    ) -> c_int;

    pub fn xed25519_verify(
        signature: *const c_uchar,
        curve25519_pubkey: *const c_uchar,
        msg: *const c_uchar,
        msg_len: c_ulong,
    ) -> c_int;

    pub fn generalized_xveddsa_25519_sign(
        signature_out: *mut c_uchar,
        eddsa_25519_privkey_scalar: *const c_uchar,
        msg: *const c_uchar,
        msg_len: c_ulong,
        random: *const c_uchar,
        customization_label: *const c_uchar,
        customization_label_len: c_ulong,
    ) -> c_int;

    pub fn generalized_xveddsa_25519_verify(
        vrf_out: *mut c_uchar,
        signature: *const c_uchar,
        eddsa_25519_pubkey_bytes: *const c_uchar,
        msg: *const c_uchar,
        msg_len: c_ulong,
        customization_label: *const c_uchar,
        customization_label_len: c_ulong,
    ) -> c_int;

    // TODO Only compile in test mode
    pub fn all_fast_tests(silent: c_int) -> c_int;
}
