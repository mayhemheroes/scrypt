#![no_main]
// OSS-Fuzz `scrypt` target, re-expressed against the current RustCrypto/password-hashes HEAD API.
//
// This is the mayhem layer's own copy of the harness (ADDITIVE — the upstream ../../fuzz target is
// left untouched). The original OSS-Fuzz harness was written against an older scrypt release that
// exposed a `simple` cargo feature, a `SaltString::encode_b64` constructor, and re-exported
// `Ident`/`Salt`/`SaltString` directly from `scrypt::password_hash`. HEAD instead gates PHC support
// behind the `phc` feature and routes those types through `scrypt::password_hash::phc::*`; `Scrypt`
// is now a parameterised struct (no unit value) and `CustomizedPasswordHasher::hash_password_customized`
// takes the raw salt bytes plus an `alg_id: Option<&str>`. Same fuzzing surface:
//   - drive the low-level `scrypt()` KDF,
//   - build a `$scrypt$...` PHC string via the high-level hasher, and
//   - parse that string back with `PasswordHash::new` and verify it (the bug-relevant parse path).
use libfuzzer_sys::arbitrary::{Arbitrary, Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use scrypt::password_hash::phc::{Ident, PasswordHash, Salt};
use scrypt::password_hash::{CustomizedPasswordHasher, PasswordVerifier};
use scrypt::{Scrypt, scrypt};

#[derive(Debug)]
pub struct ScryptRandParams(pub scrypt::Params);

impl<'a> Arbitrary<'a> for ScryptRandParams {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let log_n = u.int_in_range(0..=15)?;
        let r = u.int_in_range(1..=16)?;
        let p = u.int_in_range(1..=8)?;
        let len = u.int_in_range(10..=64)?;

        // `Params::new` no longer takes the output length; `new_with_output_len` carries it
        // (the value used by the PHC `PasswordHasher` path) and validates 10..=64.
        let params = scrypt::Params::new_with_output_len(log_n, r, p, len).unwrap();
        Ok(Self(params))
    }
}

fuzz_target!(|data: (&[u8], &[u8], ScryptRandParams)| {
    let (password, salt, ScryptRandParams(params)) = data;

    if password.len() > 64 {
        return;
    }

    // Raw salt-byte bounds accepted by `Salt::new` (PHC `Salt::MIN_LENGTH..=MAX_LENGTH`).
    if salt.len() < Salt::MIN_LENGTH || salt.len() > Salt::MAX_LENGTH {
        return;
    }

    // Check the low-level KDF.
    let mut result = [0u8; 64];
    scrypt(password, salt, &params, &mut result).unwrap();

    // Check PHC hashing: the high-level hasher takes the raw salt bytes and the requested params.
    let hasher = Scrypt::from(params);
    let phc_hash = hasher
        .hash_password_customized(
            password,
            salt,
            Some(Ident::new_unwrap("scrypt").as_str()),
            None,
            params,
        )
        .unwrap()
        .to_string();

    // Check PHC parsing + verification round-trip.
    let hash = PasswordHash::new(&phc_hash).unwrap();
    hasher.verify_password(password, &hash).unwrap();
});
