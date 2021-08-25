
//! # The lion all-or-nothing transform
//!
//! The lion transform implements a keyed permutation (block cipher) with a 
//! variable length block size. It takes a key of 32 bytes, and a message of 
//! length >= 48 bytes. 
//! 
//! The cryptographic primitives used to implement the transform are a 
//! stream cipher `PRF1(IV, KEY)` (using `crypto_stream_xsalsa20`), a message authentication 
//! code `PRF2(MSG, KEY)` (using `HMAC-SHA-512-256`) and a key derivation function `KDF(KEY, ID)` 
//! (using `Blake2b`).
//! 
//! The message to encode is split into two parts `M = [L0, R0]`, where L is 24 bytes, and 
//! R is the remaining of the message. 
//! 
//! Encoding then proceeds in 3 steps:
//! * `R1 = PRF1(L0, KDF(key, subkey_0)) XOR R0;`
//! * `L1 = PRF2(R1, KDF(key, subkey_1)) XOR L0;`
//! * `R2 = PRF1(L1, KDF(key, subkey_2)) XOR R1;`
//! 
//! The output of the transform is the concatenated byte string `M' = [L1, R2]` which has the same
//! length as the original message.
//! 
//! ## Manual key schedule.
//! 
//! If you just want to encode / decode using lion as a wide-block block cipher simply use the 
//! [lion_transform_encrypt] and [lion_transform_decrypt] functions. 
//! 
//! If you know what you are doing you can determine your own key schedule for the transform. The
//! key schedule for encypt and decrypt are [1, 2, 3] and [3, 2, 1] respectivelly. You may define 
//! a key schedule that is symmetric (such as [1, 2, 1]) to build a transform T(k,m) that has the 
//! property m = T(k, T(k, m)).


use sodiumoxide::crypto::auth;
use sodiumoxide::crypto::kdf;
use sodiumoxide::crypto::stream;
use sodiumoxide::utils::memzero;

const TAG_LEN: usize = 24;

/// The lion transform encryption function.
/// 
/// The `key` must be 32 bytes, and the `message` >= 48. The message is 
/// mutated to the encrypted message.
pub fn lion_transform_encrypt(message: &mut [u8], key: &[u8]) {
    lion_transform(message, key, [1, 2, 3]);
}

/// The lion transform decryption function.
/// 
/// The `key` must be 32 bytes, and the `message` >= 48. The message 
/// is mutated to the decrypted message.
pub fn lion_transform_decrypt(message: &mut [u8], key: &[u8]) {
    lion_transform(message, key, [3, 2, 1]);
}

/// The core of the lion transform function, that takes a message and a key, 
/// and applies the all-or-nothing transform. The key schedule represents the 
/// values of the 3 subkeys used by the 3 phases of the transform.
/// 
/// The `key` must be 32 bytes, and the `message` >= 48. 
/// 
/// Unless you know what you are doing use [lion_transform_encrypt] and 
/// [lion_transform_decrypt] instead.
pub fn lion_transform(message: &mut [u8], key: &[u8], key_schedule: [u64; 3]) {
    assert!(key.len() == 32);
    assert!(message.len() >= TAG_LEN * 2);

    // Derive the subkeys.
    const CONTEXT: [u8; 8] = *b"LIONKEYS";
    let master_key = kdf::Key::from_slice(&key[..]).expect("Incorrect master key length.");
    let mut temp_key: [u8; 32] = [0; 32];
    let subkey_ids = key_schedule;

    // Stage 1: Use stream cipher with Nonce from left size, to xor to the right side
    kdf::derive_from_key(&mut temp_key[..], subkey_ids[0], CONTEXT, &master_key)
        .expect("Subkey provided is not correct length.");
    let lion_stage_1_key: stream::Key = stream::Key::from_slice(&temp_key[..]).unwrap();
    let left_short_message: stream::Nonce = stream::Nonce::from_slice(&message[..TAG_LEN]).unwrap();
    stream::stream_xor_inplace(
        &mut message[TAG_LEN..],
        &left_short_message,
        &lion_stage_1_key,
    );

    // Stage 2: Use HMAC of right size, and xor to the left side
    kdf::derive_from_key(&mut temp_key[..], subkey_ids[1], CONTEXT, &master_key)
        .expect("Subkey provided is not correct length.");
    let lion_stage_2_key: auth::Key = auth::Key::from_slice(&temp_key[..]).unwrap();
    let tag_to_xor = auth::authenticate(&mut message[TAG_LEN..], &lion_stage_2_key);

    // Xor resulting HMAC into the left (short) message
    for i in 0..TAG_LEN {
        message[i] ^= tag_to_xor.0[i];
    }

    // Stage 3: (same as 1)
    kdf::derive_from_key(&mut temp_key[..], subkey_ids[2], CONTEXT, &master_key)
        .expect("Subkey provided is not correct length.");
    let lion_stage_3_key: stream::Key = stream::Key::from_slice(&temp_key[..]).unwrap();
    let left_short_message_final: stream::Nonce =
        stream::Nonce::from_slice(&message[..TAG_LEN]).unwrap();
    stream::stream_xor_inplace(
        &mut message[TAG_LEN..],
        &left_short_message_final,
        &lion_stage_3_key,
    );

    // clean up temp key
    memzero(&mut temp_key[..]);
}
