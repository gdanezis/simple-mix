use sodiumoxide::crypto::auth;
use sodiumoxide::crypto::kdf;
use sodiumoxide::crypto::stream;
use sodiumoxide::utils::memzero;

const TAG_LEN: usize = 24;

pub fn lion_transform_encrypt(message: &mut [u8], key: &[u8]) {
    lion_transform(message, key, [1, 2, 3]);
}

pub fn lion_transform_decrypt(message: &mut [u8], key: &[u8]) {
    lion_transform(message, key, [3, 2, 1]);
}

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
    let aead_tag_to_xor = auth::authenticate(&mut message[TAG_LEN..], &lion_stage_2_key);

    // Xor resulting HMAC into the left (short) message
    for i in 0..TAG_LEN {
        message[i] ^= aead_tag_to_xor.0[i];
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
