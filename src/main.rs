use sodiumoxide::crypto::scalarmult::curve25519;
use sodiumoxide::randombytes::randombytes;

use sodiumoxide::init;

use std::time::Instant;

use rayon::prelude::*;

use simple_mix::format::*;

pub fn main() {
    init().unwrap();

    let mix_params = MixStageParameters {
        routing_information_length_bytes: 32,
        remaining_header_length_bytes: (32 + 16 + 32) * 4,
        payload_length_bytes: 1024, // 1kb
    };

    let user_secret_bytes = randombytes(32);
    let mix_secret_bytes = randombytes(32);

    let user_secret: curve25519::Scalar =
        curve25519::Scalar::from_slice(&user_secret_bytes).unwrap();
    let mix_secret: curve25519::Scalar = curve25519::Scalar::from_slice(&mix_secret_bytes).unwrap();
    let mix_public_key = curve25519::scalarmult_base(&mix_secret);

    let routing = [0; 32];

    let mut buffer = randombytes(mix_params.incoming_packet_length());

    let _ = mix_params
        .encode_mix_layer(&mut buffer[..], &user_secret, &mix_public_key, &routing[..])
        .unwrap();

    let mut new_buffer = buffer.clone();

    let now = Instant::now();
    for _n in 0..50_000 {
        new_buffer.clear();
        new_buffer.extend(&buffer);

        let _ = mix_params
            .decode_mix_layer(&mut new_buffer[..], &mix_secret)
            .unwrap();
    }

    let new_now = now.elapsed().as_millis();
    println!("Single Thread: {} pkt / sec", 1_000 * 50_000 / new_now);

    let mut messages = Vec::new();
    for _i in 0..100000 {
        messages.push(buffer.clone());
    }

    let now = Instant::now();
    messages.par_iter_mut().for_each(|m| {
        let _ = mix_params
            .decode_mix_layer(&mut m[..], &mix_secret)
            .unwrap();
    });

    let new_now = now.elapsed().as_millis();
    println!("Parallel: {} pkt / sec", 1_000 * 100_000 / new_now);
}
