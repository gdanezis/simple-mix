#[macro_use]
extern crate criterion;
extern crate simple_mix;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sodiumoxide::randombytes::randombytes;
use sodiumoxide::crypto::scalarmult::curve25519;
use sodiumoxide::init;
use simple_mix::main::MixStageParameters;

fn bench_encode(c: &mut Criterion){
    // init().unwrap();

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

    c.bench_function("SINGLE layer encoding", |b| {
        b.iter(|| {
            let _ = mix_params.encode_mix_layer(&mut buffer[..], &user_secret, &mix_public_key, &routing[..]).unwrap();
        })
    });

}

fn bench_decode(c: &mut Criterion){
    let mix_params = MixStageParameters {
        routing_information_length_bytes: 32,
        remaining_header_length_bytes: (32 + 16 + 32) * 4,
        payload_length_bytes: 1024, // 1kb
    };

    let user_secret_bytes = randombytes(32);
    let mix_secret_bytes = randombytes(32);

    let user_secret: curve25519::Scalar =
        curve25519::Scalar::from_slice(&user_secret_bytes).unwrap();
    let mix_secret: curve25519::Scalar =
        curve25519::Scalar::from_slice(&mix_secret_bytes).unwrap();
    let mix_public_key = curve25519::scalarmult_base(&mix_secret);

    let routing = [0; 32];

    let mut buffer = randombytes(mix_params.incoming_packet_length());
    // println!("BUFFER PLAINTEXT : {:?}", buffer);
    let mut new_buffer = buffer.clone();
    // println!("NEW BUFFER PLAINTEXT : {:?}", new_buffer);

    let _ = mix_params.encode_mix_layer(&mut new_buffer[..], &user_secret, &mix_public_key, &routing[..]).unwrap();
    // println!("NEW BUFFER ENCODED : {:?}", new_buffer);

    // let _ = mix_params
    //     .decode_mix_layer(&mut new_buffer[..], &mix_secret)
    //     .unwrap();
    //
    // println!("NEW BUFFER DECODED: {:?}", new_buffer);
    //
    // assert!(&new_buffer[mix_params.payload_range()] == &buffer[mix_params.payload_range()]);
    // assert!(&new_buffer[mix_params.routing_data_range()] == &routing[..]);

    c.bench_function("SINGLE layer decoding", |b| {
        b.iter(|| {
            let _ = mix_params
                .decode_mix_layer(&mut new_buffer[..], &mix_secret);
        })
    });
}


criterion_group!(simple_mix, bench_encode, bench_decode);
criterion_main!(simple_mix);