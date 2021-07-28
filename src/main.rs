use sodiumoxide::crypto::aead::chacha20poly1305_ietf;
use sodiumoxide::crypto::scalarmult::curve25519;
use sodiumoxide::randombytes::randombytes;

use sodiumoxide::init;

use std::time::{Instant};

use sodiumoxide::crypto::auth;
use sodiumoxide::crypto::stream;

use std::ops::Range;

use rayon::prelude::*;

const TAG_LEN: usize = 24;


struct MixCreationParameters {
        // The routing information length for each stage of the packet creation
        // The routing length is inner first, so [0] is the innermost routing length, etc
        routing_information_length_by_stage: Vec<usize>,
        // The payload length
        payload_length_bytes: usize,
}

impl MixCreationParameters {

    // Create a set of parameters for a mix packet format
    fn new(payload_length_bytes : usize) -> MixCreationParameters {
        MixCreationParameters {
            routing_information_length_by_stage: Vec::new(),
            payload_length_bytes
        }
    }

    // Add another outer layer containing some byte length of routing data
    fn add_outer_layer(&mut self, routing_information_length_bytes : usize ) {
        self.routing_information_length_by_stage.push(routing_information_length_bytes);
    }

    //The length of the buffer needed to build a packet
    fn total_packet_length(&self) -> usize {
        let mut len = self.payload_length_bytes;
        for stage_len in &self.routing_information_length_by_stage {
            len += stage_len + curve25519::GROUPELEMENTBYTES + chacha20poly1305_ietf::TAGBYTES
        }
        len
    }

    fn get_stage_params(&self, layer_number : usize) -> (Range<usize>, MixStageParameters) {
        assert!(layer_number < self.routing_information_length_by_stage.len());

        let mut remaining_header_length_bytes = 0;
        for (i, stage_len) in self.routing_information_length_by_stage.iter().enumerate() {
            if i == layer_number {
                let params = MixStageParameters {
                    routing_information_length_bytes : *stage_len,
                    remaining_header_length_bytes,
                    payload_length_bytes : self.payload_length_bytes
                };

                let total_size = self.total_packet_length();
                let inner_size = params.incoming_packet_length();

                return (total_size - inner_size..total_size, params);
            }
            else {
                remaining_header_length_bytes += stage_len + curve25519::GROUPELEMENTBYTES + chacha20poly1305_ietf::TAGBYTES;
            }
        }

        unreachable!();
    }

}

struct MixStageParameters {
    // The routing information length for this stage of mixing
    routing_information_length_bytes: usize,
    // The reamining header length for this stage of mixing
    remaining_header_length_bytes: usize,
    // The payload length
    payload_length_bytes: usize,
}

impl MixStageParameters {
    fn incoming_packet_length(&self) -> usize {
        return curve25519::GROUPELEMENTBYTES
            + chacha20poly1305_ietf::TAGBYTES
            + self.outgoing_packet_length();
    }

    fn outgoing_packet_length(&self) -> usize {
        return self.routing_information_length_bytes
            + self.remaining_header_length_bytes
            + self.payload_length_bytes;
    }

    fn pub_element_range(&self) -> Range<usize> {
        0..curve25519::GROUPELEMENTBYTES
    }

    fn tag_range(&self) -> Range<usize> {
        curve25519::GROUPELEMENTBYTES
            ..curve25519::GROUPELEMENTBYTES + chacha20poly1305_ietf::TAGBYTES
    }

    fn routing_data_range(&self) -> Range<usize> {
        curve25519::GROUPELEMENTBYTES + chacha20poly1305_ietf::TAGBYTES
            ..curve25519::GROUPELEMENTBYTES
                + chacha20poly1305_ietf::TAGBYTES
                + self.routing_information_length_bytes
    }

    fn header_range(&self) -> Range<usize> {
        curve25519::GROUPELEMENTBYTES + chacha20poly1305_ietf::TAGBYTES
            ..curve25519::GROUPELEMENTBYTES
                + chacha20poly1305_ietf::TAGBYTES
                + self.routing_information_length_bytes
                + self.remaining_header_length_bytes
    }

    fn payload_range(&self) -> Range<usize> {
        self.incoming_packet_length() - self.payload_length_bytes..self.incoming_packet_length()
    }

    fn encode_mix_layer(
        &self,
        buffer: &mut [u8],
        user_secret_key: &curve25519::Scalar,
        mix_public_key: &curve25519::GroupElement,
        routing_data: &[u8],
    ) -> Result<curve25519::GroupElement, ()> {
        assert!(buffer.len() == self.incoming_packet_length());
        assert!(routing_data.len() == self.routing_information_length_bytes);

        let user_public_key = curve25519::scalarmult_base(user_secret_key);
        let shared_key = curve25519::scalarmult(user_secret_key, mix_public_key).unwrap();

        // Copy rounting data into buffer
        buffer[self.routing_data_range()].clone_from_slice(routing_data);

        // Perform the AEAD
        let header_aead_key = chacha20poly1305_ietf::Key::from_slice(&shared_key.0[..]).unwrap();
        let nonce = chacha20poly1305_ietf::Nonce([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let tag = chacha20poly1305_ietf::seal_detached(
            &mut buffer[self.header_range()],
            None,
            &nonce,
            &header_aead_key,
        );

        // Copy Tag into buffer
        buffer[self.tag_range()].clone_from_slice(&tag.0[..]);

        // Copy own public key into buffer
        buffer[self.pub_element_range()].clone_from_slice(&user_public_key.0[..]);

        // Do a round of LION on the payload
        lion_transform(&mut buffer[self.payload_range()], &shared_key[..]);

        Ok(shared_key)
    }

    fn decode_mix_layer(
        &self,
        buffer: &mut [u8],
        mix_secret_key: &curve25519::Scalar,
    ) -> Result<curve25519::GroupElement, ()> {
        // Check the length of the incoming buffer is correct.
        if buffer.len() != self.incoming_packet_length() {
            return Err(());
        }

        // Derive the shared key for this packet
        let user_public_key =
            curve25519::GroupElement::from_slice(&buffer[self.pub_element_range()]).unwrap();
        let shared_key = curve25519::scalarmult(&mix_secret_key, &user_public_key)?;

        // Compute the AEAD and check the Tag, if wrong return Err
        let header_aead_key = chacha20poly1305_ietf::Key::from_slice(&shared_key.0[..]).unwrap();
        let nonce = chacha20poly1305_ietf::Nonce([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let tag = chacha20poly1305_ietf::Tag::from_slice(&buffer[self.tag_range()]).unwrap();

        chacha20poly1305_ietf::open_detached(
            &mut buffer[self.header_range()],
            None,
            &tag,
            &nonce,
            &header_aead_key,
        )?;

        // Do a round of LION on the payload
        lion_transform(&mut buffer[self.payload_range()], &shared_key[..]);

        Ok(shared_key)
    }
}

fn lion_transform(message: &mut [u8], key: &[u8]) {
    assert!(key.len() == 32);
    assert!(message.len() >= TAG_LEN * 2);

    // Stage 1: Use stream cipher with Nonce from left size, to xor to the right side
    let lion_stage_1_key: stream::Key = stream::Key::from_slice(&key[..]).unwrap();
    let left_short_message: stream::Nonce = stream::Nonce::from_slice(&message[..TAG_LEN]).unwrap();
    stream::stream_xor_inplace(
        &mut message[TAG_LEN..],
        &left_short_message,
        &lion_stage_1_key,
    );

    // Stage 2: Use HMAC of right size, and xor to the left side
    let lion_stage_2_key: auth::Key = auth::Key::from_slice(&key[..]).unwrap();
    let aead_tag_to_xor = auth::authenticate(&mut message[TAG_LEN..], &lion_stage_2_key);

    // Xor resulting HMAC into the left (short) message
    for i in 0..TAG_LEN {
        message[i] ^= aead_tag_to_xor.0[i];
    }

    // Stage 3: (same as 1)
    let lion_stage_3_key = lion_stage_1_key;
    let left_short_message_final: stream::Nonce =
        stream::Nonce::from_slice(&message[..TAG_LEN]).unwrap();
    stream::stream_xor_inplace(
        &mut message[TAG_LEN..],
        &left_short_message_final,
        &lion_stage_3_key,
    );
}

fn main() {
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

    let _ = mix_params.encode_mix_layer(&mut buffer[..], &user_secret, &mix_public_key, &routing[..]).unwrap();

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

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_encode_decode() {
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

        let buffer = randombytes(mix_params.incoming_packet_length());

        let mut new_buffer = buffer.clone();

        let _ = mix_params.encode_mix_layer(
            &mut new_buffer[..],
            &user_secret,
            &mix_public_key,
            &routing[..],
        ).unwrap();

        assert!(&new_buffer[mix_params.payload_range()] != &buffer[mix_params.payload_range()]);
        assert!(&new_buffer[mix_params.routing_data_range()] != &routing[..]);

        let _ = mix_params
            .decode_mix_layer(&mut new_buffer[..], &mix_secret)
            .unwrap();

        assert!(&new_buffer[mix_params.payload_range()] == &buffer[mix_params.payload_range()]);
        assert!(&new_buffer[mix_params.routing_data_range()] == &routing[..]);
    }

    #[test]
    fn test_lion() {
        let key = randombytes(32);
        let message = randombytes(1024);
        
        let mut message_clone = message.clone();
        lion_transform(&mut message_clone[..], &key[..]);
        assert!(&message_clone[..] != &message[..]);

        lion_transform(&mut message_clone[..], &key[..]);
        assert!(&message_clone[..] == &message[..]);

    }


    #[test]
    fn test_packet_params() {

        // Dummy keys -- we will use the same key for each layer
        let user_secret_bytes = randombytes(32);
        let mix_secret_bytes = randombytes(32);

        let user_secret: curve25519::Scalar =
            curve25519::Scalar::from_slice(&user_secret_bytes).unwrap();
        let mix_secret: curve25519::Scalar =
            curve25519::Scalar::from_slice(&mix_secret_bytes).unwrap();
        let mix_public_key = curve25519::scalarmult_base(&mix_secret);

        let routing = [0; 32];


        let mut params = MixCreationParameters::new(1025);
        params.add_outer_layer(32);
        params.add_outer_layer(32);
        params.add_outer_layer(32);

        let mut buf = vec![0; params.total_packet_length()];

        let (range0, layer_params0) = params.get_stage_params(0);
        let _ = layer_params0.encode_mix_layer(
            &mut buf[range0.clone()],
            &user_secret,
            &mix_public_key,
            &routing[..],
        ).unwrap();

        let (range1, layer_params1) = params.get_stage_params(1);
        let _ = layer_params1.encode_mix_layer(
            &mut buf[range1.clone()],
            &user_secret,
            &mix_public_key,
            &routing[..],
        ).unwrap();

        let (range2, layer_params2) = params.get_stage_params(2);
        let _ = layer_params2.encode_mix_layer(
            &mut buf[range2.clone()],
            &user_secret,
            &mix_public_key,
            &routing[..],
        ).unwrap();

        assert!(&buf[params.total_packet_length()-1025..params.total_packet_length()] != [0;1025]);

        let _ = layer_params2
        .decode_mix_layer(&mut buf[range2], &mix_secret)
        .unwrap();

        let _ = layer_params1
        .decode_mix_layer(&mut buf[range1], &mix_secret)
        .unwrap();

        let _ = layer_params0
        .decode_mix_layer(&mut buf[range0], &mix_secret)
        .unwrap();



    }

}
