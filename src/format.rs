use sodiumoxide::crypto::aead::chacha20poly1305_ietf;
use sodiumoxide::crypto::scalarmult::curve25519;

use std::ops::Range;

use crate::lion::*;

/// A structure that holds mix packet construction parameters. These incluse the length
/// of the routing information at each hop, the number of hops, and the payload length.
pub struct MixCreationParameters {
    /// The routing length is inner first, so [0] is the innermost routing length, etc (in bytes)
    pub routing_information_length_by_stage: Vec<usize>,
    /// The payload length (in bytes)
    pub payload_length_bytes: usize,
}

impl MixCreationParameters {
    /// Create a set of parameters for a mix packet format.
    pub fn new(payload_length_bytes: usize) -> MixCreationParameters {
        MixCreationParameters {
            routing_information_length_by_stage: Vec::new(),
            payload_length_bytes,
        }
    }

    /// Add another outer layer containing some byte length of routing data.
    pub fn add_outer_layer(&mut self, routing_information_length_bytes: usize) {
        self.routing_information_length_by_stage
            .push(routing_information_length_bytes);
    }

    /// The length of the buffer needed to build a packet.
    pub fn total_packet_length(&self) -> usize {
        let mut len = self.payload_length_bytes;
        for stage_len in &self.routing_information_length_by_stage {
            len += stage_len + curve25519::GROUPELEMENTBYTES + chacha20poly1305_ietf::TAGBYTES
        }
        len
    }

    /// Get the mix packet parameters for a single stage of mixing.
    pub fn get_stage_params(&self, layer_number: usize) -> (Range<usize>, MixStageParameters) {
        assert!(layer_number < self.routing_information_length_by_stage.len());

        let mut remaining_header_length_bytes = 0;
        for (i, stage_len) in self.routing_information_length_by_stage.iter().enumerate() {
            if i == layer_number {
                let params = MixStageParameters {
                    routing_information_length_bytes: *stage_len,
                    remaining_header_length_bytes,
                    payload_length_bytes: self.payload_length_bytes,
                };

                let total_size = self.total_packet_length();
                let inner_size = params.incoming_packet_length();

                return (total_size - inner_size..total_size, params);
            } else {
                remaining_header_length_bytes +=
                    stage_len + curve25519::GROUPELEMENTBYTES + chacha20poly1305_ietf::TAGBYTES;
            }
        }

        unreachable!();
    }
}

/// A structure representing the parameters of a single stage of mixing.
pub struct MixStageParameters {
    /// The routing information length for this stage of mixing
    pub routing_information_length_bytes: usize,
    /// The reamining header length for this stage of mixing
    pub remaining_header_length_bytes: usize,
    /// The payload length
    pub payload_length_bytes: usize,
}

impl MixStageParameters {
    pub fn incoming_packet_length(&self) -> usize {
        return curve25519::GROUPELEMENTBYTES
            + chacha20poly1305_ietf::TAGBYTES
            + self.outgoing_packet_length();
    }

    pub fn outgoing_packet_length(&self) -> usize {
        return self.routing_information_length_bytes
            + self.remaining_header_length_bytes
            + self.payload_length_bytes;
    }

    pub fn pub_element_range(&self) -> Range<usize> {
        0..curve25519::GROUPELEMENTBYTES
    }

    pub fn tag_range(&self) -> Range<usize> {
        curve25519::GROUPELEMENTBYTES
            ..curve25519::GROUPELEMENTBYTES + chacha20poly1305_ietf::TAGBYTES
    }

    pub fn routing_data_range(&self) -> Range<usize> {
        curve25519::GROUPELEMENTBYTES + chacha20poly1305_ietf::TAGBYTES
            ..curve25519::GROUPELEMENTBYTES
                + chacha20poly1305_ietf::TAGBYTES
                + self.routing_information_length_bytes
    }

    pub fn header_range(&self) -> Range<usize> {
        curve25519::GROUPELEMENTBYTES + chacha20poly1305_ietf::TAGBYTES
            ..curve25519::GROUPELEMENTBYTES
                + chacha20poly1305_ietf::TAGBYTES
                + self.routing_information_length_bytes
                + self.remaining_header_length_bytes
    }

    pub fn payload_range(&self) -> Range<usize> {
        self.incoming_packet_length() - self.payload_length_bytes..self.incoming_packet_length()
    }

    pub fn encode_mix_layer(
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
        lion_transform_encrypt(&mut buffer[self.payload_range()], &shared_key[..]);

        Ok(shared_key)
    }

    pub fn decode_mix_layer(
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
        lion_transform_decrypt(&mut buffer[self.payload_range()], &shared_key[..]);

        Ok(shared_key)
    }
}
