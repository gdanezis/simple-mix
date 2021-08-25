//! # The `simple_mix` format
//! 
//! We define a simple mix packet format geared towards simplicity and performance with the features that are
//! specifically required by a stratified mix topology. 
//! 
//! `Simple_mix` assumes that all
//! paths are the same length (no need to hide path lengths), mixes are arranged in layers and therefore
//! know their position in a message path (no need to hide this position). These assumptions allow us 
//! to do away with some of the padding traditionally used; further we prioritize efficient computation 
//! over very low-bandwidth, as it seems the rate of public key operations is a bottleneck for mixes
//! rather than the availablility of bandwidth.
//! 
//! ## Overview and Parameters
//! 
//! In a mix network with a stratified topology packets are mixed by nodes at each of the layers. Each layer
//! 'strips' the packet from one layer of encryption, recovers the address of the mix at the next layer, and 
//! passes the decoded packet to them. An identifier per processed message is stored and checked to prevent 
//! replays of processed messages at each layer. Additional measures, such as adding delays, adding dummy 
//! traffic or dropping messages can be empued at each mix to frustrate traffic analysis.
//! 
//! 
//! A layer of mix processing is defined by three parameters, includes in the structure [MixStageParameters]:
//! * The `routing_information_length_bytes` (`R`) states the number of bytes representing 
//!   routing information at this layer. 
//! * The `remaining_header_length_bytes` (`H`) represents the remaining bytes of the packet header.
//! * The `payload_length_bytes` (`P`). 
//! 
//! In addition we define two system-wide constants, namely `GROUPELEMENTBYTES` (`GE`=32) and 
//! `TAGBYTES` (`T`=24).
//! 
//! ## Packet format, decoding
//! 
//! A mix at this layer takes in messages of length `GE+T+R+H+P`, and outputs messages of length `H+P`. 
//! 
//! An input message is processed as follows:
//! 
//! * The input packet is parsed as a `[Pk, Tag, Header, Payload]` of length `[GE, T, R+H, P]` respectivelly.
//! * A master key is derived by performing scalar multiplication with the mix secret 's', ie `K = s * Pk`. 
//!   The master key is stored and checked for duplicates (if it is found processing ends.)
//! * The master key is used to perform AEAD decryption of the `Header` with an IV of zeros and the `tag`. If 
//!   decryption fails processing ends. Otherwise the Header is parsed as `[Routing, Next_Header]` of length 
//!   `[R, H]` respectivelly. The routing data `Routing` can be used by the mix to dertermine the next mix.
//! * Finally, the master key is used to perform lion decoding of the `Payload` into `Next_Payload`.
//! * The output packet for the next mix is `[Next_Header, Next_Payload]`.
//! 
//! As an AEAD we use `chacha20poly1305_ietf` and for public key operations we use `curve25519`. 
//! 
//! ## Packet encoding 
//! 
//! Encoding is 
//! performed layer by layer starting with the last hop on the route, and ending with the first. At each stage 
//! of encoding a new Secret key `Sk` and corresponding `Pk` is chosen. The layer master key for the layer is 
//! derived using the mix public key. And the master key is used to AEAD encrypt the concatenation of the 
//! routing data for the layer, and the remaining Header; separately the master key is used to lion encrypt 
//! the payload. The process is repeated for each layer (from last to first) to construct the full message.

use sodiumoxide::crypto::aead::chacha20poly1305_ietf;
use sodiumoxide::crypto::scalarmult::curve25519;

use std::ops::Range;

use crate::lion::*;

/// A structure that holds mix packet construction parameters. These incluse the length
/// of the routing information at each hop, the number of hops, and the payload length.
pub struct MixCreationParameters {
    /// The routing length is inner first, so \[0\] is the innermost routing length, etc (in bytes)
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
