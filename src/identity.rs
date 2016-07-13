use std::net::SocketAddr;
use std::hash::{Hash, Hasher};
use std::fmt;

use sodiumoxide::crypto::box_ as crypto_box;
use rustc_serialize::{Encodable, Encoder, Decodable, Decoder};
use ascii::AsAsciiStr;

use keys::*;

pub const EXTENSION_SIZE: usize = 16;
fixed_length_box!(pub Extension, EXTENSION_SIZE);

impl fmt::Display for Extension {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0.as_ascii_str().unwrap())
    }
}

pub const DOMAIN_NAME_SIZE: usize = 256;
fixed_length_box!(pub DomainName, DOMAIN_NAME_SIZE);

pub struct Identity {
    pub pk: crypto_box::PublicKey,
    pub sk: crypto_box::SecretKey,
}

impl Identity {
    pub fn new() -> Identity {
        let (pk, sk) = crypto_box::gen_keypair();
        Identity {
            pk: pk,
            sk: sk,
        }
    }
}

pub struct RemoteServer {
    pub server_long_term_pk: server_long_term::PublicKey,
    pub server_addr: SocketAddr,
    pub server_extension: Extension,
}
