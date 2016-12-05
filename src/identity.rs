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

#[derive(Clone)]
pub struct Identity {
    pub pk: crypto_box::PublicKey,
    pub sk: crypto_box::SecretKey,
    pub extension: Extension,
}

impl Identity {
    pub fn new(extension: Extension) -> Identity {
        let (pk, sk) = crypto_box::gen_keypair();
        Identity {
            pk: pk,
            sk: sk,
            extension: extension,
        }
    }

    pub fn as_client(self) -> (client_long_term::PublicKey, client_long_term::SecretKey, Extension) {
        (client_long_term::PublicKey(self.pk), client_long_term::SecretKey(self.sk), self.extension)
    }

    pub fn as_server(self) -> (server_long_term::PublicKey, server_long_term::SecretKey, Extension) {
        (server_long_term::PublicKey(self.pk), server_long_term::SecretKey(self.sk), self.extension)
    }

    pub fn create_remote(&self, addr: SocketAddr) -> RemoteServer {
        let (pk, _, extension) = ((*self).clone()).as_server();

        RemoteServer {
            server_long_term_pk: pk,
            server_addr: addr,
            server_extension: extension,
        }
    }
}

#[derive(Clone)]
pub struct RemoteServer {
    pub server_long_term_pk: server_long_term::PublicKey,
    pub server_addr: SocketAddr,
    pub server_extension: Extension,
}
