use identity::{Identity, Extension, RemoteServer};
use nonces::{Nonce8, Nonce16};
use keys::*;
use boxes::Cookie;
use packet::Packet;

pub enum Client {
    New {
        my_pk: client_long_term::PublicKey,
        my_sk: client_long_term::SecretKey,
        my_extension: Extension,
        remote_id: RemoteServer,
    },
    HelloSent {
        my_pk: client_long_term::PublicKey,
        my_sk: client_long_term::SecretKey,
        my_extension: Extension,
        remote_id: RemoteServer,
        my_temp_pk: client_short_term::PublicKey,
        my_temp_sk: client_short_term::SecretKey,
        my_short_nonce: Nonce8,
    },
    InitiateSent {
        my_pk: client_long_term::PublicKey,
        my_sk: client_long_term::SecretKey,
        my_extension: Extension,
        remote_id: RemoteServer,
        my_temp_pk: client_short_term::PublicKey,
        my_temp_sk: client_short_term::SecretKey,
        precomputed_key: PrecomputedKey,
        my_short_nonce: Nonce8,
        remote_temp_pk: server_short_term::PublicKey,
        remote_cookie: Cookie,
    },
    Connected {
        my_extension: Extension,
        my_temp_pk: client_short_term::PublicKey,
        my_temp_sk: client_short_term::SecretKey,
        precomputed_key: PrecomputedKey,
        my_short_nonce: Nonce8,
        remote_short_nonce: Nonce8,
    },
}

impl Client {
    pub fn new(my_id: Identity, remote_id: RemoteServer) -> Client {
        let (pk, sk, extension) = my_id.as_client();

        Client::New {
            my_pk: pk,
            my_sk: sk,
            my_extension: extension,
            remote_id: remote_id,
        }
    }

    pub fn timeout(&mut self) {}
    pub fn process(&mut self, packet: &Packet) {}
    pub fn send(&mut self, payload: &[u8]) {}
}
