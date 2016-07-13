use sodiumoxide::crypto::box_ as crypto_box;

macro_rules! custom_keypair {
    ( $name:ident ) => {
        pub mod $name {
            use sodiumoxide::crypto::box_ as crypto_box;
            use rustc_serialize::{Encodable, Encoder};
            use rustc_serialize::{Decodable, Decoder};

            #[derive(Clone, PartialEq, Eq, Hash)]
            pub struct PublicKey(pub crypto_box::PublicKey);

            impl Encodable for PublicKey {
                fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
                    for b in (self.0).0.iter() { try!(s.emit_u8(*b)); }
                    Ok(())
                }
            }

            impl Decodable for PublicKey {
                fn decode<D: Decoder>(d: &mut D) -> Result<Self, D::Error> {
                    let mut byte_pk = [0u8; crypto_box::PUBLICKEYBYTES];
                    for b in byte_pk.iter_mut() { *b = try!(d.read_u8()); }
                    Ok(PublicKey(crypto_box::PublicKey(byte_pk)))
                }
            }

            #[derive(Clone)]
            pub struct SecretKey(pub crypto_box::SecretKey);

            impl Encodable for SecretKey {
                fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
                    for b in (self.0).0.iter() { try!(s.emit_u8(*b)); }
                    Ok(())
                }
            }

            impl Decodable for SecretKey {
                fn decode<D: Decoder>(d: &mut D) -> Result<Self, D::Error> {
                    let mut byte_sk = [0u8; crypto_box::SECRETKEYBYTES];
                    for b in byte_sk.iter_mut() { *b = try!(d.read_u8()); }
                    Ok(SecretKey(crypto_box::SecretKey(byte_sk)))
                }
            }

            pub fn gen_keypair() -> (PublicKey, SecretKey) {
                let (pk, sk) = crypto_box::gen_keypair();
                (PublicKey(pk), SecretKey(sk))
            }
        }
    }
}

custom_keypair!(client_short_term);
custom_keypair!(client_long_term);
custom_keypair!(server_short_term);
custom_keypair!(server_long_term);

#[derive(Clone)]
pub struct PrecomputedKey(pub crypto_box::PrecomputedKey);

impl PrecomputedKey {
    pub fn precompute_at_client(pk: &server_short_term::PublicKey, sk: &client_short_term::SecretKey) -> PrecomputedKey {
        PrecomputedKey(crypto_box::precompute(&pk.0, &sk.0))
    }

    pub fn precompute_at_server(pk: &client_short_term::PublicKey, sk: &server_short_term::SecretKey) -> PrecomputedKey {
        PrecomputedKey(crypto_box::precompute(&pk.0, &sk.0))
    }
}
