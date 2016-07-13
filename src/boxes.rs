use std::io::{Cursor, Read, Write};
use std::hash::{Hash, Hasher};

use rustc_serialize::{Encodable, Encoder, Decodable, Decoder};
use sodiumoxide::crypto::box_ as crypto_box;
use sodiumoxide::crypto::secretbox as crypto_secretbox;
use bincode::rustc_serialize as bcode;
use bincode::SizeLimit;

use identity::*;
use keys::*;
use nonces::*;

macro_rules! impls_for_fixed {
    ( $name:ident, $len:expr ) => {
        impl $name {
            pub fn new_empty() -> $name {
                $name([0u8; $len])
            }

            pub fn from_barr(cnt: &[u8]) -> $name {
                let mut carr = [0u8; $len];

                for i in 0..cnt.len() {
                    carr[i] = cnt[i];
                }

                $name(carr)
            }
        }

        impl Encodable for $name {
            fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
                for b in self.0.iter() { try!(s.emit_u8(*b)); }
                Ok(())
            }
        }

        impl Decodable for $name {
            fn decode<D: Decoder>(d: &mut D) -> Result<Self, D::Error> {
                let mut flbox = $name([0u8; $len]);
                for b in flbox.0.iter_mut() { *b = try!(d.read_u8()); }
                Ok(flbox)
            }
        }

        impl Clone for $name {
            fn clone(&self) -> $name {
                let mut carr = [0u8; $len];

                for i in 0..$len {
                    carr[i] = self.0[i];
                }

                $name(carr)
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &$name) -> bool {
                self.0.iter().zip(other.0.iter()).all(|(&a, &b)| a == b)
            }
        }

        impl Eq for $name {}

        impl Hash for $name {
            fn hash<H>(&self, state: &mut H) where H: Hasher {
                for c in self.0.iter() {
                    c.hash(state);
                }
            }
        }
    }
}

#[macro_export]
macro_rules! fixed_length_box {
    ( pub $name:ident, $len:expr ) => {
        pub struct $name(pub [u8; $len]);
        impls_for_fixed!($name, $len);
    };
    ( $name:ident, $len:expr ) => {
        struct $name(pub [u8; $len]);
        impls_for_fixed!($name, $len);
    }
}

macro_rules! typed_crypto_box {
    ( $box_name:ident, $plain_t:ty, $plain_size:expr, $from:ident, $to:ident, $nonce_t:ident, $nonce_prefix:ident ) => {
        pub struct $box_name {
            pub nonce: $nonce_t,
            ciphertext: [u8; $plain_size + 16],
        }

        impl Encodable for $box_name {
            fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
                try!(self.nonce.encode(s));
                for b in self.ciphertext.iter() { try!(s.emit_u8(*b)); }
                Ok(())
            }
        }

        impl Decodable for $box_name {
            fn decode<D: Decoder>(d: &mut D) -> Result<Self, D::Error> {
                let nonce = try!($nonce_t::decode(d));
                let mut ciphertext = [0u8; $plain_size + 16];
                for b in ciphertext.iter_mut() { *b = try!(d.read_u8()); }
                Ok($box_name {
                    nonce: nonce,
                    ciphertext: ciphertext,
                })
            }
        }

        impl $plain_t {
            pub fn seal(&self, custom_nonce: &$nonce_t,
                pk: &$to::PublicKey, sk: &$from::SecretKey) -> $box_name {
                    let plaintext = bcode::encode(self, SizeLimit::Infinite).unwrap();
                    let nonce = custom_nonce.prefix_with($nonce_prefix);
                    let ciphertext = crypto_box::seal(plaintext.as_slice(), &nonce, &pk.0, &sk.0);

                    let mut box_arr = [0u8; $plain_size + 16];
                    box_arr.clone_from_slice(ciphertext.as_slice());
                    $box_name {
                        nonce: custom_nonce.clone(),
                        ciphertext: box_arr,
                    }
            }
        }

        impl $box_name {
            pub fn open(&self, pk: &$from::PublicKey, sk: &$to::SecretKey) -> Result<$plain_t, ()> {
                let nonce = self.nonce.prefix_with($nonce_prefix);
                let plaintext = try!(crypto_box::open(&self.ciphertext, &nonce, &pk.0, &sk.0));
                bcode::decode(plaintext.as_slice()).or( Err(()) )
            }
        }
    };
}

pub const HELLO_BOX_NONCE_PREFIX: &'static [u8] = b"CurveCP-client-H";
pub const HELLO_BOX_SIZE: usize = PLAIN_HELLO_BOX_SIZE + 16;
pub const PLAIN_HELLO_BOX_SIZE: usize = 64;

fixed_length_box!(pub PlainHelloBox, PLAIN_HELLO_BOX_SIZE);

typed_crypto_box!(HelloBox, PlainHelloBox, PLAIN_HELLO_BOX_SIZE,
    client_short_term, server_long_term, Nonce8, HELLO_BOX_NONCE_PREFIX);

pub const COOKIE_NONCE_PREFIX: &'static [u8] = b"curvgear";
pub const CIPHERCOOKIE_SIZE: usize = PLAIN_COOKIE_SIZE + 16;
pub const COOKIE_SIZE: usize = CIPHERCOOKIE_SIZE + 16;
pub const PLAIN_COOKIE_SIZE: usize = crypto_box::PUBLICKEYBYTES + crypto_box::SECRETKEYBYTES;

fixed_length_box!(pub CipherCookie, CIPHERCOOKIE_SIZE);

#[derive(RustcEncodable, RustcDecodable)]
pub struct Cookie {
    pub cookie_nonce: CookieNonce,
    ciphercookie: CipherCookie,
}

#[derive(RustcEncodable, RustcDecodable)]
pub struct PlainCookie {
    pub client_short_term_pk: client_short_term::PublicKey,
    pub server_short_term_sk: server_short_term::SecretKey,
}

impl Cookie {
    pub fn open(&self,
        temporal_key_a: &crypto_secretbox::Key,
        temporal_key_b: &crypto_secretbox::Key) -> Result<PlainCookie, ()> {
            let nonce = self.cookie_nonce.prefix_with(COOKIE_NONCE_PREFIX);
            let plaintext = try!(crypto_secretbox::open(&self.ciphercookie.0, &nonce, temporal_key_a)
                             .or(crypto_secretbox::open(&self.ciphercookie.0, &nonce, temporal_key_b)));
            bcode::decode(plaintext.as_slice()).or( Err(()) )
    }
}

impl PlainCookie {
    pub fn seal(&self, cookie_nonce: &CookieNonce,
        temporal_key: &crypto_secretbox::Key) -> Cookie {
            let plaintext = bcode::encode(self, SizeLimit::Infinite).unwrap();
            let nonce = cookie_nonce.prefix_with(COOKIE_NONCE_PREFIX);
            let ciphertext = crypto_secretbox::seal(plaintext.as_slice(), &nonce, temporal_key);
            let mut box_arr = [0u8; CIPHERCOOKIE_SIZE];
            box_arr.clone_from_slice(ciphertext.as_slice());

            Cookie {
                cookie_nonce: cookie_nonce.clone(),
                ciphercookie: CipherCookie(box_arr),
            }
    }
}

pub const COOKIE_BOX_NONCE_PREFIX: &'static [u8] = b"CurveCPK";
pub const COOKIE_BOX_SIZE: usize = PLAIN_COOKIE_BOX_SIZE + 16;
pub const PLAIN_COOKIE_BOX_SIZE: usize = crypto_box::PUBLICKEYBYTES + COOKIE_SIZE;

#[derive(RustcEncodable, RustcDecodable)]
pub struct PlainCookieBox {
    pub server_short_term_pk: server_short_term::PublicKey,
    pub server_cookie: Cookie,
}

typed_crypto_box!(CookieBox, PlainCookieBox, PLAIN_COOKIE_BOX_SIZE,
    server_long_term, client_short_term, Nonce16, COOKIE_BOX_NONCE_PREFIX);

pub const VOUCH_NONCE_PREFIX: &'static [u8] = b"CurveCPV";
pub const VOUCH_SIZE: usize = PLAIN_VOUCH_SIZE + 16;
pub const PLAIN_VOUCH_SIZE: usize = crypto_box::PUBLICKEYBYTES;

#[derive(RustcEncodable, RustcDecodable)]
pub struct PlainVouch {
    pub client_short_term_pk: client_short_term::PublicKey,
}

typed_crypto_box!(Vouch, PlainVouch, PLAIN_VOUCH_SIZE,
    client_long_term, server_long_term, Nonce16, VOUCH_NONCE_PREFIX);

macro_rules! variable_size_crypto_box {
    ( $box_name:ident, $from:ident, $to:ident, $nonce_t:ident, $nonce_prefix:ident ) => {
        pub struct $box_name {
            pub nonce: $nonce_t,
            ciphertext: Vec<u8>,
        }

        impl Encodable for $box_name {
            fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
                try!(self.nonce.encode(s));
                for b in self.ciphertext.iter() { try!(s.emit_u8(*b)); }
                Ok(())
            }
        }

        impl Decodable for $box_name {
            fn decode<D: Decoder>(d: &mut D) -> Result<Self, D::Error> {
                let nonce = try!($nonce_t::decode(d));
                let mut ciphertext = Vec::new();

                while let Ok(c) = d.read_u8() { //FIXME: Very fragile!!!
                    ciphertext.push(c);
                }

                Ok($box_name {
                    nonce: nonce,
                    ciphertext: ciphertext,
                })
            }
        }

        impl $box_name {
            pub fn seal(plaintext: &[u8], custom_nonce: &$nonce_t,
                pk: &$to::PublicKey, sk: &$from::SecretKey) -> $box_name {
                    let nonce = custom_nonce.prefix_with($nonce_prefix);
                    $box_name {
                        nonce: custom_nonce.clone(),
                        ciphertext: crypto_box::seal(plaintext, &nonce, &pk.0, &sk.0),
                    }
            }

            pub fn seal_precomputed(plaintext: &[u8], custom_nonce: &$nonce_t, precomputed_key: &PrecomputedKey) -> $box_name {
                let nonce = custom_nonce.prefix_with($nonce_prefix);
                $box_name {
                    nonce: custom_nonce.clone(),
                    ciphertext: crypto_box::seal_precomputed(plaintext, &nonce, &precomputed_key.0),
                }
            }

            pub fn open(&self, pk: &$from::PublicKey, sk: &$to::SecretKey) -> Result<Vec<u8>, ()> {
                let nonce = self.nonce.prefix_with($nonce_prefix);
                crypto_box::open(self.ciphertext.as_slice(), &nonce, &pk.0, &sk.0)
            }

            pub fn open_precomputed(&self, precomputed_key: &PrecomputedKey) -> Result<Vec<u8>, ()> {
                let nonce = self.nonce.prefix_with($nonce_prefix);
                crypto_box::open_precomputed(self.ciphertext.as_slice(), &nonce, &precomputed_key.0)
            }
        }
    };
}

pub const INITIATE_PACKET_NONCE_PREFIX: &'static [u8] = b"CurveCP-client-I";
pub const INITIATE_BOX_BASE_SIZE: usize = PLAIN_INITIATE_BOX_BASE_SIZE + 16;
pub const PLAIN_INITIATE_BOX_BASE_SIZE: usize = crypto_box::PUBLICKEYBYTES + 16 + VOUCH_SIZE + DOMAIN_NAME_SIZE;

variable_size_crypto_box!(InitiateBox, client_short_term, server_short_term, Nonce8, INITIATE_PACKET_NONCE_PREFIX);

#[derive(RustcEncodable, RustcDecodable)]
pub struct PlainInitiateBox {
    pub client_long_term_pk: client_long_term::PublicKey,
    pub vouch: Vouch,
    pub domain_name: DomainName,
    // Payload will follow
}

impl InitiateBox {
    pub fn open_precomputed_with_payload(&self,
        precomputed_key: &PrecomputedKey) -> Result<(PlainInitiateBox, Option<Vec<u8>>), ()> {
            let plaintext = try!(self.open_precomputed(precomputed_key));
            let mut plaintext_cur = Cursor::new(plaintext);

            let plain_box = try!(bcode::decode_from(&mut plaintext_cur,
                SizeLimit::Bounded(PLAIN_INITIATE_BOX_BASE_SIZE as u64)).or( Err(()) ));

            let mut payload = Vec::with_capacity(plaintext_cur.get_ref().len() - (plaintext_cur.position() as usize));
            let size = try!(plaintext_cur.read_to_end(&mut payload).or( Err(()) ));

            if size == 0 {
                Ok((plain_box, None))
            } else {
                Ok((plain_box, Some(payload)))
            }
    }
}

impl PlainInitiateBox {
    pub fn seal_precomputed(&self, tiny_nonce: &Nonce8,
        precomputed_key: &PrecomputedKey,
        payload: Option<&[u8]>) -> InitiateBox {
            let payload_len = payload.map(|s| s.len()).unwrap_or(0);
            let plaintext = Vec::with_capacity(PLAIN_INITIATE_BOX_BASE_SIZE + payload_len);

            let mut plaintext_cur = Cursor::new(plaintext);
            bcode::encode_into(self, &mut plaintext_cur, SizeLimit::Infinite).unwrap();

            if let Some(data) = payload { plaintext_cur.write(data).unwrap(); }

            InitiateBox::seal_precomputed(plaintext_cur.get_ref().as_slice(), tiny_nonce, precomputed_key)
    }
}

pub const SERVER_MSG_NONCE_PREFIX: &'static [u8] = b"CurveCP-server-M";
pub const CLIENT_MSG_NONCE_PREFIX: &'static [u8] = b"CurveCP-client-M";

variable_size_crypto_box!(ServerMessageBox, server_short_term, client_short_term, Nonce8, SERVER_MSG_NONCE_PREFIX);
variable_size_crypto_box!(ClientMessageBox, client_short_term, server_short_term, Nonce8, CLIENT_MSG_NONCE_PREFIX);
