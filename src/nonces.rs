use std::mem;
use std::io::{Cursor, Write};
use std::hash::{Hash, Hasher};

use rustc_serialize::{Encodable, Encoder, Decodable, Decoder};
use sodiumoxide::randombytes::{randombytes, randombytes_into};
use byteorder::{LittleEndian, ByteOrder, WriteBytesExt};
use sodiumoxide::crypto::box_ as crypto_box;
use sodiumoxide::crypto::secretbox as crypto_secretbox;

#[derive(Clone, RustcEncodable, RustcDecodable, PartialEq, Eq, PartialOrd, Ord)]
pub struct Nonce8(u64);

impl Nonce8 {
    pub fn new_zero() -> Nonce8 {
        Nonce8(0u64)
    }

    pub fn new_low() -> Nonce8 {
        let rand = randombytes(mem::size_of::<u64>() - 1);
        let num = LittleEndian::read_uint(rand.as_slice(), mem::size_of::<u64>() - 1);
        Nonce8(num)
    }

    pub fn new_random() -> Nonce8 {
        let rand = randombytes(mem::size_of::<u64>());
        let num = LittleEndian::read_u64(rand.as_slice());
        Nonce8(num)
    }

    pub fn increment(&mut self) {
        self.0 += 1
    }

    pub fn prefix_with(&self, prefix: &[u8]) -> crypto_box::Nonce {
        let mut arr = [0u8; crypto_box::NONCEBYTES];

        {
            let mut arr_cur = Cursor::new(arr.as_mut());

            arr_cur.write(prefix).unwrap();
            arr_cur.write_u64::<LittleEndian>(self.0).unwrap();
        }

        crypto_box::Nonce(arr)
    }
}

fixed_length_box!(pub Nonce16, 16);

impl Nonce16 {
    pub fn new_random() -> Nonce16 {
        let mut rand_arr = [0u8; 16];
        randombytes_into(&mut rand_arr);
        Nonce16(rand_arr)
    }

    pub fn prefix_with(&self, prefix: &[u8]) -> crypto_box::Nonce {
        let mut arr = [0u8; crypto_box::NONCEBYTES];

        {
            let mut arr_cur = Cursor::new(arr.as_mut());

            arr_cur.write(prefix).unwrap();
            arr_cur.write(&self.0).unwrap();
        }

        crypto_box::Nonce(arr)
    }
}

fixed_length_box!(pub CookieNonce, 16);

impl CookieNonce {
    pub fn new_random() -> CookieNonce {
        let mut rand_arr = [0u8; 16];
        randombytes_into(&mut rand_arr);
        CookieNonce(rand_arr)
    }

    pub fn prefix_with(&self, prefix: &[u8]) -> crypto_secretbox::Nonce {
        let mut arr = [0u8; crypto_secretbox::NONCEBYTES];

        {
            let mut arr_cur = Cursor::new(arr.as_mut());

            arr_cur.write(prefix).unwrap();
            arr_cur.write(&self.0).unwrap();
        }

        crypto_secretbox::Nonce(arr)
    }
}
