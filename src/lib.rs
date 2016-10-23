use std::result;

extern crate sodiumoxide;
extern crate rustc_serialize;
extern crate bincode;
extern crate byteorder;
extern crate ascii;
#[macro_use]
extern crate log;
extern crate mioco;

pub type Result<T> = result::Result<T, ()>;

#[macro_use]
pub mod boxes;
#[macro_use]
pub mod keys;
pub mod identity;
pub mod nonces;
pub mod packet;

pub mod logic;
pub mod ccp;

pub use identity::{Identity, Extension, RemoteServer};
pub use keys::*;
pub use ccp::{Stream as CCPStream, Listener as CCPListener};
