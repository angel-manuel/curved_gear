use std::result;

extern crate sodiumoxide;
extern crate rustc_serialize;
extern crate bincode;
extern crate byteorder;
extern crate ascii;

#[macro_use]
extern crate log;

pub type Result<T> = result::Result<T, ()>;

#[macro_use]
pub mod keys;

#[macro_use]
pub mod boxes;

pub mod packet;
pub mod identity;
pub mod client;
pub mod server;
pub mod nonces;

pub use identity::{Identity, Extension, RemoteServer};
pub use keys::*;
pub use server::{Server, ServerSocket};
pub use client::Client;
