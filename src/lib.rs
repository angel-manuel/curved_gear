use std::result;

extern crate sodiumoxide;
extern crate rustc_serialize;
extern crate bincode;
extern crate byteorder;
extern crate ascii;
#[macro_use]
extern crate log;
#[macro_use]
extern crate mioco;

pub mod error;

pub type Result<T> = result::Result<T, error::Error>;

#[macro_use]
pub mod boxes;
#[macro_use]
pub mod keys;
pub mod identity;
pub mod nonces;
pub mod packet;

pub mod ccp;

pub use identity::{Identity, Extension, RemoteServer};
pub use keys::*;
pub use ccp::{Socket as CCPSocket, ClientSocket as CCPClientSocket, ServerSocket as CCPServerSocket,
    Listener as CCPListener, Demultiplexor as CCPDemultiplexor};
