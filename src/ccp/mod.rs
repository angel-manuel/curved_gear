use std::net::SocketAddr;

use ::Result;
use packet::*;

mod client_socket;
mod server_socket;

pub use self::client_socket::ClientSocket;
pub use self::server_socket::{ServerSocket, Listener};

pub enum Socket {
    Client(ClientSocket),
    Server(ServerSocket),
}

impl Socket {
    pub fn recv(&mut self) -> Result<Vec<u8>> {
        match *self {
            Socket::Client(ref mut client) => client.recv(),
            Socket::Server(ref mut server) => server.recv(),
        }
    }

    pub fn send(&mut self, msg: &[u8]) -> Result<usize> {
        match *self {
            Socket::Client(ref mut client) => client.send(msg),
            Socket::Server(ref mut server) => server.send(msg),
        }
    }
}

trait PacketProcessor {
    fn process_packet(&mut self, packet: Packet, rem_addr: SocketAddr) -> Result<()>;
}
