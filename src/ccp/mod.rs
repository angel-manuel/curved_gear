use std::io;

use mioco::udp::UdpSocket;

use identity::{Identity, RemoteServer};

pub struct Stream {

}

impl Stream {
    pub fn new() -> Stream {
        Stream {}
    }
}

pub struct Listener {
}

impl Listener {
    pub fn new(my_id: Identity, sock: UdpSocket) -> Listener {
        Listener {}
    }

    pub fn accept(&self) -> io::Result<Stream> {
        Ok(Stream::new())
    }
}
