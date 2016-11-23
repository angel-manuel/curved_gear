use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::{Rc, Weak};
use std::cell::RefCell;

use mioco::udp::UdpSocket;
use bincode::{rustc_serialize as bcode_rcs};

use ::Result;
use identity::{Identity, RemoteServer, Extension};
use packet::{Packet, PACKET_MAX_SIZE};

pub struct Stream {

}

impl Stream {
    pub fn new() -> Stream {
        Stream {}
    }
}

pub struct Demultiplexor {
    sock: UdpSocket,
    listeners: HashMap<Extension, Weak<RefCell<Listener>>>,
}

impl Demultiplexor {
    pub fn new(sock: UdpSocket) -> Demultiplexor {
        Demultiplexor {
            sock: sock,
            listeners: HashMap::new(),
        }
    }

    pub fn create_listener(&mut self, listener_id: Identity) -> Rc<RefCell<Listener>> {
        let listener_extension = listener_id.extension.clone();
        let listener = Rc::new(RefCell::new(Listener::new(listener_id)));

        self.listeners.insert(listener_extension, Rc::downgrade(&listener));

        listener
    }

    pub fn listen(&mut self) -> Result<()> {
        let mut buf = [0u8; PACKET_MAX_SIZE];
        loop {
            let (recv_len, rem_addr) = try!(self.sock.recv(&mut buf));
            let packet: Packet = try!(bcode_rcs::decode(&buf[..recv_len]));

            if let Some(ref mut listener) = {
                let dst_extension = packet.get_destination_extension();
                self.listeners.get_mut(dst_extension).and_then(|listener_weak|
                    listener_weak.upgrade()
                )
            } {
                try!(listener.borrow_mut().process(packet, rem_addr));
            }
        }
    }
}

pub struct Listener {
    my_id: Identity,
}

impl Listener {
    pub fn new(my_id: Identity) -> Listener {
        Listener {
            my_id: my_id,
        }
    }

    pub fn accept(&mut self) -> Result<Stream> {
        Ok(Stream::new())
    }

    pub fn process(&mut self, packet: Packet, rem_addr: SocketAddr) -> Result<()> {
        Ok(())
    }
}
