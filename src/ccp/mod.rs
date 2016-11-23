use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::{Rc, Weak};
use std::cell::RefCell;

use mioco::udp::UdpSocket;
use bincode::rustc_serialize as bcode_rcs;
use sodiumoxide::crypto::secretbox as crypto_secretbox;

use ::Result;
use identity::{Identity, RemoteServer, Extension};
use packet::*;
use keys::*;
use boxes::*;
use nonces::*;

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
                try!(listener.borrow_mut().process(packet, &mut self.sock, rem_addr));
            }
        }
    }
}

pub struct Listener {
    my_extension: Extension,
    my_long_term_pk: server_long_term::PublicKey,
    my_long_term_sk: server_long_term::SecretKey,
    minute_key: crypto_secretbox::Key,
    last_minute_key: crypto_secretbox::Key,
    streams: HashMap<(Extension, client_short_term::PublicKey), Weak<RefCell<Stream>>>,
}

impl Listener {
    fn new(my_id: Identity) -> Listener {
        let (my_long_term_pk, my_long_term_sk, my_extension) = my_id.as_server();

        Listener {
            my_extension: my_extension,
            my_long_term_pk: my_long_term_pk,
            my_long_term_sk: my_long_term_sk,
            minute_key: crypto_secretbox::gen_key(),
            last_minute_key: crypto_secretbox::gen_key(),
            streams: HashMap::new(),
        }
    }

    pub fn accept(&mut self) -> Result<Stream> {
        Ok(Stream::new())
    }

    pub fn process(&mut self, packet: Packet, sock: &mut UdpSocket, rem_addr: SocketAddr) -> Result<()> {
        match packet {
            Packet::ClientMessage(client_msg_packet) => {
                if let Some(stream) = {
                    let conn_key = (client_msg_packet.client_extension.clone(), client_msg_packet.client_short_term_pk.clone());
                    self.streams.get_mut(&conn_key)
                } {

                }
            },
            Packet::Initiate(initiate_packet) => {
            },
            Packet::Hello(hello_packet) => {
                try!(self.process_hello(hello_packet, sock, rem_addr));
            },
            _ => {
                debug!("Unvalid packet type");
            }
        }


        Ok(())
    }

    fn process_hello(&self, hello_packet: HelloPacket, sock: &mut UdpSocket, rem_addr: SocketAddr) -> Result<()> {
        let client_short_term_pk = hello_packet.client_short_term_pk;
        let conn_key = (hello_packet.client_extension.clone(), client_short_term_pk.clone());

        if self.streams.contains_key(&conn_key) {
            debug!("Hello packet received on open connection");
        } else {
            hello_packet.hello_box.open(&client_short_term_pk, &self.my_long_term_sk).unwrap();

            let (server_short_term_pk, server_short_term_sk) = server_short_term::gen_keypair();

            let cookie_packet: Packet = CookiePacket {
                client_extension: hello_packet.client_extension.clone(),
                server_extension: self.my_extension.clone(),
                cookie_box: PlainCookieBox {
                    server_short_term_pk: server_short_term_pk,
                    server_cookie: PlainCookie {
                        client_short_term_pk: client_short_term_pk.clone(),
                        server_short_term_sk: server_short_term_sk.clone(),
                    }.seal(&CookieNonce::new_random(), &self.minute_key),
                }.seal(&Nonce16::new_random(), &client_short_term_pk, &self.my_long_term_sk),
            }.into();

            try!(cookie_packet.send(sock, &rem_addr));
        }

        Ok(())
    }
}
