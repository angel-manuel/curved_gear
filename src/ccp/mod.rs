use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::{Rc, Weak};
use std::cell::RefCell;

use mioco::udp::UdpSocket;
use mioco::sync::mpsc::{channel, Receiver, Sender};
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

pub struct ServerSocket {
    recv_rx: Receiver<Vec<u8>>,
    sock: UdpSocket,
    rem_addr: SocketAddr,
    client_extension: Extension,
    my_extension: Extension,
    precomputed_key: PrecomputedKey,
    next_send_nonce: Nonce8,
}

struct ServerConnection {
    precomputed_key: PrecomputedKey,
    recv_tx: Sender<Vec<u8>>,
    last_recv_nonce: Nonce8,
}

pub struct Listener {
    my_extension: Extension,
    my_long_term_pk: server_long_term::PublicKey,
    my_long_term_sk: server_long_term::SecretKey,
    minute_key: crypto_secretbox::Key,
    last_minute_key: crypto_secretbox::Key,
    conns: HashMap<(Extension, client_short_term::PublicKey), ServerConnection>,
    accept_chan_tx: Sender<ServerSocket>,
    accept_chan_rx: Receiver<ServerSocket>,
}

impl Listener {
    fn new(my_id: Identity) -> Listener {
        let (my_long_term_pk, my_long_term_sk, my_extension) = my_id.as_server();
        let (accept_chan_tx, accept_chan_rx) = channel();

        Listener {
            my_extension: my_extension,
            my_long_term_pk: my_long_term_pk,
            my_long_term_sk: my_long_term_sk,
            minute_key: crypto_secretbox::gen_key(),
            last_minute_key: crypto_secretbox::gen_key(),
            conns: HashMap::new(),
            accept_chan_tx: accept_chan_tx,
            accept_chan_rx: accept_chan_rx,
        }
    }

    pub fn accept(&mut self) -> Result<ServerSocket> {
        self.accept_chan_rx.recv().or(Err("Couldnt read accept channel".into()))
    }

    pub fn process(&mut self, packet: Packet, sock: &mut UdpSocket, rem_addr: SocketAddr) -> Result<()> {
        match packet {
            Packet::ClientMessage(client_msg_packet) => {
                let mut preserve = true;
                let conn_key = (client_msg_packet.client_extension.clone(),
                                client_msg_packet.client_short_term_pk.clone());

                if let Some(server_conn) = self.conns.get_mut(&conn_key) {
                    let send_res = server_conn.recv_tx.send(vec![]);
                    preserve = send_res.is_ok();
                }

                if !preserve {
                    self.conns.remove(&conn_key);
                }
            },
            Packet::Initiate(initiate_packet) => {
                try!(self.process_initiate(initiate_packet, sock, rem_addr));
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

        if self.conns.contains_key(&conn_key) {
            debug!("Hello packet received on open connection");
            return Ok(());
        }

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

        Ok(())
    }

    fn process_initiate(&mut self, initiate_packet: InitiatePacket, sock: &mut UdpSocket, rem_addr: SocketAddr) -> Result<()> {
        let conn_key = (initiate_packet.client_extension.clone(), initiate_packet.client_short_term_pk.clone());

        if self.conns.contains_key(&conn_key) {
            debug!("Recv'd INITIATE on already initiated connection");
            return Ok(());
        }

        let cookie = initiate_packet.server_cookie.open(&self.minute_key, &self.last_minute_key).unwrap();
        let precomputed_key = PrecomputedKey::precompute_at_server(&initiate_packet.client_short_term_pk, &cookie.server_short_term_sk);
        let (initiate_box, payload) = initiate_packet.initiate_box.open_precomputed_with_payload(&precomputed_key).unwrap();

        let client_long_term_pk = initiate_box.client_long_term_pk;
        let vouch = initiate_box.vouch.open(&client_long_term_pk, &self.my_long_term_sk).unwrap();

        if vouch.client_short_term_pk != initiate_packet.client_short_term_pk {
            return try!(Err("Invalid vouch"));
        }

        //TODO: Check if client_long_term_pk is accepted

        let (recv_tx, recv_rx) = channel();

        if let Some(msg) = payload {
            recv_tx.send(msg).unwrap();
        }

        let new_conn = ServerConnection {
            precomputed_key: precomputed_key.clone(),
            recv_tx: recv_tx,
            last_recv_nonce: initiate_packet.initiate_box.nonce.clone(),
        };

        self.conns.insert(conn_key, new_conn);
        info!("\"{}\" accepting connection \"{}\"@{}", &self.my_extension, &initiate_packet.client_extension, &rem_addr);

        let new_sock = ServerSocket {
            recv_rx: recv_rx,
            sock: sock.try_clone().unwrap(),
            rem_addr: rem_addr,
            client_extension: initiate_packet.client_extension.clone(),
            my_extension: self.my_extension.clone(),
            precomputed_key: precomputed_key,
            next_send_nonce: Nonce8::new_low(),
        };

        self.accept_chan_tx.send(new_sock).or(Err("Couldnt read accept channel".into()))
    }
}
