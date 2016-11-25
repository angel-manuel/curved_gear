use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::{Rc, Weak};
use std::cell::RefCell;

use mioco::udp::UdpSocket;
use mioco::sync::mpsc::{channel, Receiver, Sender};
use bincode::rustc_serialize as bcode_rcs;
use sodiumoxide::crypto::secretbox as crypto_secretbox;

use ::Result;
use identity::{Identity, Extension, RemoteServer};
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
    clients: HashMap<Extension, Weak<RefCell<ClientSock>>>,
}

impl Demultiplexor {
    pub fn new(sock: UdpSocket) -> Demultiplexor {
        Demultiplexor {
            sock: sock,
            listeners: HashMap::new(),
            clients: HashMap::new(),
        }
    }

    pub fn create_listener(&mut self, listener_id: Identity) -> Rc<RefCell<Listener>> {
        let listener_extension = listener_id.extension.clone();
        let listener = Rc::new(RefCell::new(Listener::new(listener_id)));

        self.listeners.insert(listener_extension, Rc::downgrade(&listener));

        listener
    }

    pub fn create_client(&mut self, client_id: Identity, remote_id: RemoteServer) -> Rc<RefCell<ClientSock>> {
        let client_extension = client_id.extension.clone();
        let client = Rc::new(RefCell::new(ClientSock::new(client_id, remote_id)));

        self.clients.insert(client_extension, Rc::downgrade(&client));

        client
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
            } else if let Some(ref mut client) = {
                let dst_extension = packet.get_destination_extension();
                self.clients.get_mut(dst_extension).and_then(|client_weak|
                    client_weak.upgrade()
                )
            } {
                try!(client.borrow_mut().process(packet, &mut self.sock, rem_addr));
            }
        }
    }
}

pub struct ClientSock {

}

impl ClientSock {
    pub fn new(my_id: Identity, remote_id: RemoteServer) -> ClientSock {
        ClientSock {}
    }

    pub fn process(&mut self, packet: Packet, sock: &mut UdpSocket, rem_addr: SocketAddr) -> Result<()> {
        Ok(())
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

impl ServerSocket {
    pub fn recv(&mut self) -> Result<Vec<u8>> {
        self.recv_rx.recv().or(Err("Coudlnt read from recv channel".into()))
    }

    pub fn send(&mut self, msg: &[u8]) -> Result<usize> {
        let server_msg_packet: Packet = ServerMessagePacket {
            client_extension: self.client_extension.clone(),
            server_extension: self.my_extension.clone(),
            payload_box: ServerMessageBox::seal_precomputed(msg, &self.next_send_nonce, &self.precomputed_key),
        }.into();

        self.next_send_nonce.increment();

        let sent = try!(server_msg_packet.send(&mut self.sock, &self.rem_addr));

        if sent >= SERVER_MSG_PACKET_BASE_SIZE {
            Ok(sent - SERVER_MSG_PACKET_BASE_SIZE)
        } else {
            Err("Header trimmed".into())
        }
    }
}

pub struct Listener {
    my_extension: Extension,
    my_long_term_sk: server_long_term::SecretKey,
    minute_key: crypto_secretbox::Key,
    last_minute_key: crypto_secretbox::Key,
    conns: HashMap<(Extension, client_short_term::PublicKey), ServerConnection>,
    accept_chan_tx: Sender<ServerSocket>,
    accept_chan_rx: Receiver<ServerSocket>,
}

impl Listener {
    fn new(my_id: Identity) -> Listener {
        let (_, my_long_term_sk, my_extension) = my_id.as_server();
        let (accept_chan_tx, accept_chan_rx) = channel();

        Listener {
            my_extension: my_extension,
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
                try!(self.process_client_msg(client_msg_packet, sock, rem_addr));
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

    fn process_client_msg(&mut self, client_msg_packet: ClientMessagePacket, _sock: &mut UdpSocket, _rem_addr: SocketAddr) -> Result<()> {
        let conn_key = (client_msg_packet.client_extension.clone(),
                        client_msg_packet.client_short_term_pk.clone());

        if let Some(server_conn) = self.conns.get_mut(&conn_key) {
            try!(server_conn.process_packet(client_msg_packet));
        }

        Ok(())
    }
}

struct ServerConnection {
    precomputed_key: PrecomputedKey,
    recv_tx: Sender<Vec<u8>>,
    last_recv_nonce: Nonce8,
}

impl ServerConnection {
    pub fn process_packet(&mut self, client_msg_packet: ClientMessagePacket) -> Result<()> {
        if client_msg_packet.payload_box.nonce <= self.last_recv_nonce {
            return Err("Bad nonce".into()); // TODO: Rework to allow some packet reordering
        }

        let msg = try!(client_msg_packet.payload_box.open_precomputed(&self.precomputed_key)
            .or(Err("Bad encrypted message")));

        self.last_recv_nonce = client_msg_packet.payload_box.nonce;

        try!(self.recv_tx.send(msg).or(Err("Couldnt write to recv channel")));

        Ok(())
    }
}
