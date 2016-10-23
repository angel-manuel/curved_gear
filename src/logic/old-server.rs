use std::thread;
use std::sync::mpsc;
use std::collections::HashMap;
use std::net::{UdpSocket, SocketAddr};
use std::io::Result as IOResult;

use sodiumoxide::crypto::secretbox as crypto_secretbox;

use keys::*;
use boxes::*;
use nonces::*;
use packet::*;
use identity::*;

pub struct Server {
    accept_chan_rx: mpsc::Receiver<ServerSocket>,
}

impl Server {
    pub fn new(id: Identity, server_extension: Extension, sock: UdpSocket) -> Server {
        let (tx, rx) = mpsc::channel();

        let minute_key = crypto_secretbox::gen_key();
        let mut server_internal = ServerInternal {
            server_extension: server_extension,
            server_long_term_sk: server_long_term::SecretKey(id.sk),
            sock: sock,
            accept_chan_tx: tx,
            conns: HashMap::new(),
            minute_key: minute_key.clone(),
            last_minute_key: minute_key,
        };

        thread::spawn(move || server_internal.start());

        Server {
            accept_chan_rx: rx,
        }
    }

    pub fn accept(&self) -> ServerSocket {
        self.accept_chan_rx.recv().unwrap()
    }
}

struct ServerInternal {
    server_extension: Extension,
    server_long_term_sk: server_long_term::SecretKey,
    sock: UdpSocket, //TODO: Break 1on1 sock-server relationship and abstract with curved_gear::links
    accept_chan_tx: mpsc::Sender<ServerSocket>,
    conns: HashMap<(Extension, client_short_term::PublicKey), ServerConnection>,
    minute_key: crypto_secretbox::Key,
    last_minute_key: crypto_secretbox::Key,
}

struct ServerConnection {
    precomputed_key: PrecomputedKey,
    recv_tx: mpsc::Sender<Vec<u8>>,
    last_recv_nonce: Nonce8,
}

impl ServerInternal {
    fn start(&mut self) {
        loop {
            let (packet, rem_addr) = Packet::recv(&self.sock).unwrap();
            match packet {
                Packet::ClientMessage(client_msg_packet) => {
                    debug!("CLIENT_MSG packet!");
                    let conn_key = (client_msg_packet.client_extension, client_msg_packet.client_short_term_pk);

                    let mut server_conn = self.conns.get_mut(&conn_key).unwrap();

                    if client_msg_packet.payload_box.nonce <= server_conn.last_recv_nonce {
                        debug!("Invalid nonce!");
                        continue;
                    }

                    server_conn.last_recv_nonce = client_msg_packet.payload_box.nonce.clone();

                    let msg = client_msg_packet.payload_box.open_precomputed(&server_conn.precomputed_key).unwrap();
                    server_conn.recv_tx.send(msg).unwrap();
                },
                Packet::Initiate(initiate_packet) => {
                    debug!("INITIATE packet!");
                    self.process_initiate(initiate_packet, rem_addr);
                },
                Packet::Hello(hello_packet) => {
                    debug!("HELLO packet!");
                    self.process_hello(hello_packet, rem_addr);
                },
                _ => {
                    debug!("Unknown packet!");
                }
            };
        }
    }

    fn process_hello(&self, hello_packet: HelloPacket, rem_addr: SocketAddr) {
        let client_short_term_pk = hello_packet.client_short_term_pk;
        let conn_key = (hello_packet.client_extension.clone(), client_short_term_pk.clone());

        if self.conns.contains_key(&conn_key) {
            return;
        }

        hello_packet.hello_box.open(&client_short_term_pk, &self.server_long_term_sk).unwrap();

        let (server_short_term_pk, server_short_term_sk) = server_short_term::gen_keypair();

        let cookie_packet: Packet = CookiePacket {
            client_extension: hello_packet.client_extension.clone(),
            server_extension: self.server_extension.clone(),
            cookie_box: PlainCookieBox {
                server_short_term_pk: server_short_term_pk,
                server_cookie: PlainCookie {
                    client_short_term_pk: client_short_term_pk.clone(),
                    server_short_term_sk: server_short_term_sk.clone(),
                }.seal(&CookieNonce::new_random(), &self.minute_key),
            }.seal(&Nonce16::new_random(), &client_short_term_pk, &self.server_long_term_sk),
        }.into();

        cookie_packet.send(&self.sock, rem_addr).unwrap();
    }

    fn process_initiate(&mut self, initiate_packet: InitiatePacket, rem_addr: SocketAddr) {
        let conn_key = (initiate_packet.client_extension.clone(), initiate_packet.client_short_term_pk.clone());

        if self.conns.contains_key(&conn_key) {
            return;
        }

        let cookie = initiate_packet.server_cookie.open(&self.minute_key, &self.last_minute_key).unwrap();
        let precomputed_key = PrecomputedKey::precompute_at_server(&initiate_packet.client_short_term_pk, &cookie.server_short_term_sk);
        let (initiate_box, payload) = initiate_packet.initiate_box.open_precomputed_with_payload(&precomputed_key).unwrap();

        let client_long_term_pk = initiate_box.client_long_term_pk;
        let vouch = initiate_box.vouch.open(&client_long_term_pk, &self.server_long_term_sk).unwrap();

        if vouch.client_short_term_pk != initiate_packet.client_short_term_pk {
            return;
        }

        //TODO: Check if client_long_term_pk is accepted

        let (recv_tx, recv_rx) = mpsc::channel();

        if let Some(msg) = payload {
            recv_tx.send(msg).unwrap();
        }

        let new_conn = ServerConnection {
            precomputed_key: precomputed_key.clone(),
            recv_tx: recv_tx,
            last_recv_nonce: initiate_packet.initiate_box.nonce.clone(),
        };

        self.conns.insert(conn_key, new_conn);
        info!("\"{}\" accepting connection \"{}\"@{}", &self.server_extension, &initiate_packet.client_extension, &rem_addr);

        let new_sock = ServerSocket {
            recv_rx: recv_rx,
            sock: self.sock.try_clone().unwrap(),
            rem_addr: rem_addr,
            client_extension: initiate_packet.client_extension.clone(),
            server_extension: self.server_extension.clone(),
            precomputed_key: precomputed_key,
            next_send_nonce: Nonce8::new_low(),
        };

        self.accept_chan_tx.send(new_sock).unwrap();
    }
}

pub struct ServerSocket {
    recv_rx: mpsc::Receiver<Vec<u8>>,
    sock: UdpSocket,
    rem_addr: SocketAddr,
    client_extension: Extension,
    server_extension: Extension,
    precomputed_key: PrecomputedKey,
    next_send_nonce: Nonce8,
}

impl ServerSocket {
    pub fn send(&mut self, msg: &[u8]) -> IOResult<usize> {
        let server_msg_packet: Packet = ServerMessagePacket {
            client_extension: self.client_extension.clone(),
            server_extension: self.server_extension.clone(),
            payload_box: ServerMessageBox::seal_precomputed(msg, &self.next_send_nonce, &self.precomputed_key),
        }.into();

        self.next_send_nonce.increment();

        server_msg_packet.send(&self.sock, self.rem_addr)
    }

    pub fn recv(&self) -> Vec<u8> {
        self.recv_rx.recv().unwrap()
    }
}
