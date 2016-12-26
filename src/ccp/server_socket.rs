use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use mioco;
use mioco::timer::Timer;
use mioco::udp::UdpSocket;
use mioco::sync::mpsc::{channel, Receiver, Sender};
use sodiumoxide::crypto::secretbox as crypto_secretbox;

use ::Result;
use identity::{Identity, Extension};
use packet::*;
use keys::*;
use boxes::*;
use nonces::*;

use super::PacketProcessor;

pub struct ServerSocket {
    core: ServerSocketCore,
    _listener_internal: Arc<Mutex<ListenerInternal>>,
}

impl ServerSocket {
    pub fn recv(&mut self) -> Result<Vec<u8>> {
        self.core.recv()
    }

    pub fn send(&mut self, msg: &[u8]) -> Result<usize> {
        self.core.send(msg)
    }
}

struct ServerSocketCore {
    recv_rx: Receiver<Vec<u8>>,
    rem_addr: SocketAddr,
    client_extension: Extension,
    my_extension: Extension,
    precomputed_key: PrecomputedKey,
    next_send_nonce: Nonce8,
    sock: UdpSocket,
}

impl ServerSocketCore {
    pub fn recv(&mut self) -> Result<Vec<u8>> {
        let mut timer = Timer::new();
        timer.set_timeout(5000);

        select!(
            r:timer => {
                let _ = timer.read();
                return Err("Recv timeout".into());
            },
            r:self.recv_rx => {
                return self.recv_rx.recv().or(Err("Couldn't read from recv channel".into()));
            }
        );

        unreachable!();
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

impl Drop for ServerSocketCore {
    fn drop(&mut self) {
        debug!("Dropping ServerSocketCore");
    }
}

struct ListenerInternal {
    my_extension: Extension,
    my_long_term_sk: server_long_term::SecretKey,
    minute_key: crypto_secretbox::Key,
    last_minute_key: crypto_secretbox::Key,
    conns: HashMap<(Extension, client_short_term::PublicKey), ServerConnection>,
    accept_tx: Sender<ServerSocketCore>,
    sock: UdpSocket,
}

pub struct Listener {
    accept_rx: Receiver<ServerSocketCore>,
    internal: Arc<Mutex<ListenerInternal>>,
}

impl Listener {
    pub fn new(my_id: Identity, sock: UdpSocket) -> Listener {
        let (_, my_long_term_sk, my_extension) = my_id.as_server();
        let (accept_tx, accept_rx) = channel();

        let listener_internal = Arc::new(Mutex::new(ListenerInternal {
            my_extension: my_extension,
            my_long_term_sk: my_long_term_sk,
            minute_key: crypto_secretbox::gen_key(),
            last_minute_key: crypto_secretbox::gen_key(),
            conns: HashMap::new(),
            accept_tx: accept_tx,
            sock: sock,
        }));

        let listener_weak = Arc::downgrade(&listener_internal);
        mioco::spawn(move || -> Result<()> {
            loop {
                let listener_arc = listener_weak.upgrade();

                if let Some(listener) = listener_arc {
                    let mut listener_lock = try!(listener.lock().or(Err("Couldn't lock listener")));
                    let mut timer = Timer::new();
                    timer.set_timeout(1000);

                    select!(
                        r:timer => {
                            continue;
                        },
                        r:listener_lock.sock => {
                            let (packet, rem_addr) = try!(Packet::recv(&mut listener_lock.sock));
                            try!(listener_lock.process_packet(packet, rem_addr));
                        }
                    );
                } else {
                    debug!("Killing listener coroutine");
                    break;
                }
            }

            Ok(())
        });

        Listener {
            accept_rx: accept_rx,
            internal: listener_internal,
        }
    }

    pub fn accept_sock(&mut self) -> Result<ServerSocket> {
        let server_socket_core = try!(self.accept_rx.recv().or(Err("Couldnt read accept channel")));

        debug!("Accepting ServerSocket");

        Ok(ServerSocket {
            core: server_socket_core,
            _listener_internal: self.internal.clone(),
        })
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        debug!("Dropping Listener");
    }
}

impl ListenerInternal {
    fn process_hello(&mut self, hello_packet: HelloPacket, rem_addr: SocketAddr) -> Result<()> {
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

        try!(cookie_packet.send(&mut self.sock, &rem_addr));

        Ok(())
    }

    fn process_initiate(&mut self, initiate_packet: InitiatePacket, rem_addr: SocketAddr) -> Result<()> {
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
        info!("\"{}\" pre-accepting connection \"{}\"@{}", &self.my_extension, &initiate_packet.client_extension, &rem_addr);

        let new_sock = ServerSocketCore {
            recv_rx: recv_rx,
            sock: self.sock.try_clone().unwrap(),
            rem_addr: rem_addr,
            client_extension: initiate_packet.client_extension.clone(),
            my_extension: self.my_extension.clone(),
            precomputed_key: precomputed_key,
            next_send_nonce: Nonce8::new_low(),
        };

        try!(self.accept_tx.send(new_sock).or(Err("Couldnt read accept channel")));

        Ok(())
    }

    fn process_client_msg(&mut self, client_msg_packet: ClientMessagePacket, _rem_addr: SocketAddr) -> Result<()> {
        let conn_key = (client_msg_packet.client_extension.clone(),
                        client_msg_packet.client_short_term_pk.clone());

        if let Some(server_conn) = self.conns.get_mut(&conn_key) {
            try!(server_conn.process_packet(client_msg_packet));
        }

        Ok(())
    }
}

impl PacketProcessor for ListenerInternal {
    fn process_packet(&mut self, packet: Packet, rem_addr: SocketAddr) -> Result<()> {
        match packet {
            Packet::ClientMessage(client_msg_packet) => {
                try!(self.process_client_msg(client_msg_packet, rem_addr));
            },
            Packet::Initiate(initiate_packet) => {
                try!(self.process_initiate(initiate_packet, rem_addr));
            },
            Packet::Hello(hello_packet) => {
                try!(self.process_hello(hello_packet, rem_addr));
            },
            _ => {
                debug!("Unvalid packet type");
            }
        }

        Ok(())
    }
}

impl Drop for ListenerInternal {
    fn drop(&mut self) {
        debug!("Dropping ListenerInternal");
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
