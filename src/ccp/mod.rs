use std::collections::HashMap;
use std::net::SocketAddr;

use mioco::{spawn};
use mioco::udp::UdpSocket;
use mioco::sync::mpsc::{channel, Receiver, Sender};
use sodiumoxide::crypto::secretbox as crypto_secretbox;

use ::Result;
use identity::{Identity, Extension, RemoteServer, DomainName};
use packet::*;
use keys::*;
use boxes::*;
use nonces::*;

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

pub struct ClientSocket {
    my_extension: Extension,
    my_short_term_pk: client_short_term::PublicKey,
    precomputed_key: PrecomputedKey,
    server_extension: Extension,
    server_addr: SocketAddr,
    next_send_nonce: Nonce8,
    last_recv_nonce: Nonce8,
    sock: UdpSocket,
}

impl ClientSocket {
    pub fn connect(mut sock: UdpSocket, my_id: Identity, remote_id: RemoteServer) -> Result<ClientSocket> {
        let (my_long_term_pk, my_long_term_sk, my_extension) = my_id.as_client();
        let (my_short_term_pk, my_short_term_sk) = client_short_term::gen_keypair();
        let mut next_send_nonce = Nonce8::new_low();
        let RemoteServer { server_extension, server_long_term_pk, mut server_addr } = remote_id;

        let hello_packet: Packet = HelloPacket {
            server_extension: server_extension.clone(),
            client_extension: my_extension.clone(),
            client_short_term_pk: my_short_term_pk.clone(),
            hello_box: PlainHelloBox::new_empty().seal(&next_send_nonce, &server_long_term_pk, &my_short_term_sk),
        }.into();
        next_send_nonce.increment();

        try!(hello_packet.send(&mut sock, &server_addr));

        loop {
            let (packet, rem_addr) = try!(Packet::recv(&mut sock));

            if let Packet::Cookie(cookie_packet) = packet {
                let cookie_box = cookie_packet.cookie_box.open(&server_long_term_pk, &my_short_term_sk).unwrap();
                let server_short_term_pk = cookie_box.server_short_term_pk;
                let precomputed_key = PrecomputedKey::precompute_at_client(&server_short_term_pk, &my_short_term_sk);

                let initiate_packet: Packet = InitiatePacket {
                    server_extension: server_extension.clone(),
                    client_extension: my_extension.clone(),
                    client_short_term_pk: my_short_term_pk.clone(),
                    server_cookie: cookie_box.server_cookie,
                    initiate_box: PlainInitiateBox {
                        client_long_term_pk: my_long_term_pk.clone(),
                        vouch: PlainVouch {
                            client_short_term_pk: my_short_term_pk.clone(),
                        }.seal(&Nonce16::new_random(), &server_long_term_pk, &my_long_term_sk),
                        domain_name: DomainName::new_empty(),
                    }.seal_precomputed(&next_send_nonce, &precomputed_key, None),
                }.into();
                next_send_nonce.increment();

                try!(initiate_packet.send(&mut sock, &server_addr));

                server_addr = rem_addr;

                return Ok(ClientSocket {
                    my_extension: my_extension,
                    my_short_term_pk: my_short_term_pk,
                    precomputed_key: precomputed_key,
                    server_extension: server_extension,
                    server_addr: server_addr,
                    next_send_nonce: next_send_nonce,
                    last_recv_nonce: Nonce8::new_zero(),
                    sock: sock,
                });
            }
        }
    }

    pub fn recv(&mut self) -> Result<Vec<u8>> {
        loop {
            let (packet, rem_addr) = try!(Packet::recv(&mut self.sock));

            if let Packet::ServerMessage(server_msg_packet) = packet {
                if server_msg_packet.payload_box.nonce <= self.last_recv_nonce {
                    return Err("Bad nonce".into());
                }

                let msg = try!(server_msg_packet.payload_box.open_precomputed(&self.precomputed_key)
                    .or(Err("Bad encrypted message")));

                self.last_recv_nonce = server_msg_packet.payload_box.nonce;
                self.server_addr = rem_addr;

                return Ok(msg);
            }
        }
    }

    pub fn send(&mut self, msg: &[u8]) -> Result<usize> {
        let client_msg_packet: Packet = ClientMessagePacket {
            server_extension: self.server_extension.clone(),
            client_extension: self.my_extension.clone(),
            client_short_term_pk: self.my_short_term_pk.clone(),
            payload_box: ClientMessageBox::seal_precomputed(msg, &self.next_send_nonce,
                &self.precomputed_key),
        }.into();

        self.next_send_nonce.increment();

        let sent = try!(client_msg_packet.send(&mut self.sock, &self.server_addr));

        if sent >= CLIENT_MSG_PACKET_BASE_SIZE {
            Ok(sent - CLIENT_MSG_PACKET_BASE_SIZE)
        } else {
            Err("Header trimmed".into())
        }
    }
}

pub struct ServerSocket {
    recv_rx: Receiver<Vec<u8>>,
    rem_addr: SocketAddr,
    client_extension: Extension,
    my_extension: Extension,
    precomputed_key: PrecomputedKey,
    next_send_nonce: Nonce8,
    sock: UdpSocket,
}

impl ServerSocket {
    pub fn recv(&mut self) -> Result<Vec<u8>> {
        self.recv_rx.recv().or(Err("Couldnt read from recv channel".into()))
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

struct ListenerInternal {
    my_extension: Extension,
    my_long_term_sk: server_long_term::SecretKey,
    minute_key: crypto_secretbox::Key,
    last_minute_key: crypto_secretbox::Key,
    conns: HashMap<(Extension, client_short_term::PublicKey), ServerConnection>,
    accept_tx: Sender<ServerSocket>,
    sock: UdpSocket,
}

pub struct Listener {
    accept_rx: Receiver<ServerSocket>,
}

impl Listener {
    pub fn new(my_id: Identity, sock: UdpSocket) -> Listener {
        let (_, my_long_term_sk, my_extension) = my_id.as_server();
        let (accept_tx, accept_rx) = channel();

        let mut listener_internal = ListenerInternal {
            my_extension: my_extension,
            my_long_term_sk: my_long_term_sk,
            minute_key: crypto_secretbox::gen_key(),
            last_minute_key: crypto_secretbox::gen_key(),
            conns: HashMap::new(),
            accept_tx: accept_tx,
            sock: sock,
        };

        spawn(move || -> Result<()> {
            loop {
                let (packet, rem_addr) = try!(Packet::recv(&mut listener_internal.sock));
                try!(listener_internal.process_packet(packet, rem_addr));
            }
        });

        Listener {
            accept_rx: accept_rx,
        }
    }

    pub fn accept_sock(&mut self) -> Result<ServerSocket> {
        self.accept_rx.recv().or(Err("Couldnt read accept channel".into()))
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
        info!("\"{}\" accepting connection \"{}\"@{}", &self.my_extension, &initiate_packet.client_extension, &rem_addr);

        let new_sock = ServerSocket {
            recv_rx: recv_rx,
            sock: self.sock.try_clone().unwrap(),
            rem_addr: rem_addr,
            client_extension: initiate_packet.client_extension.clone(),
            my_extension: self.my_extension.clone(),
            precomputed_key: precomputed_key,
            next_send_nonce: Nonce8::new_low(),
        };

        self.accept_tx.send(new_sock).or(Err("Couldnt read accept channel".into()))
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
