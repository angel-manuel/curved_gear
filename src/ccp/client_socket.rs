use std::net::SocketAddr;

use mioco::udp::UdpSocket;

use ::Result;
use identity::{Identity, Extension, RemoteServer, DomainName};
use packet::*;
use keys::*;
use boxes::*;
use nonces::*;

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
