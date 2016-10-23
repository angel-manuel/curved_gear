use std::net::{SocketAddr, UdpSocket};
use std::io::Result as IOResult;

use keys::*;
use boxes::*;
use nonces::*;
use packet::*;
use identity::*;

pub struct Client {
    client_extension: Extension,
    server_extension: Extension,
    sock: UdpSocket,
    rem_addr: SocketAddr,
    precomputed_key: PrecomputedKey,
    client_short_term_pk: client_short_term::PublicKey,
    next_send_nonce: Nonce8,
    last_recv_nonce: Nonce8,
}

impl Client {
    pub fn connect(id: Identity, client_extension: Extension, sock: UdpSocket, remote_server: RemoteServer, payload: Option<&[u8]>) -> IOResult<Client> {
        let (client_short_term_pk, client_short_term_sk) = client_short_term::gen_keypair();
        let client_long_term_pk = client_long_term::PublicKey(id.pk);
        let client_long_term_sk = client_long_term::SecretKey(id.sk);
        let mut next_send_nonce = Nonce8::new_low();

        {
            let RemoteServer { ref server_extension, ref server_long_term_pk, .. } = remote_server;

            let hello_packet: Packet = HelloPacket {
                server_extension: server_extension.clone(),
                client_extension: client_extension.clone(),
                client_short_term_pk: client_short_term_pk.clone(),
                hello_box: PlainHelloBox::new_empty().seal(&next_send_nonce, &server_long_term_pk, &client_short_term_sk),
            }.into();
            next_send_nonce.increment();

            try!(hello_packet.send(&sock, remote_server.server_addr.clone()));
        }

        {
            let RemoteServer { ref server_extension, ref server_long_term_pk, .. } = remote_server;

            let (packet, rem_addr) = try!(Packet::recv(&sock));

            if let Packet::Cookie(ref cookie_packet) = packet {
                debug!("COOKIE packet!");

                let cookie_box = cookie_packet.cookie_box.open(server_long_term_pk, &client_short_term_sk).unwrap();
                let server_short_term_pk = cookie_box.server_short_term_pk;
                let precomputed_key = PrecomputedKey::precompute_at_client(&server_short_term_pk, &client_short_term_sk);

                let initiate_packet: Packet = InitiatePacket {
                    server_extension: server_extension.clone(),
                    client_extension: client_extension.clone(),
                    client_short_term_pk: client_short_term_pk.clone(),
                    server_cookie: cookie_box.server_cookie,
                    initiate_box: PlainInitiateBox {
                        client_long_term_pk: client_long_term_pk.clone(),
                        vouch: PlainVouch {
                            client_short_term_pk: client_short_term_pk.clone(),
                        }.seal(&Nonce16::new_random(), &server_long_term_pk, &client_long_term_sk),
                        domain_name: DomainName::new_empty(),
                    }.seal_precomputed(&next_send_nonce, &precomputed_key, payload),
                }.into();
                next_send_nonce.increment();

                try!(initiate_packet.send(&sock, rem_addr));

                Ok(Client {
                    client_extension: client_extension,
                    server_extension: server_extension.clone(),
                    sock: sock,
                    rem_addr: remote_server.server_addr,
                    precomputed_key: precomputed_key,
                    client_short_term_pk: client_short_term_pk,
                    next_send_nonce: next_send_nonce,
                    last_recv_nonce: Nonce8::new_zero(),
                })
            } else {
                panic!("Cookie packet not recv!!");
            }
        }
    }

    pub fn send(&mut self, msg: &[u8]) -> IOResult<usize> {
        let client_msg_packet: Packet = ClientMessagePacket {
            server_extension: self.server_extension.clone(),
            client_extension: self.client_extension.clone(),
            client_short_term_pk: self.client_short_term_pk.clone(),
            payload_box: ClientMessageBox::seal_precomputed(msg, &self.next_send_nonce, &self.precomputed_key),
        }.into();
        self.next_send_nonce.increment();

        client_msg_packet.send(&self.sock, self.rem_addr.clone())
    }

    pub fn recv(&mut self) -> IOResult<Vec<u8>> {
        loop {
            let (packet, _rem_addr) = try!(Packet::recv(&self.sock));

            if let Packet::ServerMessage(ref server_msg_packet) = packet {
                debug!("SERVER_MSG packet!");

                if server_msg_packet.payload_box.nonce <= self.last_recv_nonce {
                    debug!("Invalid nonce!");
                    continue;
                }

                self.last_recv_nonce = server_msg_packet.payload_box.nonce.clone();

                return Ok(server_msg_packet.payload_box.open_precomputed(&self.precomputed_key).unwrap());
            } else {
                debug!("Incorrect msg type recv'd");
            }
        }
    }
}
