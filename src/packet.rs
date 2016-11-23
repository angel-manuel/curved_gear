use std::io::Cursor;
use std::net::{UdpSocket, SocketAddr};
use std::convert::{From, Into};
use std::result::Result as RResult;
use std::io::Result as IOResult;
use std::hash::{Hash, Hasher};

use rustc_serialize::{Encodable, Encoder, Decodable, Decoder};
use sodiumoxide::crypto::box_ as crypto_box;
use bincode::rustc_serialize as bcode;
use bincode::SizeLimit;

use identity::*;
use keys::*;
use boxes::*;

pub const MAGIC_SIZE: usize = 8;
fixed_length_box!(pub PacketMagic, MAGIC_SIZE);

pub const HELLO_PACKET_MAGIC: &'static [u8] = b"QvnQ5XlH";
pub const HELLO_PACKET_PADDING: usize = 64;
pub const HELLO_PACKET_SIZE: usize = MAGIC_SIZE + 2*EXTENSION_SIZE + crypto_box::PUBLICKEYBYTES
                        + HELLO_PACKET_PADDING + 8 + HELLO_BOX_SIZE;

/** CurveCP Hello packet

```text
0   : 8  : magic
8   : 16 : server extension
24  : 16 : client extension
40  : 32 : client short-term public key
72  : 64 : zero
136 : 8  : compressed nonce
144 : 80 : box C'->S containing:
            0 : 64 : zero

TOTAL: 224 bytes
```
*/
#[derive(RustcEncodable, RustcDecodable)]
pub struct HelloPacket {
    pub server_extension: Extension,
    pub client_extension: Extension,
    pub client_short_term_pk: client_short_term::PublicKey,
    pub hello_box: HelloBox,
}

pub const COOKIE_PACKET_MAGIC: &'static [u8] = b"RL3aNMXK";
pub const COOKIE_PACKET_SIZE: usize = MAGIC_SIZE + 2*EXTENSION_SIZE + 16 + COOKIE_BOX_SIZE;

/** CurveCP Cookie packet

```text
0  : 8   : magic
8  : 16  : client extension
24 : 16  : server extension
40 : 16  : compressed nonce
56 : 144 : box S->C' containing:
            0  : 32 : server short-term public key
            32 : 16 : compressed nonce
            48 : 80 : minute-key secretbox containing:
                       0  : 32 : client short-term public key
                       32 : 32 : server short-term secret key

TOTAL: 200 bytes
```
*/
#[derive(RustcEncodable, RustcDecodable)]
pub struct CookiePacket {
    pub client_extension: Extension,
    pub server_extension: Extension,
    pub cookie_box: CookieBox,
}

pub const INITIATE_PACKET_MAGIC: &'static [u8] = b"QvnQ5XlI";
pub const INITIATE_PACKET_BASE_SIZE: usize = MAGIC_SIZE + 2*EXTENSION_SIZE + crypto_box::PUBLICKEYBYTES + COOKIE_SIZE + INITIATE_BOX_BASE_SIZE;
pub const INITIATE_PACKET_MAX_PAYLOAD: usize = 500; //Serialization not quite right so margin reduced.
//pub const INITIATE_PACKET_MAX_PAYLOAD: usize = 640;
pub const INITIATE_PACKET_MAX_SIZE: usize = INITIATE_PACKET_BASE_SIZE + INITIATE_PACKET_MAX_PAYLOAD;

/** CurveCP Initiate packet

```text
0   : 8     : magic
8   : 16    : server extension
24  : 16    : client extension
40  : 32    : client short-term public key
72  : 96    : server's cookie
               0  : 16 : compressed nonce
               16 : 80 : minute-key secretbox containing:
                          0  : 32 : client short-term public key
                          32 : 32 : server short-term secret key
168 : 8     : compressed nonce
176 : 368+M : box C'->S' containing:
176 :          0   : 32  : client long-term public key
208 :          32  : 16  : compressed nonce
224 :          48  : 48  : box C->S containing:
                            0 : 32 : client short-term public key
272 :          96  : 256 : server domain name
528 :          352 : M   : message

TOTAL: 544+M bytes
MAX: 1184 bytes
```
*/
#[derive(RustcEncodable, RustcDecodable)]
pub struct InitiatePacket {
    pub server_extension: Extension,
    pub client_extension: Extension,
    pub client_short_term_pk: client_short_term::PublicKey,
    pub server_cookie: Cookie,
    pub initiate_box: InitiateBox,
}

pub const PAYLOAD_MAX_SIZE: usize = 900; //Serialization not quite right so margin reduced.
//pub const PAYLOAD_MAX_SIZE: usize = 1088;

pub const SERVER_MSG_PACKET_MAGIC: &'static [u8] = b"RL3aNMXM";
pub const SERVER_MSG_PACKET_BASE_SIZE: usize = MAGIC_SIZE + 2*EXTENSION_SIZE + 8 + 16;
pub const SERVER_MSG_PACKET_MAX_SIZE: usize = SERVER_MSG_PACKET_BASE_SIZE + PAYLOAD_MAX_SIZE;

/** CurveCP ServerMessage packet

```text
0  : 8    : magic
8  : 16   : client extension
24 : 16   : server extension
40 : 8    : compressed nonce
48 : 16+M : box S'->C' containing:
             0 : M : message

TOTAL: 64+M bytes
MAX: 1152 bytes
```
*/
#[derive(RustcEncodable, RustcDecodable)]
pub struct ServerMessagePacket {
    pub client_extension: Extension,
    pub server_extension: Extension,
    pub payload_box: ServerMessageBox,
}

pub const CLIENT_MSG_PACKET_MAGIC: &'static [u8] = b"QvnQ5XlM";
pub const CLIENT_MSG_PACKET_BASE_SIZE: usize = MAGIC_SIZE + 2*EXTENSION_SIZE + crypto_box::PUBLICKEYBYTES + 8 + 16;
pub const CLIENT_MSG_PACKET_MAX_SIZE: usize = CLIENT_MSG_PACKET_BASE_SIZE + PAYLOAD_MAX_SIZE;

/** CurveCP ClientMessage packet

```text
0   : 8    : magic
8   : 16   : server extension
24  : 16   : client extension
40  : 32   : client short-term public key
72  : 8    : compressed nonce
80  : 16+M : box C'->S' containing:
              0 : M : message

TOTAL: 96+M bytes
MAX: 1184 bytes
```
*/
#[derive(RustcEncodable, RustcDecodable)]
pub struct ClientMessagePacket {
    pub server_extension: Extension,
    pub client_extension: Extension,
    pub client_short_term_pk: client_short_term::PublicKey,
    pub payload_box: ClientMessageBox,
}

pub const PACKET_MAX_SIZE: usize = CLIENT_MSG_PACKET_MAX_SIZE;

pub enum Packet {
    Hello(HelloPacket),
    Cookie(CookiePacket),
    Initiate(InitiatePacket),
    ServerMessage(ServerMessagePacket),
    ClientMessage(ClientMessagePacket),
}

impl From<HelloPacket> for Packet { fn from(packet: HelloPacket) -> Packet { Packet::Hello(packet) } }
impl From<CookiePacket> for Packet { fn from(packet: CookiePacket) -> Packet { Packet::Cookie(packet) } }
impl From<InitiatePacket> for Packet { fn from(packet: InitiatePacket) -> Packet { Packet::Initiate(packet) } }
impl From<ServerMessagePacket> for Packet { fn from(packet: ServerMessagePacket) -> Packet { Packet::ServerMessage(packet) } }
impl From<ClientMessagePacket> for Packet { fn from(packet: ClientMessagePacket) -> Packet { Packet::ClientMessage(packet) } }

impl Encodable for Packet {
    fn encode<S: Encoder>(&self, s: &mut S) -> RResult<(), S::Error> {
        match *self {
            Packet::ClientMessage(ref packet) => {
                try!(PacketMagic::from_barr(CLIENT_MSG_PACKET_MAGIC).encode(s));
                packet.encode(s)
            },
            Packet::ServerMessage(ref packet) => {
                try!(PacketMagic::from_barr(SERVER_MSG_PACKET_MAGIC).encode(s));
                packet.encode(s)
            },
            Packet::Cookie(ref packet) => {
                try!(PacketMagic::from_barr(COOKIE_PACKET_MAGIC).encode(s));
                packet.encode(s)
            },
            Packet::Initiate(ref packet) => {
                try!(PacketMagic::from_barr(INITIATE_PACKET_MAGIC).encode(s));
                packet.encode(s)
            },
            Packet::Hello(ref packet) => {
                try!(PacketMagic::from_barr(HELLO_PACKET_MAGIC).encode(s));
                packet.encode(s)
            },
        }
    }
}

impl Decodable for Packet {
    fn decode<D: Decoder>(d: &mut D) -> RResult<Self, D::Error> {
        let packet_magic = try!(PacketMagic::decode(d));

        if packet_magic.0 == CLIENT_MSG_PACKET_MAGIC {
            ClientMessagePacket::decode(d).map(Into::into)
        } else if packet_magic.0 == INITIATE_PACKET_MAGIC {
            InitiatePacket::decode(d).map(Into::into)
        } else if packet_magic.0 == HELLO_PACKET_MAGIC {
            HelloPacket::decode(d).map(Into::into)
        } else if packet_magic.0 == SERVER_MSG_PACKET_MAGIC {
            ServerMessagePacket::decode(d).map(Into::into)
        } else if packet_magic.0 == COOKIE_PACKET_MAGIC {
            CookiePacket::decode(d).map(Into::into)
        } else {
            Err(d.error("Unknown packet type"))
        }
    }
}

impl Packet {
    pub fn get_destination_extension(&self) -> &Extension {
        match *self {
            Packet::ClientMessage(ref packet) => {
                &packet.server_extension
            },
            Packet::ServerMessage(ref packet) => {
                &packet.client_extension
            },
            Packet::Cookie(ref packet) => {
                &packet.client_extension
            },
            Packet::Initiate(ref packet) => {
                &packet.server_extension
            },
            Packet::Hello(ref packet) => {
                &packet.server_extension
            },
        }
    }

    pub fn recv(sock: &UdpSocket) -> IOResult<(Packet, SocketAddr)> {
        let mut buf = [0u8; PACKET_MAX_SIZE];

        let (recv_len, rem_addr) = try!(sock.recv_from(&mut buf));

        Ok(bcode::decode(&buf[..recv_len]).map(|packet| (packet, rem_addr)).unwrap())
    }

    pub fn send(&self, sock: &UdpSocket, addr: SocketAddr) -> IOResult<usize> {
        let mut buf = [0u8; PACKET_MAX_SIZE];
        let written = {
            let mut buf_cur = Cursor::new(buf.as_mut());

            bcode::encode_into(self, &mut buf_cur, SizeLimit::Infinite).unwrap();

            buf_cur.position() as usize
        };

        sock.send_to(&buf[..written], addr)
    }
}
