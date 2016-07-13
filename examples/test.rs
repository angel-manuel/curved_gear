extern crate curved_gear;
extern crate env_logger;

use std::net::UdpSocket;

use curved_gear::*;

fn main() {
    env_logger::init().unwrap();

    let client_id = Identity::new();
    let client_ext = Extension::from_barr(b"client");
    let server_id = Identity::new();
    let server_ext = Extension::from_barr(b"server");
    let server_desc = RemoteServer {
        server_long_term_pk: server_long_term::PublicKey(server_id.pk.clone()),
        server_addr: "127.0.0.1:8888".parse().unwrap(),
        server_extension: server_ext.clone(),
    };
    let udp_7777 = UdpSocket::bind("127.0.0.1:7777").unwrap();
    let udp_8888 = UdpSocket::bind("127.0.0.1:8888").unwrap();
    let server = Server::new(server_id, server_ext, udp_8888);
    let mut client = Client::connect(client_id, client_ext, udp_7777, server_desc, Some("hello".as_bytes())).unwrap();

    let mut accepted_conn = server.accept();

    client.send("aaa".as_bytes()).unwrap();

    println!("{}", String::from_utf8(accepted_conn.recv()).unwrap());
    println!("{}", String::from_utf8(accepted_conn.recv()).unwrap());
    accepted_conn.send("bbb".as_bytes()).unwrap();
    println!("{}", String::from_utf8(client.recv().unwrap()).unwrap());
}
