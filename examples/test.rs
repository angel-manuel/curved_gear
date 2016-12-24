
extern crate curved_gear;
extern crate env_logger;
extern crate mioco;

use std::net::SocketAddr;

use curved_gear::*;
use mioco::udp::UdpSocket;

fn main() {
    env_logger::init().unwrap();

    let client_ids = vec![
        Identity::new(Extension::from_barr(b"client1")),
        Identity::new(Extension::from_barr(b"client2")),
        Identity::new(Extension::from_barr(b"client3")),
        Identity::new(Extension::from_barr(b"client4")),
        Identity::new(Extension::from_barr(b"client5")),
    ];
    let server_id = Identity::new(Extension::from_barr(b"server"));
    let server_addr: SocketAddr = "0.0.0.0:7777".parse().unwrap();
    let remote_addr: SocketAddr = "127.0.0.1:7777".parse().unwrap();
    let remote_id = server_id.create_remote(remote_addr);

    mioco::start(move || -> Result<()> {
        let mut listener = CCPListener::new(server_id.clone(), UdpSocket::bound(&server_addr).unwrap());
        let demultiplexor = CCPDemultiplexor::new(UdpSocket::v4().unwrap());
        let clients_len = client_ids.len();

        for client_id in client_ids {
            let remote_id_c = remote_id.clone();
            let client_id_c = client_id.clone();
            let demux = demultiplexor.clone();

            mioco::spawn(move || {
                let mut sock = CCPClientSocket::connect_with_demultiplexor(demux,
                    client_id_c, remote_id_c).unwrap();

                println!("Client {}: sending", client_id);
                sock.send("Hello world".as_bytes()).unwrap();
                let buf = sock.recv().unwrap();
                println!("Client {}: {}", client_id, String::from_utf8_lossy(&buf));
                sock.send("".as_bytes()).unwrap();
            });
        }

        for i in 1..(clients_len + 1) {
            let mut sock = try!(listener.accept_sock());

            mioco::spawn(move || {
                loop {
                    let msg = sock.recv().unwrap();
                    println!("Server {}: msg.len() = {}", i, msg.len());
                    if msg.len() == 0 { break; }
                    sock.send(&msg).unwrap();
                }
            });
        }

        Ok(())
    }).unwrap().unwrap();
}
