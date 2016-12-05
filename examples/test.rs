
extern crate curved_gear;
extern crate env_logger;
extern crate mioco;

use std::net::SocketAddr;

use curved_gear::*;
use mioco::udp::UdpSocket;

fn main() {
    env_logger::init().unwrap();

    let client_id = Identity::new(Extension::from_barr(b"client"));
    let server_id = Identity::new(Extension::from_barr(b"server"));
    let server_addr: SocketAddr = "0.0.0.0:7777".parse().unwrap();
    let remote_addr: SocketAddr = "127.0.0.1:7777".parse().unwrap();
    let remote_id = server_id.create_remote(remote_addr);

    mioco::start(move || -> Result<()> {
        let mut listener = CCPListener::new(server_id.clone(), UdpSocket::bound(&server_addr).unwrap());

        for i in 1..5 {
            let client_id_c = client_id.clone();
            let remote_id_c = remote_id.clone();

            mioco::spawn(move || -> Result<()> {
                let mut sock = try!(CCPClientSocket::connect(UdpSocket::v4().unwrap(),
                    client_id_c, remote_id_c));

                println!("Client connection {}", i);
                try!(sock.send("Hello world".as_bytes()));
                let buf = try!(sock.recv());
                println!("{}", String::from_utf8_lossy(&buf));
                try!(sock.send("".as_bytes()));

                Ok(())
            });
        }

        for i in 1..5 {
            let mut sock = try!(listener.accept_sock());

            println!("Server connection {}", i);

            mioco::spawn(move || -> Result<()> {
                loop {
                    let msg = try!(sock.recv());
                    println!("msg.len() = {}", msg.len());
                    if msg.len() == 0 { break; }
                    try!(sock.send(&msg));
                }

                Ok(())
            });
        }

        Ok(())
    }).unwrap().unwrap();
}
