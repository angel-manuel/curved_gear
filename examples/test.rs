
extern crate curved_gear;
extern crate env_logger;
extern crate mioco;

use std::io;
use std::net::SocketAddr;

use curved_gear::*;
use mioco::udp::UdpSocket;

fn main() {
    env_logger::init().unwrap();

    let client_id = Identity::new(Extension::from_barr(b"client"));
    let server_id = Identity::new(Extension::from_barr(b"server"));
    let server_addr: SocketAddr = "0.0.0.0:7777".parse().unwrap();
    let remote_addr: SocketAddr = "127.0.0.1:7777".parse().unwrap();

    mioco::start(|| -> io::Result<()> {
        let listener = CCPListener::new(server_id.clone(), UdpSocket::bound(&server_addr).unwrap());

        mioco::spawn(|| -> io::Result<()> {
            let mut sock = CCPSocket::connect(client_id, server_id.create_remote(remote_addr));

            try!(conn.send("Hello world".as_bytes()));
            let buf = try!(conn.read());
            println!("{}", String::from_utf8_lossy(&buf));

            Ok(())
        });

        loop {
            let mut conn = try!(listener.accept_sock());

            mioco::spawn(move || -> io::Result<()> {
                loop {
                    let buf = try!(conn.read());
                    if buf.len() == 0 { break; }
                    try!(conn.write_all(&buf));
                }

                Ok(())
            });
        }
    }).unwrap();
}
