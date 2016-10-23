
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
            let mut conn = CCPStream::connect(client_id, server_id.create_remote(remote_addr));
            let mut buf = [0u8; 1024];

            try!(conn.write_all("Hello world".as_bytes()));
            let read_len = try!(conn.read(&mut buf));
            println!("{}", String::from_utf8_lossy(&buf[0..read_len]));

            Ok(())
        });

        loop {
            let mut conn = try!(listener.accept());

            mioco::spawn(move || -> io::Result<()> {
                let mut buf = [0u8; 1024];

                loop {
                    let read_len = try!(conn.read(&mut buf));
                    if read_len == 0 { break; }
                    try!(conn.write_all(&buf[..read_len]));
                }

                Ok(())
            });
        }
    }).unwrap();
}
