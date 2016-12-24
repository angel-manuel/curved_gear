use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use mioco;
use mioco::udp::UdpSocket;
use mioco::sync::mpsc::{channel, Sender};
use mioco::sync::RwLock;

use ::Result;
use identity::Extension;
use packet::*;

pub struct Demultiplexor {
    clients: Arc<RwLock<HashMap<Extension, ClientConnection>>>,
    internal_tx: Sender<()>,
    sock: UdpSocket,
}

impl Demultiplexor {
    pub fn new(sock: UdpSocket) -> Arc<Mutex<Demultiplexor>> {
        let (internal_tx, internal_rx) = channel();
        let clients = Arc::new(RwLock::new(HashMap::<Extension, ClientConnection>::new()));

        {
            let clients = clients.clone();
            let mut sock = sock.try_clone().unwrap();
            mioco::spawn(move || -> Result<()> {
                loop {
                    select!(
                        r:sock => {
                            let (packet, rem_addr) = try!(Packet::recv(&mut sock));
                            let client_extension = packet.get_destination_extension().clone();

                            let clients_hnd = try!(clients.read().or(Err("Poisoined clients hash")));

                            if let Some(client_conn) = clients_hnd.get(&client_extension) {
                                let recv_tx = try!(client_conn.recv_tx.lock()
                                    .or(Err("Couldn't lock client recv_tx")));
                                try!(recv_tx.send((packet, rem_addr))
                                    .or(Err("Couldn't send packet to client_conn")));
                            }
                        },
                        r:internal_rx => {
                            let _read = try!(internal_rx.recv()
                                .or(Err("Couldn't empty internal_chan stack")));

                            break;
                        }
                    );
                }

                Ok(())
            });
        }

        Arc::new(Mutex::new(Demultiplexor {
            clients: clients,
            internal_tx: internal_tx,
            sock: sock,
        }))
    }

    pub fn add_listener(&mut self, extension: Extension, listener: Sender<(Packet, SocketAddr)>) {
        let mut clients_hnd = self.clients.write().unwrap();
        debug!("Adding listener to demultiplexor");
        clients_hnd.insert(extension, ClientConnection { recv_tx: Mutex::new(listener) });
    }

    pub fn remove_listener(&mut self, extension: &Extension) {
        let mut clients_hnd = self.clients.write().unwrap();
        debug!("Removing listener from demultiplexor");
        clients_hnd.remove(extension);
    }

    pub fn get_mut_sock(&mut self) -> &mut UdpSocket {
        &mut self.sock
    }
}

impl Drop for Demultiplexor {
    fn drop(&mut self) {
        debug!("Dropping Demultiplexor");
        self.internal_tx.send(()).unwrap();
    }
}

struct ClientConnection {
    recv_tx: Mutex<Sender<(Packet, SocketAddr)>>,
}
