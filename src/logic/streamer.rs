use std::io::{self, Read, Write};
use std::collections::VecDeque;

pub trait PacketIO {
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn send(&mut self, buf: &[u8]) -> io::Result<usize>;
}

struct Fragment {
    offset: usize,
    contents: Vec<u8>,
}

pub struct Streamer<S: PacketIO> {
    read_cursor: usize,
    read_queue: VecDeque<Fragment>,
    write_cursor: usize,
    write_queue: VecDeque<Fragment>,
    packet_sock: S,
}

impl<S: PacketIO> Streamer<S> {
    pub fn new(packet_sock: S) -> Streamer<S> {
        Streamer {
            read_cursor: 0,
            read_queue: VecDeque::new(),
            write_cursor: 0,
            write_queue: VecDeque::new(),
            packet_sock: packet_sock,
        }
    }
}

impl<S: PacketIO> Read for Streamer<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut buf_cursor: usize = 0;

        while buf_cursor < buf.len() && !self.read_queue.is_empty() {
            let fragment_offset = self.read_queue.front().unwrap().offset;

            if fragment_offset > self.read_cursor {
                break;
            }

            // TODO: fragment_offset < self.read_cursor

            let mut fragment = self.read_queue.pop_front().unwrap();

            if fragment.contents.len() <= buf.len() - buf_cursor {
                let next_buf_cursor = buf_cursor + fragment.contents.len();

                buf[buf_cursor..next_buf_cursor].clone_from_slice(&fragment.contents);
            } else {
                let read_len = buf.len() - buf_cursor;

                buf[buf_cursor..].clone_from_slice(&fragment.contents[..read_len]);

                fragment.offset += read_len;
                fragment.contents.drain(..read_len);

                self.read_queue.push_front(fragment);
            }
        }

        // Blocking read
        let recv_ret = self.packet_sock.recv(&mut buf[buf_cursor..]);

        if let Ok(read_len) = recv_ret {
            Ok(buf_cursor + read_len)
        } else {
            if buf_cursor > 0 {
                let mut vbuf = Vec::with_capacity(buf_cursor);
                vbuf.extend_from_slice(&buf[..buf_cursor]);

                self.read_cursor -= buf_cursor;
                self.read_queue.push_front(Fragment {
                    offset: self.read_cursor,
                    contents: vbuf,
                });
            }

            recv_ret
        }
    }
}

impl<S: PacketIO> Write for Streamer<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut vbuf = Vec::with_capacity(buf.len());
        vbuf.extend_from_slice(buf);

        self.write_queue.push_back(Fragment {
            offset: self.write_cursor,
            contents: vbuf,
        });

        self.write_cursor += buf.len();

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        while !self.write_queue.is_empty() {
            let fragment_offset = self.write_queue.front().unwrap().offset;

            if fragment_offset > self.write_cursor {
                break;
            }

            // TODO: fragment_offset < self.write_cursor

            let mut fragment = self.write_queue.pop_front().unwrap();

            let send_ret = self.packet_sock.send(&fragment.contents);

            match send_ret {
                Ok(sent) => {
                    self.write_cursor += sent;

                    if sent < fragment.contents.len() {
                        fragment.offset += sent;
                        fragment.contents.drain(..sent);
                        self.write_queue.push_front(fragment);
                    }
                },
                Err(err) => {
                    self.write_queue.push_front(fragment);
                    return Err(err);
                },
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read, Write};
    use std::collections::VecDeque;
    use super::*;

    struct PacketIOMock {
        pub in_queue: VecDeque<Option<Vec<u8>>>,
        pub out_queue: VecDeque<Vec<u8>>,
    }

    impl PacketIOMock {
        fn new() -> PacketIOMock {
            PacketIOMock {
                in_queue: VecDeque::new(),
                out_queue: VecDeque::new(),
            }
        }
    }

    impl PacketIO for PacketIOMock {
        fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.in_queue.pop_front().map(|maybe_packet| {
                maybe_packet.map(|packet| {
                    buf[..packet.len()].copy_from_slice(&packet);
                    packet.len()
                }).ok_or(io::Error::new(io::ErrorKind::Other, "Mock error"))
            }).unwrap_or(Err(io::Error::new(io::ErrorKind::Other, "in_queue empty!")))
        }

        fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut vbuf = Vec::with_capacity(buf.len());
            vbuf.extend_from_slice(buf);

            self.out_queue.push_back(vbuf);
            Ok(buf.len())
        }
    }

    #[test]
    fn can_read_a_packet_from_mock() {
        let mut mock_sock = PacketIOMock::new();
        let mut buf = [0u8; 1024];
        let msg: Vec<u8> = "Hello world".bytes().collect();

        mock_sock.in_queue.push_back(Some(msg.clone()));
        let mut streamer = Streamer::new(mock_sock);

        let read = streamer.read(&mut buf).unwrap();

        assert_eq!(&buf[..read], &msg[..]);
    }
}
