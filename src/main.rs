#![feature(await_macro, async_await, futures_api)]

#[macro_use]
extern crate tokio;

use native_tls::{TlsConnector, TlsStream};
// use std::io::{self, Read, Write};
use std::io::{self, Error, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::str::FromStr;
use url::{Host, Url};

// use futures::{Future};
use tokio::net::TcpStream;
use tokio::prelude::*;
// use tokio::io::{read_exact, write_all};

#[cfg(test)]
mod tests;

const SOCKS_VERSION: u8 = 5u8;

enum Command {
    TcpStreamConnection = 1,
    // TcpPortBinding = 2,
    // UdpPort = 3,
}

#[derive(Debug, Clone)]
struct Addr {
    url: Url,
}

impl FromStr for Addr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = if s.starts_with("http") {
            Url::parse(&s).map_err(|e| Error::new(ErrorKind::InvalidInput, e.to_string()))?
        } else {
            let mut raw = String::from(s);
            if s.ends_with(":443") || s.contains(":443/") {
                raw.insert_str(0, "https://");
            } else {
                raw.insert_str(0, "http://");
            }
            Url::parse(&raw).map_err(|e| Error::new(ErrorKind::InvalidInput, e.to_string()))?
        };
        Ok(Addr { url })
    }
}

impl Addr {
    fn is_ssl(&self) -> bool {
        self.url.scheme() == "https"
    }

    fn addr_type(&self) -> io::Result<u8> {
        match self.url.host() {
            Some(Host::Ipv4(_)) => Ok(1u8),
            Some(Host::Ipv6(_)) => Ok(4u8),
            Some(Host::Domain(_)) => Ok(3u8),
            _ => Err(Error::new(ErrorKind::InvalidData, "address host type")),
        }
    }

    fn host(&self) -> io::Result<String> {
        match self.url.host() {
            Some(Host::Ipv4(ipv4)) => Ok(ipv4.to_string()),
            Some(Host::Ipv6(ipv6)) => Ok(ipv6.to_string()),
            Some(Host::Domain(domain)) => Ok(domain.to_string()),
            None => Err(Error::new(ErrorKind::InvalidData, "unknown host type")),
        }
    }

    fn host_vec(&self) -> io::Result<Vec<u8>> {
        match self.url.host() {
            Some(Host::Ipv4(ipv4)) => Ok(ipv4.octets().to_vec()),
            Some(Host::Ipv6(ipv6)) => Ok(ipv6.octets().to_vec()),
            Some(Host::Domain(domain)) => Ok(domain.as_bytes().to_vec()),
            None => Err(Error::new(ErrorKind::InvalidInput, "unknown host type")),
        }
    }

    fn port(&self) -> Vec<u8> {
        match self.url.port_or_known_default() {
            Some(port) => vec![((port >> 8) & 0xff) as u8, (port & 0xff) as u8],
            None => vec![0u8, 80u8],
        }
    }

    fn to_vec(&self) -> io::Result<Vec<u8>> {
        let mut vec = Vec::new();
        vec.push(self.addr_type()?);
        match self.url.host() {
            Some(Host::Ipv4(_)) => vec.append(&mut self.host_vec()?),
            Some(Host::Ipv6(_)) => vec.append(&mut self.host_vec()?),
            Some(Host::Domain(_)) => {
                let mut addr = self.host_vec()?;
                vec.push(addr.len() as u8);
                vec.append(&mut addr);
            }
            None => (),
        }
        vec.append(&mut self.port());
        Ok(vec)
    }

    fn path(&self) -> String {
        self.url.path().to_string()
    }
}

#[derive(Clone, Copy)]
enum AuthMethod {
    NoAuth = 0,
    // GSSAPI = 1,
    Plain = 2,
    // CHAP = 3,
    // CRAM = 5,
    // SSL = 6,
    // Unassigned = 7,
    // Reserved = 128,
    // NoAcceptable = 255,
}

struct SocksAuth {
    method: AuthMethod,
    username: Vec<u8>,
    password: Vec<u8>,
}

impl SocksAuth {
    pub fn new_plain(username: &str, password: &str) -> Self {
        SocksAuth {
            method: AuthMethod::Plain,
            username: username.as_bytes().to_vec(),
            password: password.as_bytes().to_vec(),
        }
    }

    pub fn new() -> Self {
        SocksAuth {
            method: AuthMethod::NoAuth,
            username: Vec::new(),
            password: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub enum Stream {
    Tcp(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

#[derive(Debug)]
pub struct SocksStream {
    stream: Stream,
    target: Addr,
    bind_addr: Host,
    bind_port: u16,
}

impl SocksStream {
    pub async fn connect(proxy: &'static str, target: &'static str) -> io::Result<SocksStream> {
        await!(Self::handshake(proxy, target.parse()?, SocksAuth::new()))
    }

    pub async fn connect_plain(
        proxy: &'static str,
        target: &'static str,
        username: &'static str,
        password: &'static str,
    ) -> io::Result<SocksStream> {
        await!(Self::handshake(
            proxy,
            target.parse()?,
            SocksAuth::new_plain(username, password),
        ))
    }

    async fn handshake(proxy: &'static str, target: Addr, auth: SocksAuth) -> io::Result<SocksStream> {
        let addr = proxy.to_socket_addrs()?.next().ok_or(Error::new(ErrorKind::Interrupted, "wrong server version"))?;
        let mut stream = await!(TcpStream::connect(&addr))?;
        // The initial greeting from the client
        //      field 1: SOCKS version, 1 byte (0x05 for this version)
        //      field 2: number of authentication methods supported, 1 byte
        //      field 3: authentication methods, variable length, 1 byte per method supported
        await!(stream.write_all_async(&[SOCKS_VERSION, 1u8, auth.method as u8]))?;
        // The server's choice is communicated:
        //      field 1: SOCKS version, 1 byte (0x05 for this version)
        let mut buf = [0u8];
        await!(stream.read_exact_async(&mut buf));
        match buf[0] {
            SOCKS_VERSION => Ok(()),
            _ => Err(Error::new(ErrorKind::Interrupted, "wrong server version"))
        }?;
        //      field 2: chosen authentication method, 1 byte, or 0xFF if no acceptable methods were offered
        await!(stream.read_exact_async(&mut buf));
        match buf[0] == auth.method as u8 {
            true if buf[0] == AuthMethod::Plain as u8 => {
                //     field 2: username length, 1 byte
                //     field 3: username, 1–255 bytes
                //     field 4: password length, 1 byte
                //     field 5: password, 1–255 bytes
                let mut packet = vec![auth.username.len() as u8];
                packet.append(&mut auth.username.clone());
                packet.push(auth.password.len() as u8);
                packet.append(&mut auth.password.clone());
                await!(stream.write_all_async(&packet));
                // Server response for username/password authentication:
                //     field 1: version, 1 byte (0x01 for current version of username/password authentication)
                //     field 2: status code, 1 byte
                //         0x00: success
                //         any other value is a failure, connection must be closed
                let mut buf = [0u8; 2];
                await!(stream.read_exact_async(&mut buf));
                match (buf[0] != 1u8, buf[1] != 0u8) {
                    (true, _) => Err(Error::new(ErrorKind::Interrupted, "wrong auth version")),
                    (_, true) => Err(Error::new(ErrorKind::Interrupted, "failure, connection must be closed")),
                    _ => Ok(())
                }?
            },
            true => (),
            _ => return Err(Error::new(ErrorKind::Interrupted, "auth method not supported"))
        }
        // The client's connection request is
        //     field 1: SOCKS version number, 1 byte (0x05 for this version)
        //     field 2: command code, 1 byte:
        //         0x01: establish a TCP/IP stream connection
        //         0x02: establish a TCP/IP port binding
        //         0x03: associate a UDP port
        //     field 3: reserved, must be 0x00, 1 byte
        //     field 4: address type, 1 byte:
        //         0x01: IPv4 address
        //         0x03: Domain name
        //         0x04: IPv6 address
        //     field 5: destination address of
        //         4 bytes for IPv4 address
        //         1 byte of name length followed by 1–255 bytes the domain name
        //         16 bytes for IPv6 address
        //     field 6: port number in a network byte order, 2 bytes
        let mut packet = vec![SOCKS_VERSION, Command::TcpStreamConnection as u8, 0u8];
        packet.append(&mut target.to_vec()?);
        await!(stream.write_all_async(&packet));
        // Server response:
        //     field 1: SOCKS protocol version, 1 byte (0x05 for this version)
        await!(stream.read_exact_async(&mut buf));
        match buf[0] {
            SOCKS_VERSION => Ok(()),
            _ => Err(Error::new(ErrorKind::Interrupted, "not supporter server version"))
        }?;
        //     field 2: status, 1 byte:
        //         0x00: request granted
        //         0x01: general failure
        //         0x02: connection not allowed by ruleset
        //         0x03: network unreachable
        //         0x04: host unreachable
        //         0x05: connection refused by destination host
        //         0x06: TTL expired
        //         0x07: command not supported / protocol error
        //         0x08: address type not supported
        await!(stream.read_exact_async(&mut buf));
        match buf[0] {
            0 => Ok(()),
            1 => Err(Error::new(ErrorKind::Interrupted, "general failure")),
            2 => Err(Error::new(
                ErrorKind::Interrupted,
                "connection not allowed by ruleset",
            )),
            3 => Err(Error::new(ErrorKind::Interrupted, "network unreachable")),
            4 => Err(Error::new(ErrorKind::Interrupted, "host unreachable")),
            5 => Err(Error::new(
                ErrorKind::Interrupted,
                "connection refused by destination host",
            )),
            6 => Err(Error::new(ErrorKind::Interrupted, "TTL expired")),
            7 => Err(Error::new(
                ErrorKind::Interrupted,
                "command not supported / protocol error",
            )),
            8 => Err(Error::new(
                ErrorKind::Interrupted,
                "address type not supported",
            )),
            _ => Err(Error::new(ErrorKind::Other, "unknown error")),
        }?;
        //     field 3: reserved, must be 0x00, 1 byte
        await!(stream.read_exact_async(&mut buf));
        match buf[0] {
            0u8 => Ok(()),
            _ => Err(Error::new(ErrorKind::Interrupted, "invalid reserved byte"))
        }?;
        //     field 4: address type, 1 byte:
        //         0x01: IPv4 address
        //         0x03: Domain name
        //         0x04: IPv6 address
        await!(stream.read_exact_async(&mut buf));
        //     field 5: server bound address of
        //         4 bytes for IPv4 address
        //         1 byte of name length followed by 1–255 bytes the domain name
        //         16 bytes for IPv6 address
        let bind_addr = match buf[0] {
            1 => {
                let mut buf = [0u8; 4];
                await!(stream.read_exact_async(&mut buf));
                Ok(Host::Ipv4(Ipv4Addr::from(buf)))
            },
            3 => {
                await!(stream.read_exact_async(&mut buf));
                let mut buf = vec![0u8; buf[0] as usize];
                await!(stream.read_exact_async(&mut buf));
                if let Ok(addr) = String::from_utf8(buf) {
                        Ok(Host::Domain(addr))
                    } else {
                        Err(Error::new(ErrorKind::Other, "invalid address"))
                    }
            },
            4 => {
                let mut buf = [0u8; 16];
                await!(stream.read_exact_async(&mut buf));
                    Ok(Host::Ipv6(Ipv6Addr::from(buf)))
            },
            _ => Err(Error::new(ErrorKind::Other, "invalid address type"))
        }?;
        let mut buf = [0u8; 2];
        await!(stream.read_exact_async(&mut buf));
                    let bind_port = ((buf[16] as u16) << 8) | (buf[17] as u16);
        let stream = if target.is_ssl() {
            let builder =
                TlsConnector::new().map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
            Stream::Tls(Box::new(
                builder
                    .connect(&target.host()?, stream)
                    .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?,
            ))
        } else {
            Stream::Tcp(stream)
        };

        Ok(SocksStream {
            stream,
            target: target.clone(),
            bind_addr,
            bind_port
        })
    }
}

pub async fn get(proxy: &'static str, target: &'static str) -> io::Result<Vec<u8>> {
    let mut stream = await!(SocksStream::connect(proxy, target))?;
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\n\r\n",
        stream.target.path(),
        stream.target.host()?
    )
    .into_bytes();
    stream.write_all(&request)?;
    let mut response = vec![];
    stream.read_to_end(&mut response)?;
    let pos = response
        .windows(4)
        .position(|x| x == b"\r\n\r\n")
        .ok_or_else(|| Error::new(ErrorKind::Other, "wrong http"))?;
    let body = &response[pos + 4..response.len()];
    Ok(body.to_vec())
}

pub async fn post_json(proxy: &'static str, target: &'static str, body: &'static str) -> io::Result<Vec<u8>> {
    let mut stream = await!(SocksStream::connect(proxy, target))?;
    let body = if !body.is_empty() {
        format!("Content-Length: {}\r\n\r\n{}", body.len(), body)
    } else {
        String::new()
    };
    let request = format!(
        "POST {} HTTP/1.0\r\nHost: {}\r\nContent-Type: application/json\r\n{}\r\n",
        stream.target.path(),
        stream.target.host()?,
        body
    )
    .into_bytes();
    stream.write_all(&request)?;
    let mut response = vec![];
    stream.read_to_end(&mut response)?;
    let pos = response
        .windows(4)
        .position(|x| x == b"\r\n\r\n")
        .ok_or_else(|| Error::new(ErrorKind::Other, "wrong http"))?;
    let body = &response[pos + 4..response.len()];
    Ok(body.to_vec())
}

fn main() {
    println!("Hello, world!");
}

// let addr = proxy.to_socket_addrs()?.next().ok_or(Error::new(ErrorKind::Interrupted, "wrong server version"))?;
//         let mut stream = await!(TcpStream::connect(&addr))?;
//         // The initial greeting from the client
//         //      field 1: SOCKS version, 1 byte (0x05 for this version)
//         //      field 2: number of authentication methods supported, 1 byte
//         //      field 3: authentication methods, variable length, 1 byte per method supported
//         let greeting = write_all(conn, &[SOCKS_VERSION, 1u8, auth.method as u8]);
//         // The server's choice is communicated:
//         //      field 1: SOCKS version, 1 byte (0x05 for this version)
//         let version = greeting.and_then(|(conn, _)| read_exact(conn, [0u8; 1])).and_then(|(conn, buf)| {
//             match buf[0] {
//                 SOCKS_VERSION => Ok((conn, buf)),
//                 _ => Err(Error::new(ErrorKind::Interrupted, "wrong server version"))
//             }
//         });
//         //      field 2: chosen authentication method, 1 byte, or 0xFF if no acceptable methods were offered
//         let check_auth = version.and_then(|(conn, buf)| read_exact(conn, [0u8; 1])).and_then(|(conn, buf)| {
//             match buf[0] {
//                 (AuthMethod::Plain) as u8 => {
//                     // let mut packet = vec![1u8];
//                     //     field 2: username length, 1 byte
//                     //     field 3: username, 1–255 bytes
//                     //     field 4: password length, 1 byte
//                     //     field 5: password, 1–255 bytes
//                     write_all(version, &vec![1u8, auth.username.clone(), auth.password.len() as u8, auth.password.clone()]).and_then(|(conn, _)| read_exact(conn, [0u8; 2])).and_then(|(conn, buf)| {
//                     // Server response for username/password authentication:
//                     //     field 1: version, 1 byte (0x01 for current version of username/password authentication)
//                     //     field 2: status code, 1 byte
//                     //         0x00: success
//                     //         any other value is a failure, connection must be closed
//                         match (buf[0] != 1u8, buf[1] != 0u8) {
//                             (true, _) => Err(Error::new(ErrorKind::Interrupted, "wrong auth version")),
//                             (_, true) => Err(Error::new(ErrorKind::Interrupted, "failure, connection must be closed")),
//                             _ => Ok((conn, buf))
//                         }
//                     })
//                 },
//                 (auth.method) as u8 => Ok((conn, buf)),
//                 _ => Err(Error::new(ErrorKind::Interrupted, "auth method not supported",))
//             }
//         });
//         // The client's connection request is
//         //     field 1: SOCKS version number, 1 byte (0x05 for this version)
//         //     field 2: command code, 1 byte:
//         //         0x01: establish a TCP/IP stream connection
//         //         0x02: establish a TCP/IP port binding
//         //         0x03: associate a UDP port
//         //     field 3: reserved, must be 0x00, 1 byte
//         //     field 4: address type, 1 byte:
//         //         0x01: IPv4 address
//         //         0x03: Domain name
//         //         0x04: IPv6 address
//         //     field 5: destination address of
//         //         4 bytes for IPv4 address
//         //         1 byte of name length followed by 1–255 bytes the domain name
//         //         16 bytes for IPv6 address
//         //     field 6: port number in a network byte order, 2 bytes
//         let request = check_auth.and_then(|(conn, _)| write_all(check_auth, vec![SOCKS_VERSION, Command::TcpStreamConnection as u8, 0u8, target.to_vec()?]));
//         // Server response:
//         //     field 1: SOCKS protocol version, 1 byte (0x05 for this version)
//         let version = request.and_then(|(conn, _)| read_exact(conn, [0u8])).and_then(|conn, buf| {
//             match buf[0] {
//                 SOCKS_VERSION => Ok((conn, buf)),
//                 _ => Err(Error::new(ErrorKind::Interrupted, "not supporter server version"))
//             }
//         });
//         //     field 2: status, 1 byte:
//         //         0x00: request granted
//         //         0x01: general failure
//         //         0x02: connection not allowed by ruleset
//         //         0x03: network unreachable
//         //         0x04: host unreachable
//         //         0x05: connection refused by destination host
//         //         0x06: TTL expired
//         //         0x07: command not supported / protocol error
//         //         0x08: address type not supported
//         let status = version.and_then(|(conn, _)| read_exact(conn, [0u8])).and_then(|conn, buf| {
//             match buf[0] {
//                 0 => Ok((conn, buf)),
//                 1 => Err(Error::new(ErrorKind::Interrupted, "general failure")),
//                 2 => Err(Error::new(
//                     ErrorKind::Interrupted,
//                     "connection not allowed by ruleset",
//                 )),
//                 3 => Err(Error::new(ErrorKind::Interrupted, "network unreachable")),
//                 4 => Err(Error::new(ErrorKind::Interrupted, "host unreachable")),
//                 5 => Err(Error::new(
//                     ErrorKind::Interrupted,
//                     "connection refused by destination host",
//                 )),
//                 6 => Err(Error::new(ErrorKind::Interrupted, "TTL expired")),
//                 7 => Err(Error::new(
//                     ErrorKind::Interrupted,
//                     "command not supported / protocol error",
//                 )),
//                 8 => Err(Error::new(
//                     ErrorKind::Interrupted,
//                     "address type not supported",
//                 )),
//                 _ => Err(Error::new(ErrorKind::Other, "unknown error")),
//             }
//         });
//         //     field 3: reserved, must be 0x00, 1 byte
//         let reverved = status.and_then(|(conn, _)| read_exact(conn, [0u8])).and_then(|conn, buf| {
//             match buf[0] {
//                 0u8 => Ok((conn, buf)),
//                 _ => Err(Error::new(ErrorKind::Interrupted, "invalid reserved byte"))
//             }
//         });
//         //     field 4: address type, 1 byte:
//         //         0x01: IPv4 address
//         //         0x03: Domain name
//         //         0x04: IPv6 address
//         let addr_type = reverved.and_then(|(conn, _)| read_exact(conn, [0u8]));
//         //     field 5: server bound address of
//         //         4 bytes for IPv4 address
//         //         1 byte of name length followed by 1–255 bytes the domain name
//         //         16 bytes for IPv6 address
//         let address = addr_type.and_then(|(conn, buf)| {
//             match buf[0] {
//                 1 => {
//                     conn.and_then(|(conn, _)| read_exact(conn, [0u8; 6]).and_then(|(conn, buf)| {
//                         let addr = Host::Ipv4(Ipv4Addr::from(&buf[0..4]));
//                         let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
//                         Ok((conn, addr, port))
//                     }))
//                 },
//                 3 => {
//                     conn.and_then(|(conn, _)| read_exact(conn, [0u8]).and_then(|(conn, buf)| read_exact(conn, vec![0u8; buf[0] as usize + 2])
//                         .and_then(|(conn, buf)| {
//                             let addr = &buf[..buf.len() - 2];
//                         let addr = if let Ok(addr) = str::from_utf8(addr) {
//                             Host::Domain(addr)
//                         } else {
//                             return Err(Error::new(ErrorKind::Other, "invalid address"));
//                         };
//                         let port = ((buf[buf.len() - 2] as u16) << 8) | (buf[buf.len() - 1] as u16);
//                         Ok((conn, addr, port))
//                     }))) 
//                 },
//                 4 => {
//                     conn.and_then(|(conn, _)| read_exact(conn, [0u8; 18]).and_then(|(conn, buf)| {
//                         let addr = Host::Ipv6(Ipv6Addr::from(&buf[0..16]));
//                         let port = ((buf[16] as u16) << 8) | (buf[17] as u16);
//                         Ok((conn, addr, port))
//                     })) 
//                 }
//                 _ => Err(Error::new(ErrorKind::Other, "invalid address type")),
//             }
//         });
//         let stream = if target.is_ssl() {
//             let builder =
//                 TlsConnector::new().map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
//             Stream::Tls(Box::new(
//                 builder
//                     .connect(&target.host()?, socket)
//                     .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?,
//             ))
//         } else {
//             Stream::Tcp(socket)
//         };

//         Ok(SocksStream {
//             stream,
//             target: target.clone(),
//             bind_addr,
//             bind_port
//         })