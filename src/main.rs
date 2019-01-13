#![allow(dead_code)]

use crate::addr::Addr;
use crate::utils::{err_from, f_box};

use native_tls::{TlsConnector, TlsStream};
// use std::io::{self, Read, Write};
use std::io::{self, Error, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::str::FromStr;
use url::{Host, Url};

use futures::{future, Future};
use tokio::io::{read_exact, write_all};
use tokio::net::TcpStream;

mod addr;
mod utils;

#[cfg(test)]
mod tests;

const SOCKS_VERSION: u8 = 5u8;

enum Command {
    TcpStreamConnection = 1,
}

#[derive(Clone, Copy)]
enum AuthMethod {
    NoAuth = 0,
    Plain = 2,
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
    // pub async fn connect(proxy: &'static str, target: &'static str) -> io::Result<SocksStream> {
    //     await!(Self::handshake(proxy, target.parse()?, SocksAuth::new()))
    // }

    // pub async fn connect_plain(
    //     proxy: &'static str,
    //     target: &'static str,
    //     username: &'static str,
    //     password: &'static str,
    // ) -> io::Result<SocksStream> {
    //     await!(Self::handshake(
    //         proxy,
    //         target.parse()?,
    //         SocksAuth::new_plain(username, password),
    //     ))
    // }

    // fn handshake(proxy: &'static str, target: Addr, auth: SocksAuth) -> io::Result<SocksStream> {

    fn handshake_no_auth(
        conn: TcpStream,
    ) -> impl Future<Item = (TcpStream, Host, u16), Error = io::Error> + Send {
        let greeteng = write_all(conn, &[SOCKS_VERSION, 1u8, AuthMethod::NoAuth as u8]);
        let version = greeteng.and_then(|(conn, _buf)| {
            read_exact(conn, [0u8]).and_then(|(conn, buf)| match buf[0] {
                SOCKS_VERSION => Ok((conn, buf)),
                _ => Err(err_from("wrong server version")),
            })
        });
        let method = version.and_then(|(conn, _buf)| {
            read_exact(conn, [0u8]).and_then(|(conn, buf)| match buf[0] {
                0u8 => Ok((conn, buf)),
                _ => Err(err_from("wrong auth method")),
            })
        });

        let send_command = method.and_then(|(conn, _buf)| {
            write_all(
                conn,
                [SOCKS_VERSION, Command::TcpStreamConnection as u8, 0u8],
            )
        });
        let version = send_command.and_then(|(conn, _buf)| {
            read_exact(conn, [0u8]).and_then(|(conn, buf)| match buf[0] {
                SOCKS_VERSION => Ok((conn, buf)),
                _ => Err(err_from("not supporter server version")),
            })
        });
        let status = version.and_then(|(conn, _buf)| {
            read_exact(conn, [0u8]).and_then(|(conn, buf)| match buf[0] {
                0 => Ok((conn, buf)),
                1 => Err(err_from("general failure")),
                2 => Err(err_from("connection not allowed by ruleset")),
                3 => Err(err_from("network unreachable")),
                4 => Err(err_from("host unreachable")),
                5 => Err(err_from("connection refused by destination host")),
                6 => Err(err_from("TTL expired")),
                7 => Err(err_from("command not supported / protocol error")),
                8 => Err(err_from("address type not supported")),
                _ => Err(err_from("unknown error")),
            })
        });
        let reserved = status.and_then(|(conn, _buf)| {
            read_exact(conn, [0u8]).and_then(|(conn, buf)| match buf[0] {
                0u8 => Ok((conn, buf)),
                _ => Err(err_from("invalid reserved byte")),
            })
        });
        let address_type = reserved.and_then(|(conn, _buf)| read_exact(conn, [0u8]));
        let address = address_type.and_then(|(conn, buf)| match buf[0] {
            1u8 => f_box(read_exact(conn, [0u8; 4]).and_then(|(conn, buf)| {
                f_box(future::ok((conn, Host::Ipv4(Ipv4Addr::from(buf)))))
            })),
            3u8 => f_box(read_exact(conn, [0u8])
                .and_then(|(conn, buf)| read_exact(conn, vec![0u8; buf[0] as usize])
                .and_then(|(conn, buf)| 
                    if let Ok(addr) = String::from_utf8(buf) {
                        f_box(future::ok((conn, Host::Domain(addr))))
                    } else {
                        f_box(future::err(err_from("invalid address")))
                    }
                ))),
            4 => f_box(read_exact(conn, [0u8; 16])
                .and_then(|(conn, buf)| f_box(future::ok((conn, Host::Ipv6(Ipv6Addr::from(buf))))))),
            _ => f_box(future::err(err_from("invalid address type"))),
        });
        let full_address = address.and_then(|(conn, addr)| {
            read_exact(conn, [0u8; 2]).and_then(|(conn, buf)| {
                let port = ((buf[0] as u16) << 8) | (buf[1] as u16);
                f_box(future::ok((conn, addr, port)))
            })
        });
        full_address
        // let mut buf = [0u8; 2];
        // await!(stream.read_exact_async(&mut buf));
        // let bind_port = ((buf[16] as u16) << 8) | (buf[17] as u16);
        // let stream = if target.is_ssl() {
        //     let builder =
        //         TlsConnector::new().map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
        //     Stream::Tls(Box::new(
        //         builder
        //             .connect(&target.host()?, stream)
        //             .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?,
        //     ))
        // } else {
        //     Stream::Tcp(stream)
        // };

        // Ok(SocksStream {
        //     stream,
        //     target: target.clone(),
        //     bind_addr,
        //     bind_port,
        // })
    }
}

// pub async fn get(proxy: &'static str, target: &'static str) -> io::Result<Vec<u8>> {
//     let mut stream = await!(SocksStream::connect(proxy, target))?;
//     let request = format!(
//         "GET {} HTTP/1.0\r\nHost: {}\r\n\r\n",
//         stream.target.path(),
//         stream.target.host()?
//     )
//     .into_bytes();
//     stream.write_all(&request)?;
//     let mut response = vec![];
//     stream.read_to_end(&mut response)?;
//     let pos = response
//         .windows(4)
//         .position(|x| x == b"\r\n\r\n")
//         .ok_or_else(|| Error::new(ErrorKind::Other, "wrong http"))?;
//     let body = &response[pos + 4..response.len()];
//     Ok(body.to_vec())
// }

// pub async fn post_json(
//     proxy: &'static str,
//     target: &'static str,
//     body: &'static str,
// ) -> io::Result<Vec<u8>> {
//     let mut stream = await!(SocksStream::connect(proxy, target))?;
//     let body = if !body.is_empty() {
//         format!("Content-Length: {}\r\n\r\n{}", body.len(), body)
//     } else {
//         String::new()
//     };
//     let request = format!(
//         "POST {} HTTP/1.0\r\nHost: {}\r\nContent-Type: application/json\r\n{}\r\n",
//         stream.target.path(),
//         stream.target.host()?,
//         body
//     )
//     .into_bytes();
//     stream.write_all(&request)?;
//     let mut response = vec![];
//     stream.read_to_end(&mut response)?;
//     let pos = response
//         .windows(4)
//         .position(|x| x == b"\r\n\r\n")
//         .ok_or_else(|| Error::new(ErrorKind::Other, "wrong http"))?;
//     let body = &response[pos + 4..response.len()];
//     Ok(body.to_vec())
// }

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
