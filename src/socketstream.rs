// use anyhow::Result;

use crate::addr::Addr;
// use crate::utils::{err_from, f_box};

// use async_tls::TlsConnector;
use tokio_tls::TlsStream;
// use std::io::{self, Read, Write};
// use std::io::{Error, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
// use std::str::FromStr;
use std::time::Duration;
// use tokio::runtime::Runtime;
use url::{Host, Url};

use futures::{future, Future};
// use tokio::io::{AsyncRead, AsyncWrite, read_exact, write_all};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
// use tokio_timer::Timeout;

// mod addr;
// mod utils;

//#[cfg(test)]
//mod tests;

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
    pub async fn connect(
        proxy: &'static str,
        target: &'static str,
    ) -> Result<SocksStream, Box<dyn std::error::Error>> {
        Self::handshake(proxy, target.parse()?, SocksAuth::new()).await
    }

    pub async fn connect_plain(
        proxy: &'static str,
        target: &'static str,
        username: &'static str,
        password: &'static str,
    ) -> Result<SocksStream, Box<dyn std::error::Error>> {
        Self::handshake(
            proxy,
            target.parse()?,
            SocksAuth::new_plain(username, password),
        )
        .await
    }

    // fn handshake(proxy: &'static str, target: Addr, auth: SocksAuth) -> io::Result<SocksStream> {

    async fn handshake(
        proxy: &'static str,
        target: Addr,
        auth: SocksAuth,
    ) -> Result<SocksStream, Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect(proxy).await?;
        // The initial greeting from the client
        //      field 1: SOCKS version, 1 byte (0x05 for this version)
        //      field 2: number of authentication methods supported, 1 byte
        //      field 3: authentication methods, variable length, 1 byte per method supported
        let auth_method = auth.method as u8;
        stream.write_all(&[SOCKS_VERSION, 1u8, auth_method]).await?;
        // The server's choice is communicated:
        //      field 1: SOCKS version, 1 byte (0x05 for this version)
        //      field 2: chosen authentication method, 1 byte, or 0xFF if no acceptable methods were offered
        let mut buf = [0u8, 1];
        stream.read_exact(&mut buf).await?;
        match buf[0] {
            SOCKS_VERSION => Ok(()),
            _ => Err("wrong server version"),
        }?;
        stream.read_exact(&mut buf).await?;
        match (buf[0] == auth.method as u8, buf[0]) {
            (true, 0u8) => Ok(()),
            (true, 2u8) => {
                // For username/password authentication the client's authentication request is
                //     field 1: version number, 1 byte (0x01 for current version of username/password authentication)
                let mut packet = vec![1u8];
                //     field 2: username length, 1 byte
                packet.push(auth.username.len() as u8);
                //     field 3: username, 1–255 bytes
                packet.append(&mut auth.username.clone());
                //     field 4: password length, 1 byte
                packet.push(auth.password.len() as u8);
                //     field 5: password, 1–255 bytes
                packet.append(&mut auth.password.clone());
                stream.write_all(&packet).await?;
                let mut buf = [0u8; 2];
                stream.read_exact(&mut buf).await?;
                // Server response for username/password authentication:
                //     field 1: version, 1 byte (0x01 for current version of username/password authentication)
                //     field 2: status code, 1 byte
                //         0x00: success
                //         any other value is a failure, connection must be closed
                match (buf[0] != 1u8, buf[1] != 0u8) {
                    (true, _) => Err("wrong auth version"),
                    (_, true) => Err("failure, connection must be closed"),
                    _ => Ok(()),
                }?;
                Ok(())
            }
            _ => Err("auth method not supported"),
        }?;
        let mut packet = Vec::new();
        // The client's connection request is
        //     field 1: SOCKS version number, 1 byte (0x05 for this version)
        packet.push(SOCKS_VERSION);
        //     field 2: command code, 1 byte:
        //         0x01: establish a TCP/IP stream connection
        //         0x02: establish a TCP/IP port binding
        //         0x03: associate a UDP port
        packet.push(Command::TcpStreamConnection as u8);
        //     field 3: reserved, must be 0x00, 1 byte
        packet.push(0u8);
        //     field 4: address type, 1 byte:
        //         0x01: IPv4 address
        //         0x03: Domain name
        //         0x04: IPv6 address
        //     field 5: destination address of
        //         4 bytes for IPv4 address
        //         1 byte of name length followed by 1–255 bytes the domain name
        //         16 bytes for IPv6 address
        //     field 6: port number in a network byte order, 2 bytes
        packet.append(&mut target.to_vec().unwrap());
        stream.write_all(&packet).await?;
        // Server response:
        //     field 1: SOCKS protocol version, 1 byte (0x05 for this version)
        stream.read_exact(&mut buf).await?;
        match buf[0] {
            SOCKS_VERSION => Ok(()),
            _ => Err("not supporter server version"),
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
        stream.read_exact(&mut buf).await?;
        match buf[0] {
            0 => Ok(()),
            1 => Err("general failure"),
            2 => Err("connection not allowed by ruleset"),
            3 => Err("network unreachable"),
            4 => Err("host unreachable"),
            5 => Err("connection refused by destination host"),
            6 => Err("TTL expired"),
            7 => Err("command not supported / protocol error"),
            8 => Err("address type not supported"),
            _ => Err("unknown error"),
        }?;
        //     field 3: reserved, must be 0x00, 1 byte
        stream.read_exact(&mut buf).await?;
        match buf[0] {
            0u8 => Ok(()),
            _ => Err("invalid reserved byte"),
        }?;
        //     field 4: address type, 1 byte:
        //         0x01: IPv4 address
        //         0x03: Domain name
        //         0x04: IPv6 address
        stream.read_exact(&mut buf).await?;
        //     field 5: server bound address of
        //         4 bytes for IPv4 address
        //         1 byte of name length followed by 1–255 bytes the domain name
        //         16 bytes for IPv6 address
        let host = match buf[0] {
            1u8 => {
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await?;
                Ok(Host::Ipv4(Ipv4Addr::from(buf)))
            }
            3u8 => {
                stream.read_exact(&mut buf).await?;
                let mut buf = vec![0u8; buf[0] as usize];
                stream.read_exact(&mut buf).await?;
                if let Ok(addr) = String::from_utf8(buf) {
                    Ok(Host::Domain(addr))
                } else {
                    Err("invalid address")
                }
            }
            4 => {
                let mut buf = [0u8; 16];
                stream.read_exact(&mut buf).await?;
                Ok(Host::Ipv6(Ipv6Addr::from(buf)))
            }
            _ => Err("invalid address type"),
        }?;
        //     field 6: server bound port number in a network byte order, 2 bytes
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        let port = ((buf[0] as u16) << 8) | (buf[1] as u16);
        // let timeout = Timeout::new(full_address, Duration::new(10, 0))
        //     .map_err(|_| err_from("handshake timeout"));
        // timeout

        // let stream = if target.is_ssl() {
        //     let builder =
        //         TlsConnector::new().map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
        //     Stream::Tls(Box::new(
        //         builder
        //             .connect(&target.host()?, socket)
        //             .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?,
        //     ))
        // } else {
        //     Stream::Tcp(socket)
        // };

        Ok(SocksStream {
            stream: Stream::Tcp(stream),
            target: target.clone(),
            bind_addr: host,
            bind_port: port,
        })
        // Ok(())
    }

    //     pub async fn write_all(&mut self, body: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    //         let mut s = self.stream.clone();
    //         match s {
    //             Stream::Tcp(stream) => Ok(stream.write_all(body).await?),
    //             _ => Ok(()),
    //         }
    //     }
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
