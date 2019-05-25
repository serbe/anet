// use crate::addr::Addr;
//use crate::utils::{err_from, f_box};
use crate::errors::Error;

use std::{
    convert::From,
    fmt::{self, Debug, Formatter},
    io::{self, Cursor, Read, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs},
    u8, vec,
};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use bytes::{BufMut, Bytes, BytesMut, IntoBuf};
use futures::{try_ready, Async, Future, Poll};
//use log::error;
use tokio_io::{io::read_exact, try_nb, AsyncRead, AsyncWrite};

use super::utils::{write_bytes, WriteBytes};

mod consts {
    pub const SOCKS5_VERSION: u8 = 0x05;

    // pub const SOCKS5_AUTH_METHOD_NONE: u8 = 0x00;
    // pub const SOCKS5_AUTH_METHOD_GSSAPI: u8 = 0x01;
    // pub const SOCKS5_AUTH_METHOD_PASSWORD: u8 = 0x02;
    // pub const SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE: u8 = 0xff;

    // pub const SOCKS5_CMD_TCP_CONNECT: u8 = 0x01;
    // pub const SOCKS5_CMD_TCP_BIND: u8 = 0x02;
    // pub const SOCKS5_CMD_UDP_ASSOCIATE: u8 = 0x03;

    // pub const SOCKS5_ADDR_TYPE_IPV4: u8 = 0x01;
    // pub const SOCKS5_ADDR_TYPE_DOMAIN_NAME: u8 = 0x03;
    // pub const SOCKS5_ADDR_TYPE_IPV6: u8 = 0x04;
}

#[derive(Clone, Debug, Copy)]
pub enum Command {
    TcpConnect,
    TcpBind,
    UdpAssociate,
}

impl Command {
    fn as_u8(self) -> u8 {
        match self {
            Command::TcpConnect => 1u8,
            Command::TcpBind => 2u8,
            Command::UdpAssociate => 3u8,
        }
    }

    fn from_u8(code: u8) -> Option<Command> {
        match code {
            1u8 => Some(Command::TcpConnect),
            2u8 => Some(Command::TcpBind),
            3u8 => Some(Command::UdpAssociate),
            _ => None,
        }
    }
}

enum AddressType {
    IPv4,
    DomainName,
    IPv6,
}

impl AddressType {
    fn as_u8(self) -> u8 {
        match self {
            AddressType::IPv4 => 1u8,
            AddressType::DomainName => 3u8,
            AddressType::IPv6 => 4u8,
        }
    }

    fn from_u8(code: u8) -> Option<AddressType> {
        match code {
            1u8 => Some(AddressType::IPv4),
            3u8 => Some(AddressType::DomainName),
            4u8 => Some(AddressType::IPv6),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Copy)]
pub enum Reply {
    Succeeded,
    GeneralFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    OtherReply(u8),
}

impl Reply {
    fn as_u8(self) -> u8 {
        match self {
            Reply::Succeeded => 0u8,
            Reply::GeneralFailure => 1u8,
            Reply::ConnectionNotAllowed => 2u8,
            Reply::NetworkUnreachable => 3u8,
            Reply::HostUnreachable => 4u8,
            Reply::ConnectionRefused => 5u8,
            Reply::TtlExpired => 6u8,
            Reply::CommandNotSupported => 7u8,
            Reply::AddressTypeNotSupported => 8u8,
            Reply::OtherReply(code) => code,
        }
    }

    fn from_u8(code: u8) -> Reply {
        match code {
            0u8 => Reply::Succeeded,
            1u8 => Reply::GeneralFailure,
            2u8 => Reply::ConnectionNotAllowed,
            3u8 => Reply::NetworkUnreachable,
            4u8 => Reply::HostUnreachable,
            5u8 => Reply::ConnectionRefused,
            6u8 => Reply::TtlExpired,
            7u8 => Reply::CommandNotSupported,
            8u8 => Reply::AddressTypeNotSupported,
            _ => Reply::OtherReply(code),
        }
    }
}

impl fmt::Display for Reply {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Reply::Succeeded => write!(f, "Succeeded"),
            Reply::GeneralFailure => write!(f, "General SOCKS server failure"),
            Reply::ConnectionNotAllowed => write!(f, "Connection not allowed by ruleset"),
            Reply::NetworkUnreachable => write!(f, "Network unreachable"),
            Reply::HostUnreachable => write!(f, "Host unreachable"),
            Reply::ConnectionRefused => write!(f, "Connection refused"),
            Reply::TtlExpired => write!(f, "TTL expired"),
            Reply::CommandNotSupported => write!(f, "Command not supported"),
            Reply::AddressTypeNotSupported => write!(f, "Address type not supported"),
            Reply::OtherReply(code) => write!(f, "Other reply ({})", code),
        }
    }
}

/// SOCKS5 address type
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Address {
    /// Socket address (IP Address)
    SocketAddress(SocketAddr),
    /// Domain name address
    DomainNameAddress(String, u16),
}

impl Address {
    #[inline]
    pub fn read_from<R: AsyncRead>(stream: R) -> ReadAddress<R> {
        ReadAddress::new(stream)
    }

    /// Writes to writer
    #[inline]
    pub fn write_to<W: AsyncWrite>(self, writer: W) -> WriteBytes<W, Bytes> {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        write_bytes(writer, buf.freeze())
    }

    /// Writes to buffer
    #[inline]
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        write_address(self, buf)
    }

    #[inline]
    pub fn serialized_len(&self) -> usize {
        get_addr_len(self)
    }
}

impl Debug for Address {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Address::SocketAddress(ref addr) => write!(f, "{}", addr),
            Address::DomainNameAddress(ref addr, ref port) => write!(f, "{}:{}", addr, port),
        }
    }
}

impl fmt::Display for Address {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Address::SocketAddress(ref addr) => write!(f, "{}", addr),
            Address::DomainNameAddress(ref addr, ref port) => write!(f, "{}:{}", addr, port),
        }
    }
}

impl ToSocketAddrs for Address {
    type Iter = vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> io::Result<vec::IntoIter<SocketAddr>> {
        match self.clone() {
            Address::SocketAddress(addr) => Ok(vec![addr].into_iter()),
            Address::DomainNameAddress(addr, port) => (&addr[..], port).to_socket_addrs(),
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(s: SocketAddr) -> Address {
        Address::SocketAddress(s)
    }
}

impl From<(String, u16)> for Address {
    fn from((dn, port): (String, u16)) -> Address {
        Address::DomainNameAddress(dn, port)
    }
}

pub struct ReadAddress<R>
where
    R: AsyncRead,
{
    reader: Option<R>,
    state: ReadAddressState,
    buf: Option<BytesMut>,
    already_read: usize,
}

enum ReadAddressState {
    Type,
    Ipv4,
    Ipv6,
    DomainNameLength,
    DomainName,
}

impl<R> Future for ReadAddress<R>
where
    R: AsyncRead,
{
    type Error = Error;
    type Item = (R, Address);

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        debug_assert!(self.reader.is_some());

        loop {
            match self.state {
                ReadAddressState::Type => {
                    try_ready!(self.read_addr_type());
                }
                ReadAddressState::Ipv4 => {
                    let addr = try_ready!(self.read_ipv4());
                    let reader = self.reader.take().unwrap();
                    return Ok((reader, addr).into());
                }
                ReadAddressState::Ipv6 => {
                    let addr = try_ready!(self.read_ipv6());
                    let reader = self.reader.take().unwrap();
                    return Ok((reader, addr).into());
                }
                ReadAddressState::DomainNameLength => {
                    try_ready!(self.read_domain_name_length());
                }
                ReadAddressState::DomainName => {
                    let addr = try_ready!(self.read_domain_name());
                    let reader = self.reader.take().unwrap();
                    return Ok((reader, addr).into());
                }
            };
        }
    }
}

impl<R> ReadAddress<R>
where
    R: AsyncRead,
{
    fn new(r: R) -> ReadAddress<R> {
        ReadAddress {
            reader: Some(r),
            state: ReadAddressState::Type,
            buf: None,
            already_read: 0,
        }
    }

    fn read_addr_type(&mut self) -> Poll<(), Error> {
        let addr_type = try_nb!(self.reader.as_mut().unwrap().read_u8());
        match AddressType::from_u8(addr_type) {
            Some(AddressType::IPv4) => {
                self.state = ReadAddressState::Ipv4;
                self.alloc_buf(6);
            }
            Some(AddressType::IPv6) => {
                self.state = ReadAddressState::Ipv6;
                self.alloc_buf(18);
            }
            Some(AddressType::DomainName) => {
                self.state = ReadAddressState::DomainNameLength;
            }
            None => {
                //                error!("Invalid address type {}", addr_type);
                return Err(Error::ReplyAddressTypeNotSupported(
                    "Not supported address type",
                ));
            }
        };

        Ok(Async::Ready(()))
    }

    fn read_ipv4(&mut self) -> Poll<Address, Error> {
        try_ready!(self.read_data());
        let mut stream: Cursor<Bytes> = self.freeze_buf().into_buf();
        let v4addr = Ipv4Addr::new(
            stream.read_u8()?,
            stream.read_u8()?,
            stream.read_u8()?,
            stream.read_u8()?,
        );
        let port = stream.read_u16::<BigEndian>()?;
        let addr = Address::SocketAddress(SocketAddr::V4(SocketAddrV4::new(v4addr, port)));
        Ok(Async::Ready(addr))
    }

    fn read_ipv6(&mut self) -> Poll<Address, Error> {
        try_ready!(self.read_data());
        let mut stream: Cursor<Bytes> = self.freeze_buf().into_buf();
        let v6addr = Ipv6Addr::new(
            stream.read_u16::<BigEndian>()?,
            stream.read_u16::<BigEndian>()?,
            stream.read_u16::<BigEndian>()?,
            stream.read_u16::<BigEndian>()?,
            stream.read_u16::<BigEndian>()?,
            stream.read_u16::<BigEndian>()?,
            stream.read_u16::<BigEndian>()?,
            stream.read_u16::<BigEndian>()?,
        );
        let port = stream.read_u16::<BigEndian>()?;

        let addr = Address::SocketAddress(SocketAddr::V6(SocketAddrV6::new(v6addr, port, 0, 0)));
        Ok(Async::Ready(addr))
    }

    fn read_domain_name_length(&mut self) -> Poll<(), Error> {
        let length = try_nb!(self.reader.as_mut().unwrap().read_u8());
        self.state = ReadAddressState::DomainName;
        self.alloc_buf(length as usize + 2);
        Ok(Async::Ready(()))
    }

    fn read_domain_name(&mut self) -> Poll<Address, Error> {
        try_ready!(self.read_data());
        let buf = self.freeze_buf();
        let addr_len = buf.len() - 2;
        let mut stream: Cursor<Bytes> = buf.into_buf();

        let mut raw_addr = Vec::with_capacity(addr_len);
        unsafe {
            raw_addr.set_len(addr_len);
        }
        stream.read_exact(&mut raw_addr)?;

        let addr = match String::from_utf8(raw_addr) {
            Ok(addr) => addr,
            Err(..) => return Err(Error::ReplyGeneralFailure("Invalid address encoding")),
        };
        let port = stream.read_u16::<BigEndian>()?;

        let addr = Address::DomainNameAddress(addr, port);
        Ok(Async::Ready(addr))
    }

    fn alloc_buf(&mut self, size: usize) {
        let mut buf = BytesMut::with_capacity(size);
        unsafe {
            buf.set_len(size);
        }
        self.buf = Some(buf);
    }

    fn read_data(&mut self) -> Poll<(), io::Error> {
        let buf = self.buf.as_mut().unwrap();

        while self.already_read < buf.len() {
            match self
                .reader
                .as_mut()
                .unwrap()
                .read(&mut buf[self.already_read..])
            {
                Ok(0) => {
                    let err = io::Error::new(io::ErrorKind::Other, "Unexpected EOF");
                    return Err(err);
                }
                Ok(n) => self.already_read += n,
                Err(err) => return Err(err),
            }
        }

        Ok(Async::Ready(()))
    }

    fn freeze_buf(&mut self) -> Bytes {
        let buf = self.buf.take().unwrap();
        buf.freeze()
    }
}

fn write_ipv4_address<B: BufMut>(addr: &SocketAddrV4, buf: &mut B) {
    let mut dbuf = [0u8; 1 + 4 + 2];
    {
        let mut cur = Cursor::new(&mut dbuf[..]);
        let _ = cur.write_u8(AddressType::IPv4.as_u8()); // Address type
        let _ = cur.write_all(&addr.ip().octets()); // Ipv4 bytes
        let _ = cur.write_u16::<BigEndian>(addr.port());
    }
    buf.put_slice(&dbuf[..]);
}

fn write_ipv6_address<B: BufMut>(addr: &SocketAddrV6, buf: &mut B) {
    let mut dbuf = [0u8; 1 + 16 + 2];

    {
        let mut cur = Cursor::new(&mut dbuf[..]);
        let _ = cur.write_u8(AddressType::IPv6.as_u8());
        for seg in &addr.ip().segments() {
            let _ = cur.write_u16::<BigEndian>(*seg);
        }
        let _ = cur.write_u16::<BigEndian>(addr.port());
    }

    buf.put_slice(&dbuf[..]);
}

fn write_domain_name_address<B: BufMut>(dnaddr: &str, port: u16, buf: &mut B) {
    assert!(dnaddr.len() <= u8::max_value() as usize);

    buf.put_u8(AddressType::DomainName.as_u8());
    buf.put_u8(dnaddr.len() as u8);
    buf.put_slice(dnaddr[..].as_bytes());
    buf.put_u16_be(port);
}

fn write_socket_address<B: BufMut>(addr: &SocketAddr, buf: &mut B) {
    match *addr {
        SocketAddr::V4(ref addr) => write_ipv4_address(addr, buf),
        SocketAddr::V6(ref addr) => write_ipv6_address(addr, buf),
    }
}

fn write_address<B: BufMut>(addr: &Address, buf: &mut B) {
    match *addr {
        Address::SocketAddress(ref addr) => write_socket_address(addr, buf),
        Address::DomainNameAddress(ref dnaddr, ref port) => {
            write_domain_name_address(dnaddr, *port, buf)
        }
    }
}

#[inline]
fn get_addr_len(atyp: &Address) -> usize {
    match *atyp {
        Address::SocketAddress(SocketAddr::V4(..)) => 1 + 4 + 2,
        Address::SocketAddress(SocketAddr::V6(..)) => 1 + 8 * 2 + 2,
        Address::DomainNameAddress(ref dmname, _) => 1 + 1 + dmname.len() + 2,
    }
}

/// TCP request header after handshake
///
/// ```plain
/// +----+-----+-------+------+----------+----------+
/// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// ```
#[derive(Clone, Debug)]
pub struct TcpRequestHeader {
    /// SOCKS5 command
    pub command: Command,
    /// Remote address
    pub address: Address,
}

impl TcpRequestHeader {
    /// Creates a request header
    pub fn new(cmd: Command, addr: Address) -> TcpRequestHeader {
        TcpRequestHeader {
            command: cmd,
            address: addr,
        }
    }

    /// Read from a reader
    pub fn read_from<R>(r: R) -> impl Future<Item = (R, TcpRequestHeader), Error = Error> + Send
    where
        R: AsyncRead + Send + 'static,
    {
        read_exact(r, [0u8; 3])
            .map_err(From::from)
            .and_then(|(r, buf)| {
                let ver = buf[0];
                if ver != consts::SOCKS5_VERSION {
                    return Err(Error::ReplyConnectionRefused("Unsupported Socks version"));
                }

                let cmd = buf[1];
                let command = match Command::from_u8(cmd) {
                    Some(c) => c,
                    None => {
                        return Err(Error::ReplyCommandNotSupported("Unsupported command"));
                    }
                };

                Ok((r, command))
            })
            .and_then(|(r, command)| {
                Address::read_from(r).map(move |(conn, address)| {
                    let header = TcpRequestHeader { command, address };

                    (conn, header)
                })
            })
    }

    /// Write data into a writer
    pub fn write_to<W: AsyncWrite>(self, w: W) -> WriteBytes<W, Bytes> {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        write_bytes(w, buf.freeze())
    }

    /// Writes to buffer
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let TcpRequestHeader {
            ref address,
            ref command,
        } = *self;

        buf.put_slice(&[consts::SOCKS5_VERSION, command.as_u8(), 0x00]);
        address.write_to_buf(buf);
    }

    /// Length in bytes
    #[inline]
    pub fn serialized_len(&self) -> usize {
        self.address.serialized_len() + 3
    }
}

/// TCP response header
///
/// ```plain
/// +----+-----+-------+------+----------+----------+
/// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// ```
#[derive(Clone, Debug)]
pub struct TcpResponseHeader {
    /// SOCKS5 reply
    pub reply: Reply,
    /// Reply address
    pub address: Address,
}

impl TcpResponseHeader {
    /// Creates a response header
    pub fn new(reply: Reply, address: Address) -> TcpResponseHeader {
        TcpResponseHeader { reply, address }
    }

    /// Read from a reader
    pub fn read_from<R>(r: R) -> impl Future<Item = (R, TcpResponseHeader), Error = Error> + Send
    where
        R: AsyncRead + Send + 'static,
    {
        read_exact(r, [0u8; 3])
            .map_err(From::from)
            .and_then(|(r, buf)| {
                let ver = buf[0];
                let reply_code = buf[1];

                if ver != consts::SOCKS5_VERSION {
                    return Err(Error::ReplyConnectionRefused("Unsupported Socks version"));
                }

                Ok((r, reply_code))
            })
            .and_then(|(r, reply_code)| {
                Address::read_from(r).map(move |(r, address)| {
                    let rep = TcpResponseHeader {
                        reply: Reply::from_u8(reply_code),
                        address,
                    };

                    (r, rep)
                })
            })
    }

    /// Write to a writer
    pub fn write_to<W: AsyncWrite>(self, w: W) -> WriteBytes<W, Bytes> {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        write_bytes(w, buf.freeze())
    }

    /// Writes to buffer
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let TcpResponseHeader {
            ref reply,
            ref address,
        } = *self;
        buf.put_slice(&[consts::SOCKS5_VERSION, reply.as_u8(), 0x00]);
        address.write_to_buf(buf);
    }

    /// Length in bytes
    #[inline]
    pub fn serialized_len(&self) -> usize {
        self.address.serialized_len() + 3
    }
}

#[derive(Clone, Debug)]
pub struct HandshakeRequest {
    pub methods: Vec<u8>,
}

impl HandshakeRequest {
    pub fn new(methods: Vec<u8>) -> HandshakeRequest {
        HandshakeRequest { methods }
    }

    pub fn read_from<R>(r: R) -> impl Future<Item = (R, HandshakeRequest), Error = io::Error>
    where
        R: AsyncRead + Send + 'static,
    {
        read_exact(r, [0u8, 0u8])
            .and_then(|(r, buf)| {
                let ver = buf[0];
                let nmet = buf[1];

                if ver != consts::SOCKS5_VERSION {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Invalid Socks5 version",
                    ));
                }

                Ok((r, nmet))
            })
            .and_then(|(r, nmet)| read_exact(r, vec![0u8; nmet as usize]))
            .and_then(|(r, methods)| Ok((r, HandshakeRequest { methods })))
    }

    pub fn write_to<W: AsyncWrite>(self, w: W) -> WriteBytes<W, Bytes> {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        write_bytes(w, buf.freeze())
    }

    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let HandshakeRequest { ref methods } = *self;
        buf.put_slice(&[consts::SOCKS5_VERSION, methods.len() as u8]);
        buf.put_slice(&methods);
    }

    pub fn serialized_len(&self) -> usize {
        2 + self.methods.len()
    }
}

#[derive(Clone, Debug, Copy)]
pub struct HandshakeResponse {
    pub chosen_method: u8,
}

impl HandshakeResponse {
    pub fn new(cm: u8) -> HandshakeResponse {
        HandshakeResponse { chosen_method: cm }
    }

    pub fn read_from<R>(r: R) -> impl Future<Item = (R, HandshakeResponse), Error = io::Error>
    where
        R: AsyncRead + Send + 'static,
    {
        read_exact(r, [0u8, 0u8]).and_then(|(r, buf)| {
            let ver = buf[0];
            let met = buf[1];

            if ver != consts::SOCKS5_VERSION {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Invalid Socks5 version",
                ))
            } else {
                Ok((r, HandshakeResponse { chosen_method: met }))
            }
        })
    }

    pub fn write_to<W: AsyncWrite>(self, w: W) -> WriteBytes<W, Bytes> {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        write_bytes(w, buf.freeze())
    }

    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(&[consts::SOCKS5_VERSION, self.chosen_method]);
    }

    pub fn serialized_len(&self) -> usize {
        2
    }
}

#[derive(Clone, Debug)]
pub struct UdpAssociateHeader {
    /// Fragment
    ///
    /// ShadowSocks does not support fragment, so this frag must be 0x00
    pub frag: u8,
    /// Remote address
    pub address: Address,
}

impl UdpAssociateHeader {
    /// Creates a header
    pub fn new(frag: u8, address: Address) -> UdpAssociateHeader {
        UdpAssociateHeader { frag, address }
    }

    /// Read from a reader
    pub fn read_from<R>(r: R) -> impl Future<Item = (R, UdpAssociateHeader), Error = Error> + Send
    where
        R: AsyncRead + Send + 'static,
    {
        read_exact(r, [0u8; 3])
            .map_err(From::from)
            .and_then(|(r, buf)| {
                let frag = buf[2];
                Address::read_from(r).map(move |(r, address)| {
                    let h = UdpAssociateHeader::new(frag, address);
                    (r, h)
                })
            })
    }

    /// Write to a writer
    pub fn write_to<W: AsyncWrite>(self, w: W) -> WriteBytes<W, Bytes> {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        write_bytes(w, buf.freeze())
    }

    /// Write to buffer
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let UdpAssociateHeader {
            ref frag,
            ref address,
        } = *self;
        buf.put_slice(&[0x00, 0x00, *frag]);
        address.write_to_buf(buf);
    }

    /// Length in bytes
    #[inline]
    pub fn serialized_len(&self) -> usize {
        3 + self.address.serialized_len()
    }
}

//impl SocksStream {
//     pub fn connect(proxy: &'static str, target: &'static str) -> Result<SocksFuture<Stream<Item = SocketAddr, Error = SocksError>>, SocksError> {
//         let proxy_addr = proxy.parse()?;
//         let target_addr = target.parse()?;
//         Self::conn(proxy_addr, target_addr, SocksAuth::new())
//     }

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

//    fn conn(
//        proxy: SocketAddr,
//        target: Addr,
//        auth: SocksAuth,
//    ) -> Result<SocksFuture<Stream<Item = SocketAddr, Error = SocksError>>, SocksError> {
//        let stream = TcpStream::connect(&proxy);
//        // The initial greeting from the client
//        //      field 1: SOCKS version, 1 byte (0x05 for this version)
//        //      field 2: number of authentication methods supported, 1 byte
//        //      field 3: authentication methods, variable length, 1 byte per method supported
//        let auth_method = auth.method as u8;
//        let greeting =
//            stream.and_then(move |conn| write_all(conn, [SOCKS_VERSION, 1u8, auth_method]));
//        // The server's choice is communicated:
//        //      field 1: SOCKS version, 1 byte (0x05 for this version)
//        //      field 2: chosen authentication method, 1 byte, or 0xFF if no acceptable methods were offered
//        let socks_version = greeting.and_then(|(conn, _buf)| {
//            read_exact(conn, [0u8]).and_then(|(conn, buf)| match buf[0] {
//                SOCKS_VERSION => Ok((conn, buf)),
//                _ => Err(err_from("wrong server version")),
//            })
//        });
//        let method = socks_version.and_then(move |(conn, _buf)| {
//            read_exact(conn, [0u8]).and_then(move |(conn, buf)| {
//                match (buf[0] == auth.method as u8, buf[0]) {
//                    (true, 0u8) => f_box(future::ok(conn)),
//                    (true, 2u8) => {
//                        // For username/password authentication the client's authentication request is
//                        //     field 1: version number, 1 byte (0x01 for current version of username/password authentication)
//                        let mut packet = vec![1u8];
//                        //     field 2: username length, 1 byte
//                        packet.push(auth.username.len() as u8);
//                        //     field 3: username, 1–255 bytes
//                        packet.append(&mut auth.username.clone());
//                        //     field 4: password length, 1 byte
//                        packet.push(auth.password.len() as u8);
//                        //     field 5: password, 1–255 bytes
//                        packet.append(&mut auth.password.clone());
//                        let request = write_all(conn, packet)
//                            .and_then(|(conn, _buf)| read_exact(conn, [0u8; 2]));
//                        // Server response for username/password authentication:
//                        //     field 1: version, 1 byte (0x01 for current version of username/password authentication)
//                        //     field 2: status code, 1 byte
//                        //         0x00: success
//                        //         any other value is a failure, connection must be closed
//                        let response =
//                            request.and_then(|(conn, buf)| match (buf[0] != 1u8, buf[1] != 0u8) {
//                                (true, _) => f_box(future::err(err_from("wrong auth version"))),
//                                (_, true) => f_box(future::err(err_from(
//                                    "failure, connection must be closed",
//                                ))),
//                                _ => f_box(future::ok(conn)),
//                            });
//                        f_box(response)
//                    }
//                    _ => f_box(future::err(err_from("auth method not supported"))),
//                }
//            })
//        });
//        let mut packet = Vec::new();
//        // The client's connection request is
//        //     field 1: SOCKS version number, 1 byte (0x05 for this version)
//        packet.push(SOCKS_VERSION);
//        //     field 2: command code, 1 byte:
//        //         0x01: establish a TCP/IP stream connection
//        //         0x02: establish a TCP/IP port binding
//        //         0x03: associate a UDP port
//        packet.push(Command::TcpStreamConnection as u8);
//        //     field 3: reserved, must be 0x00, 1 byte
//        packet.push(0u8);
//        //     field 4: address type, 1 byte:
//        //         0x01: IPv4 address
//        //         0x03: Domain name
//        //         0x04: IPv6 address
//        //     field 5: destination address of
//        //         4 bytes for IPv4 address
//        //         1 byte of name length followed by 1–255 bytes the domain name
//        //         16 bytes for IPv6 address
//        //     field 6: port number in a network byte order, 2 bytes
//        packet.append(&mut target.to_vec().unwrap());
//        let connection = method.and_then(move |conn| write_all(conn, packet));
//        // Server response:
//        //     field 1: SOCKS protocol version, 1 byte (0x05 for this version)
//        let protocol_version = connection.and_then(|(conn, _buf)| {
//            read_exact(conn, [0u8]).and_then(|(conn, buf)| match buf[0] {
//                SOCKS_VERSION => Ok((conn, buf)),
//                _ => Err(err_from("not supporter server version")),
//            })
//        });
//        //     field 2: status, 1 byte:
//        //         0x00: request granted
//        //         0x01: general failure
//        //         0x02: connection not allowed by ruleset
//        //         0x03: network unreachable
//        //         0x04: host unreachable
//        //         0x05: connection refused by destination host
//        //         0x06: TTL expired
//        //         0x07: command not supported / protocol error
//        //         0x08: address type not supported
//        let status = protocol_version.and_then(|(conn, _buf)| {
//            read_exact(conn, [0u8]).and_then(|(conn, buf)| match buf[0] {
//                0 => Ok((conn, buf)),
//                1 => Err(err_from("general failure")),
//                2 => Err(err_from("connection not allowed by ruleset")),
//                3 => Err(err_from("network unreachable")),
//                4 => Err(err_from("host unreachable")),
//                5 => Err(err_from("connection refused by destination host")),
//                6 => Err(err_from("TTL expired")),
//                7 => Err(err_from("command not supported / protocol error")),
//                8 => Err(err_from("address type not supported")),
//                _ => Err(err_from("unknown error")),
//            })
//        });
//        //     field 3: reserved, must be 0x00, 1 byte
//        let reserved = status.and_then(|(conn, _buf)| {
//            read_exact(conn, [0u8]).and_then(|(conn, buf)| match buf[0] {
//                0u8 => Ok((conn, buf)),
//                _ => Err(err_from("invalid reserved byte")),
//            })
//        });
//        //     field 4: address type, 1 byte:
//        //         0x01: IPv4 address
//        //         0x03: Domain name
//        //         0x04: IPv6 address
//        let address_type = reserved.and_then(|(conn, _buf)| read_exact(conn, [0u8]));
//        //     field 5: server bound address of
//        //         4 bytes for IPv4 address
//        //         1 byte of name length followed by 1–255 bytes the domain name
//        //         16 bytes for IPv6 address
//        let address = address_type.and_then(|(conn, buf)| match buf[0] {
//            1u8 => f_box(read_exact(conn, [0u8; 4]).and_then(|(conn, buf)| {
//                f_box(future::ok((conn, Host::Ipv4(Ipv4Addr::from(buf)))))
//            })),
//            3u8 => f_box(read_exact(conn, [0u8]).and_then(|(conn, buf)| {
//                read_exact(conn, vec![0u8; buf[0] as usize]).and_then(|(conn, buf)| {
//                    if let Ok(addr) = String::from_utf8(buf) {
//                        f_box(future::ok((conn, Host::Domain(addr))))
//                    } else {
//                        f_box(future::err(err_from("invalid address")))
//                    }
//                })
//            })),
//            4 => f_box(read_exact(conn, [0u8; 16]).and_then(|(conn, buf)| {
//                f_box(future::ok((conn, Host::Ipv6(Ipv6Addr::from(buf)))))
//            })),
//            _ => f_box(future::err(err_from("invalid address type"))),
//        });
//        //     field 6: server bound port number in a network byte order, 2 bytes
//        let full_address = address.and_then(|(conn, addr)| {
//            read_exact(conn, [0u8; 2]).and_then(|(conn, buf)| {
//                let port = ((buf[0] as u16) << 8) | (buf[1] as u16);
//                f_box(future::ok((conn, addr, port)))
//            })
//        });
//        let timeout = Timeout::new(full_address, Duration::new(10, 0))
//            .map_err(|_| err_from("handshake timeout"));
//        timeout
//
//        // let stream = if target.is_ssl() {
//        //     let builder =
//        //         TlsConnector::new().map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
//        //     Stream::Tls(Box::new(
//        //         builder
//        //             .connect(&target.host()?, socket)
//        //             .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?,
//        //     ))
//        // } else {
//        //     Stream::Tcp(socket)
//        // };
//
//        // Ok(SocksStream {
//        //     stream,
//        //     target: target.clone(),
//        //     bind_addr,
//        //     bind_port
//        // });
//    }
//}

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
