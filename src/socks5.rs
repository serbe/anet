// use log::info;
use std::{
    convert::{From, TryFrom},
    net::{Ipv4Addr, Ipv6Addr},
    u8,
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::addr::Addr;
use crate::errors::{Error, Result};
use crate::stream::MaybeHttpsStream;
use crate::uri::Uri;

pub const SOCKS5_VERSION: u8 = 0x05;

pub struct Sock5Stream {
    stream: MaybeHttpsStream,
}

impl Sock5Stream {
    pub async fn get(&mut self, buf: Bytes) -> Result<String> {
        self.stream.write_all(&buf).await?;
        let mut buffer = String::new();
        self.stream.read_to_string(&mut buffer).await?;
        Ok(buffer)
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum Command {
    TCPConnection = 0x01,
    TCPBinding = 0x02,
    UDPPort = 0x03,
}

impl Into<u8> for Command {
    fn into(self) -> u8 {
        match self {
            Command::TCPConnection => 0x01,
            Command::TCPBinding => 0x02,
            Command::UDPPort => 0x03,
        }
    }
}

impl TryFrom<u8> for Command {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Command::TCPConnection),
            0x02 => Ok(Command::TCPBinding),
            0x03 => Ok(Command::UDPPort),
            v => Err(Error::CommandUnknown(v)),
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum AuthMethod {
    NoAuth = 0x00,
    GSSAPI = 0x01,
    Plain = 0x02,
    NoAccept = 0xff,
}

impl Into<u8> for AuthMethod {
    fn into(self) -> u8 {
        match self {
            AuthMethod::NoAuth => 0x00,
            AuthMethod::GSSAPI => 0x01,
            AuthMethod::Plain => 0x02,
            AuthMethod::NoAccept => 0xff,
        }
    }
}

impl TryFrom<u8> for AuthMethod {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(AuthMethod::NoAuth),
            0x01 => Ok(AuthMethod::GSSAPI),
            0x02 => Ok(AuthMethod::Plain),
            0xff => Ok(AuthMethod::NoAccept),
            v => Err(Error::MethodUnknown(v)),
        }
    }
}

#[derive(Clone, Copy)]
pub enum AddrType {
    IPv4 = 0x01,
    DomainName = 0x03,
    IPv6 = 0x04,
}

impl Into<u8> for AddrType {
    fn into(self) -> u8 {
        match self {
            AddrType::IPv4 => 0x01,
            AddrType::DomainName => 0x03,
            AddrType::IPv6 => 0x04,
        }
    }
}

impl TryFrom<u8> for AddrType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(AddrType::IPv4),
            3 => Ok(AddrType::DomainName),
            4 => Ok(AddrType::IPv6),
            v => Err(Error::AddressTypeNotSupported(v)),
        }
    }
}

/// Client auth request
///
/// ```plain
/// The client connects to the server, and sends a version
/// identifier/method selection message:
///
///                 +----+----------+----------+
///                 |VER | NMETHODS | METHODS  |
///                 +----+----------+----------+
///                 | 1  |    1     | 1 to 255 |
///                 +----+----------+----------+
///
/// The VER field is set to X'05' for this version of the protocol.  The
/// NMETHODS field contains the number of method identifier octets that
/// appear in the METHODS field.
/// ```
/// #[derive(Clone, Debug)]
struct AuthRequest {
    pub ver: u8,
    pub nmethods: u8,
    pub methods: Vec<AuthMethod>,
}

impl AuthRequest {
    fn default() -> Self {
        AuthRequest {
            ver: SOCKS5_VERSION,
            nmethods: 0u8,
            methods: Vec::new(),
        }
    }

    fn add_method(&mut self, method: AuthMethod) {
        if !self.methods.contains(&method) {
            self.nmethods += 1;
            self.methods.push(method);
        }
    }

    fn new(method: AuthMethod) -> Self {
        let mut auth_request = AuthRequest::default();
        auth_request.add_method(method);
        auth_request
    }

    fn bytes(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u8(self.ver);
        buf.put_u8(self.nmethods);
        for method in &self.methods {
            buf.put_u8(method.clone().into());
        }
        buf.freeze()
    }

    // Send auth request to server
    async fn send(&self, stream: &mut TcpStream) -> Result<()> {
        let buf = self.bytes();
        println!("AuthRequest {:?}", buf);
        stream.write_all(&buf).await?;
        Ok(())
    }
}

/// Server auth response
///
/// ```plain
/// The server selects from one of the methods given in METHODS, and
/// sends a METHOD selection message:
///
///                       +----+--------+
///                       |VER | METHOD |
///                       +----+--------+
///                       | 1  |   1    |
///                       +----+--------+
///
/// If the selected METHOD is X'FF', none of the methods listed by the
/// client are acceptable, and the client MUST close the connection.
///
/// The values currently defined for METHOD are:
///
///        o  X'00' NO AUTHENTICATION REQUIRED
///        o  X'01' GSSAPI
///        o  X'02' USERNAME/PASSWORD
///        o  X'03' to X'7F' IANA ASSIGNED
///        o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
///        o  X'FF' NO ACCEPTABLE METHODS
///
/// The client and server then enter a method-specific sub-negotiation.
/// Descriptions of the method-dependent sub-negotiations appear in
/// separate memos.
///
/// Developers of new METHOD support for this protocol should contact
/// IANA for a METHOD number.  The ASSIGNED NUMBERS document should be
/// referred to for a current list of METHOD numbers and their
/// corresponding protocols.
/// ```
struct AuthResponse {
    ver: u8,
    method: AuthMethod,
}

impl AuthResponse {
    async fn read(stream: &mut TcpStream) -> Result<Self> {
        let mut buf = BytesMut::with_capacity(2);
        stream.read_exact(&mut buf).await?;
        println!("AuthResponse {:?}", buf);
        let ver = buf[0];
        let method = AuthMethod::try_from(buf[1])?;
        if ver != SOCKS5_VERSION {
            Err(Error::NotSupportedSocksVersion(ver))
        } else {
            match method {
                AuthMethod::NoAuth | AuthMethod::Plain => Ok(AuthResponse { ver, method }),
                AuthMethod::GSSAPI => Err(Error::Unimplement),
                AuthMethod::NoAccept => Err(Error::MethodNotAccept),
            }
        }
    }
    fn check(&self, method: AuthMethod) -> Result<()> {
        if self.method != method {
            Err(Error::MethodWrong)
        } else {
            Ok(())
        }
    }
}

/// Auth with username and password
///
/// ```plain
/// Once the SOCKS V5 server has started, and the client has selected the
/// Username/Password Authentication protocol, the Username/Password
/// subnegotiation begins.  This begins with the client producing a
/// Username/Password request:
///
///         +----+------+----------+------+----------+
///         |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
///         +----+------+----------+------+----------+
///         | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
///         +----+------+----------+------+----------+
///
/// The VER field contains the current version of the subnegotiation,
/// which is X'01'. The ULEN field contains the length of the UNAME field
/// that follows. The UNAME field contains the username as known to the
/// source operating system. The PLEN field contains the length of the
/// PASSWD field that follows. The PASSWD field contains the password
/// association with the given UNAME.
/// ```
struct UserPassRequest {
    ver: u8,
    ulen: usize,
    uname: Vec<u8>,
    plen: usize,
    passwd: Vec<u8>,
}

impl UserPassRequest {
    fn new(username: &str, password: &str) -> Result<UserPassRequest> {
        let ver = 1u8;
        let uname = username.as_bytes().to_vec();
        let passwd = password.as_bytes().to_vec();
        match (uname.len(), passwd.len()) {
            (u, _) if u > 255 => Err(Error::UnameLenOverflow(u)),
            (_, p) if p > 255 => Err(Error::PasswdLenOverflow(p)),
            (ulen, plen) => Ok(UserPassRequest {
                ver,
                ulen,
                uname,
                plen,
                passwd,
            }),
        }
    }

    fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.ver.into());
        buf.push(self.ulen as u8);
        buf.extend_from_slice(&self.uname);
        buf.push(self.plen as u8);
        buf.extend_from_slice(&self.passwd);
        buf
    }

    async fn send(&self, stream: &mut TcpStream) -> Result<()> {
        let buf = self.to_vec();
        println!("UserPassRequest {:?}", buf);
        stream.write_all(&buf).await?;
        Ok(())
    }
}

/// Check plain auth response
///
/// ```plain
///    The server verifies the supplied UNAME and PASSWD, and sends the
///    following response:
///
///                         +----+--------+
///                         |VER | STATUS |
///                         +----+--------+
///                         | 1  |   1    |
///                         +----+--------+
///
///    A STATUS field of X'00' indicates success. If the server returns a
///    `failure' (STATUS value other than X'00') status, it MUST close the
///    connection.
/// ```
struct UserPassResponse {
    ver: u8,
    status: u8,
}

impl UserPassResponse {
    async fn read(stream: &mut TcpStream) -> Result<UserPassResponse> {
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        println!("UserPassResponse {:?}", buf);
        let ver = buf[0];
        let status = buf[1];
        if ver != 1u8 {
            Err(Error::NotSupportedVersion(ver))
        } else if status != 0u8 {
            Err(Error::WrongStatus(status))
        } else {
            Ok(UserPassResponse { ver, status })
        }
    }
}

/// Client to socks request
///
/// ```plain
/// The SOCKS request is formed as follows:
///
/// +----+-----+-------+------+----------+----------+
/// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
///
/// Where:
///
///   o  VER    protocol version: X'05'
///   o  CMD
///      o  CONNECT X'01'
///      o  BIND X'02'
///      o  UDP ASSOCIATE X'03'
///   o  RSV    RESERVED
///   o  ATYP   address type of following address
///      o  IP V4 address: X'01'
///      o  DOMAINNAME: X'03'
///      o  IP V6 address: X'04'
///   o  DST.ADDR       desired destination address
///   o  DST.PORT desired destination port in network octet
///      order
///
/// The SOCKS server will typically evaluate the request based on source
/// and destination addresses, and return one or more reply messages, as
/// appropriate for the request type.
/// ```
struct SocksRequest {
    ver: u8,
    cmd: Command,
    rsv: u8,
    atyp: AddrType,
    dst_addr: Addr,
    dst_port: u16,
}

impl SocksRequest {
    fn new(command: Command, uri: &Uri) -> Result<SocksRequest> {
        let atyp = AddrType::try_from(uri.addr_type())?;
        let dst_addr = uri.addr();
        let dst_port = uri.default_port();
        Ok(SocksRequest {
            ver: SOCKS5_VERSION,
            cmd: command,
            rsv: 0u8,
            atyp,
            dst_addr,
            dst_port,
        })
    }

    fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.ver);
        buf.push(self.cmd.into());
        buf.push(self.rsv);
        buf.push(self.atyp.into());
        for method in self.dst_addr.to_vec() {
            buf.push(method);
        }
        buf.push(((self.dst_port >> 8) & 0xff) as u8);
        buf.push((self.dst_port & 0xff) as u8);
        buf
    }

    async fn send(&self, stream: &mut TcpStream) -> Result<()> {
        let buf = self.to_vec();
        println!("{:?}", buf);
        stream.write_all(&buf).await?;
        Ok(())
    }
}

/// Read socks replies
///
/// ```plain
/// The SOCKS request information is sent by the client as soon as it has
/// established a connection to the SOCKS server, and completed the
/// authentication negotiations.  The server evaluates the request, and
/// returns a reply formed as follows:
///
///      +----+-----+-------+------+----------+----------+
///      |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
///      +----+-----+-------+------+----------+----------+
///      | 1  |  1  | X'00' |  1   | Variable |    2     |
///      +----+-----+-------+------+----------+----------+
///
///   Where:
///
///        o  VER    protocol version: X'05'
///        o  REP    Reply field:
///           o  X'00' succeeded
///           o  X'01' general SOCKS server failure
///           o  X'02' connection not allowed by ruleset
///           o  X'03' Network unreachable
///           o  X'04' Host unreachable
///           o  X'05' Connection refused
///           o  X'06' TTL expired
///           o  X'07' Command not supported
///           o  X'08' Address type not supported
///           o  X'09' to X'FF' unassigned
///        o  RSV    RESERVED
///        o  ATYP   address type of following address
///           o  IP V4 address: X'01'
///           o  DOMAINNAME: X'03'
///           o  IP V6 address: X'04'
///        o  BND.ADDR       server bound address
///        o  BND.PORT       server bound port in network octet order
///
/// Fields marked RESERVED (RSV) must be set to X'00'.
///
/// If the chosen method includes encapsulation for purposes of
/// authentication, integrity and/or confidentiality, the replies are
/// encapsulated in the method-dependent encapsulation.
/// ```
struct SocksResponse {
    ver: u8,
    rep: u8,
    rsv: u8,
    atyp: AddrType,
    bndaddr: Addr,
    bndport: u16,
}

impl SocksResponse {
    async fn read(stream: &mut TcpStream) -> Result<Self> {
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await?;
        println!("{:?}", buf);
        let ver = buf[0];
        let rep = buf[1];
        let rsv = buf[2];
        let atyp = AddrType::try_from(buf[3])?;
        if ver != SOCKS5_VERSION {
            return Err(Error::NotSupportedSocksVersion(ver));
        }
        match rep {
            0u8 => Ok(()),
            1u8 => Err(Error::ReplyGeneralFailure),
            2u8 => Err(Error::ReplyConnectionNotAllowed),
            3u8 => Err(Error::ReplyNetworkUnreachable),
            4u8 => Err(Error::ReplyHostUnreachable),
            5u8 => Err(Error::ReplyConnectionRefused),
            6u8 => Err(Error::ReplyTtlExpired),
            7u8 => Err(Error::ReplyCommandNotSupported),
            8u8 => Err(Error::ReplyAddressTypeNotSupported),
            v => Err(Error::ReplyUnassigned(v)),
        }?;
        if rsv != 0u8 {
            return Err(Error::WrongReserved(rsv));
        }
        let addr: Result<Addr> = match atyp {
            AddrType::IPv4 => {
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await?;
                Ok(Addr::Ipv4(Ipv4Addr::from(buf)))
            }
            AddrType::IPv6 => {
                let mut buf = [0u8; 16];
                stream.read_exact(&mut buf).await?;
                Ok(Addr::Ipv6(Ipv6Addr::from(buf)))
            }
            AddrType::DomainName => {
                let mut buf = [0u8];
                stream.read_exact(&mut buf).await?;
                let mut buf = Vec::with_capacity(buf[0] as usize);
                stream.read_buf(&mut buf).await?;
                Ok(Addr::Domain(String::from_utf8(buf)?))
            }
        };
        let bndaddr = addr?;
        let bndport = stream.read_u16().await?;
        Ok(SocksResponse {
            ver,
            rep,
            rsv,
            atyp,
            bndaddr,
            bndport,
        })
    }
}

pub async fn connect(proxy: &str, target: &str) -> Result<Sock5Stream> {
    let mut stream = TcpStream::connect(proxy).await?;
    AuthRequest::new(AuthMethod::NoAuth)
        .send(&mut stream)
        .await?;
    AuthResponse::read(&mut stream)
        .await?
        .check(AuthMethod::NoAuth)?;
    let uri = target.parse::<Uri>()?;
    SocksRequest::new(Command::TCPConnection, &uri)?
        .send(&mut stream)
        .await?;
    SocksResponse::read(&mut stream).await?;
    let maybe_stream = if uri.is_ssl() {
        let connector = native_tls::TlsConnector::builder().build()?;
        let connector = tokio_tls::TlsConnector::from(connector);
        let tls_stream = connector.connect(&uri.host(), stream).await?;
        MaybeHttpsStream::from(tls_stream)
    } else {
        MaybeHttpsStream::from(stream)
    };
    Ok(Sock5Stream {
        stream: maybe_stream,
    })
}

pub async fn connect_plain(
    proxy: &str,
    target: &str,
    username: &str,
    password: &str,
) -> Result<Sock5Stream> {
    let mut stream = TcpStream::connect(proxy).await?;
    AuthRequest::new(AuthMethod::Plain)
        .send(&mut stream)
        .await?;
    AuthResponse::read(&mut stream)
        .await?
        .check(AuthMethod::Plain)?;
    UserPassRequest::new(username, password)?
        .send(&mut stream)
        .await?;
    UserPassResponse::read(&mut stream).await?;
    let uri = target.parse::<Uri>()?;
    SocksRequest::new(Command::TCPConnection, &uri)?
        .send(&mut stream)
        .await?;
    SocksResponse::read(&mut stream).await?;
    let maybe_stream = if uri.is_ssl() {
        let connector = native_tls::TlsConnector::builder().build()?;
        let connector = tokio_tls::TlsConnector::from(connector);
        let tls_stream = connector.connect(&uri.host(), stream).await?;
        MaybeHttpsStream::from(tls_stream)
    } else {
        MaybeHttpsStream::from(stream)
    };
    Ok(Sock5Stream {
        stream: maybe_stream,
    })
}
