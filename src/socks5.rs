// use crate::addr::Addr;
//use crate::utils::{err_from, f_box};
// use crate::errors::Error;
use std::{
    convert::{From, TryFrom},
    net::{Ipv4Addr, Ipv6Addr},
    u8, vec,
};

// use futures::{Future};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
// use url::Host;

use crate::addr::Addr;
use crate::errors::{Error, Result};

pub const SOCKS5_VERSION: u8 = 0x05;

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

pub struct SocksAuth {
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

    fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.ver);
        buf.push(self.nmethods);
        for method in &self.methods {
            buf.push(method.clone().into());
        }
        buf
    }

    // Send auth request to server
    async fn send(&self, stream: &mut TcpStream) -> Result<()> {
        let buf = self.to_vec();
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
    async fn read(stream: &mut TcpStream) -> Result<AuthResponse> {
        let mut buf = [0u8, 0u8];
        stream.read_exact(&mut buf).await?;
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
pub async fn auth_plain(stream: &mut TcpStream, auth: SocksAuth) -> Result<()> {
    let mut buf = vec![1u8];
    buf.push(auth.username.len() as u8);
    buf.append(&mut auth.username.clone());
    buf.push(auth.password.len() as u8);
    buf.append(&mut auth.password.clone());
    stream.write_all(&buf).await?;
    Ok(())
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
pub async fn check_auth_plain_status(stream: &mut TcpStream) -> Result<()> {
    let mut buf = [0u8, 0u8];
    stream.read_exact(&mut buf).await?;
    let ver = buf[0];
    let status = buf[1];

    match (ver, status) {
        (1u8, 0u8) => Ok(()),
        _ => {
            stream.shutdown().await?;
            Err(Error::NotSupportedSocksVersion(ver))
        }
    }
}

pub async fn handshake(mut stream: &mut TcpStream, auth: &SocksAuth) -> Result<()> {
    AuthRequest::new(auth.method).send(&mut stream).await?;
    let auth_response = AuthResponse::read(&mut stream).await?;
    if auth_response.method != auth.method {
        Err(Error::MethodWrong)
    } else {
        Ok(())
    }
}

pub async fn read_host(stream: &mut TcpStream) -> Result<Addr> {
    let mut buf = [0u8];
    stream.read_exact(&mut buf).await?;
    let addr_type = buf[0];
    match AddrType::try_from(addr_type)? {
        AddrType::IPv4 => {
            let mut buf = [0u8, 0u8, 0u8, 0u8];
            stream.read_exact(&mut buf).await?;
            Ok(Addr::Ipv4(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3])))
        }
        AddrType::IPv6 => {
            let mut buf = [
                0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            ];
            stream.read_exact(&mut buf).await?;
            Ok(Addr::Ipv6(Ipv6Addr::from(buf)))
            // Ok(Host::Ipv6(Ipv6Addr::from([
            //     buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
            //     buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
            // ])))
        }
        AddrType::DomainName => {
            let mut buf = [0u8];
            stream.read_exact(&mut buf).await?;
            let mut buf = Vec::with_capacity(buf[0] as usize);
            stream.read_buf(&mut buf).await?;
            Ok(Addr::Domain(String::from_utf8(buf)?))
        }
    }
}

pub async fn read_port(stream: &mut TcpStream) -> Result<u16> {
    let port = stream.read_u16().await?;
    Ok(port)
}

/// Client request
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
    atyp: u8,
    dst_addr: Addr,
    dst_port: u16,
}

// impl SocksRequest {
//     fn new(command: Command, target: &str) -> Result<Self> {

//     }
// }

// pub async fn request(stream: &mut TcpStream, target: &Addr) -> Result<()> {
//     let mut buf = Vec::new();
//     buf.push(SOCKS5_VERSION);
//     buf.push(Command::TCPConnection.into());
//     buf.push(0u8);
//     // buf.append(&mut target.to_vec().unwrap());
//     stream.write_all(&buf).await?;
//     Ok(())
// }

/// Read replies
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
pub async fn replies(stream: &mut TcpStream) -> Result<()> {
    let mut buf = [0u8, 0u8, 0u8];
    stream.read_exact(&mut buf).await?;
    let ver = buf[0];
    let rep = buf[1];
    let rsv = buf[2];
    if ver != SOCKS5_VERSION {
        stream.shutdown().await?;
        return Err(Error::NotSupportedSocksVersion(ver));
    }
    match rep {
        0 => Ok(()),
        1 => Err(Error::GeneralFailure),
        2 => Err(Error::WrongRuleset),
        3 => Err(Error::NetworkUnreachable),
        4 => Err(Error::HostUnreachable),
        5 => Err(Error::ConnectionRefused),
        6 => Err(Error::TtlExpired),
        7 => Err(Error::CommandOrProtocolError),
        8 => Err(Error::WrongAddressType),
        _ => Err(Error::UnknownError),
    }?;
    if rsv != 0u8 {
        stream.shutdown().await?;
        return Err(Error::WrongReserved(rsv));
    };
    Ok(())
}

pub async fn start_connect(
    proxy: &'static str,
    target: Addr,
    auth: SocksAuth,
) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await?;
    handshake(&mut stream, &auth).await?;
    if auth.method == AuthMethod::Plain {
        auth_plain(&mut stream, auth).await?;
    }
    // request(&mut stream, &target).await?;
    // replies(&mut stream).await?;
    // let _host = read_host(&mut stream).await?;
    // let _port = read_port(&mut stream).await?;
    Ok(stream)
}

pub async fn connect(proxy: &'static str, target: &'static str) -> Result<TcpStream> {
    start_connect(proxy, target.parse()?, SocksAuth::new()).await
}

pub async fn connect_plain(
    proxy: &'static str,
    target: &'static str,
    username: &'static str,
    password: &'static str,
) -> Result<TcpStream> {
    start_connect(
        proxy,
        target.parse()?,
        SocksAuth::new_plain(username, password),
    )
    .await
}
