
pub const SOCKS5_VERSION: u8 = 0x05;

pub enum Command {
    TCPConnection = 0x01,
    TCPBinding = 0x02,
    UDPPort = 0x03,
}

#[derive(Clone, Copy)]
pub enum AuthMethod {
    NoAuth = 0x00,
    GSSAPI = 0x01,
    Plain = 0x02,
    NoAccept = 0xff,
}

impl From<u8> for AuthMethod {
    fn from(value: u8) -> Self {
        match value {
            0x00 => AuthMethod::NoAuth,
            0x01 => AuthMethod::GSSAPI,
            0x02 => AuthMethod::Plain,
            _ => AuthMethod::NoAccept,
        }
    }
}