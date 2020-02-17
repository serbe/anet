use std::{io, result};

use thiserror::Error;

pub type Result<T> = result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Socks version: {0} - not supported")]
    NotSupportedSocksVersion(u8),
    #[error("io error")]
    IO(#[from] io::Error),
    #[error("Unimplement feature")]
    Unimplement,
    #[error("Auth method not accepted")]
    MethodNotAccept,
    #[error("Unknown auth method")]
    MethodUnknown,
    #[error("Wrong method")]
    MethodWrong,
    // #[fail(display = "{}", _0)]
    // Io(#[cause] std::io::Error),
    // #[fail(display = "{}", _0)]
    // ParseError(#[cause] std::string::ParseError),
    // #[fail(display = "Target address is invalid: {}", _0)]
    // InvalidTargetAddress(&'static str),
    // #[fail(display = "Url fragment is invalid: {}", _0)]
    // ParseFragment(&'static str),
    // #[fail(display = "Url host is invalid: {}", _0)]
    // ParseHost(&'static str),
    // #[fail(display = "Url IPv6 is invalid: {}", _0)]
    // ParseIPv6(&'static str),
    // #[fail(display = "Url path is invalid: {}", _0)]
    // ParsePath(&'static str),
    // #[fail(display = "Url port is invalid: {}", _0)]
    // ParsePort(&'static str),
    // #[fail(display = "Url query is invalid: {}", _0)]
    // ParseQuery(&'static str),
    // #[fail(display = "Url scheme is invalid: {}", _0)]
    // ParseScheme(&'static str),
    // #[fail(display = "Url UserInfo is invalid: {}", _0)]
    // ParseUserInfo(&'static str),
    // #[fail(display = "General SOCKS server failure: {}", _0)]
    // ReplyGeneralFailure(&'static str),
    // #[fail(display = "Connection not allowed by ruleset: {}", _0)]
    // ReplyConnectionNotAllowed(&'static str),
    // #[fail(display = "Network unreachable: {}", _0)]
    // ReplyNetworkUnreachable(&'static str),
    // #[fail(display = "Host unreachable: {}", _0)]
    // ReplyHostUnreachable(&'static str),
    // #[fail(display = "Connection refused: {}", _0)]
    // ReplyConnectionRefused(&'static str),
    // #[fail(display = "TTL expired: {}", _0)]
    // ReplyTtlExpired(&'static str),
    // #[fail(display = "Command not supported: {}", _0)]
    // ReplyCommandNotSupported(&'static str),
    // #[fail(display = "Address type not supported: {}", _0)]
    // ReplyAddressTypeNotSupported(&'static str),
    // #[fail(display = "Other reply: {} {}", _0, _1)]
    // ReplyOtherReply(&'static str, u8),
}

// impl From<std::io::Error> for Error {
//     fn from(err: std::io::Error) -> Error {
//         Error::Io(err)
//     }
// }

// impl From<String> for Error {
//     fn from(err: String) -> Error {
//         Error::Io(std::io::Error::new(
//             std::io::ErrorKind::Other,
//             err,
//         ))
//     }
// }

// impl From<&str> for Error {
//     fn from(err: &str) -> Error {
//         Error::Io(std::io::Error::new(
//             std::io::ErrorKind::Other,
//             err,
//         ))
//     }
// }

// impl From<Error> for std::io::Error {
//     fn from(err: Error) -> std::io::Error {
//         std::io::Error::new(
//             std::io::ErrorKind::Other,
//             err.to_string(),
//         )
//     }
// }