use failure::Fail;

#[derive(Debug, Fail)]
pub enum SocksError {
    #[fail(display = "{}", _0)]
    Io(#[cause] std::io::Error),
    #[fail(display = "{}", _0)]
    ParseError(#[cause] std::string::ParseError),
    #[fail(display = "Target address is invalid: {}", _0)]
    InvalidTargetAddress(&'static str),
}

impl From<std::io::Error> for SocksError {
    fn from(err: std::io::Error) -> SocksError {
        SocksError::Io(err)
    }
}

impl From<String> for SocksError {
    fn from(err: String) -> SocksError {
        SocksError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("{}", err),
        ))
    }
}
