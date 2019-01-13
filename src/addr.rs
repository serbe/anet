use std::io::{self, Error, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::str::FromStr;
use url::{Host, Url};

#[derive(Debug, Clone)]
pub struct Addr {
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
