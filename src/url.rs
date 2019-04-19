
// use std::net::{SocketAddr, ToSocketAddrs};


#[derive(Debug, Default, PartialEq)]
pub struct Url<'a> {
    scheme: Option<&'a str>,
    user: Option<&'a str>,
    password: Option<&'a str>,
    host: &'a str,
    port: Option<&'a str>,
    path: Option<&'a str>,
    query: Option<&'a str>,
    fragment: Option<&'a str>,
}

impl<'a> Url<'a> {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn hostname(self) -> String {
        if let Some(port) = self.port {
            format!("{}:{}", self.host, port)
        } else {
            self.host.to_string()
        }
    }

    pub fn from(s: &str) -> Result<Url, &str> {
        let raw = s;


        let (raw, fragment) = if let Some(pos) = raw.find('#') {
            (
                raw.get(..pos).ok_or_else(|| "bad fragment")?,
                raw.get(pos + 1..),
            )
        } else {
            (raw, None)
        };

        let (raw, query) = if let Some(pos) = raw.find('?') {
            (
                raw.get(..pos).ok_or_else(|| "bad query")?,
                raw.get(pos + 1..),
            )
        } else {
            (raw, None)
        };

        let (raw, scheme) = if let Some(pos) = raw.find("://") {
            (
                raw.get(pos + 3..).ok_or_else(|| "bad scheme")?,
                raw.get(..pos),
            )
        } else {
            (raw, None)
        };

        let (raw, user, password) = if let Some(pos) = raw.find('@') {
            let new_raw = raw.get(pos + 1..).ok_or_else(|| "bad user info")?;
            let userinfo = raw.get(..pos);
            match userinfo {
                Some(user) => {
                    if let Some(pos) = user.find(':') {
                        (new_raw, user.get(..pos), user.get(pos + 1..))
                    } else {
                        (new_raw, Some(user), None)
                    }
                }
                None => (new_raw, None, None),
            }
        } else {
            (raw, None, None)
        };

        let (raw, path) = if let Some(pos) = raw.find('/') {
            (raw.get(..pos).ok_or_else(|| "bad path")?, raw.get(pos..))
        } else {
            (raw, None)
        };

        let (host, port) = if let Some(pos) = raw.find(':') {
            if let Some(start) = raw.find('[') {
                if let Some(end) = raw.find(']') {
                    if start < end && pos == end + 1 {
                        (
                            raw.get(..pos).ok_or_else(|| "bad host")?,
                            raw.get(pos + 1..),
                        )
                    } else {
                        Err("bad ipv6 address")?
                    }
                } else {
                    Err("bad ipv6 address")?
                }
            } else {
                (
                    raw.get(..pos).ok_or_else(|| "bad host")?,
                    raw.get(pos + 1..),
                )
            }
        } else {
            (raw, None)
        };

        if let Some(port) = port {
            let _ = port.parse::<u32>().map_err(|_| "bad port")?;
        }

        Ok(Url {
            scheme,
            user,
            password,
            host,
            port,
            path,
            query,
            fragment,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test1() {
        let url = Url::from("http://www.google.com/?q=go+language#foo").unwrap();
        assert_eq!(
            Url {
                scheme: Some("http"),
                user: None,
                password: None,
                host: "www.google.com",
                port: None,
                path: Some("/"),
                query: Some("q=go+language"),
                fragment: Some("foo"),
            },
            url
        );
    }
}