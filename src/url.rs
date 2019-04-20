
use std::net::{SocketAddr, ToSocketAddrs};
use std::{error, fmt};
#[derive(Debug)]
pub enum UrlError<'a> {
    ParseFragment(&'a str),
    ParseHost(&'a str),
    ParseIPv6(&'a str),
    ParsePath(&'a str),
    ParsePort(&'a str),
    ParseQuery(&'a str),
    ParseScheme(&'a str),
    ParseUserInfo(&'a str),
}

impl<'a> fmt::Display for UrlError<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            UrlError::ParseFragment(ref e) => write!(f, "not parse fragment in {}", e),
            UrlError::ParseHost(ref e) => write!(f, "not parse host in {}", e),
            UrlError::ParseIPv6(ref e) => write!(f, "not parse IPv6 in {}", e),
            UrlError::ParsePath(ref e) => write!(f, "not parse path in {}", e),
            UrlError::ParsePort(ref e) => write!(f, "not parse port in {}", e),
            UrlError::ParseQuery(ref e) => write!(f, "not parse query in {}", e),
            UrlError::ParseScheme(ref e) => write!(f, "not parse scheme in {}", e),
            UrlError::ParseUserInfo(ref e) => write!(f, "not parse UserInfo in {}", e),
        }
    }
}

impl<'a> error::Error for UrlError<'a> {
    fn description(&self) -> &str {
        match *self {
            UrlError::ParseFragment(ref e) => e,
            UrlError::ParseHost(ref e) => e,
            UrlError::ParseIPv6(ref e) => e,
            UrlError::ParsePath(ref e) => e,
            UrlError::ParsePort(ref e) => e,
            UrlError::ParseQuery(ref e) => e,
            UrlError::ParseScheme(ref e) => e,
            UrlError::ParseUserInfo(ref e) => e,
        }
    }
}

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

    pub fn hostname(&self) -> String {
        if let Some(port) = self.port {
            format!("{}:{}", self.host, port)
        } else {
            self.host.to_string()
        }
    }

    pub fn hostport(&self) -> String {
        format!("{}:{}", self.host, self.port())
    }

    pub fn path(&self) -> String {
        if let Some(path) = self.path {
            path.to_string()
        } else {
            String::new()
        }
    }

    pub fn port(&self) -> String {
        if let Some(port) = self.port {
            port.to_string()
        } else {
            match self.scheme {
                Some("ftp") => "21",
                Some("git") => "9418",
                Some("http") => "80",
                Some("https") => "443",
                Some("imap") => "143",
                Some("irc") => "194",
                Some("ldap") => "389",
                Some("ldaps") => "636",
                Some("nfs") => "111",
                Some("pop") => "110",
                Some("redis") => "6379",
                Some("rsync") => "873",
                Some("sftp") => "22",
                Some("smb") => "445",
                Some("snmp") => "161",
                Some("ssh") => "22",
                Some("telnet") => "23",
                Some("vnc") => "5900",
                Some("ws") => "80",
                Some("wss") => "443",
                _ => "80",
            }
            .to_string()
        }
    }

    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.hostport().to_socket_addrs().ok()?.next()
    }

    pub fn from(s: &str) -> Result<Url, UrlError> {
        let raw = s;

        let (raw, fragment) = if let Some(pos) = raw.find('#') {
            (
                raw.get(..pos).ok_or_else(|| UrlError::ParseFragment(raw))?,
                raw.get(pos + 1..),
            )
        } else {
            (raw, None)
        };

        let (raw, query) = if let Some(pos) = raw.find('?') {
            (
                raw.get(..pos).ok_or_else(|| UrlError::ParseQuery(raw))?,
                raw.get(pos + 1..),
            )
        } else {
            (raw, None)
        };

        let (raw, scheme) = if let Some(pos) = raw.find("://") {
            (
                raw.get(pos + 3..)
                    .ok_or_else(|| UrlError::ParseScheme(raw))?,
                raw.get(..pos),
            )
        } else {
            (raw, None)
        };

        let (raw, user, password) = if let Some(pos) = raw.find('@') {
            let new_raw = raw
                .get(pos + 1..)
                .ok_or_else(|| UrlError::ParseUserInfo(raw))?;
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
            (
                raw.get(..pos).ok_or_else(|| UrlError::ParsePath(raw))?,
                raw.get(pos..),
            )
        } else {
            (raw, None)
        };

        let (host, port) = if let Some(pos) = raw.rfind(':') {
            if let Some(start) = raw.find('[') {
                if let Some(end) = raw.find(']') {
                    if start == 0 && pos == end + 1 {
                        (
                            raw.get(..pos).ok_or_else(|| UrlError::ParseHost(raw))?,
                            raw.get(pos + 1..),
                        )
                    } else if start == 0 && end == raw.len() - 1 {
                        (raw, None)
                    } else {
                        Err(UrlError::ParseIPv6(raw))?
                    }
                } else {
                    Err(UrlError::ParseIPv6(raw))?
                }
            } else {
                (
                    raw.get(..pos).ok_or_else(|| UrlError::ParseHost(raw))?,
                    raw.get(pos + 1..),
                )
            }
        } else {
            (raw, None)
        };

        if let Some(port) = port {
            let _ = port.parse::<u32>().map_err(|_| UrlError::ParsePort(raw))?;
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
    fn no_path() {
        let s = Url::from("http://www.example.org").unwrap();
        let mut u = Url::new();
        u.scheme = Some("http");
        u.host = "www.example.org";
        assert_eq!(s, u);
    }

    #[test]
    fn with_path() {
        let s = Url::from("http://www.example.org/").unwrap();
        let mut u = Url::new();
        u.scheme = Some("http");
        u.host = "www.example.org";
        u.path = Some("/");
        assert_eq!(s, u);
    }

    // #[test]
    // fn path_with_hex_escaping() {
    //     let mut u = Url::new();
    //     let s = Url::from("http://www.example.org/file%20one%26two").unwrap();
    //     u.scheme = Some("http");
    //     u.host = "www.example.org";
    //     // u.path = Some("/file one&two");
    //     u.path = Some("/file%20one%26two");
    //     assert_eq!(s, u);
    // }

    #[test]
    fn user() {
        let mut u = Url::new();
        let s = Url::from("ftp://webmaster@www.example.org/").unwrap();
        u.scheme = Some("ftp");
        u.user = Some("webmaster");
        u.host = "www.example.org";
        u.path = Some("/");
        assert_eq!(s, u);
    }

    // #[test]
    // fn escape_sequence_in_username() {
    //     let mut u = Url::new();
    //     let s = Url::from("ftp://john%20doe@www.example.org/").unwrap();
    //     u.scheme = Some("ftp");
    //     // u.user = Some("john doe");
    //     u.user = Some("john%20doe");
    //     u.host = "www.example.org";
    //     u.path = Some("/");
    //     assert_eq!(s, u);
    // }

    #[test]
    fn empty_query() {
        let mut u = Url::new();
        let s = Url::from("http://www.example.org/?").unwrap();
        u.scheme = Some("http");
        u.host = "www.example.org";
        u.path = Some("/");
        u.query = Some("");
        assert_eq!(s, u);
    }

    #[test]
    fn query_ending_in_question_mark() {
        let mut u = Url::new();
        let s = Url::from("http://www.example.org/?foo=bar?").unwrap();
        u.scheme = Some("http");
        u.host = "www.example.org";
        u.path = Some("/");
        u.query = Some("foo=bar?");
        assert_eq!(s, u);
    }

    #[test]
    fn query() {
        let mut u = Url::new();
        let s = Url::from("http://www.example.org/?q=rust+language").unwrap();
        u.scheme = Some("http");
        u.host = "www.example.org";
        u.path = Some("/");
        u.query = Some("q=rust+language");
        assert_eq!(s, u);
    }

    // #[test]
    // fn query_with_hex_escaping() {
    //     let mut u = Url::new();
    //     let s = Url::from("http://www.example.org/?q=go%20language").unwrap();
    //     u.scheme = Some("http");
    //     u.host = "www.example.org";
    //     u.path = Some("/");
    //     u.query = Some("q=go%20language");
    //     assert_eq!(s, u);
    // }

    // #[test]
    // fn outside_query() {
    //     let mut u = Url::new();
    //     let s = Url::from("http://www.example.org/a%20b?q=c+d").unwrap();
    //     u.scheme = Some("http");
    //     u.host = "www.example.org";
    //     u.path = Some("/a b");
    //     u.query = Some("q=c+d");
    //     assert_eq!(s, u);
    // }

    #[test]
    fn path_without_leading2() {
        let mut u = Url::new();
        let s = Url::from("http://www.example.org/?q=rust+language").unwrap();
        u.scheme = Some("http");
        u.host = "www.example.org";
        u.path = Some("/");
        u.query = Some("q=rust+language");
        assert_eq!(s, u);
    }

    // #[test]
    // fn path_without_leading() {
    //     let mut u = Url::new();
    //     let s = Url::from("http:%2f%2fwww.example.org/?q=rust+language").unwrap();
    //     u.scheme = Some("http");
    //     // Opaque:   "%2f%2fwww.example.org/",
    //     u.query = Some("q=rust+language");
    //     assert_eq!(s, u);
    // }

    #[test]
    fn non() {
        let mut u = Url::new();
        let s = Url::from("mailto://webmaster@example.org").unwrap();
        u.scheme = Some("mailto");
        u.user = Some("webmaster");
        u.host = "example.org";
        assert_eq!(s, u);
    }

    #[test]
    fn unescaped() {
        let mut u = Url::new();
        let s = Url::from("/foo?query=http://bad").unwrap();
        u.path = Some("/foo");
        u.query = Some("query=http://bad");
        assert_eq!(s, u);
    }

    #[test]
    fn leading() {
        let mut u = Url::new();
        let s = Url::from("foo").unwrap();
        u.host = "foo";
        assert_eq!(s, u);
    }

    #[test]
    fn leading2() {
        let mut u = Url::new();
        let s = Url::from("user@foo/path?a=b").unwrap();
        u.user = Some("user");
        u.host = "foo";
        u.path = Some("/path");
        u.query = Some("a=b");
        assert_eq!(s, u);
    }

    #[test]
    fn same_codepath() {
        let mut u = Url::new();
        let s = Url::from("/threeslashes").unwrap();
        u.path = Some("/threeslashes");
        assert_eq!(s, u);
    }


    // #[test]
    // fn relative_path() {
    //     let mut u = Url::new();
    //     let s = Url::from("a/b/c").unwrap();
    //     u.path = Some("a/b/c");
    //     assert_eq!(s, u);
    // }

    // #[test]
    // fn escaped() {
    //     let mut u = Url::new();
    //     let s = Url::from("http://%3Fam:pa%3Fsword@google.com").unwrap();
    //     u.scheme = Some("http");
    //     u.user = Some("?am");
    //     u.password = Some("pa?sword");
    //     u.host = "google.com";
    //     assert_eq!(s, u);
    // }

    #[test]
    fn host_subcomponent() {
        let mut u = Url::new();
        let s = Url::from("http://192.168.0.1/").unwrap();
        u.scheme = Some("http");
        u.host = "192.168.0.1";
        u.path = Some("/");
        assert_eq!(s, u);
    }

    #[test]
    fn host_and_port_subcomponents() {
        let mut u = Url::new();
        let s = Url::from("http://192.168.0.1:8080/").unwrap();
        u.scheme = Some("http");
        u.host = "192.168.0.1";
        u.port = Some("8080");
        u.path = Some("/");
        assert_eq!(s, u);
    }

    #[test]
    fn host_subcomponent2() {
        let mut u = Url::new();
        let s = Url::from("http://[fe80::1]/").unwrap();
        u.scheme = Some("http");
        u.host = "[fe80::1]";
        u.path = Some("/");
        assert_eq!(s, u);
    }

    #[test]
    fn host_and_port_subcomponents2() {
        let mut u = Url::new();
        let s = Url::from("http://[fe80::1]:8080/").unwrap();
        u.scheme = Some("http");
        u.host = "[fe80::1]";
        u.port = Some("8080");
        u.path = Some("/");
        assert_eq!(s, u);
    }

    // #[test]
    // fn host_subcomponent3() {
    //     let mut u = Url::new();
    //     let s = Url::from("http://[fe80::1%25en0]/").unwrap();
    //     u.scheme = Some("http");
    //     u.host = "[fe80::1%en0]";
    //     u.path = Some("/");
    //     assert_eq!(s, u);
    // }

    // #[test]
    // fn host_and_port_subcomponents3() {
    //     let mut u = Url::new();
    //     let s = Url::from("http://[fe80::1%25en0]:8080/").unwrap();
    //     u.scheme = Some("http");
    //     u.host = "[fe80::1%en0]";
    //     u.port = Some("8080");
    //     u.path = Some("/");
    //     assert_eq!(s, u);
    // }

    // #[test]
    // fn host_subcomponent4() {
    //     let mut u = Url::new();
    //     let s = Url::from("http:[fe80::1%25%65%6e%301-._~]/").unwrap();
    //     u.scheme = Some("http");
    //     u.host = "[fe80::1%en01-._~]";
    //     u.path = Some("/");
    //     assert_eq!(s, u);
    // }

    // #[test]
    // fn host_and_port_subcomponents4() {
    //     let mut u = Url::new();
    //     let s = Url::from("http:[fe80::1%25%65%6e%301-._~]:8080/").unwrap();
    //     u.scheme = Some("http");
    //     u.host = "[fe80::1%en01-._~]";
    //     u.port = Some("8080");
    //     u.path = Some("/");
    //     assert_eq!(s, u);
    // }

    // #[test]
    // fn alternate_escapings_of_path_survive_round_trip() {
    //     let mut u = Url::new();
    //     let s = Url::from("http://rest.rsc.io/foo%2fbar/baz%2Fquux?alt=media").unwrap();
    //     u.scheme = Some("http");
    //     u.host = "rest.rsc.io";
    //     u.path = Some("/foo/bar/baz/quux");
    //     // Rawu.path = Some("/foo%2fbar/baz%2Fquux");
    //     u.query = Some("alt=media");
    //     assert_eq!(s, u);
    // }

    #[test]
    fn issue_12036() {
        let mut u = Url::new();
        let s = Url::from("mysql://a,b,c/bar").unwrap();
        u.scheme = Some("mysql");
        u.host = "a,b,c";
        u.path = Some("/bar");
        assert_eq!(s, u);
    }

    // #[test]
    // fn worst_case_host() {
    //     let mut u = Url::new();
    //     let s = Url::from("scheme://!$&'()*+,;=hello!:port/path").unwrap();
    //     u.scheme = Some("scheme");
    //     u.host = "!$&'()*+,;=hello!";
    //     u.port = Some(":port");
    //     u.path = Some("/path");
    //     assert_eq!(s, u);
    // }

    // #[test]
    // fn worst_case_path() {
    //     let mut u = Url::new();
    //     let s = Url::from("http://host/!$&'()*+,;=:@[hello]").unwrap();
    //     u.scheme = Some("http");
    //     u.host = "host";
    //     u.path = Some("/!$&'()*+,;=:@[hello]");
    //     // Rawu.path = Some("/!$&'()*+,;=:@[hello]");
    //     assert_eq!(s, u);
    // }

    #[test]
    fn example() {
        let mut u = Url::new();
        let s = Url::from("http://example.com/oid/[order_id]").unwrap();
        u.scheme = Some("http");
        u.host = "example.com";
        u.path = Some("/oid/[order_id]");
        // Rawu.path = Some("/oid/[order_id]");
        assert_eq!(s, u);
    }

    #[test]
    fn example2() {
        let mut u = Url::new();
        let s = Url::from("http://192.168.0.2:8080/foo").unwrap();
        u.scheme = Some("http");
        u.host = "192.168.0.2";
        u.port = Some("8080");
        u.path = Some("/foo");
        assert_eq!(s, u);
    }

    //      let mut u = Url::new();
    //      let s = Url::from("http://192.168.0.2:/foo").unwrap();
    //      		u.scheme = Some("http");
    //      		u.host = "192.168.0.2:";
    //      		u.path = Some("/foo");
    //      assert_eq!(s, u);
    // }

    //      let mut u = Url::new();
    //      	 Malformed IPv6 but still accepted.
    //      let s = Url::from("http://2b01:e34:ef40:7730:8e70:5aff:fefe:edac:8080/foo").unwrap();
    //      		u.scheme = Some("http");
    //      		u.host = "2b01:e34:ef40:7730:8e70:5aff:fefe:edac:8080";
    //      		u.path = Some("/foo");
    //      assert_eq!(s, u);
    // }

    //      let mut u = Url::new();
    //      	 Malformed IPv6 but still accepted.
    //      let s = Url::from("http://2b01:e34:ef40:7730:8e70:5aff:fefe:edac:/foo").unwrap();
    //      		u.scheme = Some("http");
    //      		u.host = "2b01:e34:ef40:7730:8e70:5aff:fefe:edac:";
    //      		u.path = Some("/foo");
    //      assert_eq!(s, u);
    // }

    //      let mut u = Url::new();
    //      let s = Url::from("http:[2b01:e34:ef40:7730:8e70:5aff:fefe:edac]:8080/foo").unwrap();
    //      		u.scheme = Some("http");
    //      		u.host = "[2b01:e34:ef40:7730:8e70:5aff:fefe:edac]:8080";
    //      		u.path = Some("/foo");
    //      assert_eq!(s, u);
    // }

    //      let mut u = Url::new();
    //      let s = Url::from("http:[2b01:e34:ef40:7730:8e70:5aff:fefe:edac]:/foo").unwrap();
    //      		u.scheme = Some("http");
    //      		u.host = "[2b01:e34:ef40:7730:8e70:5aff:fefe:edac]:";
    //      		u.path = Some("/foo");
    //      assert_eq!(s, u);
    // }

    #[test]
    fn example3() {
        let mut u = Url::new();
        let s = Url::from("http://hello.世界.com/foo").unwrap();
        u.scheme = Some("http");
        u.host = "hello.世界.com";
        u.path = Some("/foo");
        assert_eq!(s, u);
    }

    //      let mut u = Url::new();
    //      let s = Url::from("http://hello.%e4%b8%96%e7%95%8c.com/foo").unwrap();
    //      		u.scheme = Some("http");
    //      		u.host = "hello.世界.com";
    //      		u.path = Some("/foo");
    //      assert_eq!(s, u);
    //      let s = Url::from("http://hello.%E4%B8%96%E7%95%8C.com/foo").unwrap();
    //      }

    //      let mut u = Url::new();
    //      let s = Url::from("http://hello.%E4%B8%96%E7%95%8C.com/foo").unwrap();
    //      		u.scheme = Some("http");
    //      		u.host = "hello.世界.com";
    //      		u.path = Some("/foo");
    //      assert_eq!(s, u);
    // }

    #[test]
    fn example4() {
        let mut u = Url::new();
        let s = Url::from("http://example.com//foo").unwrap();
        u.scheme = Some("http");
        u.host = "example.com";
        u.path = Some("//foo");
        assert_eq!(s, u);
    }

    #[test]
    fn test_that_we_can_reparse_the_host_names_we_accept() {
        let mut u = Url::new();
        let s = Url::from("myscheme://authority<\"hi\">/foo").unwrap();
        u.scheme = Some("myscheme");
        u.host = "authority<\"hi\">";
        u.path = Some("/foo");
        assert_eq!(s, u);
    }

    // #[test]
    // fn example5() {
    //     let mut u = Url::new();
    //     let s = Url::from("tcp:[2020::2020:20:2020:2020%25Windows%20Loves%20Spaces]:2020").unwrap();
    //     u.scheme = Some("tcp");
    //     u.host = "[2020::2020:20:2020:2020%Windows Loves Spaces]:2020";
    //     assert_eq!(s, u);
    // }
}