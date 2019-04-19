
use std::net::{SocketAddr, ToSocketAddrs};

#[derive(Debug, Default)]
pub struct Url<'a> {
    shcheme: Option<&'a str>,
    user: Option<&'a str>,
    password: Option<&'a str>,
    host: &'a str,
    port: Option<&'a str>,
    // path: &'a str,
}

impl<'a> Url<'a> {
    fn new() -> Self {
        Default::default()
    }
}

fn get_path(addr: &str) -> Result<(&str, &str), &str> {
    if let Some(pos) = addr.find('/') {
        let left = addr.get(..pos).ok_or_else(|| "error ger left")?;
        let right = addr.get(pos+1..).ok_or_else(|| "error ger left")?;
        Ok((left, right))
    } else {
        Ok((addr, ""))
    }
} 

fn get_scheme(input: &str) -> Option<&str> {
    let v: Vec<&str> = input.splitn(2, "://").collect();
    if v.len() == 2 {
        Some(v[0])
    } else {
        None
    }
}

fn get_userinfo(input: &str) -> (Option<&str>, Option<&str>) {
    if let Some(pos) = input.find('@') {
        match input.get(..pos) {
            Some(user) => {
                if let Some(pos) = user.find(':') {
                    (user.get(..pos), user.get(pos+1..))
                } else {
                    (Some(user), None)
                }
            },
            None => (None, None)
        }
    } else {
        (None, None)
    }
}

fn get_port(input: &str) -> Option<&str> {
    if let Some(pos) = input.find(':') {
        let host = input.get(..pos)?;
        let other = input.get(pos+1..)?;
        if let Some(pos) = input.find('/') {
            other.get(..pos)
        } else {
            Some(other)
        }
    } else {
        None
    }
}

fn lookup(input: &str) -> Result<Url, &str> {
    let mut input = input;
    let mut host;
    let scheme = get_scheme(input);
    if let Some(scheme) = scheme {
        input = input.get(scheme.len()+3..).ok_or_else(|| "bad address")?;
    }
    let (user, password) = get_userinfo(input);
    if user.is_some() {
        if let Some(pos) = input.find('@') {
            input = input.get(pos+1..).ok_or_else(|| "bad address")?;
        }
    }
    let port = get_port(input);
    if port.is_some() {
        if let Some(pos) = input.find(':') {
            host = input.get(..pos).ok_or_else(|| "bad address")?;
            input = input.get(port.ok_or_else(|| "bad address")?.len()+pos+1..).ok_or_else(|| "bad address")?;
        }
    } else {

    }
    Ok(Url{
        scheme,
        hostname: hostname.to_string(),
        path: path.to_string()
    })
}
