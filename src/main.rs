// extern crate futures;
// extern crate native_tls;
// extern crate tokio;
// extern crate tokio_io;
// extern crate tokio_tls;

// use std::io;
use std::net::{SocketAddr, ToSocketAddrs};

// use futures::Future;
// use native_tls::TlsConnector;
// use tokio::net::TcpStream;
// use tokio::runtime::Runtime;

#[derive(Debug)]
struct Url {
    socket_addr: SocketAddr,
    hostname: String,
    path: String,
}

// impl Url {
//     fn new() -> Self {

//     }
// }

fn get_path(addr: &str) -> Result<(&str, &str), &str> {
    if let Some(pos) = addr.find('/') {
        let left = addr.get(..pos).ok_or_else(|| "error ger left")?;
        let right = addr.get(pos+1..).ok_or_else(|| "error ger left")?;
        Ok((left, right))
    } else {
        Ok((addr, ""))
    }
} 

fn lookup(addr: &str) -> Result<Url, &str> {
    let mut scheme = "http";
    let mut port = "80";
    let mut addr = addr;
    let path;
    if addr.starts_with("https://") {
        scheme = "https";
        addr = addr.get(8..).ok_or_else(|| "wrong https address")?;
    } else if addr.starts_with("http://") {
        addr = addr.get(7..).ok_or_else(|| "wrong http address")?;
    };
    if let Some(pos) = addr.find(':') {
        port = addr.get(pos+1..).ok_or_else(||"wrong port")?;
        addr = addr.get(..pos).ok_or_else(|| "wrong address")?;
        let tpath = get_path(port)?;
        port = tpath.0;
        path = tpath.1;
    } else {
        let tpath = get_path(addr)?;
        addr = tpath.0;
        path = tpath.1;
        if port == "80" && scheme == "https" {
            port = "443";
        }
    };
    let hostname = format!("{}:{}", addr, port);
    let s_addr = hostname.to_socket_addrs().map_err(|_| "failed to socket")?
    .next()
    .ok_or_else(|| "failed to resolve")?;
    Ok(Url{
        socket_addr: s_addr,
        hostname: hostname.to_string(),
        path: path.to_string()
    })
}

fn main() -> Result<(), Box<std::error::Error>> {
    println!("{:?}", lookup("ident.me:90/.json"));
    println!("{:?}", lookup("ident.me:80/.json"));
    println!("{:?}", lookup("ident.me:/.json"));
    // let mut runtime = Runtime::new()?;
    // let addr = "ident.me/.json"
    //     .to_socket_addrs()?
    //     .next()
    //     .ok_or("failed to resolve ident.me")?;

    // let socket = TcpStream::connect(&addr);
    // let cx = TlsConnector::builder().build()?;
    // let cx = tokio_tls::TlsConnector::from(cx);

    // let tls_handshake = socket.and_then(move |socket| {
    //     cx.connect("www.rust-lang.org", socket)
    //         .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    // });
    // let request = tls_handshake.and_then(|socket| {
    //     tokio_io::io::write_all(
    //         socket,
    //         "\
    //          GET / HTTP/1.0\r\n\
    //          Host: www.rust-lang.org\r\n\
    //          \r\n\
    //          "
    //         .as_bytes(),
    //     )
    // });
    // let response = request.and_then(|(socket, _)| tokio_io::io::read_to_end(socket, Vec::new()));

    // let (_, data) = runtime.block_on(response)?;
    // println!("{}", String::from_utf8_lossy(&data));
    Ok(())
}