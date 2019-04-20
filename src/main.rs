// extern crate futures;
// extern crate native_tls;
// extern crate tokio;
// extern crate tokio_io;
// extern crate tokio_tls;

// use std::io;

// use futures::Future;
// use native_tls::TlsConnector;
// use tokio::net::TcpStream;
// use tokio::runtime::Runtime;

// mod from_go;
pub mod url;

use url::Url;

fn main() -> Result<(), Box<std::error::Error>> {
    println!("{:?}", Url::from("ident.me/.json")?.hostname());
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