// use url::Url;
// use std::io;
// use futures::Future;
// use tokio::prelude::*;
// use socks::Address;
// use tokio::runtime::Runtime;
// use tokio_io::io::{flush, read_to_end, write_all};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use bytes::Bytes;

// use socketstream::SocksStream;

mod addr;
mod authority;
mod errors;
mod range;
mod socks5;
mod stream;
mod uri;

// use tokio::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // env_logger::init();
    // let mut stream = socks5::connect("127.0.0.1:9050", "http://api.ipify.org").await?;

    //     let mut runtime = Runtime::new().unwrap();
    // //    let url = Url::from("ident.me/.json").unwrap();
    //     let url = Url::parse("https://httpbin.org/ip").unwrap();
    //     dbg!(&url);
    //     let proxy = Url::parse("http://127.0.0.1:9050").unwrap();
    //     dbg!(&proxy);
    //     let proxy_sa = proxy.socket_addrs(|| Some(9050)).unwrap();
    //     dbg!(&proxy_sa);

    //     let client =
    //         client::Socks5Client::connect(Address::DomainNameAddress("ident.me".to_owned(), 80), *proxy_sa.first().unwrap());

    let mut stream = socks5::connect("127.0.0.1:5959", "https://api.ipify.org").await?;
    let get = Bytes::from("GET / HTTP/1.0\r\nHost: api.ipify.org\r\n\r\n");
        // .to_string()
        // .into_bytes();
    let buffer = stream.get(get).await?;
    // stream.read_to_string(&mut buffer).await?;
    println!("{}", buffer);

    // let mut stream =
    //     socks5::connect_plain("127.0.0.1:5757", "http://api.ipify.org", "test", "tset").await?;
    // let get = "GET / HTTP/1.0\r\nHost: api.ipify.org\r\n\r\n"
    //     .to_string()
    //     .into_bytes();
    // stream.write_all(&get).await?;
    // let mut buffer = String::new();
    // stream.read_to_string(&mut buffer).await?;
    // println!("{}", buffer);

    //     let request = client.and_then(|c| {
    //         write_all(c, get)
    //             .and_then(|(c, _)| flush(c))
    //             .and_then(|c| read_to_end(c, Vec::new()))
    //             .map(|(_, buf)| {
    //                 println!("Got reply from server: {}", String::from_utf8(buf).unwrap());
    //             })
    //     });
    //     //  and_then(move |stream| io::write_all(stream, get));
    //     // let response = request.and_then(|(stream, _)| io::read_to_end(stream, Vec::new()));

    //     runtime.block_on(request).unwrap();
    //     // println!("{}", String::from_utf8_lossy(&data));
    Ok(())
    //
}
