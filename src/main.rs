// use url::Url;
// use std::io;
// use futures::Future;
// use tokio::prelude::*;
// use socks::Address;
// use tokio::runtime::Runtime;
// use tokio_io::io::{flush, read_to_end, write_all};
use tokio::io::{AsyncWriteExt, AsyncReadExt};

use socketstream::SocksStream;

// mod client;
mod addr;
mod socketstream;
// mod errors;
// mod url;
// mod utils;

// use tokio::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Hello from Tokio!");
    let socket = SocksStream::connect("127.0.0.1:5959", "http://api.ipify.org").await?;
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

    // let get = "GET / HTTP/1.0\r\nHost: ident.me\r\n\r\n"
    //     .to_string()
    //     .into_bytes();

    // socket.write_all(&get).await?;
    // let buffer = socket.read_string().await?;

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
