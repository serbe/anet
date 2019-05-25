use crate::url::Url;
use futures::Future;
use socks::Address;
use tokio::runtime::Runtime;
use tokio_io::io::{flush, read_to_end, write_all};

mod client;
mod socks;
// mod addr;
mod errors;
mod url;
mod utils;

fn main() {
    let mut runtime = Runtime::new().unwrap();
    let url = Url::from("ident.me/.json").unwrap();
    let proxy = Url::from("127.0.0.1:9050").unwrap().socket_addr().unwrap();
    let client =
        client::Socks5Client::connect(Address::DomainNameAddress("ident.me".to_owned(), 80), proxy);

    let get = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\n\r\n",
        url.path(),
        url.hostname()
    )
    .into_bytes();

    let request = client.and_then(|c| {
        write_all(c, get)
            .and_then(|(c, _)| flush(c))
            .and_then(|c| read_to_end(c, Vec::new()))
            .map(|(_, buf)| {
                println!("Got reply from server: {}", String::from_utf8(buf).unwrap());
            })
    });
    //  and_then(move |stream| io::write_all(stream, get));
    // let response = request.and_then(|(stream, _)| io::read_to_end(stream, Vec::new()));

    runtime.block_on(request).unwrap();
    // println!("{}", String::from_utf8_lossy(&data));
    // Ok(())
}
