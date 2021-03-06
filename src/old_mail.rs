use futures::future::Future;
use tokio::io;
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use url::Url;

pub mod url;

fn main() -> Result<(), Box<std::error::Error>> {
    let mut runtime = Runtime::new()?;
    let url = Url::from("ident.me/.json")?;
    let addr = url.socket_addr().ok_or_else(|| "bad socket addr")?;

    let socket = TcpStream::connect(&addr);
    let get = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\n\r\n",
        url.path(),
        url.hostname()
    )
    .into_bytes();

    let request = socket.and_then(move |stream| io::write_all(stream, get));
    let response = request.and_then(|(stream, _)| io::read_to_end(stream, Vec::new()));

    let (_, data) = runtime.block_on(response)?;
    println!("{}", String::from_utf8_lossy(&data));
    Ok(())
}


mod future;
mod interval;

use self::future::IntervalFuture;
use self::interval::Interval;
use tokio::prelude::*;

struct IntervalPrinter(IntervalFuture);

impl Future for IntervalPrinter {
    type Item = ();
    type Error = ();
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.0.poll() {
            Ok(Async::Ready(curr)) => {
                println!("Counter is: {}", curr);
                Ok(Async::Ready(()))
            }
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(e) => Err(e),
        }
    }
}

fn main() {
    let interval = Interval::from_millis(500); // half a second
    let interval_future = IntervalFuture::new(interval);
    let interval_printer = IntervalPrinter(interval_future);

    tokio::run(interval_printer)
}