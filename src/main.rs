extern crate tokio;
extern crate native_tls;

mod stream;

use std::fmt;
use std::io;
use futures::{Async, Future, Poll};
use tokio::net::{Connect, Connected, Destination, HttpConnector};
use native_tls::{Error, HandshakeError, TlsConnector};

#[macro_use]
extern crate tokio_io;

use self::stream::{MaybeHttpsStream, TlsStream};

#[derive(Clone)]
pub struct SOCKSConnector<T> {
    force_https: bool,
    http: T,
    tls: TlsConnector,
}

impl SOCKSConnector<HttpConnector> {
    pub fn new(threads: usize) -> Result<Self, Error> {
        TlsConnector::builder()
            .build()
            .map(|tls| SOCKSConnector::new_(threads, tls))
    }

    fn new_(threads: usize, tls: TlsConnector) -> Self {
        let mut http = HttpConnector::new(threads);
        http.enforce_http(false);
        SOCKSConnector::from((http, tls))
    }
}

impl<T> SOCKSConnector<T> {
    pub fn https_only(&mut self, enable: bool) {
        self.force_https = enable;
    }
}

impl<T> From<(T, TlsConnector)> for SOCKSConnector<T> {
    fn from(args: (T, TlsConnector)) -> SOCKSConnector<T> {
        SOCKSConnector {
            force_https: false,
            http: args.0,
            tls: args.1,
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for SOCKSConnector<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("HttpsConnector")
            .field("force_https", &self.force_https)
            .field("http", &self.http)
            .finish()
    }
}

impl<T> Connect for SOCKSConnector<T>
where
    T: Connect<Error=io::Error>,
    T::Transport: 'static,
    T::Future: 'static,
{
    type Transport = MaybeHttpsStream<T::Transport>;
    type Error = io::Error;
    type Future = HttpsConnecting<T::Transport>;

    fn connect(&self, dst: Destination) -> Self::Future {
        let is_https = dst.scheme() == "https";
        let host = dst.host().to_owned();
        let connecting = self.http.connect(dst);
        let tls = self.tls.clone();
        let fut: BoxedFut<T::Transport> = if is_https {
            let fut = connecting.and_then(move |(tcp, connected)| {
                let handshake = Handshaking {
                    inner: Some(tls.connect(&host, tcp)),
                };
                handshake
                    .map(|conn| (MaybeHttpsStream::Https(TlsStream::new(conn)), connected))
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
            });
            Box::new(fut)
        } else {
            Box::new(connecting.map(|(tcp, connected)| {
                (MaybeHttpsStream::Http(tcp), connected)
            }))
        };
        HttpsConnecting(fut)
    }
}

type BoxedFut<T> = Box<Future<Item=(MaybeHttpsStream<T>, Connected), Error=io::Error> + Send>;

pub struct HttpsConnecting<T>(BoxedFut<T>);

impl<T> Future for HttpsConnecting<T> {
    type Item = (MaybeHttpsStream<T>, Connected);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

impl<T> fmt::Debug for HttpsConnecting<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.pad("HttpsConnecting")
    }
}

struct Handshaking<T> {
    inner: Option<Result<native_tls::TlsStream<T>, HandshakeError<T>>>,
}

impl<T: io::Read + io::Write> Future for Handshaking<T> {
    type Item = native_tls::TlsStream<T>;
    type Error = native_tls::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.inner.take().expect("polled after ready") {
            Ok(stream) => Ok(stream.into()),
            Err(HandshakeError::WouldBlock(mid)) => {
                match mid.handshake() {
                    Ok(stream) => Ok(stream.into()),
                    Err(HandshakeError::Failure(err)) => Err(err),
                    Err(HandshakeError::WouldBlock(mid)) => {
                        self.inner = Some(Err(HandshakeError::WouldBlock(mid)));
                        Ok(Async::NotReady)
                    }
                }
            },
            Err(HandshakeError::Failure(err)) => Err(err),
        }
    }
}

fn main() {
    println!("Hello, world!");
}
