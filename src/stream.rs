use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut};
// use futures::Poll;
use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tls::TlsStream;

pub enum MaybeHttpsStream {
    /// A stream over plain text.
    Http(TcpStream),
    /// A stream protected with TLS.
    Https(TlsStream<TcpStream>),
}

// /// A stream protected with TLS.
// pub struct TlsStream<T> {
//     inner: native_tls::TlsStream<T>,
// }

impl fmt::Debug for MaybeHttpsStream {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MaybeHttpsStream::Http(s) => f.debug_tuple("Http").field(s).finish(),
            MaybeHttpsStream::Https(s) => f.debug_tuple("Https").field(s).finish(),
        }
    }
}

impl From<TcpStream> for MaybeHttpsStream {
    fn from(inner: TcpStream) -> Self {
        MaybeHttpsStream::Http(inner)
    }
}

impl From<TlsStream<TcpStream>> for MaybeHttpsStream {
    fn from(inner: TlsStream<TcpStream>) -> Self {
        MaybeHttpsStream::Https(inner)
    }
}

impl AsyncRead for MaybeHttpsStream {
    #[inline]
    unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [std::mem::MaybeUninit<u8>]) -> bool {
        match self {
            MaybeHttpsStream::Http(s) => s.prepare_uninitialized_buffer(buf),
            MaybeHttpsStream::Https(s) => s.prepare_uninitialized_buffer(buf),
        }
    }

    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_read(cx, buf),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_read(cx, buf),
        }
    }

    #[inline]
    fn poll_read_buf<B: BufMut>(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut B,
    ) -> Poll<Result<usize, io::Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_read_buf(cx, buf),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_read_buf(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeHttpsStream {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_write(cx, buf),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_write_buf<B: Buf>(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut B,
    ) -> Poll<Result<usize, io::Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_write_buf(cx, buf),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_write_buf(cx, buf),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_flush(cx),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_shutdown(cx),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

// impl<T: AsyncRead + AsyncWrite + Connection + Unpin> Connection for MaybeHttpsStream<T> {
//     fn connected(&self) -> Connected {
//         match self {
//             MaybeHttpsStream::Http(s) => s.connected(),
//             MaybeHttpsStream::Https(s) => s.get_ref().connected(),
//         }
//     }
// }
