use std::io::{Error, ErrorKind};
use futures::Future;

pub fn err_from(s: &str) -> Error {
    Error::new(ErrorKind::Other, s)
}

pub fn f_box<F: Future + 'static + Send>(f: F) -> Box<Future<Item = F::Item, Error = F::Error> + Send> {
    Box::new(f)
}