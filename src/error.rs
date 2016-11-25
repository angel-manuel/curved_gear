use std::io;
use std::string::String;
use std::convert::From;
use std::borrow::Cow;

use bincode::rustc_serialize as bcode_rcs;

#[derive(Debug)]
pub enum Error {
    CCP(Cow<'static, str>),
    IO(io::Error),
    DecodingError(bcode_rcs::DecodingError),
}

impl From<Cow<'static, str>> for Error {
    fn from(desc: Cow<'static, str>) -> Error {
        Error::CCP(desc)
    }
}

impl From<String> for Error {
    fn from(desc: String) -> Error {
        Cow::Owned::<'static, str>(desc).into()
    }
}

impl From<&'static str> for Error {
    fn from(desc: &'static str) -> Error {
        Cow::Borrowed(desc).into()
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IO(err)
    }
}

impl From<bcode_rcs::DecodingError> for Error {
    fn from(err: bcode_rcs::DecodingError) -> Error {
        Error::DecodingError(err)
    }
}
