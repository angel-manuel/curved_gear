use std::io;
use std::string::String;
use std::convert::From;

use bincode::rustc_serialize as bcode_rcs;

pub enum Error {
    CCP(String),
    IO(io::Error),
    DecodingError(bcode_rcs::DecodingError),
}

impl From<String> for Error {
    fn from(desc: String) -> Error {
        Error::CCP(desc)
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
