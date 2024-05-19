use std::{fmt::{self, Formatter, Display}, error::Error, io};

#[derive(Debug)]
pub enum PassNMError {
    MissingConnection,
    InvalidSecurity,
    DbusError(dbus::Error),
    NonExistentNetwork,
    NoPassValue,
    IoError(io::Error),
    Unknown(String)
}

impl Display for PassNMError {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), fmt::Error> {
        match self {
            Self::MissingConnection => write!(fmt, "Missing required connection or network ID"),
            Self::InvalidSecurity => write!(fmt, "Missing or invalid network security"),
            Self::DbusError(err) => write!(fmt, "D-BUS error: {}", err),
            Self::NoPassValue => write!(fmt, "Value does not exist in pass"),
            Self::IoError(err) => write!(fmt, "IO error: {}", err),
            Self::NonExistentNetwork => write!(fmt, "Network does not exist"),
            Self::Unknown(err) => write!(fmt, "An unknown error occurred: {}", err)
        }
    }
}

impl Error for PassNMError {}
