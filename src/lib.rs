use std::{error::Error, fmt::Display};

mod de;
mod ser;
mod tcp;

#[derive(Debug)]
pub enum TomError {}

impl Display for TomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unimplemented!()
    }
}

impl Error for TomError {}
