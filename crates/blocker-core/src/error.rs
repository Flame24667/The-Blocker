use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockerError {
    EmptyDomain,
    InvalidDomain(String),
    InvalidRule(String),
}

impl Display for BlockerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyDomain => write!(f, "domain is empty"),
            Self::InvalidDomain(domain) => write!(f, "invalid domain: {domain}"),
            Self::InvalidRule(rule) => write!(f, "invalid rule: {rule}"),
        }
    }
}

impl Error for BlockerError {}
