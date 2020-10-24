///! Helpers for NTFS volume version

use std::str::FromStr;
use itertools::Itertools;

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct Version(pub u8, pub u8);

impl FromStr for Version {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s.split('.').collect_vec();
        if parts.len() != 2 {
            return Err("Version must be in the x.y format".to_owned());
        }

        Ok(Self(
            parts[0].parse().map_err(|_| "Major version is not a proper number")?,
            parts[1].parse().map_err(|_| "Minor version is not a proper number")?,
        ))
    }
}