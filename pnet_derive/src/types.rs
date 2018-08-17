use std::fmt;
use std::result::Result as StdResult;

use failure::Error;
use regex::Regex;
use syn;

pub type Result<T> = StdResult<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Endianness {
    Little,
    Big,
}

impl Endianness {
    pub fn name(self) -> &'static str {
        match self {
            Endianness::Little => "little",
            Endianness::Big => "big",
        }
    }
}

impl fmt::Display for Endianness {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

pub fn parse_primitive(ty: &syn::Ident) -> Option<(usize, Option<Endianness>)> {
    let re = Regex::new(r"^u([0-9]+)(be|le|he)?$").unwrap();
    let ty_name = ty.to_string();
    let m = re.captures_iter(&ty_name).next()?;
    let size = m.get(1)?.as_str().parse().ok()?;
    let endianess = match m.get(2).map(|m| m.as_str()) {
        Some("le") => Some(Endianness::Little),
        Some("be") | None => Some(Endianness::Big),
        Some("he") => None,
        _ => return None,
    };

    Some((size, endianess))
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! ident {
        ($name:expr) => {
            ident!($name, ::proc_macro2::Span::call_site())
        };
        ($name:expr, $span:expr) => {
            ::syn::Ident::new($name, $span)
        };
    }

    #[test]
    fn test_parse_primitive() {
        assert_eq!(
            parse_primitive(&ident!("u8")),
            Some((8, Some(Endianness::Big)))
        );
        assert_eq!(
            parse_primitive(&ident!("u21be")),
            Some((21, Some(Endianness::Big)))
        );
        assert_eq!(
            parse_primitive(&ident!("u21le")),
            Some((21, Some(Endianness::Little)))
        );
        assert_eq!(parse_primitive(&ident!("u21he")), Some((21, None)));
        assert_eq!(
            parse_primitive(&ident!("u9")),
            Some((9, Some(Endianness::Big)))
        );
        assert_eq!(
            parse_primitive(&ident!("u16")),
            Some((16, Some(Endianness::Big)))
        );
        assert_eq!(parse_primitive(&ident!("uable")), None);
        assert_eq!(parse_primitive(&ident!("u21re")), None);
        assert_eq!(parse_primitive(&ident!("i21be")), None);
    }
}
