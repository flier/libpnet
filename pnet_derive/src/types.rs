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

pub fn parse_primitive(ty: &str) -> Option<(usize, Option<Endianness>)> {
    let re = Regex::new(r"^u([0-9]+)(be|le|he)?$").unwrap();
    let m = re.captures_iter(ty).next()?;
    let size = m.get(1)?.as_str().parse().ok()?;
    let endianess = match m.get(2).map(|m| m.as_str()) {
        Some("le") => Some(Endianness::Little),
        Some("be") | None => Some(Endianness::Big),
        Some("he") => None,
        _ => return None,
    };

    if endianess.is_some() && size < 8 {
        panic!("endianness must be specified for types of size >= 8")
    }

    Some((size, endianess))
}

pub fn parse_vec(ty: &syn::Type) -> Option<(syn::Ident, usize, Option<Endianness>)> {
    match ty {
        syn::Type::Path(syn::TypePath {
            path: syn::Path { ref segments, .. },
            ..
        }) if segments.len() == 1 && segments.last()?.value().ident == "Vec" =>
        {
            match segments.last()?.value().arguments {
                syn::PathArguments::AngleBracketed(syn::AngleBracketedGenericArguments {
                    ref args,
                    ..
                }) if args.len() == 1 =>
                {
                    match args.last()?.value() {
                        syn::GenericArgument::Type(syn::Type::Path(syn::TypePath {
                            path: syn::Path { segments, .. },
                            ..
                        })) if segments.len() == 1 =>
                        {
                            let inner_ty = segments.last()?.value().ident.clone();

                            parse_primitive(&inner_ty.to_string())
                                .map(|(size, endianness)| (inner_ty, size, endianness))
                        }
                        _ => None,
                    }
                }
                _ => None,
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_as_primitive() {
        assert_eq!(parse_primitive("u8"), Some((8, Some(Endianness::Big))));
        assert_eq!(parse_primitive("u21be"), Some((21, Some(Endianness::Big))));
        assert_eq!(
            parse_primitive("u21le"),
            Some((21, Some(Endianness::Little)))
        );
        assert_eq!(parse_primitive("u21he"), Some((21, None)));
        assert_eq!(parse_primitive("u9"), Some((9, Some(Endianness::Big))));
        assert_eq!(parse_primitive("u16"), Some((16, Some(Endianness::Big))));
        assert_eq!(parse_primitive("uable"), None);
        assert_eq!(parse_primitive("u21re"), None);
        assert_eq!(parse_primitive("i21be"), None);
    }
}
