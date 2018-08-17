use std::fmt;
use std::iter::once;
use std::result::Result as StdResult;

use failure::Error;
use proc_macro2::TokenStream;
use quote::{ToTokens, TokenStreamExt};
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

#[derive(Clone, Debug, PartialEq)]
pub enum Length {
    Bits(usize),
    Expr(syn::Expr),
    Func(syn::Ident),
}

impl ToTokens for Length {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self {
            Length::Bits(bits) => bits.to_tokens(tokens),
            Length::Expr(expr) => expr.to_tokens(tokens),
            Length::Func(func) => tokens.append_all(quote! {
                #func(&self.to_immutable())
            }),
        }
    }
}

pub trait ToBytesOffset {
    fn bytes_offset(&self) -> TokenStream;
}

impl ToBytesOffset for usize {
    fn bytes_offset(&self) -> TokenStream {
        let offset = (*self + 7) / 8;

        quote! { #offset }
    }
}

impl<'a> ToBytesOffset for &'a [Length] {
    fn bytes_offset(&self) -> TokenStream {
        let offsets = reduce_offset(self.iter()).collect::<Vec<_>>();

        match offsets.first() {
            Some(Length::Bits(bits)) if offsets.len() == 1 => {
                let offset = (bits + 7) / 8;

                quote! { #offset }
            }
            _ => {
                let length_funcs = self;

                quote! { #(#length_funcs)+* }
            }
        }
    }
}

fn reduce_offset<'a, I: IntoIterator<Item = &'a Length>>(lens: I) -> impl Iterator<Item = Length> {
    let (length_funcs, total_bits) =
        lens.into_iter()
            .fold((vec![], 0), |(mut lens, total_bits), len| {
                if let Length::Bits(bits) = len {
                    (lens, total_bits + bits)
                } else {
                    lens.push(len.clone());
                    (lens, total_bits)
                }
            });

    let total_len = Length::Bits(total_bits);

    once(total_len).chain(length_funcs.into_iter())
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
