use std::fmt;
use std::iter::once;
use std::mem;
use std::result::Result as StdResult;

use either::Either;
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
            Length::Expr(expr) => tokens.append_all(quote! { ( #expr ) }),
            Length::Func(func) => tokens.append_all(quote! { #func(&self.to_immutable()) }),
        }
    }
}

impl From<usize> for Length {
    fn from(bits: usize) -> Self {
        Length::Bits(bits)
    }
}

impl From<syn::Expr> for Length {
    fn from(expr: syn::Expr) -> Self {
        Length::Expr(expr)
    }
}

impl From<syn::Ident> for Length {
    fn from(func: syn::Ident) -> Self {
        Length::Func(func)
    }
}

pub trait ToBitsOffset {
    fn bits_offset(&self) -> Either<usize, TokenStream>;
}

pub trait ToBytesOffset {
    fn prev_bytes(&self) -> Either<usize, TokenStream>;

    fn next_bytes(&self) -> Either<usize, TokenStream>;

    fn prev_bytes_offset(&self) -> TokenStream {
        self.prev_bytes()
            .either(|offset| quote! { #offset }, |offset| offset)
    }

    fn next_bytes_offset(&self) -> TokenStream {
        self.next_bytes()
            .either(|offset| quote! { #offset }, |offset| offset)
    }
}

impl ToBitsOffset for usize {
    fn bits_offset(&self) -> Either<usize, TokenStream> {
        Either::Left(*self)
    }
}

impl ToBytesOffset for usize {
    fn prev_bytes(&self) -> Either<usize, TokenStream> {
        Either::Left(self / 8)
    }

    fn next_bytes(&self) -> Either<usize, TokenStream> {
        Either::Left((*self + 7) / 8)
    }
}

impl<'a> ToBitsOffset for &'a [Length] {
    fn bits_offset(&self) -> Either<usize, TokenStream> {
        let mut offsets = reduce_offsets(self.iter());

        match (offsets.next(), offsets.next()) {
            (Some(Length::Bits(bits)), None) => Either::Left(bits),
            (Some(Length::Bits(bits)), offset) => Either::Right(quote! {
                #bits + (#offset #( + #offsets )*) * 8
            }),
            _ => Either::Left(0),
        }
    }
}

impl<'a> ToBytesOffset for &'a [Length] {
    fn prev_bytes(&self) -> Either<usize, TokenStream> {
        let mut offsets = reduce_offsets(self.iter());

        match (offsets.next(), offsets.next()) {
            (Some(Length::Bits(bits)), None) => Either::Left(bits / 8),
            (Some(Length::Bits(bits)), offset) => {
                let off = bits / 8;

                Either::Right(quote! {
                    #off + #offset #( + #offsets )*
                })
            }
            _ => Either::Left(0),
        }
    }

    fn next_bytes(&self) -> Either<usize, TokenStream> {
        let mut offsets = reduce_offsets(self.iter());

        match (offsets.next(), offsets.next()) {
            (Some(Length::Bits(bits)), None) => Either::Left(bits / 8),
            (Some(Length::Bits(bits)), Some(offset)) => {
                let off = (bits + 7) / 8;

                Either::Right(quote! {
                    #off + #offset #( + #offsets )*
                })
            }
            _ => Either::Left(0),
        }
    }
}

fn reduce_offsets<'a, I: IntoIterator<Item = &'a Length>>(lens: I) -> impl Iterator<Item = Length> {
    let (length_funcs, total_bits, aligned) = lens.into_iter().fold(
        (vec![], 0, false),
        |(mut lens, total_bits, aligned), len| {
            if let Length::Bits(bits) = len {
                (lens, total_bits + bits, aligned)
            } else {
                lens.push(len.clone());

                (lens, align_offset::<u8>(total_bits), true)
            }
        },
    );

    let total_len = Length::Bits(total_bits);

    once(total_len).chain(length_funcs.into_iter())
}

pub fn align_offset<T>(bits: usize) -> usize {
    let align = mem::align_of::<T>() * 8;

    ((bits + align - 1) / align) * align
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
    fn test_length() {
        let len = Length::Bits(32);
        assert_eq!(len, 32.into());
        assert_eq!(len.into_token_stream().to_string(), "32usize");

        let expr: syn::Expr = parse_quote!{ 1 + 2 };
        let len = Length::Expr(expr.clone());

        assert_eq!(len, expr.into());
        assert_eq!(len.into_token_stream().to_string(), "( 1 + 2 )");

        let func = ident!("foo");
        let len = Length::Func(func.clone());

        assert_eq!(len, func.into());
        assert_eq!(
            len.into_token_stream().to_string(),
            "foo ( & self . to_immutable ( ) )"
        );
    }

    #[test]
    fn test_bytes_offset() {
        assert_eq!(12usize.prev_bytes_offset().to_string(), "1usize");
        assert_eq!(16usize.prev_bytes_offset().to_string(), "2usize");
        assert_eq!(18usize.prev_bytes_offset().to_string(), "2usize");

        assert_eq!(12usize.next_bytes_offset().to_string(), "2usize");
        assert_eq!(16usize.next_bytes_offset().to_string(), "2usize");
        assert_eq!(18usize.next_bytes_offset().to_string(), "3usize");

        let funcs = &[
            Length::Bits(1),
            Length::Bits(2),
            Length::Expr(parse_quote! { 1 + 2 * 3 }),
            Length::Bits(4),
            Length::Func(ident!("foo")),
            Length::Bits(8),
            Length::Bits(3),
        ][..];

        assert_eq!(
            funcs.prev_bytes_offset().to_string(),
            "3usize + ( 1 + 2 * 3 ) + foo ( & self . to_immutable ( ) )"
        );

        assert_eq!(
            funcs.next_bytes_offset().to_string(),
            "4usize + ( 1 + 2 * 3 ) + foo ( & self . to_immutable ( ) )"
        );
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
