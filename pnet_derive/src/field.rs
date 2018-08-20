use proc_macro2::{Span, TokenStream};
use quote::{ToTokens, TokenStreamExt};
use syn::{self, spanned::Spanned};

use gen::{read_operations, write_operations};
use types::{parse_primitive, Endianness, Length, Result};

#[derive(Clone, Debug, PartialEq)]
pub struct Field {
    pub ident: syn::Ident,
    pub ty: syn::Type,
    pub kind: Kind,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    Primitive {
        bits: usize,
        endianness: Option<Endianness>,
    },
    Vec {
        item_ty: syn::Ident,
        item_bits: usize,
        endianness: Option<Endianness>,
        packet_length: Option<Length>,
    },
    Custom {
        construct_with: Vec<syn::Ident>,
    },
}

impl Field {
    pub fn parse(field: syn::Field) -> Result<Self> {
        let field_name = field
            .ident
            .ok_or_else(|| format_err!("all fields in a packet must be named"))?;
        let field_ty = field.ty;

        let mut is_payload = false;
        let mut packet_length = None;
        let mut construct_with = vec![];

        for attr in field.attrs {
            match attr.interpret_meta() {
                Some(syn::Meta::Word(ref ident)) if ident == "payload" => {
                    is_payload = true;
                }
                Some(syn::Meta::List(syn::MetaList {
                    ref ident,
                    ref nested,
                    ..
                })) if ident == "construct_with" =>
                {
                    if nested.is_empty() {
                        bail!("#[construct_with] must have at least one argument")
                    }

                    for meta in nested {
                        if let syn::NestedMeta::Meta(syn::Meta::Word(ident)) = meta {
                            if parse_primitive(&ident).is_none() {
                                bail!("arguments to #[construct_with] must be primitives")
                            }

                            construct_with.push(ident.clone())
                        } else {
                            bail!("#[construct_with] should be of the form #[construct_with(<types>)]")
                        }
                    }
                }
                Some(syn::Meta::NameValue(syn::MetaNameValue {
                    ref ident, ref lit, ..
                })) if ident == "length" =>
                {
                    packet_length = match lit {
                        syn::Lit::Str(lit) => {
                            let expr: syn::Expr = syn::parse_str(&lit.value())?;

                            Some(Length::Expr(expr))
                        }
                        syn::Lit::Int(lit) => {
                            let n = lit.value() as usize;

                            Some(Length::Bits(n))
                        }
                        _ => bail!("expected attribute to be a string `{} = \"...\"`", ident),
                    };
                }
                Some(syn::Meta::NameValue(syn::MetaNameValue {
                    ref ident, ref lit, ..
                })) if ident == "length_fn" =>
                {
                    let length_fn = match lit {
                        syn::Lit::Str(lit) => syn::Ident::new(&lit.value(), Span::call_site()),
                        _ => bail!("expected attribute to be a string `{} = \"...\"`", ident),
                    };

                    packet_length = Some(Length::Func(length_fn));
                }
                _ => bail!("unknown attribute {}", attr.into_token_stream()),
            }
        }

        match field_ty {
            syn::Type::Path(syn::TypePath {
                path: syn::Path { ref segments, .. },
                ..
            }) if segments.len() == 1 =>
            {
                let segment = segments.last().unwrap();
                let ty = segment.value();

                if ty.ident == "Vec" {
                    match ty.arguments {
                        syn::PathArguments::AngleBracketed(
                            syn::AngleBracketedGenericArguments { ref args, .. },
                        ) if args.len() == 1 =>
                        {
                            match args.last().unwrap().value() {
                                syn::GenericArgument::Type(syn::Type::Path(syn::TypePath {
                                    path: syn::Path { segments, .. },
                                    ..
                                })) if segments.len() == 1 =>
                                {
                                    let segment = segments.last().unwrap();
                                    let item_ty = &segment.value().ident;

                                    if let Some((item_bits, endianness)) = parse_primitive(item_ty)
                                    {
                                        if !is_payload && packet_length.is_none() {
                                            bail!("variable length field must have #[length] or #[length_fn] attribute")
                                        }
                                        if item_ty == "Vec" {
                                            bail!("variable length fields may not contain vectors")
                                        }
                                        if item_bits % 8 != 0 {
                                            bail!("variable length fields must align to byte")
                                        }

                                        Some(Kind::Vec {
                                            item_ty: item_ty.clone(),
                                            item_bits,
                                            endianness,
                                            packet_length,
                                        })
                                    } else {
                                        None
                                    }
                                }
                                _ => None,
                            }
                        }
                        _ => None,
                    }
                } else if let Some((bits, endianness)) = parse_primitive(&ty.ident) {
                    Some(Kind::Primitive { bits, endianness })
                } else {
                    None
                }
            }
            _ => None,
        }.or_else(|| {
            if !construct_with.is_empty() || is_payload {
                Some(Kind::Custom { construct_with })
            } else {
                None
            }
        })
            .ok_or_else(|| format_err!("non-primitive field types must specify #[construct_with]"))
            .map(|kind| Field {
                ident: field_name,
                ty: field_ty,
                kind,
            })
    }

    pub fn name(&self) -> &syn::Ident {
        &self.ident
    }

    pub fn ty(&self) -> &syn::Type {
        &self.ty
    }

    pub fn span(&self) -> Span {
        self.ident.span()
    }

    pub fn bits(&self) -> Option<Length> {
        match self.kind {
            Kind::Primitive { bits, .. } => Some(Length::Bits(bits)),
            Kind::Vec {
                ref packet_length, ..
            } => packet_length.clone(),
            Kind::Custom { ref construct_with } => Some(Length::Bits(
                construct_with
                    .iter()
                    .flat_map(|ty| parse_primitive(ty).map(|(bits, _)| bits))
                    .sum(),
            )),
        }
    }

    pub fn len(&self) -> Option<Length> {
        match self.kind {
            Kind::Primitive { bits, .. } => Some(Length::Bits(bits)),
            Kind::Vec { .. } => {
                let field_name = self.name();

                Some(Length::Expr(parse_quote!{ self.packet.#field_name.len() }))
            }
            Kind::Custom { ref construct_with } => Some(Length::Bits(
                construct_with
                    .iter()
                    .flat_map(|ty| parse_primitive(ty).map(|(bits, _)| bits))
                    .sum(),
            )),
        }
    }

    pub fn as_primitive(&self) -> Option<(usize, Option<Endianness>)> {
        match self.kind {
            Kind::Primitive { bits, endianness } => Some((bits, endianness)),
            _ => None,
        }
    }

    pub fn as_vec(&self) -> Option<(&syn::Ident, usize, Option<Endianness>, Option<&Length>)> {
        match self.kind {
            Kind::Vec {
                ref item_ty,
                item_bits,
                endianness,
                ref packet_length,
            } => Some((item_ty, item_bits, endianness, packet_length.as_ref())),
            _ => None,
        }
    }

    pub fn as_custom(&self) -> Option<&[syn::Ident]> {
        match self.kind {
            Kind::Custom { ref construct_with } => Some(construct_with),
            _ => None,
        }
    }

    pub fn is_payload(&self) -> bool {
        match self.kind {
            Kind::Vec {
                ref packet_length, ..
            } => packet_length.is_none(),
            Kind::Custom {
                ref construct_with, ..
            } => construct_with.is_empty(),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

}
