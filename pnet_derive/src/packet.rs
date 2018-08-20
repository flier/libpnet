use proc_macro2::{Span, TokenStream};
use quote::{ToTokens, TokenStreamExt};
use syn::{self, spanned::Spanned};

use field::Field;
use gen::{Generator, PacketGenerator};
use types::Result;

pub fn parse(input: syn::DeriveInput) -> Result<Vec<Packet>> {
    let name = input.ident;

    match input.vis {
        syn::Visibility::Public(_) => {}
        _ => bail!("#[packet] structs/enums {} must be public", name),
    }

    match input.data {
        syn::Data::Struct(s) => Packet::parse(name, s.fields).map(|packet| vec![packet]),
        syn::Data::Enum(e) => e
            .variants
            .into_iter()
            .map(|v| Packet::parse(v.ident, v.fields))
            .collect(),
        syn::Data::Union(_) => unimplemented!(),
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Packet {
    pub ident: syn::Ident,
    pub fields: Vec<Field>,
}

impl Packet {
    fn base_name(&self) -> &syn::Ident {
        &self.ident
    }

    fn immutable_packet_name(&self) -> syn::Ident {
        syn::Ident::new(&format!("{}Packet", self.base_name()), Span::call_site())
    }

    fn mutable_packet_name(&self) -> syn::Ident {
        syn::Ident::new(
            &format!("Mutable{}Packet", self.base_name()),
            Span::call_site(),
        )
    }

    fn packet_name(&self, mutable: bool) -> syn::Ident {
        if mutable {
            self.mutable_packet_name()
        } else {
            self.immutable_packet_name()
        }
    }

    fn packet_data(&self, mutable: bool) -> syn::Ident {
        syn::Ident::new(
            if mutable {
                "MutPacketData"
            } else {
                "PacketData"
            },
            Span::call_site(),
        )
    }

    fn parse(ident: syn::Ident, fields: syn::Fields) -> Result<Packet> {
        if let syn::Fields::Named(fields) = fields {
            let fields = fields
                .named
                .into_iter()
                .map(Field::parse)
                .collect::<Result<Vec<_>>>()?;

            if fields.iter().rev().skip(1).any(|field| {
                field
                    .as_vec()
                    .map(|(_, _, _, packet_length)| packet_length.is_none() && field.is_payload())
                    .unwrap_or_default()
            }) {
                bail!("#[payload] must specify a #[length] or #[length_fn] attribute, unless it is the last field of a packet")
            }

            match fields.iter().filter(|field| field.is_payload()).count() {
                0 => bail!("#[packet] must contain a payload field"),
                1 => Ok(Packet { ident, fields }),
                _ => bail!("#[packet] may not have multiple payloads"),
            }
        } else {
            bail!("{} all fields in a packet must be named", ident)
        }
    }
}

impl ToTokens for Packet {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.append_all(&[
            PacketGenerator::new(self, false).tokens(),
            PacketGenerator::new(self, true).tokens(),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_struct() {
        let foo: syn::DeriveInput = parse_quote! {
            #[packet]
            struct Foo{
                bar: Vec<u8>,
            }
        };

        assert_eq!(
            parse(foo).unwrap_err().to_string(),
            "#[packet] structs/enums Foo must be public"
        );
    }

    #[test]
    fn test_payload_field_without_length_in_middle() {
        let foo: syn::DeriveInput = parse_quote! {
            #[packet]
            pub struct Foo{
                #[payload]
                bar: Vec<u8>,

                payload: Vec<u8>
            }
        };

        assert_eq!(
            parse(foo).unwrap_err().to_string(),
            "variable length field must have #[length] or #[length_fn] attribute"
        );
    }

    #[test]
    fn test_packet_without_payload() {
        let foo: syn::DeriveInput = parse_quote! {
            #[packet]
            pub struct Foo{
                bar: u8
            }
        };

        assert_eq!(
            parse(foo).unwrap_err().to_string(),
            "#[packet] must contain a payload field"
        );
    }

    #[test]
    fn test_packet_with_multi_payload() {
        let foo: syn::DeriveInput = parse_quote! {
            #[packet]
            pub struct Foo{
                #[payload]
                foo: Bar,

                #[payload]
                bar: Vec<u8>,
            }
        };

        assert_eq!(
            parse(foo).unwrap_err().to_string(),
            "#[packet] may not have multiple payloads"
        );
    }
}
